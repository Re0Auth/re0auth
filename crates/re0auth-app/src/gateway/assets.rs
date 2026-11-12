use super::*;

use crate::gateway_assets::{MagicStatus, asset_stream, validate_magic_prefix};
use re0auth_api::connector::{AssetPayload, AssetResponse, ResponseKind};

struct FlightGuard {
    key: String,
    flights: FlightMap,
    flight: Arc<AssetFlight>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    detached: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        self.flights.lock().remove(&self.key);
        if self.flight.outcome().is_none() {
            self.flight.finish(Err(UpstreamError::Internal));
        }
    }
}

impl GatewayService {
    pub async fn fetch_asset(
        &self,
        request: GatewayRequest<'_>,
        accept: Option<&str>,
    ) -> Result<AssetResponse, GatewayError> {
        let AuthorizedFetch {
            endpoint,
            spec,
            binding,
            subject,
            params,
            cache_key,
            ..
        } = self.authorize(&request).await?;
        if spec.response != ResponseKind::Binary {
            return Err(GatewayError::UnknownResource);
        }
        if self.asset_spawner.is_none() {
            return Err(GatewayError::Internal);
        }
        let acceptable = accept.is_some_and(|accept| {
            accept.split(',').any(|entry| {
                let media = entry.split(';').next().unwrap_or_default().trim();
                media == "*/*" || spec.content_types.iter().any(|allowed| allowed == media)
            })
        });
        if !acceptable {
            return Err(GatewayError::NotAcceptable);
        }
        if let Some(cached) = self.asset_cache.get(&cache_key).await {
            self.observer.cache_hit(&endpoint.name, request.resource);
            self.record_access(&request, &endpoint, AccessSource::Cache, 0);
            return Ok(AssetResponse::Buffered(AssetPayload {
                content_type: cached.content_type().to_string(),
                body: cached.body_bytes(),
            }));
        }
        self.observer.cache_miss(&endpoint.name, request.resource);

        if let Some(flight) = self.existing_flight(&cache_key)? {
            return asset_stream(flight)
                .await
                .map(AssetResponse::Streaming)
                .map_err(GatewayError::Upstream);
        }

        let now = self.clock.now();
        let connector_probe = self
            .circuit
            .probe(CircuitKey::Connector(endpoint.id), now)
            .map_err(|retry_after_secs| GatewayError::CircuitOpen { retry_after_secs })?;
        let binding_probe = match &binding {
            Some(binding) => Some(
                self.circuit
                    .probe(CircuitKey::Binding(endpoint.id, binding.id), now)
                    .map_err(|retry_after_secs| GatewayError::CircuitOpen { retry_after_secs })?,
            ),
            None => None,
        };
        let sub_token = match &binding {
            Some(binding) => {
                self.access_token(binding, now, request.correlation_id)
                    .await?
            }
            None => re0auth_api::SecretString::from(String::new()),
        };
        let permit = match tokio::time::timeout(
            self.asset_acquire_timeout,
            self.global_loaders.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) | Err(_) => return Err(UpstreamError::Overloaded.into()),
        };
        let (flight, created) = {
            let mut flights = self.flights.lock();
            if let Some(flight) = flights.get(&cache_key) {
                (Arc::clone(flight), false)
            } else {
                if let Some(error) = self
                    .failure_cache
                    .as_ref()
                    .and_then(|cache| cache.get(&cache_key))
                {
                    return Err(GatewayError::Upstream(error));
                }
                let flight = AssetFlight::new();
                flights.insert(cache_key.clone(), Arc::clone(&flight));
                (flight, true)
            }
        };
        if !created {
            drop(permit);
            return asset_stream(flight)
                .await
                .map(AssetResponse::Streaming)
                .map_err(GatewayError::Upstream);
        }
        let resource = ResourceRequest::new(request.resource, subject).with_params(params);
        self.spawn_asset_loader(
            endpoint,
            spec,
            sub_token,
            resource,
            cache_key,
            Arc::clone(&flight),
            permit,
            connector_probe,
            binding_probe,
        );
        asset_stream(flight)
            .await
            .map(AssetResponse::Streaming)
            .map_err(GatewayError::Upstream)
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_asset_loader(
        &self,
        endpoint: ConnectorEndpoint,
        spec: ResourceSpec,
        sub_token: re0auth_api::SecretString,
        resource: ResourceRequest,
        cache_key: String,
        flight: Arc<AssetFlight>,
        permit: tokio::sync::OwnedSemaphorePermit,
        mut connector_probe: Probe,
        mut binding_probe: Option<Probe>,
    ) {
        use futures_util::FutureExt;

        let service = self.clone();
        let spawner = self
            .asset_spawner
            .clone()
            .expect("asset spawner checked by fetch_asset");
        let task = async move {
            let mut guard = FlightGuard {
                key: cache_key.clone(),
                flights: Arc::clone(&service.flights),
                flight: Arc::clone(&flight),
                _permit: permit,
                detached: None,
            };
            let now = service.clock.now();
            let result = tokio::time::timeout(service.asset_deadline, async {
                let (content_type, full) = service
                    .run_asset_loader(
                        &endpoint,
                        &spec,
                        &sub_token,
                        &resource,
                        Arc::clone(&flight),
                        &mut guard,
                    )
                    .await?;
                service
                    .asset_cache
                    .put(
                        &cache_key,
                        &re0auth_api::cache::CachedResponse::new(
                            content_type.clone(),
                            full.clone(),
                        ),
                        service.cache_ttl,
                    )
                    .await;
                Ok::<_, UpstreamError>((content_type, full))
            })
            .await;
            match result {
                Ok(Ok((_content_type, full))) => {
                    flight.finish(Ok(full));
                    connector_probe.settle(Outcome::Success, now);
                    if let Some(probe) = &mut binding_probe {
                        probe.settle(Outcome::Success, now);
                    }
                }
                Ok(Err(error)) => {
                    if !service.asset_negative_ttl.is_zero()
                        && matches!(
                            error,
                            UpstreamError::NotFound
                                | UpstreamError::Unavailable
                                | UpstreamError::ContractChanged
                        )
                        && let Some(cache) = &service.failure_cache
                    {
                        cache.put(cache_key, error.clone(), service.asset_negative_ttl);
                    }
                    let outcome = Outcome::from_fault_class(error.fault_class());
                    flight.finish(Err(error));
                    connector_probe.settle(outcome, now);
                    if let Some(probe) = &mut binding_probe {
                        probe.settle(outcome, now);
                    }
                }
                Err(_) => {
                    let outcome = Outcome::Internal;
                    flight.finish(Err(UpstreamError::Unavailable));
                    connector_probe.settle(outcome, now);
                    if let Some(probe) = &mut binding_probe {
                        probe.settle(outcome, now);
                    }
                }
            }
        };
        spawner.spawn(Box::pin(async move {
            if let Err(panic) = std::panic::AssertUnwindSafe(task).catch_unwind().await {
                let message = panic
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("non-string panic");
                tracing::error!(message, "asset loader panicked");
            }
        }));
    }

    async fn run_asset_loader(
        &self,
        endpoint: &ConnectorEndpoint,
        spec: &ResourceSpec,
        sub_token: &re0auth_api::SecretString,
        resource: &ResourceRequest,
        flight: Arc<AssetFlight>,
        guard: &mut FlightGuard,
    ) -> Result<(String, bytes::Bytes), UpstreamError> {
        use futures_util::StreamExt;

        let accept = spec.content_types.join(",");
        let max_body = spec
            .max_bytes
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(self.max_response_bytes)
            .min(self.max_response_bytes);
        let mut upstream = self
            .broker
            .fetch_asset_stream(endpoint, sub_token, resource, &accept, max_body)
            .await?;
        if !spec.content_types.contains(&upstream.content_type) {
            return Err(UpstreamError::ContractChanged);
        }
        let content_type = upstream.content_type;
        let mut prefix = bytes::BytesMut::new();
        let mut published = false;
        let mut total = 0usize;
        while let Some(chunk) = upstream.body.next().await {
            let chunk = chunk?;
            total = total
                .checked_add(chunk.len())
                .filter(|total| *total <= max_body)
                .ok_or(UpstreamError::Truncated)?;
            if !published {
                prefix.extend_from_slice(&chunk);
                if prefix.len() < 12 {
                    continue;
                }
                match validate_magic_prefix(&content_type, &prefix, false) {
                    MagicStatus::Incomplete => continue,
                    MagicStatus::Invalid => return Err(UpstreamError::ContractChanged),
                    MagicStatus::Valid => {}
                }
                flight.publish_content_type(Ok(content_type.clone()));
                self.ensure_asset_reader_permit(&flight, guard)?;
                flight.append(prefix.split().freeze());
                published = true;
            } else {
                self.ensure_asset_reader_permit(&flight, guard)?;
                flight.append(chunk);
            }
        }
        if !published {
            if validate_magic_prefix(&content_type, &prefix, true) != MagicStatus::Valid {
                return Err(UpstreamError::ContractChanged);
            }
            flight.publish_content_type(Ok(content_type.clone()));
            self.ensure_asset_reader_permit(&flight, guard)?;
            flight.append(prefix.freeze());
        }
        Ok((content_type, flight.assemble()))
    }

    fn ensure_asset_reader_permit(
        &self,
        flight: &Arc<AssetFlight>,
        guard: &mut FlightGuard,
    ) -> Result<(), UpstreamError> {
        if flight.subscriber_count() == 0 && guard.detached.is_none() {
            let permit = self
                .detached_fill
                .clone()
                .try_acquire_owned()
                .map_err(|_| UpstreamError::Internal)?;
            guard.detached = Some(permit);
        }
        Ok(())
    }

    fn existing_flight(&self, cache_key: &str) -> Result<Option<Arc<AssetFlight>>, GatewayError> {
        let flights = self.flights.lock();
        if let Some(flight) = flights.get(cache_key) {
            return Ok(Some(Arc::clone(flight)));
        }
        if let Some(error) = self
            .failure_cache
            .as_ref()
            .and_then(|cache| cache.get(cache_key))
        {
            return Err(GatewayError::Upstream(error));
        }
        Ok(None)
    }
}
