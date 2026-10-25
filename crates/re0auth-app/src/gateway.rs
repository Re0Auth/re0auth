//! Gateway use case: scope check -> binding lookup -> connector fetch.
//!
//! Identity flows do not depend on this module (INV-LOGIN-03).
use re0auth_api::audit::{AccessSource, AccessTelemetry, AuditAction, SecurityFact};

use std::sync::Arc;

use re0auth_api::cache::Cache;
use re0auth_api::connector::{
    BindingAction, ConnectorBroker, ConnectorEndpoint, ConnectorRegistry, FaultClass,
    ResourceRequest, UpstreamError, UpstreamPayload,
};
use re0auth_api::ports::{Binding, BindingStatus, NoTelemetry, Storage, TelemetrySink};
use re0auth_api::secret::SecretSealer;
use re0auth_api::{AuditId, ClientId, Clock, ConnectorId, Re0Error, UserId};
use re0auth_domain::gateway::{self, InvalidResource, ResourceField};
use uuid::Uuid;

use crate::circuit::{Admission, CircuitKey, CircuitTracker, Outcome};

#[derive(Clone, Debug)]
pub struct GatewayRequest<'a> {
    pub user_id: UserId,
    /// The client that owns the access token. Trusted: it comes from the
    /// verified token, never from a request parameter.
    pub client_id: &'a str,
    pub granted_scopes: &'a [String],
    pub connector_id: ConnectorId,
    pub resource: &'a str,
    /// Raw view (INV-RAW-01). Requires both `client.raw_access` and the
    /// `<connector>.raw.read` scope; either one missing is a refusal.
    pub raw: bool,
    /// The HTTP `X-Request-Id`, recorded on any audit row this call produces.
    pub correlation_id: Option<&'a str>,
}

impl GatewayRequest<'_> {
    /// The subject is read from the binding, never from a request parameter:
    /// `DESIGN.md` §9 requires identity parameters to be injected by the
    /// server. Letting a caller choose the subject would be a direct IDOR.
    fn subject_for(binding: &Binding) -> Result<&str, GatewayError> {
        let subject = binding.upstream_user_id.as_str();
        gateway::validate_subject(subject)
            .map_err(|error| GatewayError::InvalidResource(error.field(ResourceField::Subject)))?;
        Ok(subject)
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GatewayError {
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("invalid {0}")]
    InvalidResource(InvalidResource),
    #[error("insufficient scope")]
    InsufficientScope,
    #[error("binding required")]
    BindingRequired,
    #[error("binding needs reauthentication")]
    BindingNeedsReauth,
    #[error("binding is not active")]
    BindingInactive,
    #[error("connector not registered")]
    ConnectorNotFound,
    #[error("resource not registered on this connector")]
    UnknownResource,
    /// INV-RAW-01: the client is not approved for the raw view. Distinct from
    /// `insufficient_scope` on purpose — the caller cannot fix this by asking
    /// for another scope, because `raw_access` is an operator decision.
    #[error("client is not allowed the raw view")]
    RawNotAllowed,
    #[error("circuit open")]
    CircuitOpen { retry_after_secs: i64 },
    #[error("upstream: {0}")]
    Upstream(#[from] UpstreamError),
    #[error("internal error")]
    Internal,
}

impl GatewayError {
    /// Only internal failures feed metrics and breakers (INV-GW-03).
    #[must_use]
    pub fn fault_class(&self) -> FaultClass {
        match self {
            Self::Upstream(error) => error.fault_class(),
            Self::Internal => FaultClass::Internal,
            _ => FaultClass::Business,
        }
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) | Self::InvalidResource(_) => "invalid_request",
            Self::InsufficientScope => "insufficient_scope",
            Self::BindingRequired => "binding_required",
            Self::BindingNeedsReauth => "upstream_needs_reauth",
            Self::BindingInactive => "access_denied",
            Self::ConnectorNotFound => "unknown_connector",
            Self::UnknownResource => "endpoint_not_found",
            Self::RawNotAllowed => "raw_not_allowed",
            Self::CircuitOpen { .. } => "upstream_busy",
            Self::Upstream(UpstreamError::CredentialExpired) => "upstream_needs_reauth",
            Self::Upstream(UpstreamError::InsufficientScope) => "insufficient_scope",
            Self::Upstream(UpstreamError::NotFound) => "not_found",
            Self::Upstream(UpstreamError::RateLimited { .. }) => "upstream_rate_limited",
            Self::Upstream(UpstreamError::Truncated) => "upstream_response_too_large",
            // The upstream refused the parameters we sent. That is a request
            // problem on this endpoint, not a broken upstream, and it must not
            // share `upstream_unavailable` — that would read as "the upstream is
            // down" and send operators looking in the wrong place.
            Self::Upstream(UpstreamError::Rejected) => "invalid_parameter",
            // INV-RES-01: distinct from `upstream_unavailable` on purpose. The
            // upstream is healthy; we refused the request before sending it. An
            // operator who sees `upstream_unavailable` here would investigate the
            // wrong system.
            Self::Upstream(UpstreamError::Overloaded) => "upstream_capacity_exhausted",
            Self::Upstream(_) => "upstream_unavailable",
            Self::Internal => "internal_error",
        }
    }
}

/// Maps a connector's configured name to its id. The name is part of the public
/// URL, so the id must be stable across restarts and deploys; a name-based
/// UUIDv5 gives the same value every time without persisting a lookup table.
#[must_use]
pub fn connector_id_for_name(name: &str) -> ConnectorId {
    ConnectorId(Uuid::new_v5(&CONNECTOR_NAMESPACE, name.as_bytes()))
}

/// Fixed namespace for connector ids. Changing it re-keys every binding.
const CONNECTOR_NAMESPACE: Uuid = Uuid::from_bytes([
    0x52, 0x65, 0x30, 0x41, 0x75, 0x74, 0x68, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72,
]);

pub struct GatewayService {
    storage: Arc<dyn Storage>,
    registry: Arc<dyn ConnectorRegistry>,
    broker: Arc<dyn ConnectorBroker>,
    sealer: Arc<dyn SecretSealer>,
    clock: Arc<dyn Clock>,
    circuit: Arc<CircuitTracker>,
    max_response_bytes: usize,
    /// INV-CACHE-01: consulted only after the scope gate, the binding lookup and
    /// the binding status check have all passed. Moving a read above any of
    /// those would serve another scope's or a revoked binding's data.
    cache: Arc<dyn Cache>,
    /// How long a written entry stays fresh. Staleness beyond this is handled by
    /// the cache port, which keeps the entry readable for the outage path.
    cache_ttl: std::time::Duration,
    /// Lossy access telemetry (ADR-0025). Defaults to a discarding sink, so an
    /// unwired deployment has no ledger rather than a silent half-one.
    telemetry: Arc<dyn TelemetrySink>,
}

impl GatewayService {
    #[must_use]
    pub fn new(
        storage: Arc<dyn Storage>,
        registry: Arc<dyn ConnectorRegistry>,
        broker: Arc<dyn ConnectorBroker>,
        sealer: Arc<dyn SecretSealer>,
        clock: Arc<dyn Clock>,
        circuit: Arc<CircuitTracker>,
        max_response_bytes: usize,
    ) -> Self {
        Self {
            storage,
            registry,
            broker,
            sealer,
            clock,
            circuit,
            max_response_bytes,
            cache: Arc::new(re0auth_api::cache::NoCache),
            cache_ttl: std::time::Duration::from_secs(300),
            telemetry: Arc::new(NoTelemetry),
        }
    }

    /// Enables access telemetry (ADR-0025).
    ///
    /// Separate from [`Self::new`] so un-wired deployments keep compiling, and
    /// so "no access ledger" is an explicit default instead of an oversight.
    #[must_use]
    pub fn with_telemetry(mut self, telemetry: Arc<dyn TelemetrySink>) -> Self {
        self.telemetry = telemetry;
        self
    }

    /// Records one served read. Best-effort: a full queue drops, never blocks.
    fn record_access(
        &self,
        request: &GatewayRequest<'_>,
        endpoint: &ConnectorEndpoint,
        source: AccessSource,
        latency_ms: u64,
    ) {
        let client_id = uuid::Uuid::parse_str(request.client_id).ok().map(ClientId);
        let event = AccessTelemetry {
            id: AuditId::new(),
            occurred_at: self.clock.now(),
            actor_user_id: Some(request.user_id),
            client_id,
            connector: endpoint.name.clone(),
            resource: request.resource.to_string(),
            source,
            latency_ms,
            request_id: request.correlation_id.map(str::to_string),
        };
        self.telemetry.record(event);
    }

    /// Enables the response cache.
    ///
    /// Separate from [`Self::new`] so existing wiring keeps compiling without
    /// opting in, and so the default is "cache nothing" rather than a silent
    /// behaviour change.
    #[must_use]
    pub fn with_cache(mut self, cache: Arc<dyn Cache>, ttl: std::time::Duration) -> Self {
        self.cache = cache;
        self.cache_ttl = ttl;
        self
    }

    pub async fn fetch(
        &self,
        request: GatewayRequest<'_>,
    ) -> Result<UpstreamPayload, GatewayError> {
        gateway::validate_resource_name(request.resource)
            .map_err(|error| GatewayError::InvalidResource(error.field(ResourceField::Name)))?;

        let endpoint = match self.registry.resolve(&request.connector_id).await {
            Ok(endpoint) => endpoint,
            Err(Re0Error::Business(_)) => return Err(GatewayError::ConnectorNotFound),
            Err(Re0Error::Internal(_)) => return Err(GatewayError::Internal),
        };

        // Registered resources only: an unlisted name never reaches the broker.
        // The required scope comes from the registry entry, so a caller cannot
        // declare its own scope.
        let Some(spec) = endpoint.resource(request.resource) else {
            return Err(GatewayError::UnknownResource);
        };
        let required_scope = spec.required_scope.clone();

        if !gateway::scope_allows(request.granted_scopes, &required_scope) {
            return Err(GatewayError::InsufficientScope);
        }

        if request.raw {
            self.authorize_raw(&request, &endpoint.name).await?;
        }

        // `bindings.upstream_id` stores the connector's name, not its derived
        // id: the name is what the operator configured and what the portal
        // shows, and it survives a change to the id derivation.
        let binding = self
            .storage
            .bindings()
            .find(&request.user_id, &endpoint.name)
            .await
            .map_err(|_| GatewayError::Internal)?
            .ok_or(GatewayError::BindingRequired)?;

        match binding.status {
            BindingStatus::Active => {}
            BindingStatus::NeedsReauth => return Err(GatewayError::BindingNeedsReauth),
            _ => return Err(GatewayError::BindingInactive),
        }

        let subject = GatewayRequest::subject_for(&binding)?;

        // INV-CACHE-01: the cache is consulted HERE and nowhere earlier. By
        // this line the scope gate, the binding lookup and the binding status
        // check have all passed. Moving this read above any of them would let a
        // caller without the scope — or with a revoked binding — receive a
        // cached payload, which is a privilege escalation rather than a cache
        // bug.
        //
        // Raw requests are never cached (INV-CACHE-03): the raw view exists to
        // show what the upstream actually returned, so a replayed older body
        // would misrepresent the current state.
        let cache_key = re0auth_api::cache::key(&binding.id, &endpoint.name, request.resource);
        // Short-circuit order matters: `request.raw` is checked first, so a raw
        // request never even touches the cache.
        if !request.raw
            && let Some(cached) = self.cache.get(&cache_key).await
        {
            // A cache hit is still a read of this user's data, so it belongs in
            // the access ledger; `latency_ms = 0` marks that no upstream call
            // was made.
            self.record_access(&request, &endpoint, AccessSource::Cache, 0);
            return Ok(UpstreamPayload {
                content_type: cached.content_type,
                body: cached.body,
            });
        }

        let sealed = self
            .storage
            .bindings()
            .load_sub_credential(&binding.id)
            .await
            .map_err(|_| GatewayError::Internal)?
            .ok_or(GatewayError::BindingNeedsReauth)?;
        let sub_token = self
            .sealer
            .open(&binding.id, &sealed)
            .map_err(|_| GatewayError::Internal)?;

        let connector_key = CircuitKey::Connector(endpoint.id);
        let binding_key = CircuitKey::Binding(endpoint.id, binding.id);
        let now = self.clock.now();
        // `admit` claims the single half-open probe slot as a side effect, so
        // every early exit below has to give back whatever it took. Otherwise
        // the key stays half-open with the slot held forever and rejects every
        // later caller until restart.
        if let Admission::Reject { retry_after_secs } = self.circuit.admit(&connector_key, now) {
            return Err(GatewayError::CircuitOpen { retry_after_secs });
        }
        if let Admission::Reject { retry_after_secs } = self.circuit.admit(&binding_key, now) {
            self.circuit.release_probe(&connector_key, now);
            return Err(GatewayError::CircuitOpen { retry_after_secs });
        }

        let resource = ResourceRequest::new(request.resource, subject);
        let started = std::time::Instant::now();
        match self
            .broker
            .fetch_raw_data(&endpoint, &sub_token, &resource)
            .await
        {
            Ok(payload) => {
                if payload.body.len() > self.max_response_bytes {
                    // An oversized response is an upstream-wide condition, so it
                    // counts against the connector only. Opening the binding
                    // breaker as well would refuse that one binding for 30
                    // minutes over a problem that is not specific to it.
                    self.circuit.settle(&connector_key, Outcome::Internal, now);
                    return Err(UpstreamError::Truncated.into());
                }
                self.circuit.settle(&connector_key, Outcome::Success, now);
                self.circuit.settle(&binding_key, Outcome::Success, now);
                // Only a complete response is cached. A truncated one is
                // rejected above, so reaching here means the body is whole.
                if !request.raw {
                    self.cache
                        .put(
                            &cache_key,
                            &re0auth_api::cache::CachedResponse {
                                content_type: payload.content_type.clone(),
                                body: payload.body.clone(),
                                stale: false,
                            },
                            self.cache_ttl,
                        )
                        .await;
                }
                // Recorded only on a served read: a failure is an error, not a
                // read, and inventing a ledger row for it would blur the two.
                let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                self.record_access(&request, &endpoint, AccessSource::Upstream, latency_ms);
                Ok(payload)
            }
            Err(error) => {
                self.apply_failure(
                    &binding,
                    &connector_key,
                    &binding_key,
                    &error,
                    now,
                    request.correlation_id,
                )
                .await?;
                Err(error.into())
            }
        }
    }

    /// INV-RAW-01: two independent gates, both required.
    ///
    /// `raw_access` is an operator decision recorded on the client; the raw scope
    /// is a per-token grant the user consented to. Requiring both means a leaked
    /// token from an ordinary client cannot reach the raw view, and flipping
    /// `raw_access` on does not retroactively widen tokens already issued.
    async fn authorize_raw(
        &self,
        request: &GatewayRequest<'_>,
        connector_name: &str,
    ) -> Result<(), GatewayError> {
        let client_id: ClientId = request
            .client_id
            .parse::<Uuid>()
            .map(ClientId)
            .map_err(|_| GatewayError::InvalidRequest("client id is malformed"))?;
        let client = self
            .storage
            .clients()
            .get(&client_id)
            .await
            .map_err(|_| GatewayError::Internal)?
            .ok_or(GatewayError::InvalidRequest("client is unknown"))?;
        if !client.raw_access {
            return Err(GatewayError::RawNotAllowed);
        }

        let raw_scope = format!("{connector_name}.raw.read");
        if !gateway::scope_allows(request.granted_scopes, &raw_scope) {
            return Err(GatewayError::RawNotAllowed);
        }
        Ok(())
    }

    async fn apply_failure(
        &self,
        binding: &Binding,
        connector_key: &CircuitKey,
        binding_key: &CircuitKey,
        error: &UpstreamError,
        now: i64,
        correlation_id: Option<&str>,
    ) -> Result<(), GatewayError> {
        match error.fault_class() {
            FaultClass::Business => {
                // A 4xx still proves reachability: close any open probe.
                self.circuit.settle(connector_key, Outcome::Business, now);
                self.circuit.settle(binding_key, Outcome::Business, now);
                if error.binding_action() == BindingAction::NeedsReauth {
                    self.storage
                        .bindings()
                        .mark_needs_reauth(
                            &binding.id,
                            "upstream_401",
                            &SecurityFact::new(
                                AuditAction::BindingNeedsReauth,
                                now,
                                format!("binding:{}", binding.id.0),
                            )
                            .actor(binding.user_id)
                            .with_request_id(correlation_id),
                            now,
                        )
                        .await
                        .map_err(|_| GatewayError::Internal)?;
                }
            }
            FaultClass::Internal => {
                self.circuit.settle(connector_key, Outcome::Internal, now);
                // The binding key was admitted for this request, so it must be
                // settled too. Leaving it half-open holds its probe slot and
                // rejects every later request for this binding — a permanent
                // 503 that outlives the upstream's outage.
                self.circuit.settle(binding_key, Outcome::Internal, now);
            }
            _ => {}
        }
        Ok(())
    }

    /// Exposed so the caller can verify breaker state without reading internals.
    #[must_use]
    pub fn retry_after(&self, connector_id: ConnectorId, now: i64) -> Option<i64> {
        self.circuit
            .retry_after(&CircuitKey::Connector(connector_id), now)
    }

    #[must_use]
    pub fn binding_retry_after(
        &self,
        connector_id: ConnectorId,
        binding_id: re0auth_api::BindingId,
        now: i64,
    ) -> Option<i64> {
        self.circuit
            .retry_after(&CircuitKey::Binding(connector_id, binding_id), now)
    }
}
