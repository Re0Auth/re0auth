//! Gateway use case: scope check -> binding lookup -> connector fetch.
//!
//! Identity flows do not depend on this module (INV-LOGIN-03).
use re0auth_api::audit::{AccessSource, AccessTelemetry, AuditAction, SecurityFact};

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::ExposeSecret;
use serde::Serialize;
use serde_json::Value;

use re0auth_api::cache::Cache;
use re0auth_api::connector::{
    BindingAction, ConnectorBroker, ConnectorEndpoint, ConnectorRegistry, FaultClass, ParamKind,
    ResourceRequest, ResourceSpec, UpstreamError, UpstreamPayload, ValidatedParamValue,
};
use re0auth_api::ports::{Binding, BindingStatus, NoTelemetry, Storage, TelemetrySink, UserStatus};
use re0auth_api::secret::SecretSealer;
use re0auth_api::view::{ViewOutput, ViewSpec};
use re0auth_api::{AuditId, ClientId, Clock, ConnectorId, Re0Error, UserId};
use re0auth_domain::gateway::{self, InvalidResource, ResourceField};
use uuid::Uuid;

use crate::circuit::{CircuitKey, CircuitTracker, Outcome, Probe};
use crate::credentials::{CredentialError, CredentialSource};
use crate::upstream_models::UpstreamData;

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
    /// `limit`/`cursor` from the query string. Only list views accept them.
    pub pagination: Pagination,
    /// Complete raw query map, including `limit`/`cursor`; validated below.
    pub params: &'a BTreeMap<String, String>,
}

/// Query-string pagination, before it is checked against the resource's view.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Pagination {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
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
    #[error("binding has been revoked")]
    BindingRevoked,
    /// The upstream JSON does not satisfy the declared view (ADR-0049).
    #[error("upstream response does not match the declared view")]
    ContractChanged,
    /// The account is banned (B15); checked on every data-plane read.
    #[error("account is banned")]
    AccountBanned,
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

/// One page of a list view, carried inside the envelope's `data`.
#[derive(Serialize, utoipa::ToSchema)]
pub struct PageBody {
    items: Vec<Value>,
    next_cursor: Option<String>,
}

/// The B8 envelope (ADR-0049). Six fields, no more.
#[derive(Serialize, utoipa::ToSchema)]
pub struct Envelope<'a> {
    upstream: &'a str,
    endpoint: &'a str,
    fetched_at: i64,
    request_id: Option<&'a str>,
    stability: &'static str,
    #[schema(value_type = UpstreamData)]
    data: Value,
}

/// What the cache stores for a normalized resource.
///
/// `fetched_at` travels with the data so a cache hit can keep telling the truth
/// about when the upstream was actually read.
#[derive(Serialize, serde::Deserialize)]
struct CachedView {
    fetched_at: i64,
    /// The view-applied JSON, already encoded.
    ///
    /// Keeping bytes (rather than a `Value`) means a cache hit splices the data
    /// into the envelope instead of rebuilding the whole JSON tree.
    data: Vec<u8>,
}

const DEFAULT_PAGE_LIMIT: u32 = 20;
const MAX_PAGE_LIMIT: u32 = 100;
const MAX_ATTEMPTS: u32 = 3;
const RETRY_BASE_MS: u64 = 100;

/// Only transport failures are worth a second attempt.
///
/// Every business outcome (401/403/404/400/422) is permanent for this request,
/// and a 500 was mapped to Internal before reaching here.
fn retryable(error: &UpstreamError) -> bool {
    matches!(error, UpstreamError::Unavailable)
}

/// Exponential backoff with jitter.
///
/// The jitter exists so instances that failed together do not retry together.
/// It carries no business meaning, so it deliberately does not go through the
/// clock port.
fn retry_delay(attempt: u32) -> std::time::Duration {
    let base = RETRY_BASE_MS << (attempt - 1).min(4);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::from(elapsed.subsec_nanos()))
        .unwrap_or(0);
    std::time::Duration::from_millis(base + nanos % (base + 1))
}

impl CachedView {
    /// Parses the upstream body and applies the declared view.
    fn from_body(
        body: &[u8],
        view: Option<&ViewSpec>,
        fetched_at: i64,
    ) -> Result<Self, GatewayError> {
        let value: Value =
            serde_json::from_slice(body).map_err(|_| GatewayError::ContractChanged)?;
        let data = match view {
            None => value,
            Some(view) => match view
                .apply(&value)
                .map_err(|_| GatewayError::ContractChanged)?
            {
                ViewOutput::Single(value) => value,
                ViewOutput::Items(items) => Value::Array(items),
            },
        };
        let data = serde_json::to_vec(&data).map_err(|_| GatewayError::Internal)?;
        Ok(Self { fetched_at, data })
    }

    /// `[fetched_at: i64 BE][data JSON]`.
    ///
    /// A hand-rolled header rather than a JSON wrapper: the point is to avoid
    /// re-serialising the view on the way into the cache.
    fn encode(&self) -> Result<Vec<u8>, GatewayError> {
        let mut out = Vec::with_capacity(8 + self.data.len());
        out.extend_from_slice(&self.fetched_at.to_be_bytes());
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    fn decode(body: &[u8]) -> Result<Self, GatewayError> {
        if body.len() < 8 {
            return Err(GatewayError::Internal);
        }
        let (head, data) = body.split_at(8);
        let fetched_at = i64::from_be_bytes(head.try_into().map_err(|_| GatewayError::Internal)?);
        Ok(Self {
            fetched_at,
            data: data.to_vec(),
        })
    }
}

fn page_body(pagination: &Pagination, items: &[Value]) -> Result<PageBody, GatewayError> {
    let limit = usize::try_from(pagination.limit.unwrap_or(DEFAULT_PAGE_LIMIT))
        .map_err(|_| GatewayError::Internal)?;
    let offset = match &pagination.cursor {
        None => 0,
        Some(raw) => decode_cursor(raw)?,
    };
    let start = offset.min(items.len());
    let end = start.saturating_add(limit).min(items.len());
    let next_cursor = (end < items.len()).then(|| encode_cursor(end));
    Ok(PageBody {
        items: items[start..end].to_vec(),
        next_cursor,
    })
}

fn encode_cursor(offset: usize) -> String {
    URL_SAFE_NO_PAD.encode(offset.to_string())
}

fn decode_cursor(raw: &str) -> Result<usize, GatewayError> {
    let invalid = || GatewayError::InvalidRequest("cursor is invalid");
    let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| invalid())?;
    let text = String::from_utf8(bytes).map_err(|_| invalid())?;
    text.parse().map_err(|_| invalid())
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
            Self::BindingRevoked => "binding_revoked",
            Self::ContractChanged => "upstream_contract_changed",
            Self::AccountBanned => "account_banned",
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
    /// Optional credential provider. When absent (tests, legacy wiring), the
    /// gateway reads the sealed access token directly and cannot refresh.
    credentials: Option<Arc<dyn CredentialSource>>,
}

/// Applies the resource's declarative allow-list to the complete raw query map.
fn validate_params(
    spec: &ResourceSpec,
    supplied: &BTreeMap<String, String>,
    allow_pagination: bool,
) -> Result<BTreeMap<String, ValidatedParamValue>, GatewayError> {
    let mut validated = BTreeMap::new();
    for param in &spec.params {
        let Some(raw) = supplied.get(&param.name) else {
            if param.required {
                return Err(GatewayError::InvalidRequest("missing required parameter"));
            }
            continue;
        };
        let value = match param.kind {
            ParamKind::String => {
                let length = raw.chars().count();
                let min = param.min_len.unwrap_or(0);
                let max = param.max_len.unwrap_or(usize::MAX);
                if !(min..=max).contains(&length) {
                    return Err(GatewayError::InvalidRequest("invalid parameter value"));
                }
                ValidatedParamValue::String(raw.clone())
            }
            ParamKind::Enum => {
                if !param.values.iter().any(|value| value == raw) {
                    return Err(GatewayError::InvalidRequest("invalid parameter value"));
                }
                ValidatedParamValue::String(raw.clone())
            }
            ParamKind::Integer => {
                let parsed = raw
                    .parse::<i64>()
                    .map_err(|_| GatewayError::InvalidRequest("invalid parameter value"))?;
                if let Some(min) = param.min.as_ref().and_then(serde_json::Number::as_i64)
                    && parsed < min
                {
                    return Err(GatewayError::InvalidRequest("invalid parameter value"));
                }
                if let Some(max) = param.max.as_ref().and_then(serde_json::Number::as_i64)
                    && parsed > max
                {
                    return Err(GatewayError::InvalidRequest("invalid parameter value"));
                }
                ValidatedParamValue::Integer(parsed)
            }
            ParamKind::Number => {
                let parsed = raw
                    .parse::<f64>()
                    .map_err(|_| GatewayError::InvalidRequest("invalid parameter value"))?;
                if !parsed.is_finite() {
                    return Err(GatewayError::InvalidRequest("invalid parameter value"));
                }
                if let Some(min) = param.min.as_ref().and_then(serde_json::Number::as_f64)
                    && parsed < min
                {
                    return Err(GatewayError::InvalidRequest("invalid parameter value"));
                }
                if let Some(max) = param.max.as_ref().and_then(serde_json::Number::as_f64)
                    && parsed > max
                {
                    return Err(GatewayError::InvalidRequest("invalid parameter value"));
                }
                let value = serde_json::Number::from_f64(parsed)
                    .ok_or(GatewayError::InvalidRequest("invalid parameter value"))?;
                ValidatedParamValue::Number {
                    raw: raw.clone(),
                    value,
                }
            }
            ParamKind::Boolean => match raw.as_str() {
                "true" => ValidatedParamValue::Boolean(true),
                "false" => ValidatedParamValue::Boolean(false),
                _ => return Err(GatewayError::InvalidRequest("invalid parameter value")),
            },
        };
        validated.insert(param.name.clone(), value);
    }

    for key in supplied.keys() {
        if allow_pagination && matches!(key.as_str(), "limit" | "cursor") {
            continue;
        }
        if !spec.params.iter().any(|param| param.name == *key) {
            return Err(GatewayError::InvalidRequest("unknown query parameter"));
        }
    }
    Ok(validated)
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
            credentials: None,
        }
    }

    /// Enables on-demand upstream refresh.
    #[must_use]
    pub fn with_credentials(mut self, credentials: Arc<dyn CredentialSource>) -> Self {
        self.credentials = Some(credentials);
        self
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

        // B15: admission is enforced here too, not only at login. A banned
        // account keeps a valid-looking token until it expires, so a login-only
        // check would leave the data plane open for minutes.
        match self.storage.users().get(&request.user_id).await {
            Ok(Some(user)) if user.status == UserStatus::Banned => {
                return Err(GatewayError::AccountBanned);
            }
            Ok(Some(_)) => {}
            // A token naming a vanished user is an internal inconsistency, not a
            // client error.
            Ok(None) | Err(_) => return Err(GatewayError::Internal),
        }

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

        // Pagination belongs to the view, not to the upstream. Checking it here
        // keeps a malformed page from ever costing an upstream call.
        let list_view = spec
            .view
            .as_ref()
            .is_some_and(|view| view.items_path.is_some());
        let wants_page = request.pagination.limit.is_some() || request.pagination.cursor.is_some();
        if wants_page && (request.raw || !list_view) {
            return Err(GatewayError::InvalidRequest(
                "pagination is only available for list resources",
            ));
        }
        if let Some(limit) = request.pagination.limit
            && !(1..=MAX_PAGE_LIMIT).contains(&limit)
        {
            return Err(GatewayError::InvalidRequest(
                "limit must be between 1 and 100",
            ));
        }
        let params = validate_params(spec, request.params, list_view)?;

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
            BindingStatus::Revoked => return Err(GatewayError::BindingRevoked),
            // 生产不创建 pending，保留旧码避免误报
            BindingStatus::Pending => return Err(GatewayError::BindingInactive),
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
        let cache_key = re0auth_api::cache::key_with_params(
            &binding.id,
            &endpoint.name,
            request.resource,
            &params,
        );
        // Short-circuit order matters: `request.raw` is checked first, so a raw
        // request never even touches the cache.
        if !request.raw
            && let Some(cached) = self.cache.get(&cache_key).await
        {
            let snapshot = CachedView::decode(cached.body())?;
            // A cache hit is still a read of this user's data, so it belongs in
            // the access ledger; `latency_ms = 0` marks that no upstream call
            // was made.
            self.record_access(&request, &endpoint, AccessSource::Cache, 0);
            return self.normalized(&request, &endpoint, list_view, snapshot);
        }

        let now = self.clock.now();
        let sub_token = self
            .access_token(&binding, now, request.correlation_id)
            .await?;

        // Admission hands back a claim that releases its slot on drop, so a
        // cancelled request (timeout, client disconnect) cannot leave the key
        // half-open and rejecting every later caller until restart.
        let mut connector_probe = self
            .circuit
            .probe(CircuitKey::Connector(endpoint.id), now)
            .map_err(|retry_after_secs| GatewayError::CircuitOpen { retry_after_secs })?;
        let mut binding_probe = self
            .circuit
            .probe(CircuitKey::Binding(endpoint.id, binding.id), now)
            .map_err(|retry_after_secs| GatewayError::CircuitOpen { retry_after_secs })?;

        let resource = ResourceRequest::new(request.resource, subject).with_params(params);
        let started = std::time::Instant::now();
        match self
            .fetch_with_retry(&endpoint, &sub_token, &resource, spec.idempotent)
            .await
        {
            Ok(payload) => {
                self.finish_fetch(
                    &request,
                    &endpoint,
                    spec,
                    list_view,
                    payload,
                    started,
                    &mut connector_probe,
                    &mut binding_probe,
                    &cache_key,
                    now,
                )
                .await
            }
            Err(error) => {
                if matches!(error, UpstreamError::CredentialExpired)
                    && let Some(credentials) = &self.credentials
                {
                    match credentials
                        .refresh(&binding, sub_token.expose_secret())
                        .await
                    {
                        Ok(token) => {
                            match self
                                .fetch_with_retry(&endpoint, &token, &resource, spec.idempotent)
                                .await
                            {
                                Ok(payload) => {
                                    return self
                                        .finish_fetch(
                                            &request,
                                            &endpoint,
                                            spec,
                                            list_view,
                                            payload,
                                            started,
                                            &mut connector_probe,
                                            &mut binding_probe,
                                            &cache_key,
                                            now,
                                        )
                                        .await;
                                }
                                Err(retry_error) => {
                                    self.apply_failure(
                                        &binding,
                                        &mut connector_probe,
                                        &mut binding_probe,
                                        &retry_error,
                                        now,
                                        request.correlation_id,
                                    )
                                    .await?;
                                    return Err(retry_error.into());
                                }
                            }
                        }
                        Err(CredentialError::NeedsReauth) => {
                            connector_probe.settle(Outcome::Business, now);
                            binding_probe.settle(Outcome::Business, now);
                            self.mark_needs_reauth(
                                &binding,
                                "refresh_invalid_grant",
                                now,
                                request.correlation_id,
                            )
                            .await?;
                            return Err(error.into());
                        }
                        Err(CredentialError::Unavailable) => {
                            self.apply_failure(
                                &binding,
                                &mut connector_probe,
                                &mut binding_probe,
                                &UpstreamError::Unavailable,
                                now,
                                request.correlation_id,
                            )
                            .await?;
                            return Err(UpstreamError::Unavailable.into());
                        }
                        Err(CredentialError::Internal) => {
                            connector_probe.settle(Outcome::Internal, now);
                            binding_probe.settle(Outcome::Internal, now);
                            return Err(GatewayError::Internal);
                        }
                    }
                }
                self.apply_failure(
                    &binding,
                    &mut connector_probe,
                    &mut binding_probe,
                    &error,
                    now,
                    request.correlation_id,
                )
                .await?;
                Err(error.into())
            }
        }
    }

    async fn access_token(
        &self,
        binding: &Binding,
        now: re0auth_api::Unix,
        correlation_id: Option<&str>,
    ) -> Result<re0auth_api::SecretString, GatewayError> {
        let Some(credentials) = &self.credentials else {
            let sealed = self
                .storage
                .bindings()
                .load_sub_credential(&binding.id)
                .await
                .map_err(|_| GatewayError::Internal)?
                .ok_or(GatewayError::BindingNeedsReauth)?;
            return self
                .sealer
                .open(&binding.id, &sealed)
                .map_err(|_| GatewayError::Internal);
        };
        match credentials.access_token(binding).await {
            Ok(token) => Ok(token),
            Err(CredentialError::NeedsReauth) => {
                self.mark_needs_reauth(binding, "refresh_invalid_grant", now, correlation_id)
                    .await?;
                Err(GatewayError::BindingNeedsReauth)
            }
            Err(CredentialError::Unavailable) => Err(UpstreamError::Unavailable.into()),
            Err(CredentialError::Internal) => Err(GatewayError::Internal),
        }
    }

    async fn mark_needs_reauth(
        &self,
        binding: &Binding,
        reason: &str,
        now: re0auth_api::Unix,
        correlation_id: Option<&str>,
    ) -> Result<(), GatewayError> {
        self.storage
            .bindings()
            .mark_needs_reauth(
                &binding.id,
                reason,
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
            .map_err(|_| GatewayError::Internal)
    }

    // Shared by the first attempt and the post-refresh retry; keeping one path
    // is what guarantees they settle breakers, cache, and telemetry identically.
    #[allow(clippy::too_many_arguments)]
    async fn finish_fetch(
        &self,
        request: &GatewayRequest<'_>,
        endpoint: &ConnectorEndpoint,
        spec: &re0auth_api::connector::ResourceSpec,
        list_view: bool,
        payload: UpstreamPayload,
        started: std::time::Instant,
        connector_probe: &mut Probe,
        binding_probe: &mut Probe,
        cache_key: &str,
        now: re0auth_api::Unix,
    ) -> Result<UpstreamPayload, GatewayError> {
        if payload.body.len() > self.max_response_bytes {
            // An oversized response is an upstream-wide condition, so it counts
            // against the connector only. Opening the binding breaker as well
            // would refuse that one binding for 30 minutes over a problem that
            // is not specific to it. The binding claim is dropped unsettled,
            // which hands its slot back without opening anything.
            connector_probe.settle(Outcome::Internal, now);
            return Err(UpstreamError::Truncated.into());
        }
        connector_probe.settle(Outcome::Success, now);
        binding_probe.settle(Outcome::Success, now);
        if request.raw {
            // Recorded only on a served read: a failure is an error, not a read,
            // and inventing a ledger row for it would blur the two.
            let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            self.record_access(request, endpoint, AccessSource::Upstream, latency_ms);
            return Ok(payload);
        }
        // The upstream itself answered fine, so the success is settled above; a
        // view mismatch is business-class and never feeds the breaker (ADR-0049).
        let snapshot = CachedView::from_body(&payload.body, spec.view.as_ref(), now)?;
        let encoded = snapshot.encode()?;
        // Only a complete response is cached. A truncated one is rejected above,
        // so reaching here means the body is whole.
        self.cache
            .put(
                cache_key,
                &re0auth_api::cache::CachedResponse::new("application/json", encoded),
                self.cache_ttl,
            )
            .await;
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.record_access(request, endpoint, AccessSource::Upstream, latency_ms);
        self.normalized(request, endpoint, list_view, snapshot)
    }

    /// Retries an idempotent read on transport failures (F-4).
    ///
    /// Bounded at three attempts with exponential backoff plus jitter. Only
    /// idempotent resources are retried, and only for transport class failures:
    /// a 500 has already been mapped to Internal upstream of this point, because
    /// retrying a broken server multiplies the load that broke it.
    async fn fetch_with_retry(
        &self,
        endpoint: &ConnectorEndpoint,
        token: &re0auth_api::SecretString,
        resource: &ResourceRequest,
        idempotent: bool,
    ) -> Result<UpstreamPayload, UpstreamError> {
        let mut attempt = 1;
        loop {
            match self.broker.fetch_raw_data(endpoint, token, resource).await {
                Ok(payload) => return Ok(payload),
                Err(error) if idempotent && attempt < MAX_ATTEMPTS && retryable(&error) => {
                    tokio::time::sleep(retry_delay(attempt)).await;
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Builds the normalized envelope from a snapshot (ADR-0049).
    fn normalized(
        &self,
        request: &GatewayRequest<'_>,
        endpoint: &ConnectorEndpoint,
        list_view: bool,
        snapshot: CachedView,
    ) -> Result<UpstreamPayload, GatewayError> {
        let body = if list_view {
            let value: Value =
                serde_json::from_slice(&snapshot.data).map_err(|_| GatewayError::Internal)?;
            let items = value.as_array().ok_or(GatewayError::Internal)?;
            let page = page_body(&request.pagination, items)?;
            let data = serde_json::to_value(page).map_err(|_| GatewayError::Internal)?;
            let envelope = Envelope {
                upstream: &endpoint.name,
                endpoint: request.resource,
                fetched_at: snapshot.fetched_at,
                request_id: request.correlation_id,
                stability: "declared",
                data,
            };
            serde_json::to_vec(&envelope).map_err(|_| GatewayError::Internal)?
        } else {
            envelope_raw(
                &endpoint.name,
                request.resource,
                snapshot.fetched_at,
                request.correlation_id,
                &snapshot.data,
            )?
        };
        Ok(UpstreamPayload {
            content_type: "application/json".to_string(),
            body,
        })
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
        connector_probe: &mut Probe,
        binding_probe: &mut Probe,
        error: &UpstreamError,
        now: i64,
        correlation_id: Option<&str>,
    ) -> Result<(), GatewayError> {
        match error.fault_class() {
            FaultClass::Business => {
                // A 4xx still proves reachability: close any open probe.
                connector_probe.settle(Outcome::Business, now);
                binding_probe.settle(Outcome::Business, now);
                if error.binding_action() == BindingAction::NeedsReauth {
                    self.mark_needs_reauth(binding, "upstream_401", now, correlation_id)
                        .await?;
                }
            }
            FaultClass::Internal => {
                connector_probe.settle(Outcome::Internal, now);
                // The binding key was admitted for this request, so it must be
                // settled too. Leaving it half-open holds its probe slot and
                // rejects every later request for this binding — a permanent
                // 503 that outlives the upstream's outage.
                binding_probe.settle(Outcome::Internal, now);
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

#[cfg(test)]
mod p03_tests {
    use super::*;
    use re0auth_api::connector::{ParamLocation, ParamSpec};

    fn param(name: &str, kind: ParamKind) -> ParamSpec {
        ParamSpec {
            name: name.to_string(),
            upstream: name.to_string(),
            location: ParamLocation::Query,
            kind,
            required: true,
            min_len: None,
            max_len: None,
            min: None,
            max: None,
            values: Vec::new(),
        }
    }

    fn resource(params: Vec<ParamSpec>) -> ResourceSpec {
        let mut resource = ResourceSpec::new("scores", "/v1/scores").expect("resource");
        resource.params = params;
        resource
    }

    #[test]
    fn p03_params_are_allowlisted_and_typed() {
        let mut rank = param("rank", ParamKind::Enum);
        rank.values = vec!["EZ".into(), "HD".into(), "IN".into(), "AT".into()];
        let mut limit = param("limit", ParamKind::Integer);
        limit.min = Some(1.into());
        limit.max = Some(100.into());
        let mut ratio = param("ratio", ParamKind::Number);
        ratio.min = Some(serde_json::Number::from_f64(0.0).expect("finite"));
        ratio.max = Some(serde_json::Number::from_f64(1.0).expect("finite"));
        let spec = resource(vec![
            param("song_id", ParamKind::String),
            rank,
            limit,
            ratio,
            param("flag", ParamKind::Boolean),
        ]);
        let supplied = BTreeMap::from([
            ("song_id".to_string(), "s".to_string()),
            ("rank".to_string(), "IN".to_string()),
            ("limit".to_string(), "30".to_string()),
            ("ratio".to_string(), "0.5".to_string()),
            ("flag".to_string(), "true".to_string()),
        ]);
        let values = validate_params(&spec, &supplied, false).expect("valid params");
        assert_eq!(values["song_id"], ValidatedParamValue::String("s".into()));
        assert_eq!(values["rank"], ValidatedParamValue::String("IN".into()));
        assert_eq!(values["limit"], ValidatedParamValue::Integer(30));
        assert_eq!(
            values["ratio"],
            ValidatedParamValue::Number {
                raw: "0.5".into(),
                value: serde_json::Number::from_f64(0.5).expect("finite"),
            }
        );
        assert_eq!(values["flag"], ValidatedParamValue::Boolean(true));
    }

    #[test]
    fn p03_params_reject_unknown_missing_and_bad_values() {
        let mut long = param("song_id", ParamKind::String);
        long.max_len = Some(2);
        let mut rank = param("rank", ParamKind::Enum);
        rank.values = vec!["HD".into()];
        let mut count = param("count", ParamKind::Integer);
        count.min = Some(1.into());
        let mut ratio = param("ratio", ParamKind::Number);
        ratio.max = Some(serde_json::Number::from_f64(1.0).expect("finite"));
        let spec = resource(vec![
            long,
            rank,
            count,
            ratio,
            param("flag", ParamKind::Boolean),
        ]);

        assert!(
            validate_params(
                &spec,
                &BTreeMap::from([("other".into(), "x".into())]),
                false
            )
            .is_err()
        );
        assert!(validate_params(&spec, &BTreeMap::new(), false).is_err());
        assert!(
            validate_params(
                &spec,
                &BTreeMap::from([("song_id".into(), "abc".into())]),
                false
            )
            .is_err()
        );
        assert!(
            validate_params(
                &spec,
                &BTreeMap::from([("rank".into(), "IN".into())]),
                false
            )
            .is_err()
        );
        assert!(
            validate_params(
                &spec,
                &BTreeMap::from([("count".into(), "0".into())]),
                false
            )
            .is_err()
        );
        assert!(
            validate_params(
                &spec,
                &BTreeMap::from([("count".into(), "1.5".into())]),
                false
            )
            .is_err()
        );
        assert!(
            validate_params(
                &spec,
                &BTreeMap::from([("ratio".into(), "1.5".into())]),
                false
            )
            .is_err()
        );
        assert!(
            validate_params(
                &spec,
                &BTreeMap::from([("ratio".into(), "NaN".into())]),
                false
            )
            .is_err()
        );
        assert!(
            validate_params(&spec, &BTreeMap::from([("flag".into(), "1".into())]), false).is_err()
        );
        assert!(
            validate_params(
                &spec,
                &BTreeMap::from([("limit".into(), "10".into())]),
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn p03_pagination_keys_are_allowed_only_for_list_resources() {
        let spec = resource(Vec::new());
        let supplied = BTreeMap::from([
            ("limit".to_string(), "10".to_string()),
            ("cursor".to_string(), "abc".to_string()),
        ]);
        let values = validate_params(&spec, &supplied, true).expect("pagination keys");
        assert!(values.is_empty());
    }

    #[test]
    fn p03_pagination_slices_without_cloning_the_whole_list() {
        let items: Vec<Value> = (0..50)
            .map(|index| serde_json::json!({ "index": index }))
            .collect();
        let page = page_body(
            &Pagination {
                limit: Some(10),
                cursor: None,
            },
            &items,
        )
        .expect("page");
        assert_eq!(page.items.len(), 10);
        assert_eq!(page.items[0]["index"], 0);
        assert!(page.next_cursor.is_some());
    }
}

/// Builds the envelope around already-encoded view bytes.
///
/// String fields go through `serde_json::to_string`; the data is valid JSON by
/// construction (it was serialised once on the way into the cache).
fn envelope_raw(
    upstream: &str,
    endpoint: &str,
    fetched_at: i64,
    request_id: Option<&str>,
    data: &[u8],
) -> Result<Vec<u8>, GatewayError> {
    let upstream = serde_json::to_string(upstream).map_err(|_| GatewayError::Internal)?;
    let endpoint = serde_json::to_string(endpoint).map_err(|_| GatewayError::Internal)?;
    let request_id = match request_id {
        Some(id) => serde_json::to_string(id).map_err(|_| GatewayError::Internal)?,
        None => "null".to_string(),
    };
    let mut out = Vec::with_capacity(128 + data.len());
    out.extend_from_slice(
        format!(
            r#"{{"upstream":{upstream},"endpoint":{endpoint},"fetched_at":{fetched_at},"request_id":{request_id},"stability":"declared","data":"#
        )
        .as_bytes(),
    );
    out.extend_from_slice(data);
    out.push(b'}');
    Ok(out)
}

#[cfg(test)]
mod p01_tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn p01_cached_bytes_round_trip_and_splice_into_valid_json() {
        let cached = CachedView {
            fetched_at: 1_700_000_000,
            data: br#"{"score":42}"#.to_vec(),
        };
        let encoded = cached.encode().expect("encode");
        let decoded = CachedView::decode(&encoded).expect("decode");
        assert_eq!(decoded.fetched_at, cached.fetched_at);
        assert_eq!(decoded.data, cached.data);

        let body = envelope_raw(
            "phigros",
            "scores",
            decoded.fetched_at,
            Some("req-1"),
            &decoded.data,
        )
        .expect("envelope");
        let value: Value = serde_json::from_slice(&body).expect("valid JSON");
        assert_eq!(value["upstream"], "phigros");
        assert_eq!(value["request_id"], "req-1");
        assert_eq!(value["data"]["score"], 42);
    }

    proptest! {
        #[test]
        fn p01_encoded_views_round_trip(
            fetched_at in any::<i64>(),
            data in proptest::collection::vec(any::<u8>(), 0..40),
        ) {
            let view = CachedView {
                fetched_at,
                data: data.clone(),
            };
            let decoded = CachedView::decode(&view.encode().expect("encode"))
                .expect("decode");
            prop_assert_eq!(decoded.fetched_at, fetched_at);
            prop_assert_eq!(decoded.data, data);
        }

        #[test]
        fn p01_bodies_shorter_than_the_header_are_rejected(
            data in proptest::collection::vec(any::<u8>(), 0..8),
        ) {
            prop_assert!(CachedView::decode(&data).is_err());
        }

        #[test]
        fn p01_the_envelope_escapes_every_metadata_field(
            upstream in "\\PC{0,30}",
            endpoint in "\\PC{0,30}",
            request_id in proptest::option::of("\\PC{0,30}"),
            fetched_at in any::<i64>(),
            values in proptest::collection::vec(any::<i64>(), 0..4),
        ) {
            let count = values.len();
            let data = serde_json::to_vec(&serde_json::json!({
                "values": values,
                "note": endpoint,
            }))
            .expect("data");
            let body = envelope_raw(
                &upstream,
                &endpoint,
                fetched_at,
                request_id.as_deref(),
                &data,
            )
            .expect("envelope");
            let parsed: Value = serde_json::from_slice(&body).expect("valid JSON");
            prop_assert_eq!(parsed["upstream"].as_str(), Some(upstream.as_str()));
            prop_assert_eq!(parsed["endpoint"].as_str(), Some(endpoint.as_str()));
            prop_assert_eq!(parsed["request_id"].as_str(), request_id.as_deref());
            prop_assert_eq!(parsed["fetched_at"].as_i64(), Some(fetched_at));
            prop_assert_eq!(
                parsed["data"]["values"].as_array().map(Vec::len),
                Some(count)
            );
        }
    }
}
