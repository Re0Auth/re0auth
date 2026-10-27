//! Production connector registry and broker.
//!
//! The registry is the only source of upstream URLs (ADR-0008). The broker
//! builds request paths from the registry's templates only: it never accepts a
//! URL or a raw path (ADR-0032), and every request goes through
//! [`GuardedClient`] so the SSRF guard applies (HR-05).
//!
//! Neither type starts background work; expiry and probing belong to the
//! composition root's single scheduler.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use secrecy::ExposeSecret;
use url::Url;

use re0auth_api::connector::{
    BodyValue, ConnectorBroker, ConnectorEndpoint, ConnectorRegistry, EgressPolicy, InflightBudget,
    ResourceMethod, ResourceRequest, ResourceSpec, UnlimitedInflight, UpstreamError,
    UpstreamPayload,
};
use re0auth_api::{ConnectorId, Re0Error, Re0Result, SecretString};

use re0auth_runtime::http_client::GuardedClient;
use re0auth_runtime::outbound::OutboundPolicy;
use re0auth_runtime::tls::TlsConfig;

/// Static registry loaded from config at startup.
///
/// A `connectors` table is not implemented yet (`ISSUE-0003`); changing a
/// connector means editing config and restarting, which `ADR-0015` accepts.
#[derive(Clone, Debug, Default)]
pub struct StaticRegistry {
    endpoints: HashMap<ConnectorId, ConnectorEndpoint>,
}

impl StaticRegistry {
    #[must_use]
    pub fn new(endpoints: Vec<ConnectorEndpoint>) -> Self {
        let endpoints = endpoints
            .into_iter()
            .map(|endpoint| (endpoint.id, endpoint))
            .collect();
        Self { endpoints }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }
}

#[async_trait]
impl ConnectorRegistry for StaticRegistry {
    async fn resolve(&self, id: &ConnectorId) -> Re0Result<ConnectorEndpoint> {
        self.endpoints
            .get(id)
            .cloned()
            .ok_or_else(|| Re0Error::Business(format!("unknown connector {}", id.0)))
    }
}

/// One guarded client per connector, built from that connector's egress policy.
///
/// A shared client cannot express "A may reach the private network, B may not":
/// its policy and its host→client pool are fixed. The map is the boundary that
/// keeps a BYOC exception from widening every other connector.
#[derive(Clone)]
pub struct ConnectorClients {
    clients: HashMap<ConnectorId, Arc<GuardedClient>>,
}

impl ConnectorClients {
    pub fn new(endpoints: &[ConnectorEndpoint], tls: TlsConfig) -> anyhow::Result<Self> {
        let mut clients = HashMap::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let (policy, allow_http) = runtime_policy(endpoint.egress);
            let client = GuardedClient::with_tls(policy, allow_http, tls.clone())?;
            clients.insert(endpoint.id, Arc::new(client));
        }
        Ok(Self { clients })
    }

    pub(crate) fn get(
        &self,
        endpoint: &ConnectorEndpoint,
    ) -> Result<Arc<GuardedClient>, UpstreamError> {
        self.clients
            .get(&endpoint.id)
            .cloned()
            .ok_or(UpstreamError::Unavailable)
    }
}

fn runtime_policy(egress: EgressPolicy) -> (OutboundPolicy, bool) {
    match egress {
        EgressPolicy::Public => (OutboundPolicy::PublicOnly, false),
        EgressPolicy::PrivateNet => (OutboundPolicy::AllowPrivateNet, false),
        EgressPolicy::LinkLocalMetadata => (OutboundPolicy::AllowLinkLocalMetadata, false),
        EgressPolicy::Loopback => (OutboundPolicy::AllowLoopback, true),
    }
}

/// Fetches a registered resource over the connector's guarded client.
pub struct HttpBroker {
    clients: ConnectorClients,
    max_body: usize,
    /// INV-RES-01: aggregate bytes in flight across this connector's fetches.
    /// `Unlimited` when no budget is configured, which is a deliberate choice
    /// recorded in config, not an accidental absence.
    inflight: Arc<dyn InflightBudget>,
}

impl HttpBroker {
    /// `max_body` mirrors `limits.upstream_response_bytes` (HR-02).
    #[must_use]
    pub fn new(clients: ConnectorClients, max_body: usize) -> Self {
        Self {
            clients,
            max_body,
            inflight: Arc::new(UnlimitedInflight),
        }
    }

    /// Applies `limits.upstream_inflight_bytes` to every fetch.
    #[must_use]
    pub fn with_inflight_budget(mut self, inflight: Arc<dyn InflightBudget>) -> Self {
        self.inflight = inflight;
        self
    }
}

#[async_trait]
impl ConnectorBroker for HttpBroker {
    async fn fetch_raw_data(
        &self,
        endpoint: &ConnectorEndpoint,
        sub_token: &SecretString,
        resource: &ResourceRequest,
    ) -> Result<UpstreamPayload, UpstreamError> {
        let spec = endpoint
            .resource(&resource.resource)
            .ok_or(UpstreamError::NotFound)?;

        let url = build_url(&endpoint.base_url, &spec.path_template, &resource.subject)
            .map_err(|_| UpstreamError::Rejected)?;

        // INV-RES-01: reserve before the request, release on drop. Reserving the
        // whole response cap is deliberate — it is the worst case, so the budget
        // can never be exceeded by a body that turns out larger than expected.
        let _reservation = self
            .inflight
            .reserve(&endpoint.id, self.max_body as u64)
            .ok_or(UpstreamError::Overloaded)?;

        let http = self.clients.get(endpoint)?;
        let response = match spec.method {
            ResourceMethod::Get => {
                http.get_with_bearer(&url, sub_token.expose_secret(), self.max_body)
                    .await
            }
            ResourceMethod::Post => {
                let (body, credential_in_body) =
                    build_body(spec, &resource.subject, sub_token.expose_secret());
                // The credential goes in the body when the template says so, and
                // then it must not also travel in the header: sending the same
                // secret twice doubles where it can leak and buys nothing.
                let bearer = if credential_in_body {
                    None
                } else {
                    Some(sub_token.expose_secret())
                };
                http.post_json_raw(&url, bearer, &body, self.max_body).await
            }
        }
        .map_err(|error| map_transport_error(&error))?;

        Ok(UpstreamPayload {
            content_type: response.content_type,
            body: response.body,
        })
    }
}

/// Builds the request body from the registry's template.
///
/// Only the registry (constants) and the binding (`subject`, `credential`) can
/// contribute a value, and each is inserted as a JSON **string**: a subject
/// containing `"` or `},` can never change the document's shape, because
/// `serde_json` encodes it rather than interpolating it (ADR-0046).
///
/// Returns the body and whether the credential was placed in it.
fn build_body(spec: &ResourceSpec, subject: &str, credential: &str) -> (serde_json::Value, bool) {
    let mut map = serde_json::Map::new();
    let mut credential_in_body = false;
    for field in &spec.body {
        let value = match &field.value {
            BodyValue::Constant(value) => serde_json::Value::String(value.clone()),
            BodyValue::Subject => serde_json::Value::String(subject.to_string()),
            BodyValue::Credential => {
                credential_in_body = true;
                serde_json::Value::String(credential.to_string())
            }
        };
        map.insert(field.name.clone(), value);
    }
    (serde_json::Value::Object(map), credential_in_body)
}

/// Joins the registry's base URL with the template, percent-encoding the
/// subject. Rejects anything that escapes the base path.
pub fn build_url(
    base_url: &str,
    path_template: &str,
    subject: &str,
) -> Result<String, &'static str> {
    re0auth_api::connector::validate_path_template(path_template)
        .map_err(|_| "invalid template")?;

    let mut base = Url::parse(base_url).map_err(|_| "invalid base url")?;
    if base.scheme() != "https" && base.scheme() != "http" {
        return Err("base url must be http(s)");
    }
    if base.query().is_some() || base.fragment().is_some() {
        return Err("base url must not carry a query or fragment");
    }

    let base_path = base.path().trim_end_matches('/').to_string();
    // Treat the base as a directory, or `Url::join` would drop its last segment.
    base.set_path(&format!("{base_path}/"));

    let filled = path_template.replace("{subject}", &percent_encode(subject));
    // Templates are relative to the base path, so a leading slash is stripped
    // before joining; otherwise `Url::join` would replace the whole path.
    let relative = filled.trim_start_matches('/');

    let url = base
        .join(relative)
        .map_err(|_| "template does not join with the base url")?;

    // Defence in depth: `..` is rejected above, but a normalising join could
    // still escape the base path.
    let expected_prefix = format!("{base_path}/");
    let resolved = url.path().to_string();
    if !resolved.starts_with(&expected_prefix) && format!("{resolved}/") != expected_prefix {
        return Err("template escapes the base path");
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("template must not introduce a query or fragment");
    }
    Ok(url.to_string())
}

/// Percent-encodes everything outside the RFC 3986 unreserved set, so a subject
/// can never introduce a path separator or a query.
///
/// `NON_ALPHANUMERIC` escapes all but `A-Za-z0-9`; the four unreserved
/// punctuation characters are added back. A subject containing `%` therefore
/// becomes `%25` rather than being taken as an escape.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn percent_encode(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT).to_string()
}

fn map_transport_error(error: &anyhow::Error) -> UpstreamError {
    use re0auth_runtime::http_client::{UpstreamStatus, UpstreamTooLarge};

    // Typed downcasts, not message text. String matching classified by accident:
    // any error whose text contained "401" became an auth failure regardless of
    // what actually went wrong.
    if error.downcast_ref::<UpstreamTooLarge>().is_some() {
        return UpstreamError::Truncated;
    }
    let Some(reported) = error.downcast_ref::<UpstreamStatus>() else {
        return UpstreamError::Unavailable;
    };
    match reported.status {
        401 => UpstreamError::CredentialExpired,
        403 => UpstreamError::InsufficientScope,
        404 => UpstreamError::NotFound,
        // The hint is passed through rather than invented: the upstream knows
        // when it will be ready and we do not, and a made-up value either gives
        // up too early or hammers a source that asked for room.
        429 => UpstreamError::RateLimited {
            retry_after_secs: reported.retry_after_secs,
        },
        // A 400 means we sent something the upstream rejected — a bad parameter,
        // not a broken upstream. Classifying it as internal would count it toward
        // the breaker and let a permanently-misconfigured resource trip the whole
        // connector for unrelated callers (ADR-0025).
        400 | 422 => UpstreamError::Rejected,
        _ => UpstreamError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use re0auth_api::connector::BodyField;
    use re0auth_api::connector::FaultClass;
    use re0auth_api::connector::ResourceSpec;

    fn endpoint() -> ConnectorEndpoint {
        ConnectorEndpoint {
            id: ConnectorId::new(),
            name: "test-connector".to_string(),
            base_url: "https://api.example.com".to_string(),
            egress: EgressPolicy::Public,
            resources: vec![
                ResourceSpec::new("scores", "/v1/scores/{subject}").expect("spec"),
                ResourceSpec::new("me", "/v1/me").expect("spec"),
            ],
        }
    }

    #[test]
    fn substitutes_and_encodes_the_subject() {
        let url = build_url(
            "https://api.example.com",
            "/v1/scores/{subject}",
            "ab12cd34",
        )
        .expect("url");
        assert_eq!(url, "https://api.example.com/v1/scores/ab12cd34");
    }

    #[test]
    fn encodes_path_separators_in_the_subject() {
        let url = build_url("https://api.example.com", "/v1/scores/{subject}", "a/b").expect("url");
        assert_eq!(url, "https://api.example.com/v1/scores/a%2Fb");
    }

    #[test]
    fn encodes_traversal_in_the_subject() {
        let url =
            build_url("https://api.example.com", "/v1/scores/{subject}", "../etc").expect("url");
        assert_eq!(url, "https://api.example.com/v1/scores/..%2Fetc");
    }

    #[test]
    fn rejects_templates_that_escape_the_base_path() {
        assert!(build_url("https://api.example.com", "//evil.example/x", "s").is_err());
        assert!(build_url("https://api.example.com", "/v1/../../x", "s").is_err());
        assert!(build_url("https://api.example.com", "v1/scores", "s").is_err());
    }

    #[test]
    fn keeps_a_base_path_prefix() {
        let url = build_url("https://api.example.com/api", "/v1/me", "s").expect("url");
        assert_eq!(url, "https://api.example.com/api/v1/me");
    }

    #[test]
    fn rejects_base_urls_with_query_or_fragment() {
        assert!(build_url("https://api.example.com?x=1", "/v1/me", "s").is_err());
        assert!(build_url("https://api.example.com#frag", "/v1/me", "s").is_err());
    }

    /// Pins the exact character set, because the encoder is now a library call
    /// configured by a set rather than a visible match arm. Getting the set
    /// wrong would either escape characters upstreams expect (`~`) or leave a
    /// separator (`/`) able to change the path.
    #[test]
    fn percent_encoding_matches_the_rfc3986_unreserved_set() {
        assert_eq!(percent_encode("abcXYZ019"), "abcXYZ019");
        assert_eq!(
            percent_encode("-._~"),
            "-._~",
            "unreserved must pass through"
        );
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("a/b"), "a%2Fb");
        assert_eq!(percent_encode("a+b"), "a%2Bb");
        assert_eq!(percent_encode("a@b"), "a%40b");
        assert_eq!(
            percent_encode("a%2Fb"),
            "a%252Fb",
            "existing escapes double"
        );
        assert_eq!(percent_encode("日本"), "%E6%97%A5%E6%9C%AC");
    }

    #[tokio::test]
    async fn registry_returns_business_error_for_unknown_id() {
        let registry = StaticRegistry::new(vec![endpoint()]);
        let missing = ConnectorId::new();
        assert!(matches!(
            registry.resolve(&missing).await,
            Err(Re0Error::Business(_))
        ));
    }

    #[tokio::test]
    async fn registry_resolves_configured_endpoints() {
        let configured = endpoint();
        let id = configured.id;
        let registry = StaticRegistry::new(vec![configured.clone()]);
        assert_eq!(registry.resolve(&id).await.expect("resolve"), configured);
    }

    #[test]
    fn egress_policy_maps_to_one_client_policy() {
        assert_eq!(
            runtime_policy(EgressPolicy::Public),
            (OutboundPolicy::PublicOnly, false)
        );
        assert_eq!(
            runtime_policy(EgressPolicy::PrivateNet),
            (OutboundPolicy::AllowPrivateNet, false)
        );
        assert_eq!(
            runtime_policy(EgressPolicy::LinkLocalMetadata),
            (OutboundPolicy::AllowLinkLocalMetadata, false)
        );
        assert_eq!(
            runtime_policy(EgressPolicy::Loopback),
            (OutboundPolicy::AllowLoopback, true)
        );
    }

    /// The same address must be allowed or denied according to the connector
    /// that owns the request, not a process-wide switch.
    #[tokio::test]
    async fn connector_policies_are_isolated() {
        let mut public = endpoint();
        public.egress = EgressPolicy::Public;
        let mut private = endpoint();
        private.id = ConnectorId::new();
        private.egress = EgressPolicy::PrivateNet;
        let mut metadata = endpoint();
        metadata.id = ConnectorId::new();
        metadata.egress = EgressPolicy::LinkLocalMetadata;
        let mut loopback = endpoint();
        loopback.id = ConnectorId::new();
        loopback.egress = EgressPolicy::Loopback;

        let clients = ConnectorClients::new(
            &[
                public.clone(),
                private.clone(),
                metadata.clone(),
                loopback.clone(),
            ],
            TlsConfig::default(),
        )
        .expect("clients");

        let public_client = clients.get(&public).expect("public client");
        let private_client = clients.get(&private).expect("private client");
        let metadata_client = clients.get(&metadata).expect("metadata client");
        let loopback_client = clients.get(&loopback).expect("loopback client");

        assert!(
            public_client.vet("https://10.1.2.3/").await.is_err(),
            "a public connector must not reach RFC1918"
        );
        assert!(
            private_client.vet("https://10.1.2.3/").await.is_ok(),
            "the private connector must reach RFC1918"
        );
        assert!(
            private_client
                .vet("https://169.254.169.254/")
                .await
                .is_err(),
            "private-net must not imply metadata"
        );
        assert!(
            metadata_client
                .vet("https://169.254.169.254/")
                .await
                .is_ok(),
            "the metadata connector must reach its explicit range"
        );
        assert!(
            public_client.vet("https://127.0.0.1/").await.is_err(),
            "loopback must not be inherited"
        );
        assert!(
            loopback_client.vet("https://127.0.0.1/").await.is_ok(),
            "the explicit loopback connector must reach loopback"
        );
    }

    /// INV-RES-01: an exhausted budget refuses the fetch *before* any request is
    /// built. The broker targets `api.example.com`, which no test environment can
    /// reach — so reaching it would surface as a transport error, not
    /// `Overloaded`. Getting `Overloaded` proves the request was never attempted.
    #[tokio::test]
    async fn an_exhausted_budget_refuses_before_reaching_out() {
        let endpoint = endpoint();
        // A budget smaller than the response cap, so one reservation fills it.
        let budget = Arc::new(crate::ByteBudget::new(1024));
        let held = budget.reserve(&endpoint.id, 1024).expect("fill the budget");
        let clients = ConnectorClients::new(std::slice::from_ref(&endpoint), TlsConfig::default())
            .expect("clients");
        let broker = HttpBroker::new(clients, 4 * 1024 * 1024).with_inflight_budget(budget);

        let result = broker
            .fetch_raw_data(
                &endpoint,
                &SecretString::from("token".to_string()),
                &ResourceRequest::new("scores", "player-1"),
            )
            .await;

        assert!(
            matches!(result, Err(UpstreamError::Overloaded)),
            "must refuse before sending, got {result:?}"
        );
        drop(held);
    }

    #[test]
    fn an_exhausted_budget_is_a_business_fault() {
        // INV-GW-03: counting this as internal would let a busy minute open a
        // 30-minute circuit for every user of the connector.
        assert_eq!(
            UpstreamError::Overloaded.fault_class(),
            FaultClass::Business
        );
        assert_eq!(
            UpstreamError::Overloaded.binding_action(),
            re0auth_api::connector::BindingAction::Keep,
            "capacity pressure must never force a re-login"
        );
    }

    fn transport(status: u16) -> anyhow::Error {
        re0auth_runtime::http_client::UpstreamStatus {
            status,
            retry_after_secs: None,
        }
        .into()
    }

    #[test]
    fn transport_status_classes_follow_the_upstream_contract() {
        // 401 and 403 stay distinct: merging them sends users into a
        // re-authorize loop that never resolves (ADR-0025).
        assert_eq!(
            map_transport_error(&transport(401)),
            UpstreamError::CredentialExpired
        );
        assert_eq!(
            map_transport_error(&transport(403)),
            UpstreamError::InsufficientScope
        );
        assert_eq!(
            map_transport_error(&transport(404)),
            UpstreamError::NotFound
        );
        assert_eq!(
            map_transport_error(&transport(429)),
            UpstreamError::RateLimited {
                retry_after_secs: None
            }
        );
        assert_eq!(
            map_transport_error(&transport(500)),
            UpstreamError::Unavailable
        );
    }

    #[test]
    fn a_rate_limit_hint_is_carried_through_verbatim() {
        // The upstream is the only party that knows when it will be ready, so its
        // hint has to survive the classification instead of being dropped on the
        // floor — the client then retries blind and adds to the load.
        let error = re0auth_runtime::http_client::UpstreamStatus {
            status: 429,
            retry_after_secs: Some(42),
        };
        assert_eq!(
            map_transport_error(&error.into()),
            UpstreamError::RateLimited {
                retry_after_secs: Some(42)
            }
        );
    }

    #[test]
    fn a_rejected_parameter_is_business_not_internal() {
        // A 400 is our request being wrong, not the upstream being sick. If it
        // landed in Unavailable it would count toward the breaker, so one
        // misconfigured resource could trip the whole connector for everyone.
        for status in [400, 422] {
            let mapped = map_transport_error(&transport(status));
            assert_eq!(mapped, UpstreamError::Rejected, "status {status}");
            assert_eq!(mapped.fault_class(), FaultClass::Business);
        }
    }

    #[test]
    fn classification_ignores_message_text() {
        // The old implementation matched substrings of the error message, so any
        // error whose text contained "401" became an auth failure. A plain
        // transport error mentioning 401 is still not an auth failure.
        let misleading = anyhow::anyhow!("connection reset after upstream returned 401");
        assert_eq!(map_transport_error(&misleading), UpstreamError::Unavailable);

        let oversized =
            anyhow::Error::new(re0auth_runtime::http_client::UpstreamTooLarge { limit: 1024 });
        assert_eq!(map_transport_error(&oversized), UpstreamError::Truncated);
    }

    fn post_spec(body: Vec<BodyField>) -> ResourceSpec {
        ResourceSpec::new("scores", "/v1/read")
            .expect("spec")
            .with_transport(ResourceMethod::Post, body, true)
            .expect("transport")
    }

    #[test]
    fn a_subject_is_json_encoded_not_interpolated() {
        // A subject carrying JSON punctuation must stay one string value, or the
        // caller could change the document's shape through the binding.
        let spec = post_spec(vec![
            BodyField {
                name: "api_user_id".to_string(),
                value: BodyValue::Subject,
            },
            BodyField {
                name: "token".to_string(),
                value: BodyValue::Credential,
            },
        ]);
        let (body, credential_in_body) = build_body(&spec, "a\"b,}", "secret");
        assert!(credential_in_body, "the credential is a body field");
        assert_eq!(body["api_user_id"], serde_json::Value::from("a\"b,}"));
        assert_eq!(
            body.as_object().expect("object").len(),
            2,
            "an injected comma must not add a field"
        );
    }

    #[test]
    fn a_body_without_a_credential_field_keeps_the_bearer() {
        let spec = post_spec(vec![BodyField {
            name: "api_user_id".to_string(),
            value: BodyValue::Subject,
        }]);
        let (body, credential_in_body) = build_body(&spec, "player", "secret");
        assert!(!credential_in_body);
        assert_eq!(body["api_user_id"], serde_json::Value::from("player"));
        assert!(body.get("secret").is_none());
    }

    #[test]
    fn a_constant_is_a_literal_and_a_get_resource_has_no_body() {
        let spec = post_spec(vec![BodyField {
            name: "scope".to_string(),
            value: BodyValue::Constant("read".to_string()),
        }]);
        let (body, credential_in_body) = build_body(&spec, "player", "secret");
        assert!(!credential_in_body);
        assert_eq!(body["scope"], serde_json::Value::from("read"));

        let get = ResourceSpec::new("me", "/v1/me").expect("spec");
        let (body, credential_in_body) = build_body(&get, "player", "secret");
        assert!(!credential_in_body);
        assert!(body.as_object().expect("object").is_empty());
    }
}
