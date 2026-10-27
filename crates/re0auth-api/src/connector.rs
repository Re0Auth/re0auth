//! Data-plane ports.
//!
//! Identity code must not depend on this module: login and device approval
//! work with an empty connector registry (INV-LOGIN-03).

use async_trait::async_trait;

use crate::{ConnectorId, Re0Result, SecretString};

/// One resource the connector exposes, and the path template that reaches it.
///
/// The template lives in the registry, never in a request (ADR-0032). It is a
/// relative path and may contain the single placeholder `{subject}`, which the
/// broker substitutes with the binding's upstream user id after percent-encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceSpec {
    pub name: String,
    pub path_template: String,
    /// Scope required to read this resource. It is part of the registry entry,
    /// never a request parameter, so a caller cannot choose its own scope
    /// (`SCOPES.md` §2, INV-SCOPE-01).
    pub required_scope: String,
    /// How the broker reaches this resource (ADR-0046). `Get` is the default.
    pub method: ResourceMethod,
    /// Server-generated request body, empty for `Get`.
    ///
    /// Values come only from the registry and the binding; a caller can never
    /// add, rename, or override a field.
    pub body: Vec<BodyField>,
    /// Whether the broker may retry this resource once retries exist (F-4).
    ///
    /// Reads are idempotent; a `Post` that changes state must leave this
    /// `false`. Default is `true` only because `ResourceMethod::Get` is the
    /// default; `with_transport` requires the author to state it.
    pub idempotent: bool,
}

/// The HTTP method a resource is read with.
///
/// Method-agnostic on purpose (ADR-0046): real upstreams read data with POST,
/// and forcing them to expose GET would make Re0Auth's availability depend on
/// their cooperation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceMethod {
    Get,
    Post,
}

impl ResourceMethod {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Post => "post",
        }
    }

    /// Parses the config spelling. Unknown values are `None`, never a default:
    /// silently reading `"postt"` as GET would send a read down the wrong verb.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "get" => Some(Self::Get),
            "post" => Some(Self::Post),
            _ => None,
        }
    }
}

/// One field of a server-generated request body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyField {
    pub name: String,
    pub value: BodyValue,
}

/// Where one body field's value comes from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodyValue {
    /// A literal the registry author wrote.
    Constant(String),
    /// The binding's upstream subject (`bindings.upstream_user_id`).
    Subject,
    /// The binding's stored credential.
    Credential,
}

impl BodyValue {
    /// The stable string form used by config and the connector mirror: the two
    /// placeholder tokens, otherwise the literal itself.
    #[must_use]
    pub fn as_token(&self) -> String {
        match self {
            Self::Constant(value) => value.clone(),
            Self::Subject => "{subject}".to_string(),
            Self::Credential => "{credential}".to_string(),
        }
    }

    /// Inverse of [`Self::as_token`]. Anything that is not a placeholder is a
    /// literal, which is how one spelling is shared by config and storage.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw {
            "{subject}" => Self::Subject,
            "{credential}" => Self::Credential,
            other => Self::Constant(other.to_string()),
        }
    }
}

impl ResourceSpec {
    /// Rejects anything that could change the request target.
    ///
    /// Defaults to a GET with no body: every existing resource keeps working
    /// unchanged (ADR-0046).
    pub fn new(name: impl Into<String>, path_template: impl Into<String>) -> Re0Result<Self> {
        let name = name.into();
        let path_template = path_template.into();
        if !valid_name(&name) {
            return Err(crate::Re0Error::Internal(format!(
                "invalid resource name {name:?}"
            )));
        }
        validate_path_template(&path_template)
            .map_err(|reason| crate::Re0Error::Internal(format!("resource {name}: {reason}")))?;
        Ok(Self {
            required_scope: scope_for_resource(&name),
            name,
            path_template,
            method: ResourceMethod::Get,
            body: Vec::new(),
            idempotent: true,
        })
    }

    /// Overrides the derived scope. Rejects malformed scopes so a typo cannot
    /// silently widen access.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Re0Result<Self> {
        let scope = scope.into();
        if !valid_scope(&scope) {
            return Err(crate::Re0Error::Internal(format!(
                "invalid scope {scope:?}"
            )));
        }
        self.required_scope = scope;
        Ok(self)
    }

    /// Declares the transport and whether a retry is safe.
    ///
    /// `idempotent` is a required argument, not a default: a `Post` that changes
    /// state must say so rather than inherit "reads are safe" by accident
    /// (ADR-0046).
    pub fn with_transport(
        mut self,
        method: ResourceMethod,
        body: Vec<BodyField>,
        idempotent: bool,
    ) -> Re0Result<Self> {
        validate_transport(method, &body).map_err(|reason| {
            crate::Re0Error::Internal(format!("resource {}: {reason}", self.name))
        })?;
        self.method = method;
        self.body = body;
        self.idempotent = idempotent;
        Ok(self)
    }
}

/// A transport declaration must be internally consistent.
///
/// `Get` never carries a body (nothing to inject, and a body on GET is a
/// smuggling surface); `Post` must carry one or it is indistinguishable from a
/// misconfiguration. Field names must be unique so a later field cannot silently
/// win over an earlier one.
fn validate_transport(method: ResourceMethod, body: &[BodyField]) -> Result<(), String> {
    match method {
        ResourceMethod::Get if !body.is_empty() => {
            return Err("a GET resource must not declare a body".to_string());
        }
        ResourceMethod::Post if body.is_empty() => {
            return Err("a POST resource must declare a body".to_string());
        }
        _ => {}
    }
    let mut seen = std::collections::BTreeSet::new();
    for field in body {
        if !valid_body_field_name(&field.name) {
            return Err(format!("invalid body field name {:?}", field.name));
        }
        if !seen.insert(field.name.as_str()) {
            return Err(format!("duplicate body field {:?}", field.name));
        }
        if let BodyValue::Constant(value) = &field.value
            && (value.contains('{') || value.contains('}'))
        {
            return Err(format!(
                "body field {:?} constant contains braces",
                field.name
            ));
        }
    }
    Ok(())
}

fn valid_body_field_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Derives the default scope for a resource: `<connector>.<resource>.read` is
/// not knowable here, so the resource name alone forms `upstream.<name>.read`.
fn scope_for_resource(name: &str) -> String {
    format!("upstream.{name}.read")
}

/// Mirrors `SCOPES.md` §1: lowercase, dot-separated, `[a-z0-9_.]` only.
fn valid_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'_'
        })
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
}

/// A template must be a relative path with no traversal and no scheme.
///
/// This is the second SSRF surface: if a connector could accept an absolute URL
/// or `..`, the gateway would proxy to an arbitrary host (INV-GW-06).
pub fn validate_path_template(template: &str) -> Result<(), String> {
    if template.is_empty() {
        return Err("path template is empty".to_string());
    }
    if !template.starts_with('/') {
        return Err("path template must start with '/'".to_string());
    }
    if template.starts_with("//") {
        return Err("path template must not start with '//'".to_string());
    }
    if template.contains("..") {
        return Err("path template must not contain '..'".to_string());
    }
    if template.contains('\\') {
        return Err("path template must not contain '\\'".to_string());
    }
    if template.contains('#') {
        return Err("path template must not contain a fragment".to_string());
    }
    if template.matches('{').count() != template.matches('}').count() {
        return Err("unbalanced braces in path template".to_string());
    }
    // Only `{subject}` is a permitted placeholder.
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let end = rest[start..]
            .find('}')
            .ok_or_else(|| "unbalanced braces in path template".to_string())?;
        let placeholder = &rest[start + 1..start + end];
        if placeholder != "subject" {
            return Err(format!("unknown placeholder {{{placeholder}}}"));
        }
        rest = &rest[start + end + 1..];
    }
    Ok(())
}

/// How far one connector may reach on the network.
///
/// This is per-connector, not global: opening private networking for a BYOC
/// connector must not widen every other connector. The global `[tls]` flags act
/// only as a ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressPolicy {
    Public,
    PrivateNet,
    LinkLocalMetadata,
    Loopback,
}

/// A registered upstream endpoint. URLs never come from request parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorEndpoint {
    pub id: ConnectorId,
    /// Configured name, e.g. `phigros`. This is what `bindings.upstream_id`
    /// stores: the id is derived from it, so storing the id instead would make
    /// the binding list unreadable and would silently break if the derivation
    /// namespace ever changed.
    pub name: String,
    pub base_url: String,
    pub egress: EgressPolicy,
    /// Resources this connector exposes. An empty list means "nothing reachable".
    pub resources: Vec<ResourceSpec>,
}

impl ConnectorEndpoint {
    #[must_use]
    pub fn resource(&self, name: &str) -> Option<&ResourceSpec> {
        self.resources.iter().find(|spec| spec.name == name)
    }
}

/// What the gateway wants, not how to reach it.
///
/// The connector owns the path template; the core never passes a URL or a raw
/// path. `resource` and `subject` are validated by the gateway before use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRequest {
    pub resource: String,
    pub subject: String,
}

impl ResourceRequest {
    #[must_use]
    pub fn new(resource: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            subject: subject.into(),
        }
    }
}

/// Raw upstream body after the connector's size limit has been applied.
///
/// There is no `truncated` flag: a body over the limit is rejected as
/// [`UpstreamError::Truncated`], never returned in part. A flag would describe a
/// state the guard never produces, and a consumer that checked it would look
/// defended against something that cannot happen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamPayload {
    pub content_type: String,
    pub body: Vec<u8>,
}

/// Only internal failures feed circuit breakers (INV-GW-03).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FaultClass {
    Business,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BindingAction {
    Keep,
    NeedsReauth,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum UpstreamError {
    #[error("upstream credential expired")]
    CredentialExpired,
    #[error("upstream insufficient scope")]
    InsufficientScope,
    #[error("upstream resource not found")]
    NotFound,
    #[error("upstream rate limited")]
    RateLimited { retry_after_secs: Option<u64> },
    #[error("upstream unavailable")]
    Unavailable,
    #[error("upstream response truncated")]
    Truncated,
    #[error("upstream rejected the request")]
    Rejected,
    #[error("upstream internal error")]
    Internal,
    /// INV-RES-01: the connector's in-flight byte budget is exhausted.
    ///
    /// Deliberately a *business* fault, not internal: the upstream is healthy and
    /// the request never reached it. Counting this toward the breaker would let a
    /// busy minute open a 30-minute circuit and take the connector down for
    /// everyone — the exact failure INV-GW-03 exists to prevent.
    #[error("upstream in-flight budget exhausted")]
    Overloaded,
}

impl UpstreamError {
    /// 401 and 403 are business outcomes; they must never trip a breaker.
    #[must_use]
    pub fn fault_class(&self) -> FaultClass {
        match self {
            Self::CredentialExpired
            | Self::InsufficientScope
            | Self::NotFound
            | Self::Rejected
            | Self::Overloaded => FaultClass::Business,
            Self::RateLimited { .. } | Self::Unavailable | Self::Truncated | Self::Internal => {
                FaultClass::Internal
            }
        }
    }

    #[must_use]
    pub fn binding_action(&self) -> BindingAction {
        match self {
            Self::CredentialExpired => BindingAction::NeedsReauth,
            _ => BindingAction::Keep,
        }
    }
}

#[async_trait]
pub trait ConnectorRegistry: Send + Sync {
    async fn resolve(&self, id: &ConnectorId) -> Re0Result<ConnectorEndpoint>;
}

/// A reservation against one connector's in-flight byte budget (INV-RES-01).
///
/// Dropping it releases the bytes. The broker holds one for the whole duration of
/// a fetch, so a cancelled request cannot leak capacity.
///
/// Reserving *before* the request means the budget can be exceeded only by the
/// bytes already in flight, never by a body that turns out larger than declared.
pub trait InflightReservation: Send + Sync {}

/// Per-connector aggregate limit on bytes being fetched concurrently.
///
/// Single responses are already capped at 4 MiB; this is the *sum*. Without it,
/// N concurrent requests each within the per-response cap can still exhaust
/// memory, which is the gap `ISSUE-0006` recorded.
///
/// The `wanted` amount is an estimate supplied by the caller (the response cap,
/// which is the worst case). An implementation must fail closed: if it cannot
/// guarantee the reservation, it returns `None` rather than admitting the
/// request.
pub trait InflightBudget: Send + Sync {
    /// Reserves at least `wanted` bytes for `connector`.
    ///
    /// Returns `None` when the budget cannot accommodate the request. The
    /// returned guard must release the reservation on drop.
    fn reserve(&self, connector: &ConnectorId, wanted: u64)
    -> Option<Box<dyn InflightReservation>>;
}

/// A budget that never limits anything.
///
/// This is the honest default, not a silent bypass: `limits.upstream_inflight_bytes`
/// is validated at startup, so reaching this type means no budget was configured
/// for this broker at all.
#[derive(Debug, Default)]
pub struct UnlimitedInflight;

impl InflightBudget for UnlimitedInflight {
    fn reserve(
        &self,
        _connector: &ConnectorId,
        _wanted: u64,
    ) -> Option<Box<dyn InflightReservation>> {
        Some(Box::new(NoReservation))
    }
}

struct NoReservation;

impl InflightReservation for NoReservation {}

#[async_trait]
pub trait ConnectorBroker: Send + Sync {
    /// Fetches a resource named by the connector's own registry entry.
    /// Implementations apply the outbound policy, the path template, and the
    /// response size limit.
    async fn fetch_raw_data(
        &self,
        endpoint: &ConnectorEndpoint,
        sub_token: &SecretString,
        resource: &ResourceRequest,
    ) -> Result<UpstreamPayload, UpstreamError>;
}

/// What an authorization-code exchange yields: the credential, and whose it is.
///
/// The subject travels with the credential because it is established by the same
/// call and by nothing else. A caller that has a credential but not its subject
/// cannot serve a request: the gateway's `subject` parameter comes from
/// `bindings.upstream_user_id` (`DATA-PLANE.md` §7), which must name the upstream
/// account, not ours. Returning only the secret pushes callers into inventing a
/// value — the exact defect this type removes.
#[derive(Clone, Debug)]
pub struct ExchangedCredential {
    /// The credential to store, sealed at rest.
    pub credential: SecretString,
    /// The upstream account this credential speaks for, as the source names it.
    pub subject: String,
}

/// Turns an upstream authorization code into a credential.
///
/// Separate from [`ConnectorBroker`] on purpose. The broker reads data with a
/// credential that already exists; this is how one comes to exist. Folding the
/// two together would give the gateway a path to a credential-minting call,
/// which is exactly what the read-only invariant (`INV-GW-*`) rules out by
/// construction rather than by convention.
#[async_trait]
pub trait ConnectorAuth: Send + Sync {
    /// The URL to send the browser to.
    ///
    /// `state` is ours, not the connector's: it is what ties the callback back to
    /// the flow that started it.
    fn authorization_url(
        &self,
        endpoint: &ConnectorEndpoint,
        state: &str,
        redirect_uri: &str,
        pkce_challenge: Option<&str>,
    ) -> Result<String, UpstreamError>;

    /// Exchanges `code` for the credential to store, and the subject it speaks for.
    async fn exchange_code(
        &self,
        endpoint: &ConnectorEndpoint,
        code: &str,
        redirect_uri: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<ExchangedCredential, UpstreamError>;
}

/// Connector-owned vault for upstream root credentials (INV-CONN-02).
/// It is not backed by the core database and is never read by identity code.
#[async_trait]
pub trait ConnectorSecretStore: Send + Sync {
    async fn put(&self, key: &str, secret: &SecretString) -> Re0Result<()>;
    async fn get(&self, key: &str) -> Re0Result<Option<SecretString>>;
    async fn delete(&self, key: &str) -> Re0Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn business_and_internal_classes_are_split() {
        assert_eq!(
            UpstreamError::CredentialExpired.fault_class(),
            FaultClass::Business
        );
        assert_eq!(
            UpstreamError::InsufficientScope.fault_class(),
            FaultClass::Business
        );
        assert_eq!(UpstreamError::NotFound.fault_class(), FaultClass::Business);
        assert_eq!(
            UpstreamError::RateLimited {
                retry_after_secs: Some(10)
            }
            .fault_class(),
            FaultClass::Internal
        );
        assert_eq!(
            UpstreamError::Unavailable.fault_class(),
            FaultClass::Internal
        );
        assert_eq!(UpstreamError::Truncated.fault_class(), FaultClass::Internal);
    }

    #[test]
    fn only_401_requires_reauth() {
        assert_eq!(
            UpstreamError::CredentialExpired.binding_action(),
            BindingAction::NeedsReauth
        );
        assert_eq!(
            UpstreamError::InsufficientScope.binding_action(),
            BindingAction::Keep
        );
    }

    #[test]
    fn a_resource_defaults_to_an_idempotent_get_without_a_body() {
        let spec = ResourceSpec::new("scores", "/v1/scores/{subject}").expect("spec");
        assert_eq!(spec.method, ResourceMethod::Get);
        assert!(spec.body.is_empty());
        assert!(spec.idempotent, "a read is safe to retry by default");
    }

    #[test]
    fn a_get_resource_may_not_declare_a_body() {
        let result = ResourceSpec::new("scores", "/v1/scores/{subject}")
            .expect("spec")
            .with_transport(
                ResourceMethod::Get,
                vec![BodyField {
                    name: "token".to_string(),
                    value: BodyValue::Credential,
                }],
                true,
            );
        assert!(result.is_err(), "a GET bait with a body must be refused");
    }

    #[test]
    fn a_post_resource_requires_a_body() {
        let result = ResourceSpec::new("scores", "/v1/scores/{subject}")
            .expect("spec")
            .with_transport(ResourceMethod::Post, Vec::new(), true);
        assert!(
            result.is_err(),
            "a POST without a body is a misconfiguration"
        );
    }

    #[test]
    fn body_fields_must_be_unique_and_well_named() {
        let duplicate = ResourceSpec::new("scores", "/v1/scores/{subject}")
            .expect("spec")
            .with_transport(
                ResourceMethod::Post,
                vec![
                    BodyField {
                        name: "token".to_string(),
                        value: BodyValue::Credential,
                    },
                    BodyField {
                        name: "token".to_string(),
                        value: BodyValue::Subject,
                    },
                ],
                false,
            );
        assert!(duplicate.is_err(), "a later field must not silently win");

        let bad_name = ResourceSpec::new("scores", "/v1/scores/{subject}")
            .expect("spec")
            .with_transport(
                ResourceMethod::Post,
                vec![BodyField {
                    name: "apiUser".to_string(),
                    value: BodyValue::Subject,
                }],
                true,
            );
        assert!(bad_name.is_err(), "field names are `[a-z0-9_]`");
    }

    #[test]
    fn constant_values_may_not_smuggle_a_placeholder() {
        let result = ResourceSpec::new("scores", "/v1/scores/{subject}")
            .expect("spec")
            .with_transport(
                ResourceMethod::Post,
                vec![BodyField {
                    name: "scope".to_string(),
                    value: BodyValue::Constant("{subject}".to_string()),
                }],
                true,
            );
        assert!(result.is_err(), "constants are literals, not templates");
    }

    #[test]
    fn method_parsing_rejects_unknown_spellings() {
        assert_eq!(ResourceMethod::parse("get"), Some(ResourceMethod::Get));
        assert_eq!(ResourceMethod::parse(" POST "), Some(ResourceMethod::Post));
        assert_eq!(ResourceMethod::parse("postt"), None);
    }
}
