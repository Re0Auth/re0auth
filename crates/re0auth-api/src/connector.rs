//! Data-plane ports.
//!
//! Identity code must not depend on this module: login and device approval
//! work with an empty connector registry (INV-LOGIN-03).

use async_trait::async_trait;

use crate::view::ViewSpec;
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
    /// Server-generated request body fields, empty for `Get`.
    pub body: Vec<BodyField>,
    /// Server-generated JSON document interpolated recursively at build time.
    pub raw_body: Option<serde_json::Value>,
    /// Whether the broker may retry this resource once retries exist (F-4).
    ///
    /// Reads are idempotent; a `Post` that changes state must leave this
    /// `false`. Default is `true` only because `ResourceMethod::Get` is the
    /// default; `with_transport` requires the author to state it.
    pub idempotent: bool,
    /// Declarative view for the normalized endpoint (ADR-0049). `None` means
    /// the envelope carries the upstream JSON unchanged.
    pub view: Option<ViewSpec>,
    /// Declared downstream query parameters and their upstream mapping.
    pub params: Vec<ParamSpec>,
    pub response: ResponseKind,
    pub content_types: Vec<String>,
    pub max_bytes: Option<u64>,
    pub shared: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseKind {
    Json,
    Binary,
}

impl ResponseKind {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "binary" => Some(Self::Binary),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Binary => "binary",
        }
    }
}

/// Where a declared downstream parameter is injected upstream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParamLocation {
    Query,
    Body,
    Path,
}

/// The validated wire kind of one declared downstream parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParamKind {
    String,
    Enum,
    Integer,
    Number,
    Boolean,
}

/// One allow-listed downstream parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParamSpec {
    pub name: String,
    pub upstream: String,
    pub location: ParamLocation,
    pub kind: ParamKind,
    pub required: bool,
    pub min_len: Option<usize>,
    pub max_len: Option<usize>,
    pub min: Option<serde_json::Number>,
    pub max: Option<serde_json::Number>,
    pub values: Vec<String>,
    /// Whether the caller supplies a set by repeating the key.
    ///
    /// A set has no order: members are sorted and de-duplicated before they
    /// reach the upstream or the cache key, so two callers that pass the same
    /// members in a different order share one entry.
    pub array: bool,
    /// Member cap; `None` means [`MAX_ARRAY_ITEMS`]. Ignored for scalars.
    pub max_items: Option<usize>,
}

/// Hard ceiling on declared array members, enforced when the request arrives.
pub const MAX_ARRAY_ITEMS: usize = 32;

/// A downstream parameter after validation. The type is preserved so the
/// broker never reparses a value that already passed the boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidatedParamValue {
    String(String),
    Integer(i64),
    Number {
        raw: String,
        value: serde_json::Number,
    },
    Boolean(bool),
    /// A canonicalised set: sorted and de-duplicated.
    List(Vec<ValidatedParamValue>),
}

impl ValidatedParamValue {
    /// Canonical query/cache spelling. Numbers keep the caller's raw literal.
    ///
    /// Lists join with a comma, which is only a display form: the broker expands
    /// them into repeated pairs rather than sending the joined string.
    #[must_use]
    pub fn as_query_string(&self) -> String {
        match self {
            Self::String(value) => value.clone(),
            Self::Integer(value) => value.to_string(),
            Self::Number { raw, .. } => raw.clone(),
            Self::Boolean(value) => value.to_string(),
            Self::List(items) => items
                .iter()
                .map(Self::as_query_string)
                .collect::<Vec<_>>()
                .join(","),
        }
    }
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
    Literal(serde_json::Value),
    Subject,
    Credential,
}

impl BodyValue {
    #[must_use]
    pub fn as_token(&self) -> String {
        match self {
            Self::Literal(serde_json::Value::String(value)) => value.clone(),
            Self::Literal(value) => value.to_string(),
            Self::Subject => "{subject}".to_string(),
            Self::Credential => "{credential}".to_string(),
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw {
            "{subject}" => Self::Subject,
            "{credential}" => Self::Credential,
            other => Self::Literal(serde_json::Value::String(other.to_string())),
        }
    }
}

impl serde::Serialize for BodyValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Subject => serializer.serialize_str("{subject}"),
            Self::Credential => serializer.serialize_str("{credential}"),
            Self::Literal(serde_json::Value::String(value)) => serializer.serialize_str(value),
            Self::Literal(value) => serde_json::json!({ "json": value }).serialize(serializer),
        }
    }
}

impl<'de> serde::Deserialize<'de> for BodyValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <serde_json::Value as serde::Deserialize>::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(value) => Ok(Self::parse(&value)),
            serde_json::Value::Object(mut object)
                if object.len() == 1 && object.contains_key("json") =>
            {
                Ok(Self::Literal(object.remove("json").expect("checked key")))
            }
            _ => Err(serde::de::Error::custom(
                "body value must be a string or an object containing only json",
            )),
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
            raw_body: None,
            idempotent: true,
            view: None,
            params: Vec::new(),
            response: ResponseKind::Json,
            content_types: Vec::new(),
            max_bytes: None,
            shared: false,
        })
    }

    /// Attaches the declarative view used by the normalized endpoint.
    #[must_use]
    pub fn with_view(mut self, view: ViewSpec) -> Self {
        self.view = Some(view);
        self
    }

    /// Attaches parameter declarations after matching path placeholders.
    pub fn with_params(mut self, params: Vec<ParamSpec>) -> Re0Result<Self> {
        let allowed = params
            .iter()
            .filter(|param| param.location == ParamLocation::Path)
            .map(|param| param.upstream.clone())
            .chain(std::iter::once("subject".to_string()))
            .collect();
        let placeholders = validate_path_placeholders(&self.path_template, &allowed)
            .map_err(crate::Re0Error::Internal)?;
        for param in params
            .iter()
            .filter(|param| param.location == ParamLocation::Path)
        {
            if !placeholders.contains(&param.upstream) {
                return Err(crate::Re0Error::Internal(format!(
                    "path parameter {} has no placeholder in the template",
                    param.upstream
                )));
            }
        }
        self.params = params;
        Ok(self)
    }

    #[must_use]
    pub fn path_param_names(&self) -> Vec<String> {
        template_placeholders(&self.path_template)
            .map(|names| names.into_iter().filter(|name| name != "subject").collect())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn with_response(
        mut self,
        response: ResponseKind,
        content_types: Vec<String>,
        max_bytes: Option<u64>,
    ) -> Self {
        self.response = response;
        self.content_types = content_types;
        self.max_bytes = max_bytes;
        self
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
        self,
        method: ResourceMethod,
        body: Vec<BodyField>,
        idempotent: bool,
    ) -> Re0Result<Self> {
        let declared = !body.is_empty();
        self.with_transport_declared(method, body, idempotent, declared)
    }

    /// Like [`Self::with_transport`], but states whether the configuration
    /// declared a body at all.
    ///
    /// An explicit empty body (`body = {}`) is a legitimate shape for a POST
    /// endpoint that takes no fields: the broker then sends `{}`. An absent
    /// body is still a misconfiguration, and the two must not be conflated.
    pub fn with_transport_declared(
        mut self,
        method: ResourceMethod,
        body: Vec<BodyField>,
        idempotent: bool,
        body_declared: bool,
    ) -> Re0Result<Self> {
        validate_transport(method, &body, body_declared, &self.raw_body).map_err(|reason| {
            crate::Re0Error::Internal(format!("resource {}: {reason}", self.name))
        })?;
        self.method = method;
        self.body = body;
        self.idempotent = idempotent;
        Ok(self)
    }

    pub fn with_raw_body(mut self, raw_body: serde_json::Value) -> Re0Result<Self> {
        validate_transport(self.method, &self.body, true, &Some(raw_body.clone())).map_err(
            |reason| crate::Re0Error::Internal(format!("resource {}: {reason}", self.name)),
        )?;
        self.raw_body = Some(raw_body);
        Ok(self)
    }
}

/// A transport declaration must be internally consistent.
///
/// `Get` never carries a body (nothing to inject, and a body on GET is a
/// smuggling surface); `Post` must declare one, because an absent body is
/// indistinguishable from a misconfiguration. "Declared" is not the same as
/// "non-empty": an explicit empty body is allowed for upstreams that take none.
/// Field names must be unique so a later field cannot silently win over an
/// earlier one.
fn validate_transport(
    method: ResourceMethod,
    body: &[BodyField],
    body_declared: bool,
    raw_body: &Option<serde_json::Value>,
) -> Result<(), String> {
    match method {
        ResourceMethod::Get if !body.is_empty() || raw_body.is_some() => {
            return Err("a GET resource must not declare a body".to_string());
        }
        ResourceMethod::Post if !body_declared && raw_body.is_none() => {
            return Err(
                "a POST resource must declare a body (write `body = {}` when the \
                 upstream takes none)"
                    .to_string(),
            );
        }
        ResourceMethod::Post if raw_body.is_some() && !body.is_empty() => {
            return Err("raw_body and body fields are mutually exclusive".to_string());
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
    if template.contains("//") {
        return Err("path template must not contain '//'".to_string());
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
    template_placeholders(template).map(|_| ())
}

pub fn validate_path_placeholders(
    template: &str,
    allowed: &std::collections::BTreeSet<String>,
) -> Result<Vec<String>, String> {
    validate_path_template(template)?;
    let placeholders = template_placeholders(template)?;
    let mut seen = std::collections::BTreeSet::new();
    for name in &placeholders {
        if !allowed.contains(name) {
            return Err(format!("unknown placeholder {{{name}}}"));
        }
        if !seen.insert(name.as_str()) {
            return Err(format!("duplicate placeholder {{{name}}}"));
        }
    }
    Ok(placeholders)
}

fn template_placeholders(template: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find(['{', '}']) {
        if rest.as_bytes()[start] == b'}' {
            return Err("unbalanced braces in path template".to_string());
        }
        let end = rest[start + 1..]
            .find('}')
            .map(|end| start + 1 + end)
            .ok_or_else(|| "unbalanced braces in path template".to_string())?;
        let name = &rest[start + 1..end];
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(format!("invalid placeholder {{{name}}}"));
        }
        if rest[end + 1..].contains('{') && rest[end + 1..].contains('}') {
            let next_open = rest[end + 1..].find('{');
            let next_close = rest[end + 1..].find('}');
            if next_close.is_some_and(|close| next_open.is_none_or(|open| close < open)) {
                return Err("unbalanced braces in path template".to_string());
            }
        }
        names.push(name.to_string());
        rest = &rest[end + 1..];
    }
    Ok(names)
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
    pub params: std::collections::BTreeMap<String, ValidatedParamValue>,
}

impl ResourceRequest {
    #[must_use]
    pub fn new(resource: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            subject: subject.into(),
            params: std::collections::BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_params(
        mut self,
        params: std::collections::BTreeMap<String, ValidatedParamValue>,
    ) -> Self {
        self.params = params;
        self
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

pub struct AssetStream {
    pub content_type: String,
    pub body: futures_util::stream::BoxStream<'static, Result<bytes::Bytes, UpstreamError>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetPayload {
    pub content_type: String,
    pub body: bytes::Bytes,
}

pub enum AssetResponse {
    Buffered(AssetPayload),
    Streaming(AssetStream),
}

impl std::fmt::Debug for AssetResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Buffered(payload) => formatter.debug_tuple("Buffered").field(payload).finish(),
            Self::Streaming(stream) => formatter
                .debug_struct("Streaming")
                .field("content_type", &stream.content_type)
                .finish_non_exhaustive(),
        }
    }
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
    #[error("upstream response contract changed")]
    ContractChanged,
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
            Self::RateLimited { .. }
            | Self::Unavailable
            | Self::ContractChanged
            | Self::Truncated
            | Self::Internal => FaultClass::Internal,
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

    async fn fetch_asset_stream(
        &self,
        endpoint: &ConnectorEndpoint,
        sub_token: &SecretString,
        resource: &ResourceRequest,
        accept: &str,
        max_body: usize,
    ) -> Result<AssetStream, UpstreamError>;
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
    /// The rotating refresh token, when the upstream issues one.
    pub refresh_token: Option<SecretString>,
    /// Access-token lifetime in seconds, as returned by the upstream.
    pub expires_in: Option<u64>,
    /// Refresh-token lifetime in seconds, as returned by the upstream.
    pub refresh_expires_in: Option<u64>,
    /// The upstream account this credential speaks for, as the source names it.
    pub subject: String,
}

/// A rotated credential pair. The subject is already known from the binding.
#[derive(Clone, Debug)]
pub struct RefreshedCredential {
    pub credential: SecretString,
    pub refresh_token: Option<SecretString>,
    pub expires_in: Option<u64>,
    pub refresh_expires_in: Option<u64>,
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

    /// Tells the upstream to invalidate a credential we are dropping.
    ///
    /// Best effort by contract: a connector without a revocation endpoint, or an
    /// upstream that is down, must not stop the local revocation that already
    /// succeeded. A default no-op keeps connectors that mint tokens but never
    /// revoke them (or test doubles) from having to write one.
    async fn revoke_token(
        &self,
        _endpoint: &ConnectorEndpoint,
        _credential: &SecretString,
    ) -> Result<(), UpstreamError> {
        Ok(())
    }
}

/// Rotates an upstream refresh token.
///
/// Deliberately separate from [`ConnectorAuth`]: the data plane asks a
/// credential provider for a usable token, and only that provider may reach a
/// token-minting call. `None` means this connector has no refresh endpoint.
#[async_trait]
pub trait ConnectorRefresh: Send + Sync {
    async fn refresh_token(
        &self,
        endpoint: &ConnectorEndpoint,
        refresh_token: &SecretString,
    ) -> Result<Option<RefreshedCredential>, UpstreamError>;
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
    fn a_post_resource_may_declare_an_empty_body() {
        let spec = ResourceSpec::new("player", "/v1/player")
            .expect("spec")
            .with_transport_declared(ResourceMethod::Post, Vec::new(), true, true)
            .expect("an explicit empty body is allowed");
        assert_eq!(spec.method, ResourceMethod::Post);
        assert!(spec.body.is_empty(), "the broker sends an empty object");

        let absent = ResourceSpec::new("player", "/v1/player")
            .expect("spec")
            .with_transport_declared(ResourceMethod::Post, Vec::new(), true, false);
        assert!(
            absent.is_err(),
            "an absent body is still a misconfiguration"
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
    fn raw_body_requires_post_and_replaces_nonempty_fields() {
        let spec = ResourceSpec::new("sync", "/v1/sync")
            .expect("spec")
            .with_transport_declared(ResourceMethod::Post, Vec::new(), false, true)
            .expect("raw body is attached next")
            .with_raw_body(serde_json::json!({"history": null}))
            .expect("raw body");
        assert_eq!(spec.raw_body, Some(serde_json::json!({"history": null})));

        let get = ResourceSpec::new("sync", "/v1/sync")
            .expect("spec")
            .with_raw_body(serde_json::json!({}));
        assert!(get.is_err());
    }

    #[test]
    fn method_parsing_rejects_unknown_spellings() {
        assert_eq!(ResourceMethod::parse("get"), Some(ResourceMethod::Get));
        assert_eq!(ResourceMethod::parse(" POST "), Some(ResourceMethod::Post));
        assert_eq!(ResourceMethod::parse("postt"), None);
    }

    fn path_parameter(name: &str) -> ParamSpec {
        ParamSpec {
            name: name.to_string(),
            upstream: name.to_string(),
            location: ParamLocation::Path,
            kind: ParamKind::String,
            required: true,
            min_len: Some(1),
            max_len: Some(64),
            min: None,
            max: None,
            values: Vec::new(),
            array: false,
            max_items: None,
        }
    }

    #[test]
    fn dynamic_path_placeholders_follow_template_order() {
        let allowed = ["subject", "user", "song"]
            .into_iter()
            .map(str::to_string)
            .collect();
        assert_eq!(
            validate_path_placeholders("/v1/{user}/songs/{song}/{subject}", &allowed)
                .expect("placeholders"),
            ["user", "song", "subject"]
        );
        assert!(validate_path_placeholders("/v1/{missing}", &allowed).is_err());
        assert!(validate_path_placeholders("/v1/{user}/{user}", &allowed).is_err());
        assert!(validate_path_template("/v1//{user}").is_err());
        assert!(validate_path_template("/v1/{User}").is_err());
        assert!(validate_path_template("/v1/{user").is_err());
    }

    #[test]
    fn resource_params_match_declared_placeholders() {
        let spec = ResourceSpec::new("jacket", "/v1/{user}/songs/{song}")
            .expect("spec")
            .with_params(vec![path_parameter("song"), path_parameter("user")])
            .expect("matching path params");
        assert_eq!(spec.path_param_names(), ["user", "song"]);

        let missing = ResourceSpec::new("jacket", "/v1/{song}")
            .expect("spec")
            .with_params(vec![path_parameter("other")]);
        assert!(missing.is_err());
    }
}
