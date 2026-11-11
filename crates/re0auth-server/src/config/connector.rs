use serde::Deserialize;

use super::is_https_or_local_http;

/// One upstream connector. Path templates live here, never in a request
/// (ADR-0032), so a caller can never choose the URL.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorConfig {
    /// Stable identifier, e.g. `phigros`. Also the bindings' `upstream_id`.
    pub id: String,
    /// Label shown to people; the id stays the URL and binding key.
    #[serde(default)]
    pub display_name: String,
    pub base_url: String,
    #[serde(default)]
    pub allow_private_net: bool,
    #[serde(default)]
    pub allow_link_local_metadata: bool,
    /// Explicit local connector exception. Never inherited from `tls.allow_loopback`.
    #[serde(default)]
    pub allow_loopback: bool,
    /// Whether this connector may appear in the public `/openapi.json`.
    #[serde(default = "default_true")]
    pub expose_in_openapi: bool,
    #[serde(default)]
    pub resources: Vec<ResourceConfig>,
    /// Endpoints used to bind a user to this upstream (INV-BIND-03).
    ///
    /// Absent means the connector is read-only here: it serves data for bindings
    /// created elsewhere, and the binding routes answer 404. Present means the
    /// user can start a flow.
    #[serde(default)]
    pub oauth: Option<ConnectorOAuthConfig>,
}

impl ConnectorConfig {
    #[must_use]
    pub fn egress_policy(&self) -> re0auth_api::connector::EgressPolicy {
        use re0auth_api::connector::EgressPolicy;
        if self.allow_link_local_metadata {
            EgressPolicy::LinkLocalMetadata
        } else if self.allow_loopback {
            EgressPolicy::Loopback
        } else if self.allow_private_net {
            EgressPolicy::PrivateNet
        } else {
            EgressPolicy::Public
        }
    }
}

/// How to obtain a user credential from one upstream.
///
/// Distinct from `identity_providers`: those authenticate the user to *us*, these
/// authorize *us* to act upstream. Sharing the type would let a change made for
/// login silently alter binding.
#[derive(Debug, Deserialize)]
pub struct ConnectorOAuthConfig {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// Optional: when absent, the client cannot refresh and an expired
    /// credential requires reauthorization.
    #[serde(default)]
    pub refresh_endpoint: Option<String>,
    pub client_id: String,
    /// Prefer `client_secret_file` in deployment; see `IDP-SETUP.md`.
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub client_secret_file: String,
    /// Required: there is no provider-neutral default (see `IDP-SETUP.md` §2.1).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Where the upstream account is read after the exchange.
    ///
    /// Required whenever `oauth` is present. The exchange yields a credential but
    /// not whose it is, and a binding without an upstream subject cannot serve a
    /// single read — so a deployment missing this is refused at startup rather
    /// than at the first bind.
    pub userinfo_endpoint: String,
    /// The field in the userinfo document that names the account.
    ///
    /// One of `id`, `openid`, `login`, `name`. A field rather than a JSON path:
    /// `INV-CONN-01` forbids reaching into an undeclared document.
    pub subject_field: String,
    /// Where the upstream invalidates a credential when its binding is revoked.
    ///
    /// Optional: an upstream that offers no revocation endpoint leaves the
    /// credential valid until expiry; the local revocation still happens.
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResourceConfig {
    /// Name used in `/api/v1/upstreams/{id}/{name}`.
    pub name: String,
    /// Relative path; may contain the single placeholder `{subject}`.
    pub path: String,
    /// Required scope. Defaults to `upstream.<name>.read`.
    #[serde(default)]
    pub scope: Option<String>,
    /// `get` (default) or `post` (ADR-0046).
    #[serde(default)]
    pub method: Option<String>,
    /// Whether a retry is safe (F-4). Defaults to `true` for `get`, `false` for `post`.
    #[serde(default)]
    pub idempotent: Option<bool>,
    /// Server-generated body: field name → value. Value syntax: a literal, or the
    /// placeholders `{subject}` / `{credential}`. Only valid with `method = "post"`.
    #[serde(default)]
    pub body: Option<std::collections::BTreeMap<String, String>>,
    /// Declarative view for the normalized endpoint (ADR-0049). Absent means the
    /// envelope carries the upstream JSON unchanged.
    #[serde(default)]
    pub view: Option<ViewConfig>,
    /// Declared downstream query parameters, validated and mapped upstream.
    #[serde(default)]
    pub params: Vec<ParamConfig>,
}

/// One `[[connectors.resources.params]]` entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamConfig {
    pub name: String,
    #[serde(rename = "in", default)]
    pub location: Option<String>,
    pub upstream: Option<String>,
    pub kind: Option<String>,
    #[serde(default)]
    pub required: bool,
    pub min_len: Option<usize>,
    pub max_len: Option<usize>,
    pub min: Option<serde_json::Number>,
    pub max: Option<serde_json::Number>,
    #[serde(default)]
    pub values: Vec<String>,
    /// Repeat the key downstream to supply a set (sorted, de-duplicated).
    #[serde(default)]
    pub array: bool,
    /// Member cap for arrays; defaults to [`re0auth_api::connector::MAX_ARRAY_ITEMS`].
    pub max_items: Option<usize>,
}

/// `[connectors.resources.view]`: how the normalized endpoint shapes one resource.
#[derive(Debug, Deserialize, Default)]
pub struct ViewConfig {
    /// Data root for non-list resources; defaults to `$`.
    #[serde(default)]
    pub data_path: Option<String>,
    /// Array position for list resources. Mutually exclusive with `data_path`.
    #[serde(default)]
    pub items_path: Option<String>,
    /// Output field name → path relative to the data root or to each item.
    #[serde(default)]
    pub fields: Option<std::collections::BTreeMap<String, String>>,
}

impl ViewConfig {
    fn to_spec(&self, resource: &str) -> anyhow::Result<re0auth_api::view::ViewSpec> {
        use re0auth_api::view::{FieldMapping, JsonPath, ViewSpec};

        if self.data_path.is_some() && self.items_path.is_some() {
            anyhow::bail!("resource {resource}: data_path and items_path are mutually exclusive");
        }
        let path = |raw: &str| {
            JsonPath::parse(raw).map_err(|error| {
                anyhow::anyhow!("resource {resource}: invalid view path {raw:?}: {error}")
            })
        };
        let data_path = match &self.data_path {
            Some(raw) => path(raw)?,
            None => path("$")?,
        };
        let items_path = match &self.items_path {
            Some(raw) => Some(path(raw)?),
            None => None,
        };
        let fields = self
            .fields
            .as_ref()
            .map(|map| {
                map.iter()
                    .map(|(name, raw)| {
                        if name.trim().is_empty() {
                            anyhow::bail!("resource {resource}: view field name is empty");
                        }
                        Ok(FieldMapping {
                            name: name.clone(),
                            path: path(raw)?,
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(ViewSpec {
            data_path,
            items_path,
            fields,
        })
    }
}

impl ResourceConfig {
    /// Turns the config entry into a validated [`ResourceSpec`].
    ///
    /// One conversion used by both `--check-config` and startup, so a file that
    /// passes validation cannot then fail assembly (ADR-0046).
    pub fn to_spec(&self) -> anyhow::Result<re0auth_api::connector::ResourceSpec> {
        use re0auth_api::connector::{BodyField, ResourceMethod, ResourceSpec};

        let method = match &self.method {
            None => ResourceMethod::Get,
            Some(raw) => ResourceMethod::parse(raw).ok_or_else(|| {
                anyhow::anyhow!(
                    "resource {}: unknown method {:?} (use get or post)",
                    self.name,
                    raw
                )
            })?,
        };
        let body: Vec<BodyField> = self
            .body
            .as_ref()
            .map(|map| {
                map.iter()
                    .map(|(name, raw)| BodyField {
                        name: name.clone(),
                        value: body_value(raw),
                    })
                    .collect()
            })
            .unwrap_or_default();
        // A read is safe to retry; a write is not until its author says so.
        let idempotent = self.idempotent.unwrap_or(method == ResourceMethod::Get);
        let body_names: Vec<String> = body.iter().map(|field| field.name.clone()).collect();
        let params = self.params_to_spec(method, &body_names)?;

        let spec = ResourceSpec::new(self.name.clone(), self.path.clone())
            .map_err(|error| anyhow::anyhow!("resource {}: {error}", self.name))?;
        let spec = spec
            .with_transport_declared(method, body, idempotent, self.body.is_some())
            .map_err(|error| anyhow::anyhow!("resource {}: {error}", self.name))?;
        let spec = match &self.view {
            Some(view) => spec.with_view(view.to_spec(&self.name)?),
            None => spec,
        };
        let spec = match &self.scope {
            Some(scope) => spec
                .with_scope(scope.clone())
                .map_err(|error| anyhow::anyhow!("resource {}: {error}", self.name))?,
            None => spec,
        };
        Ok(spec.with_params(params))
    }

    fn params_to_spec(
        &self,
        method: re0auth_api::connector::ResourceMethod,
        body_names: &[String],
    ) -> anyhow::Result<Vec<re0auth_api::connector::ParamSpec>> {
        use re0auth_api::connector::{ParamKind, ParamLocation, ParamSpec};
        use std::collections::BTreeSet;

        if self.params.len() > 16 {
            anyhow::bail!("resource {}: more than 16 parameters", self.name);
        }
        let mut names = BTreeSet::new();
        let mut upstreams: BTreeSet<String> = body_names.iter().cloned().collect();
        let mut specs = Vec::with_capacity(self.params.len());
        for param in &self.params {
            if !valid_param_name(&param.name) {
                anyhow::bail!(
                    "resource {}: invalid parameter name {:?}",
                    self.name,
                    param.name
                );
            }
            if matches!(
                param.name.as_str(),
                "limit" | "cursor" | "subject" | "credential"
            ) {
                anyhow::bail!(
                    "resource {}: reserved parameter name {:?}",
                    self.name,
                    param.name
                );
            }
            if !names.insert(param.name.clone()) {
                anyhow::bail!(
                    "resource {}: duplicate parameter name {:?}",
                    self.name,
                    param.name
                );
            }
            let location = match param.location.as_deref().unwrap_or("query") {
                "query" => ParamLocation::Query,
                "body" => ParamLocation::Body,
                other => anyhow::bail!(
                    "resource {} parameter {}: unknown location {:?}",
                    self.name,
                    param.name,
                    other
                ),
            };
            if location == ParamLocation::Body
                && method != re0auth_api::connector::ResourceMethod::Post
            {
                anyhow::bail!(
                    "resource {} parameter {}: body parameters require method post",
                    self.name,
                    param.name
                );
            }
            let upstream = param.upstream.clone().unwrap_or_else(|| param.name.clone());
            if !valid_upstream_name(&upstream, location) {
                anyhow::bail!(
                    "resource {} parameter {}: invalid upstream name {:?}",
                    self.name,
                    param.name,
                    upstream
                );
            }
            if !upstreams.insert(upstream.clone()) {
                anyhow::bail!(
                    "resource {} parameter {}: upstream field {:?} collides with another field",
                    self.name,
                    param.name,
                    upstream
                );
            }
            let kind = match param.kind.as_deref().unwrap_or("string") {
                "string" => ParamKind::String,
                "enum" => ParamKind::Enum,
                "integer" => ParamKind::Integer,
                "number" => ParamKind::Number,
                "boolean" => ParamKind::Boolean,
                other => anyhow::bail!(
                    "resource {} parameter {}: unknown kind {:?}",
                    self.name,
                    param.name,
                    other
                ),
            };
            if !param.values.is_empty() && kind != ParamKind::Enum {
                anyhow::bail!(
                    "resource {} parameter {}: values are only allowed for enum",
                    self.name,
                    param.name
                );
            }
            if (param.min.is_some() || param.max.is_some())
                && !matches!(kind, ParamKind::Integer | ParamKind::Number)
            {
                anyhow::bail!(
                    "resource {} parameter {}: min/max are only allowed for integer/number",
                    self.name,
                    param.name
                );
            }
            if (param.min_len.is_some() || param.max_len.is_some()) && kind != ParamKind::String {
                anyhow::bail!(
                    "resource {} parameter {}: min_len/max_len are only allowed for string",
                    self.name,
                    param.name
                );
            }
            self.validate_array_param(param)?;
            let mut spec = ParamSpec {
                name: param.name.clone(),
                upstream,
                location,
                kind,
                required: param.required,
                min_len: None,
                max_len: None,
                min: None,
                max: None,
                values: Vec::new(),
                array: param.array,
                max_items: param.max_items,
            };
            match kind {
                ParamKind::String => {
                    let min_len = param.min_len.unwrap_or(1);
                    let max_len = param.max_len.unwrap_or(64);
                    if !(1..=256).contains(&min_len)
                        || !(1..=256).contains(&max_len)
                        || min_len > max_len
                    {
                        anyhow::bail!(
                            "resource {} parameter {}: invalid string length bounds {}..{}",
                            self.name,
                            param.name,
                            min_len,
                            max_len
                        );
                    }
                    spec.min_len = Some(min_len);
                    spec.max_len = Some(max_len);
                }
                ParamKind::Enum => {
                    if param.values.is_empty() || param.values.len() > 32 {
                        anyhow::bail!(
                            "resource {} parameter {}: enum values must be 1..=32",
                            self.name,
                            param.name
                        );
                    }
                    let mut seen = BTreeSet::new();
                    for value in &param.values {
                        let len = value.chars().count();
                        if !(1..=64).contains(&len) || !seen.insert(value.clone()) {
                            anyhow::bail!(
                                "resource {} parameter {}: invalid or duplicate enum value {:?}",
                                self.name,
                                param.name,
                                value
                            );
                        }
                    }
                    spec.values = param.values.clone();
                }
                ParamKind::Integer => {
                    if let Some(min) = &param.min
                        && min.as_i64().is_none()
                    {
                        anyhow::bail!(
                            "resource {} parameter {}: integer min must be an i64",
                            self.name,
                            param.name
                        );
                    }
                    if let Some(max) = &param.max
                        && max.as_i64().is_none()
                    {
                        anyhow::bail!(
                            "resource {} parameter {}: integer max must be an i64",
                            self.name,
                            param.name
                        );
                    }
                    if let (Some(min), Some(max)) = (
                        param.min.as_ref().and_then(|n| n.as_i64()),
                        param.max.as_ref().and_then(|n| n.as_i64()),
                    ) && min > max
                    {
                        anyhow::bail!(
                            "resource {} parameter {}: integer min > max",
                            self.name,
                            param.name
                        );
                    }
                    spec.min = param.min.clone();
                    spec.max = param.max.clone();
                }
                ParamKind::Number => {
                    for bound in [&param.min, &param.max].into_iter().flatten() {
                        if bound.as_f64().is_none_or(|value| !value.is_finite()) {
                            anyhow::bail!(
                                "resource {} parameter {}: number bounds must be finite",
                                self.name,
                                param.name
                            );
                        }
                    }
                    if let (Some(min), Some(max)) = (
                        param.min.as_ref().and_then(|n| n.as_f64()),
                        param.max.as_ref().and_then(|n| n.as_f64()),
                    ) && min > max
                    {
                        anyhow::bail!(
                            "resource {} parameter {}: number min > max",
                            self.name,
                            param.name
                        );
                    }
                    spec.min = param.min.clone();
                    spec.max = param.max.clone();
                }
                ParamKind::Boolean => {}
            }
            specs.push(spec);
        }
        Ok(specs)
    }
}

fn valid_param_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

fn valid_upstream_name(value: &str, location: re0auth_api::connector::ParamLocation) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| match location {
            re0auth_api::connector::ParamLocation::Body => {
                byte.is_ascii_alphanumeric() || byte == b'_'
            }
            re0auth_api::connector::ParamLocation::Query => {
                byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'.'
            }
        })
}

fn body_value(raw: &str) -> re0auth_api::connector::BodyValue {
    re0auth_api::connector::BodyValue::parse(raw)
}

fn default_true() -> bool {
    true
}

/// Checks the bind endpoints of one connector.
///
/// Three of these are called by the server and therefore go through the outbound
/// guard, so they must satisfy the same scheme rule the guard enforces —
/// `--check-config` passing while startup rejects the same file is the failure
/// this pairing exists to prevent. `authorization_endpoint` is the exception: the
/// browser navigates to it, the server never requests it.
pub(super) fn validate_connector_oauth(
    connector: &ConnectorConfig,
    oauth: &ConnectorOAuthConfig,
) -> anyhow::Result<()> {
    let label = format!("connector {}.oauth", connector.id);
    // Required-ness first: an empty endpoint would otherwise fail the scheme
    // check below and report "must be https", which sends the reader looking for
    // a scheme problem instead of a missing field.
    if oauth.userinfo_endpoint.trim().is_empty() {
        anyhow::bail!(
            "{label}.userinfo_endpoint is required: the bind cannot establish \
             which upstream account the credential belongs to without it"
        );
    }
    if oauth.subject_field.trim().is_empty() {
        anyhow::bail!(
            "{label}.subject_field is required: the bind cannot establish which \
             upstream account the credential belongs to without it"
        );
    }
    // A flat field name, not a path: INV-CONN-01 forbids digging through an
    // undeclared document, and a dot or bracket is what would make it one.
    // A closed list would reject standard OIDC (`sub`) and every new upstream,
    // so the charset is the rule rather than a set of vendor names.
    if !oauth
        .subject_field
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        || oauth.subject_field.len() > 64
    {
        anyhow::bail!(
            "{label}.subject_field must be a flat field name \
             ([A-Za-z0-9_-], at most 64 chars): got {:?}",
            oauth.subject_field
        );
    }
    if oauth.scopes.iter().all(|scope| scope.trim().is_empty()) {
        anyhow::bail!("{label}.scopes must name at least one scope");
    }
    // The browser navigates to the authorization endpoint; we never request it,
    // so loopback http is fine there regardless of the outbound policy. The other
    // two we do request, so they must satisfy what the guard will enforce —
    // otherwise `--check-config` passes a file that startup then rejects.
    if !is_https_or_local_http(&oauth.authorization_endpoint, true) {
        anyhow::bail!("{label}.authorization_endpoint must be an absolute https URL");
    }
    for endpoint in [&oauth.token_endpoint, &oauth.userinfo_endpoint] {
        if !is_https_or_local_http(endpoint, connector.allow_loopback) {
            anyhow::bail!(
                "{label} endpoints must be https URLs \
                 (http only for loopback with connector allow_loopback): {endpoint}"
            );
        }
    }
    // 这个地址我们也会请求，所以受同一条出网策略约束。
    if let Some(endpoint) = oauth.revocation_endpoint.as_deref()
        && !is_https_or_local_http(endpoint, connector.allow_loopback)
    {
        anyhow::bail!(
            "{label}.revocation_endpoint must be an https URL \
             (http only for loopback with connector allow_loopback): {endpoint}"
        );
    }
    Ok(())
}

impl ConnectorConfig {
    /// The operator's label, falling back to the id when unset.
    #[must_use]
    pub fn effective_display_name(&self) -> &str {
        let trimmed = self.display_name.trim();
        if trimmed.is_empty() { &self.id } else { trimmed }
    }
}

impl ResourceConfig {
    pub(super) fn validate_array_param(&self, param: &ParamConfig) -> anyhow::Result<()> {
        if param.max_items.is_some() && !param.array {
            anyhow::bail!(
                "resource {} parameter {}: max_items requires array = true",
                self.name,
                param.name
            );
        }
        if let Some(max) = param.max_items
            && !(1..=re0auth_api::connector::MAX_ARRAY_ITEMS).contains(&max)
        {
            anyhow::bail!(
                "resource {} parameter {}: max_items must be between 1 and {}",
                self.name,
                param.name,
                re0auth_api::connector::MAX_ARRAY_ITEMS
            );
        }
        Ok(())
    }
}
