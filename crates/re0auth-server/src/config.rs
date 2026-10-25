use std::borrow::Cow;
use std::path::Path;

use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub crypto: CryptoConfig,
    pub limits: LimitsConfig,
    /// INV-RATE-01. Absent means "no per-lane budget", which the composition
    /// root wires as `Unlimited` rather than leaving the field `None`.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// INV-CACHE-01..03. Absent means caching is off.
    #[serde(default)]
    pub cache: CacheConfig,
    /// Retention windows (Q-032). Defaults are the decided policy.
    #[serde(default)]
    pub retention: RetentionConfig,
    #[serde(default)]
    pub tls: TlsSettings,
    /// Identity providers, selected by the `idp` query parameter on `/auth/login`.
    ///
    /// A list rather than a single block: an instance that serves several
    /// communities needs more than one IdP, and the old `[identity_provider]`
    /// form is still accepted as a one-element list (`identity_provider_alias`).
    #[serde(default)]
    pub identity_providers: Vec<IdentityProviderConfig>,
    /// Backwards compatibility for the pre-list `[identity_provider]` block.
    #[serde(default)]
    identity_provider: Option<IdentityProviderConfig>,
    /// Set when both spellings are present, so `validate` can reject it.
    #[serde(skip)]
    legacy_identity_provider_conflict: bool,
    /// Registered upstreams. Empty means the gateway has nothing to proxy.
    #[serde(default)]
    pub connectors: Vec<ConnectorConfig>,
}

/// One upstream connector. Path templates live here, never in a request
/// (ADR-0032), so a caller can never choose the URL.
#[derive(Debug, Deserialize)]
pub struct ConnectorConfig {
    /// Stable identifier, e.g. `phigros`. Also the bindings' `upstream_id`.
    pub id: String,
    pub base_url: String,
    #[serde(default)]
    pub allow_private_net: bool,
    #[serde(default)]
    pub allow_link_local_metadata: bool,
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

/// How to obtain a user credential from one upstream.
///
/// Distinct from `identity_providers`: those authenticate the user to *us*, these
/// authorize *us* to act upstream. Sharing the type would let a change made for
/// login silently alter binding.
#[derive(Debug, Deserialize)]
pub struct ConnectorOAuthConfig {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
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

        let spec = ResourceSpec::new(self.name.clone(), self.path.clone())
            .map_err(|error| anyhow::anyhow!("resource {}: {error}", self.name))?;
        let spec = spec
            .with_transport(method, body, idempotent)
            .map_err(|error| anyhow::anyhow!("resource {}: {error}", self.name))?;
        match &self.scope {
            Some(scope) => spec
                .with_scope(scope.clone())
                .map_err(|error| anyhow::anyhow!("resource {}: {error}", self.name)),
            None => Ok(spec),
        }
    }
}

fn body_value(raw: &str) -> re0auth_api::connector::BodyValue {
    re0auth_api::connector::BodyValue::parse(raw)
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub bind: String,
    pub issuer: String,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct CryptoConfig {
    pub master_key_file: String,
    pub signing_key_file: String,
    /// Keys a rotation must still be able to open, as `(version, file)`.
    ///
    /// Declared explicitly rather than discovered: a record wrapped under a key
    /// that is not listed here is unreadable, and silently skipping it would let
    /// an operator drop the old key believing the rotation finished.
    #[serde(default)]
    pub retired_master_key_files: Vec<RetiredKeyConfig>,
    /// Connector root-credential vault (ADR-0039). Empty disables it, which is
    /// correct when every connector uses in-memory relay only.
    #[serde(default)]
    pub connector_secret_file: String,
}

/// A retired master key, kept readable only so a rotation can re-wrap with it.
#[derive(Debug, Clone, Deserialize)]
pub struct RetiredKeyConfig {
    pub version: u32,
    pub file: String,
}

#[derive(Debug, Deserialize)]
pub struct LimitsConfig {
    pub upstream_response_bytes: u64,
    pub upstream_inflight_bytes: u64,
    pub inbound_body_bytes: u64,
}

/// Response cache (INV-CACHE-01..03).
///
/// Off unless `enabled = true`: caching changes what callers observe during an
/// outage, so it is an explicit operator decision rather than a default.
#[derive(Debug, Deserialize)]
pub struct CacheConfig {
    #[serde(default)]
    pub enabled: bool,
    /// How long a stored response stays fresh.
    #[serde(default = "default_cache_ttl_secs")]
    pub ttl_secs: u64,
    /// Upper bound on stored bytes, evicted by `moka`.
    #[serde(default = "default_cache_max_bytes")]
    pub max_bytes: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_secs: default_cache_ttl_secs(),
            max_bytes: default_cache_max_bytes(),
        }
    }
}

fn default_cache_ttl_secs() -> u64 {
    // test-v1.3.md §6.8.
    300
}

/// How long audit rows and revoked-binding identities are kept, in days.
///
/// Zero is refused for every window: a zero-day retention would delete evidence
/// as it is written, which reads like "cleanup is off" but behaves like
/// "everything is expired".
#[derive(Debug, Deserialize)]
pub struct RetentionConfig {
    /// Security facts, kept for post-incident review.
    #[serde(default = "default_audit_fact_days")]
    pub audit_fact_days: u64,
    /// Access telemetry, kept long enough to answer "who read what recently".
    #[serde(default = "default_access_telemetry_days")]
    pub access_telemetry_days: u64,
    /// How long a revoked binding keeps its upstream account identity.
    #[serde(default = "default_revoked_binding_anonymize_days")]
    pub revoked_binding_anonymize_days: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            audit_fact_days: default_audit_fact_days(),
            access_telemetry_days: default_access_telemetry_days(),
            revoked_binding_anonymize_days: default_revoked_binding_anonymize_days(),
        }
    }
}

fn default_audit_fact_days() -> u64 {
    365
}

fn default_access_telemetry_days() -> u64 {
    90
}

fn default_revoked_binding_anonymize_days() -> u64 {
    30
}

fn default_cache_max_bytes() -> u64 {
    // Matches the raw-cache budget in DATA-MODEL.md §220.
    8 * 1024 * 1024
}

/// Per-lane budgets (INV-RATE-01).
///
/// The lanes are separate on purpose. Unauthenticated traffic is cheap to send
/// and expensive to serve (it mints state), so its budget is tighter;
/// authenticated data-plane traffic is already attributed to a client, so the
/// budget there is about fairness between bots rather than abuse prevention.
/// The per-user budget guards the other axis: many bots may share one client id,
/// so a client ceiling alone would let them spend a single player's allowance
/// without limit.
#[derive(Debug, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_unauth_burst")]
    pub unauthenticated_burst: u32,
    #[serde(default = "default_unauth_period")]
    pub unauthenticated_period_secs: u64,
    #[serde(default = "default_auth_burst")]
    pub authenticated_burst: u32,
    #[serde(default = "default_auth_period")]
    pub authenticated_period_secs: u64,
    #[serde(default = "default_user_burst")]
    pub per_user_burst: u32,
    #[serde(default = "default_user_period")]
    pub per_user_period_secs: u64,
    /// `true` disables both lanes. Exists for benchmarks and development only;
    /// startup logs a warning when it is set.
    #[serde(default)]
    pub disabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            unauthenticated_burst: default_unauth_burst(),
            unauthenticated_period_secs: default_unauth_period(),
            authenticated_burst: default_auth_burst(),
            authenticated_period_secs: default_auth_period(),
            per_user_burst: default_user_burst(),
            per_user_period_secs: default_user_period(),
            disabled: false,
        }
    }
}

fn default_unauth_burst() -> u32 {
    30
}

fn default_unauth_period() -> u64 {
    60
}

fn default_auth_burst() -> u32 {
    120
}

fn default_auth_period() -> u64 {
    60
}

fn default_user_burst() -> u32 {
    60
}

fn default_user_period() -> u64 {
    60
}

/// Outbound TLS trust. `extra_ca_file` is appended to Mozilla's bundle (§6.9).
#[derive(Debug, Default, Deserialize)]
pub struct TlsSettings {
    #[serde(default)]
    pub extra_ca_file: Option<String>,
    /// Only for an explicitly configured local IdP/connector. Default off.
    #[serde(default)]
    pub allow_loopback: bool,
    /// Private-network connectors (BYOC). Default off.
    #[serde(default)]
    pub allow_private_net: bool,
}

impl TlsSettings {
    pub fn trust_config(&self) -> anyhow::Result<re0auth_runtime::tls::TlsConfig> {
        let config = re0auth_runtime::tls::TlsConfig::mozilla_only();
        match self.extra_ca_file.as_deref().map(str::trim) {
            None | Some("") => Ok(config),
            Some(path) => config.with_extra_ca_file(std::path::Path::new(path)),
        }
    }

    #[must_use]
    pub fn policy(&self) -> re0auth_runtime::outbound::OutboundPolicy {
        use re0auth_runtime::outbound::OutboundPolicy;
        if self.allow_loopback {
            OutboundPolicy::AllowLoopback
        } else if self.allow_private_net {
            OutboundPolicy::AllowPrivateNet
        } else {
            OutboundPolicy::PublicOnly
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum IdentityProviderKind {
    /// OpenID Connect: `id_token` plus a JWKS to verify it against.
    #[default]
    Oidc,
    /// GitHub OAuth 2.0: no `id_token`, identity read from `api.github.com/user`.
    Github,
    /// QQ OAuth 2.0: no `id_token`, identity read from a JSONP-wrapped endpoint.
    Qq,
}

#[derive(Deserialize)]
pub struct IdentityProviderConfig {
    /// Stable name used in `/auth/login?idp=<name>`. Defaults to the issuer host
    /// when omitted, so a single-provider setup needs no new field.
    #[serde(default)]
    pub name: String,
    /// Stable namespace recorded in `identities.issuer`.
    ///
    /// For `oidc` this is the protocol issuer and is checked against discovery.
    /// For the OAuth2 kinds it is a name we own: those providers issue no `iss`
    /// claim, so `validate` pins it to the kind's fixed value.
    pub issuer: String,
    #[serde(default)]
    pub kind: IdentityProviderKind,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    /// Path to a file holding the client secret.
    ///
    /// An alternative to `client_secret` for deployments that mount a secret
    /// instead of passing it in an environment variable, which leaks through
    /// `/proc/<pid>/environ` and container inspect output. Setting both is an
    /// error.
    #[serde(default)]
    pub client_secret_file: Option<String>,
    pub redirect_uri: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub discovery_url: Option<String>,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Required for the OAuth2 kinds: where the identity document is read.
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
}

impl IdentityProviderConfig {
    /// The selector used by `/auth/login?idp=`.
    ///
    /// Falls back to the issuer host so a legacy single-provider file keeps
    /// working without a new field. The host rather than the whole URL keeps the
    /// selector readable in a query string, where `https://` would be escaped.
    /// Two providers on the same host must be told apart by an explicit `name`,
    /// which `validate` enforces.
    #[must_use]
    pub fn effective_name(&self) -> Cow<'_, str> {
        if !self.name.trim().is_empty() {
            return Cow::Borrowed(self.name.trim());
        }
        let issuer = self.issuer.trim();
        let host = url::Url::parse(issuer).ok().and_then(|url| {
            // The port is kept: two providers on one host told apart by port must
            // not collapse into one name (a collision `validate` would report).
            let host = url.host_str()?;
            Some(match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            })
        });
        match host {
            Some(host) => Cow::Owned(host),
            // An issuer that does not parse is compared as written, so a duplicate
            // is still caught before the malformed URL is reported.
            None => Cow::Borrowed(issuer.trim_end_matches('/')),
        }
    }
}

impl std::fmt::Debug for IdentityProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityProviderConfig")
            .field("name", &self.name)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

pub fn load_config(path: &Path) -> anyhow::Result<Config> {
    // Keys that address a provider by index are withheld from `Env`: `split("__")`
    // turns `IDENTITY_PROVIDERS__0__X` into a nested *map*, while the schema wants
    // a `Vec`, and figment fails the whole extract on the type mismatch. They are
    // applied to the parsed struct instead (ISSUE-0007).
    let mut cfg: Config = Figment::new()
        .merge(Toml::file(path))
        .merge(
            // The filter runs before `split`, because `Env` chains its transforms:
            // placed after, it would see `identity_providers.0.client_secret` and
            // the `__`-separated test below would never match.
            Env::prefixed("RE0AUTH_")
                .filter(|key| !crate::config_env::is_provider_override_key(key.as_str()))
                .split("__"),
        )
        .extract()?;
    // Fold first: `[identity_provider]` only becomes an element of
    // `identity_providers` here, so anything that walks the list has to run after
    // it. Applying overrides or secret files before the fold silently skipped the
    // legacy spelling — an OIDC provider accepts an empty secret, so the config
    // validated and the secret simply was never read.
    fold_legacy_identity_provider(&mut cfg);
    crate::config_env::apply_provider_overrides(
        &mut cfg,
        &crate::config_env::provider_override_vars(),
    )?;
    crate::config_env::resolve_secret_files(&mut cfg)?;
    validate(&cfg)?;
    Ok(cfg)
}

/// Folds `[identity_provider]` into the list.
///
/// Two spellings for one setting is a trap: whichever wins silently, and the
/// operator reading the file sees the other. Rejecting the combination outright
/// is the only version that cannot mislead.
fn fold_legacy_identity_provider(cfg: &mut Config) {
    let Some(legacy) = cfg.identity_provider.take() else {
        return;
    };
    if cfg.identity_providers.is_empty() {
        cfg.identity_providers.push(legacy);
    } else {
        // Recorded here so `validate` can report it with the other config errors
        // rather than panicking during deserialization.
        cfg.legacy_identity_provider_conflict = true;
    }
}

/// True when `raw` is an absolute `https` URL, or plain `http` to a loopback
/// host and `allow_loopback` is set.
///
/// Parsed rather than prefix-matched: `http://localhost.evil.com` starts with
/// `http://localhost` but its host is `localhost.evil.com`, which is a name an
/// attacker can register. Only `host_str()` answers the actual question.
///
/// `allow_loopback` is a parameter rather than an unconditional allowance
/// because the runtime guard refuses plain http unless it is set. Accepting the
/// URL here without it produced a config that passed `--check-config` and then
/// died on the first request with `scheme http is not allowed`: the two checks
/// have to agree, or the early one is lying.
fn is_https_or_local_http(raw: &str, allow_loopback: bool) -> bool {
    let Ok(url) = url::Url::parse(raw) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => {
            allow_loopback && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
        }
        _ => false,
    }
}

/// Maps a config kind to the adapter kind it drives.
///
/// One conversion, in one place: the namespace a provider stores its subjects
/// under is defined by the adapter, so config checks that value instead of
/// repeating the string.
pub fn oauth2_kind(kind: IdentityProviderKind) -> re0auth_idp::oauth2::OAuth2Kind {
    match kind {
        IdentityProviderKind::Github => re0auth_idp::oauth2::OAuth2Kind::GitHub,
        IdentityProviderKind::Qq => re0auth_idp::oauth2::OAuth2Kind::Qq,
        IdentityProviderKind::Oidc => {
            unreachable!("oidc has no oauth2 equivalent")
        }
    }
}

/// Checks the fields that only apply to one provider kind.
///
/// Two rules carry the weight here:
///
/// - An OAuth2 provider must name where identity comes from and where the code
///   is exchanged, because there is no discovery document to consult.
/// - Its `issuer` is a namespace we own, not something the provider tells us. If
///   an operator changed it the rows in `identities` would no longer match, and
///   every existing user of that provider would silently become a new user. It is
///   therefore pinned to the kind's fixed value instead of being free text.
fn validate_provider_kind(idp: &IdentityProviderConfig, label: &str) -> anyhow::Result<()> {
    match idp.kind {
        IdentityProviderKind::Oidc => {
            if idp.userinfo_endpoint.is_some() {
                anyhow::bail!(
                    "{label}.userinfo_endpoint only applies to the oauth2 kinds; \
                     oidc reads identity from the id_token"
                );
            }
        }
        IdentityProviderKind::Github | IdentityProviderKind::Qq => {
            let expected = oauth2_kind(idp.kind).namespace();
            if idp.issuer.trim_end_matches('/') != expected {
                anyhow::bail!(
                    "{label}.issuer must be {expected:?} for the {:?} kind; it is a namespace \
                     recorded in `identities`, and changing it orphans existing accounts",
                    idp.kind
                );
            }
            for (field, value) in [
                ("authorization_endpoint", &idp.authorization_endpoint),
                ("token_endpoint", &idp.token_endpoint),
                ("userinfo_endpoint", &idp.userinfo_endpoint),
            ] {
                if value
                    .as_deref()
                    .is_none_or(|endpoint| endpoint.trim().is_empty())
                {
                    anyhow::bail!(
                        "{label}.{field} is required for the {:?} kind; \
                         these providers publish no discovery document",
                        idp.kind
                    );
                }
            }
            if idp.jwks_uri.is_some() {
                anyhow::bail!(
                    "{label}.jwks_uri must be omitted for the {:?} kind; \
                     these providers publish no signing keys to verify",
                    idp.kind
                );
            }
            if idp.client_secret.trim().is_empty() {
                anyhow::bail!(
                    "{label}.client_secret is required for the {:?} kind; \
                     the token endpoint is authenticated with it",
                    idp.kind
                );
            }
        }
    }
    Ok(())
}

/// `Config` is the single configuration schema; example files are validated in
/// CI and startup reports every failure at once (INV-CONFIG-01).
fn validate(cfg: &Config) -> anyhow::Result<()> {
    if cfg.server.bind.trim().is_empty() {
        anyhow::bail!("server.bind is required");
    }
    // The issuer is what clients see, not something we fetch, so it does not
    // depend on the outbound policy.
    if !is_https_or_local_http(&cfg.server.issuer, true) {
        anyhow::bail!("server.issuer must be https:// (or localhost for development)");
    }
    if !cfg.database.url.starts_with("sqlite:") {
        anyhow::bail!("database.url must be sqlite://");
    }
    if cfg.crypto.master_key_file.trim().is_empty() {
        anyhow::bail!("crypto.master_key_file is required");
    }
    if cfg.crypto.signing_key_file.trim().is_empty() {
        anyhow::bail!("crypto.signing_key_file is required");
    }
    if cfg.limits.upstream_response_bytes == 0 {
        anyhow::bail!("limits.upstream_response_bytes must be > 0");
    }
    if cfg.limits.upstream_inflight_bytes == 0 {
        anyhow::bail!("limits.upstream_inflight_bytes must be > 0");
    }
    if cfg.limits.inbound_body_bytes == 0 {
        anyhow::bail!("limits.inbound_body_bytes must be > 0");
    }
    // A zero-capacity cache evicts everything immediately, which looks like a
    // broken cache rather than a misconfiguration.
    if cfg.cache.enabled && cfg.cache.max_bytes == 0 {
        anyhow::bail!("cache.max_bytes must be > 0 when the cache is enabled");
    }
    // Zero would delete evidence as it is written, not disable cleanup.
    if cfg.retention.audit_fact_days == 0 {
        anyhow::bail!("retention.audit_fact_days must be > 0");
    }
    if cfg.retention.access_telemetry_days == 0 {
        anyhow::bail!("retention.access_telemetry_days must be > 0");
    }
    if cfg.retention.revoked_binding_anonymize_days == 0 {
        anyhow::bail!("retention.revoked_binding_anonymize_days must be > 0");
    }
    // Fail here, not at first request: a bad CA path looks like an outage.
    cfg.tls.trust_config()?;
    if !cfg.crypto.connector_secret_file.trim().is_empty() {
        let vault = cfg.crypto.connector_secret_file.trim();
        if vault == cfg.crypto.master_key_file.trim() {
            anyhow::bail!(
                "crypto.connector_secret_file must not be the master key file; the vault is encrypted by that key"
            );
        }
        if let Some(database) = re0auth_adapters::sqlite_path::database_file_path(&cfg.database.url)
            && database == Path::new(vault)
        {
            anyhow::bail!(
                "crypto.connector_secret_file must not be the core database (ADR-0039); use a separate path"
            );
        }
    }
    for proxy in &cfg.server.trusted_proxies {
        if proxy == "0.0.0.0/0" || proxy == "::/0" {
            anyhow::bail!(
                "server.trusted_proxies must not contain {proxy}; that disables the client-address guard"
            );
        }
    }
    if cfg.legacy_identity_provider_conflict {
        anyhow::bail!(
            "use either `[[identity_providers]]` or the legacy `[identity_provider]`, not both"
        );
    }
    let mut provider_names = std::collections::HashSet::new();
    for (index, idp) in cfg.identity_providers.iter().enumerate() {
        let label = format!("identity_providers[{index}]");
        let name = idp.effective_name();
        if !provider_names.insert(name.to_string()) {
            anyhow::bail!(
                "duplicate identity provider name {name:?}; set `name` explicitly to disambiguate"
            );
        }
        if idp.issuer.trim().is_empty() {
            anyhow::bail!("{label}.issuer is required");
        }
        if idp.client_id.trim().is_empty() {
            anyhow::bail!("{label}.client_id is required");
        }
        // `redirect_uri` and `authorization_endpoint` are navigated to by the
        // browser; we never send a request to them, so the outbound guard is not
        // involved and loopback http is legitimate there regardless of policy.
        if !is_https_or_local_http(&idp.redirect_uri, true) {
            anyhow::bail!("{label}.redirect_uri must be an absolute https URL");
        }
        if idp
            .authorization_endpoint
            .as_deref()
            .is_some_and(|endpoint| !is_https_or_local_http(endpoint, true))
        {
            anyhow::bail!("{label}.authorization_endpoint must be an absolute https URL");
        }
        // These four are fetched by the server, so the check has to match what
        // the outbound guard will actually permit.
        for endpoint in [
            idp.discovery_url.as_deref(),
            idp.token_endpoint.as_deref(),
            idp.jwks_uri.as_deref(),
            idp.userinfo_endpoint.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !is_https_or_local_http(endpoint, cfg.tls.allow_loopback) {
                anyhow::bail!(
                    "{label} endpoints must be https URLs \
                     (http only for loopback with tls.allow_loopback): {endpoint}"
                );
            }
        }
        validate_provider_kind(idp, &label)?;
        // A default here would have to guess the provider's vocabulary, and the
        // vocabularies do not overlap: OIDC wants `openid`, GitHub wants
        // `read:user`, QQ wants `get_user_info`. A `["openid", "profile"]` guess
        // sent to GitHub or QQ is not merely redundant — it is a scope those
        // providers do not define, which they may reject or silently narrow.
        // Requiring the operator to name the scopes keeps the value honest.
        if idp.scopes.iter().all(|scope| scope.trim().is_empty()) {
            anyhow::bail!(
                "{label}.scopes must name at least one scope; there is no provider-neutral \
                 default (oidc uses `openid`, github uses `read:user`, qq uses `get_user_info`)"
            );
        }
        if idp
            .client_secret_file
            .as_deref()
            .is_some_and(|path| !path.trim().is_empty())
            && !idp.client_secret.trim().is_empty()
        {
            anyhow::bail!(
                "{label} sets both client_secret and client_secret_file; keep exactly one"
            );
        }
    }
    let mut seen = std::collections::HashSet::new();
    for connector in &cfg.connectors {
        if connector.id.trim().is_empty() {
            anyhow::bail!("connectors[].id is required");
        }
        if !seen.insert(connector.id.as_str()) {
            anyhow::bail!("duplicate connector id {}", connector.id);
        }
        let url = url::Url::parse(&connector.base_url)
            .map_err(|error| anyhow::anyhow!("connector {}: {error}", connector.id))?;
        let scheme = url.scheme();
        let loopback = url
            .host_str()
            .is_some_and(|host| host == "127.0.0.1" || host == "localhost");
        if scheme != "https" && !(scheme == "http" && loopback && cfg.tls.allow_loopback) {
            anyhow::bail!(
                "connector {}: base_url must be https (http only for loopback with tls.allow_loopback)",
                connector.id
            );
        }
        for resource in &connector.resources {
            resource
                .to_spec()
                .map_err(|error| anyhow::anyhow!("connector {}: {error}", connector.id))?;
        }
        if let Some(oauth) = &connector.oauth {
            validate_connector_oauth(cfg, &connector.id, oauth)?;
        }
    }
    Ok(())
}

/// Checks the bind endpoints of one connector.
///
/// Three of these are called by the server and therefore go through the outbound
/// guard, so they must satisfy the same scheme rule the guard enforces —
/// `--check-config` passing while startup rejects the same file is the failure
/// this pairing exists to prevent. `authorization_endpoint` is the exception: the
/// browser navigates to it, the server never requests it.
fn validate_connector_oauth(
    cfg: &Config,
    id: &str,
    oauth: &ConnectorOAuthConfig,
) -> anyhow::Result<()> {
    let label = format!("connector {id}.oauth");
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
    if !matches!(
        oauth.subject_field.as_str(),
        "id" | "openid" | "login" | "name"
    ) {
        anyhow::bail!(
            "{label}.subject_field must be one of id, openid, login, name \
             (got {:?})",
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
        if !is_https_or_local_http(endpoint, cfg.tls.allow_loopback) {
            anyhow::bail!(
                "{label} endpoints must be https URLs \
                 (http only for loopback with tls.allow_loopback): {endpoint}"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_path() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml")
    }

    fn docker_path() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.docker.toml")
    }

    fn example() -> Config {
        load_config(&example_path()).expect("config.example.toml is valid")
    }

    #[test]
    fn docker_config_is_valid() {
        let cfg = load_config(&docker_path()).expect("config.docker.toml is valid");
        assert_eq!(cfg.server.bind, "0.0.0.0:8080");
        assert_eq!(cfg.server.issuer, "http://127.0.0.1:8080");
        assert_eq!(cfg.database.url, "sqlite:///app/data/re0auth.db");
    }

    /// The legacy `[identity_provider]` block is folded into the list at load
    /// time, so secret-file resolution has to run *after* the fold. Placed
    /// before it, the list is still empty, nothing gets resolved, and an OIDC
    /// provider — whose secret is optional — validates with an empty secret.
    ///
    /// Written as a file-level test because the bug was an ordering mistake
    /// between two steps of `load_config`, not a defect inside either step.
    #[test]
    fn the_legacy_block_still_honours_a_secret_file() {
        let dir = std::env::temp_dir().join(format!("re0auth-legacy-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let secret_path = dir.join("secret");
        std::fs::write(&secret_path, "legacy-secret\n").expect("write secret");
        let config_path = dir.join("config.toml");
        let secret_toml_path = secret_path.to_string_lossy().replace('\\', "/");
        std::fs::write(
            &config_path,
            format!(
                r#"
[server]
bind = "127.0.0.1:8080"
issuer = "https://auth.example.com"

[database]
url = "sqlite://data/re0auth.db"

[crypto]
master_key_file = "data/master.key"
signing_key_file = "data/signing-key.pem"

[limits]
upstream_response_bytes = 4194304
upstream_inflight_bytes = 67108864
inbound_body_bytes = 1048576

[identity_provider]
issuer = "https://idp.example.com"
client_id = "client"
redirect_uri = "https://auth.example.com/auth/callback"
scopes = ["openid"]
client_secret_file = "{secret_toml_path}"
"#
            ),
        )
        .expect("write config");

        let cfg = load_config(&config_path).expect("legacy config is valid");
        let idp = cfg.identity_providers.first().expect("legacy block folded");
        assert_eq!(
            idp.client_secret, "legacy-secret",
            "the secret file must be read after the legacy block is folded"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn example_config_is_valid() {
        let cfg = example();
        assert_eq!(cfg.server.bind, "127.0.0.1:8080");
        assert_eq!(cfg.server.issuer, "https://auth.example.com");
        assert!(cfg.server.trusted_proxies.is_empty());
        assert_eq!(cfg.limits.upstream_response_bytes, 4_194_304);
        assert_eq!(cfg.limits.upstream_inflight_bytes, 67_108_864);
        assert_eq!(cfg.limits.inbound_body_bytes, 1_048_576);
    }

    #[test]
    fn identity_provider_config_parses_and_redacts_secret() {
        let raw = r#"
[server]
bind = "127.0.0.1:8080"
issuer = "https://auth.example.com"

[database]
url = "sqlite://data/re0auth.db"

[crypto]
master_key_file = "data/master.key"
signing_key_file = "data/signing-key.pem"

[limits]
upstream_response_bytes = 4194304
upstream_inflight_bytes = 67108864
inbound_body_bytes = 1048576

[identity_provider]
issuer = "https://idp.example.com"
client_id = "re0auth"
client_secret = "super-secret"
redirect_uri = "https://auth.example.com/auth/callback"
scopes = ["openid", "profile"]
"#;
        let cfg: Config = Figment::from(Toml::string(raw)).extract().expect("config");
        validate(&cfg).expect("valid identity provider");
        let idp = cfg.identity_provider.as_ref().expect("idp");
        assert_eq!(idp.client_id, "re0auth");
        let debug = format!("{idp:?}");
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn wildcard_trusted_proxy_is_rejected() {
        let mut cfg = example();
        cfg.server.trusted_proxies = vec!["0.0.0.0/0".to_string()];
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn non_sqlite_database_is_rejected() {
        let mut cfg = example();
        cfg.database.url = "postgres://localhost/re0auth".to_string();
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn zero_limit_is_rejected() {
        let mut cfg = example();
        cfg.limits.upstream_response_bytes = 0;
        assert!(validate(&cfg).is_err());
    }

    fn two_providers() -> Config {
        let raw = r#"
[server]
bind = "127.0.0.1:8080"
issuer = "https://auth.example.com"

[database]
url = "sqlite://data/re0auth.db"

[crypto]
master_key_file = "data/master.key"
signing_key_file = "data/signing-key.pem"

[limits]
upstream_response_bytes = 4194304
upstream_inflight_bytes = 67108864
inbound_body_bytes = 1048576

[[identity_providers]]
name = "corp"
issuer = "https://corp-idp.example.com"
client_id = "re0auth"
redirect_uri = "https://auth.example.com/auth/callback"
scopes = ["openid"]

[[identity_providers]]
name = "guild"
issuer = "https://guild-idp.example.com"
client_id = "re0auth"
redirect_uri = "https://auth.example.com/auth/callback"
scopes = ["openid"]
"#;
        Figment::from(Toml::string(raw)).extract().expect("config")
    }

    #[test]
    fn several_identity_providers_are_accepted() {
        let cfg = two_providers();
        validate(&cfg).expect("two providers");
        let names: Vec<_> = cfg
            .identity_providers
            .iter()
            .map(IdentityProviderConfig::effective_name)
            .collect();
        assert_eq!(names, ["corp", "guild"]);
    }

    #[test]
    fn duplicate_provider_names_are_rejected() {
        let mut cfg = two_providers();
        cfg.identity_providers[1].name = "corp".to_string();
        let error = validate(&cfg).expect_err("duplicate names");
        assert!(error.to_string().contains("duplicate"), "{error}");
    }

    fn oauth2_provider(kind: IdentityProviderKind, issuer: &str) -> IdentityProviderConfig {
        IdentityProviderConfig {
            name: "external".to_string(),
            issuer: issuer.to_string(),
            kind,
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            client_secret_file: None,
            redirect_uri: "https://auth.example.com/auth/callback".to_string(),
            scopes: vec!["read".to_string()],
            discovery_url: None,
            authorization_endpoint: Some("https://idp.example.com/authorize".to_string()),
            token_endpoint: Some("https://idp.example.com/token".to_string()),
            jwks_uri: None,
            userinfo_endpoint: Some("https://idp.example.com/user".to_string()),
        }
    }

    #[test]
    fn an_oauth2_provider_with_all_endpoints_is_accepted() {
        let mut cfg = example();
        cfg.identity_providers = vec![oauth2_provider(
            IdentityProviderKind::Github,
            "https://github.com",
        )];
        validate(&cfg).expect("a complete oauth2 provider");
    }

    /// There is no provider-neutral scope list: the vocabularies do not overlap
    /// (`openid` for OIDC, `read:user` for GitHub, `get_user_info` for QQ). The
    /// old `["openid", "profile"]` fallback sent OIDC scopes to GitHub and QQ,
    /// which do not define them. Requiring an explicit list is the only version
    /// that cannot send a provider something it never asked for.
    #[test]
    fn a_provider_without_scopes_is_rejected() {
        let mut cfg = example();
        let mut idp = oauth2_provider(IdentityProviderKind::Github, "https://github.com");
        idp.scopes.clear();
        cfg.identity_providers = vec![idp];
        let error = validate(&cfg).expect_err("an empty scope list must be refused");
        assert!(error.to_string().contains("scopes"), "{error}");
        assert!(
            error.to_string().contains("read:user"),
            "the message should name the per-provider vocabularies: {error}"
        );
    }

    /// Whitespace-only entries would produce `scope=` with nothing usable in it.
    #[test]
    fn blank_scopes_are_rejected_like_an_empty_list() {
        let mut cfg = example();
        let mut idp = oauth2_provider(IdentityProviderKind::Qq, "https://graph.qq.com");
        idp.scopes = vec!["  ".to_string(), "".to_string()];
        cfg.identity_providers = vec![idp];
        let error = validate(&cfg).expect_err("blank scopes must be refused");
        assert!(error.to_string().contains("scopes"), "{error}");
    }

    /// OIDC is held to the same rule, so an operator cannot rely on the removed
    /// fallback for the one kind where it happened to be correct.
    #[test]
    fn an_oidc_provider_without_scopes_is_also_rejected() {
        let mut cfg = example();
        cfg.identity_providers = vec![IdentityProviderConfig {
            name: "corp".to_string(),
            issuer: "https://corp-idp.example.com".to_string(),
            kind: IdentityProviderKind::Oidc,
            client_id: "re0auth".to_string(),
            client_secret: "secret".to_string(),
            client_secret_file: None,
            redirect_uri: "https://auth.example.com/auth/callback".to_string(),
            scopes: Vec::new(),
            discovery_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
            userinfo_endpoint: None,
        }];
        let error = validate(&cfg).expect_err("oidc also needs an explicit scope list");
        assert!(error.to_string().contains("scopes"), "{error}");
    }

    /// The namespace is what `identities.issuer` stores. Letting an operator
    /// change it would keep the config valid while orphaning every existing
    /// account, so it is pinned to the value the adapter uses.
    #[test]
    fn an_oauth2_provider_must_use_its_fixed_namespace() {
        let mut cfg = example();
        cfg.identity_providers = vec![oauth2_provider(
            IdentityProviderKind::Github,
            "https://github.example.com",
        )];
        let error = validate(&cfg).expect_err("a foreign namespace must be refused");
        assert!(error.to_string().contains("namespace"), "{error}");
    }

    #[test]
    fn an_oauth2_provider_without_userinfo_is_rejected() {
        let mut cfg = example();
        let mut idp = oauth2_provider(IdentityProviderKind::Qq, "https://graph.qq.com");
        idp.userinfo_endpoint = None;
        cfg.identity_providers = vec![idp];
        let error = validate(&cfg).expect_err("userinfo is required");
        assert!(error.to_string().contains("userinfo_endpoint"), "{error}");
    }

    #[test]
    fn an_oauth2_provider_without_a_secret_is_rejected() {
        let mut cfg = example();
        let mut idp = oauth2_provider(IdentityProviderKind::Github, "https://github.com");
        idp.client_secret.clear();
        cfg.identity_providers = vec![idp];
        let error = validate(&cfg).expect_err("the token endpoint needs a secret");
        assert!(error.to_string().contains("client_secret"), "{error}");
    }

    /// A JWKS URI on a provider that publishes no keys is a configuration
    /// mistake: it would look like the token is signature-verified when the
    /// identity actually came from userinfo.
    #[test]
    fn an_oauth2_provider_must_not_declare_a_jwks_uri() {
        let mut cfg = example();
        let mut idp = oauth2_provider(IdentityProviderKind::Github, "https://github.com");
        idp.jwks_uri = Some("https://github.com/keys".to_string());
        cfg.identity_providers = vec![idp];
        let error = validate(&cfg).expect_err("jwks_uri is meaningless here");
        assert!(error.to_string().contains("jwks_uri"), "{error}");
    }

    #[test]
    fn an_oidc_provider_must_not_declare_a_userinfo_endpoint() {
        let mut cfg = example();
        let mut idp = oauth2_provider(IdentityProviderKind::Oidc, "https://idp.example.com");
        idp.userinfo_endpoint = Some("https://idp.example.com/user".to_string());
        cfg.identity_providers = vec![idp];
        let error = validate(&cfg).expect_err("oidc reads the id_token, not userinfo");
        assert!(error.to_string().contains("userinfo_endpoint"), "{error}");
    }

    #[test]
    fn a_provider_without_a_name_is_named_after_its_issuer_host() {
        let mut cfg = two_providers();
        cfg.identity_providers[0].name.clear();
        cfg.identity_providers[1].name.clear();
        cfg.identity_providers[0].issuer = "https://one.example.com".to_string();
        cfg.identity_providers[1].issuer = "https://two.example.com".to_string();
        validate(&cfg).expect("distinct hosts");
        assert_eq!(
            cfg.identity_providers[0].effective_name(),
            "one.example.com"
        );
    }

    /// The name is the host, not the whole URL: a tenant path must not become
    /// part of the selector, and a port must stay distinguishing.
    #[test]
    fn the_issuer_host_is_read_by_parsing_not_by_splitting() {
        let mut idp = oauth2_provider(IdentityProviderKind::Oidc, "https://idp.example.com");
        idp.name.clear();
        for (issuer, expected) in [
            ("https://idp.example.com/tenant/one", "idp.example.com"),
            (
                "https://idp.example.com:8443/tenant",
                "idp.example.com:8443",
            ),
            ("https://idp.example.com/", "idp.example.com"),
            // Not a URL: compared as written so a duplicate is still caught.
            ("idp.example.com", "idp.example.com"),
        ] {
            idp.issuer = issuer.to_string();
            assert_eq!(idp.effective_name(), expected, "{issuer}");
        }
    }

    /// Both spellings carry the same setting. Accepting both would make the
    /// winner depend on merge order, so it is refused instead.
    #[test]
    fn mixing_the_list_and_the_legacy_block_is_rejected() {
        let mut cfg = example();
        cfg.identity_providers = two_providers().identity_providers;
        cfg.legacy_identity_provider_conflict = true;
        let error = validate(&cfg).expect_err("both spellings");
        assert!(error.to_string().contains("not both"), "{error}");
    }

    /// ADR-0039: the vault holds root credentials, so it must not be the file
    /// operators copy around as "the database", nor the file that encrypts it.
    #[test]
    fn the_connector_vault_must_be_its_own_file() {
        let mut cfg = example();
        cfg.crypto.connector_secret_file =
            cfg.database.url.trim_start_matches("sqlite://").to_string();
        let error = validate(&cfg).expect_err("vault equals database");
        assert!(error.to_string().contains("core database"), "{error}");

        let mut cfg = example();
        cfg.crypto.connector_secret_file = cfg.crypto.master_key_file.clone();
        let error = validate(&cfg).expect_err("vault equals key file");
        assert!(error.to_string().contains("master key file"), "{error}");

        let mut cfg = example();
        cfg.crypto.connector_secret_file = "data/connector-secrets.json".to_string();
        validate(&cfg).expect("a separate path is fine");
    }

    /// A prefix check accepted `http://localhost.evil.com`, a registrable name
    /// that an attacker controls. The host has to be parsed to tell the two
    /// apart, so these cases pin the parser-based behaviour.
    #[test]
    fn a_lookalike_loopback_host_is_not_loopback() {
        assert!(is_https_or_local_http("https://auth.example.com/cb", false));
        assert!(is_https_or_local_http("http://127.0.0.1:8080/cb", true));
        assert!(is_https_or_local_http("http://localhost:3000/cb", true));
        assert!(is_https_or_local_http("http://[::1]:8080/cb", true));

        assert!(!is_https_or_local_http(
            "http://localhost.evil.com/cb",
            true
        ));
        assert!(!is_https_or_local_http(
            "http://127.0.0.1.evil.com/cb",
            true
        ));
        assert!(!is_https_or_local_http("ftp://example.com/cb", true));
        assert!(!is_https_or_local_http("not a url", true));
        assert!(!is_https_or_local_http("", true));
    }

    /// The early check and the runtime guard have to agree. A config that
    /// `--check-config` accepts must not die on the first request, which is what
    /// happened when loopback http was allowed here but the guard refused it.
    #[test]
    fn loopback_http_endpoints_need_the_same_switch_the_guard_needs() {
        for url in [
            "http://127.0.0.1:8080/cb",
            "http://localhost:3000/cb",
            "http://[::1]:8080/cb",
        ] {
            assert!(
                !is_https_or_local_http(url, false),
                "{url} must be rejected while tls.allow_loopback is off, \
                 because the outbound guard would reject it later"
            );
            assert!(is_https_or_local_http(url, true));
        }
        // https never depends on the switch.
        assert!(is_https_or_local_http("https://auth.example.com/cb", false));
    }

    /// And the rejection is reported by `validate`, not left to startup.
    #[test]
    fn a_loopback_idp_endpoint_fails_config_check_when_loopback_is_off() {
        let mut cfg = example();
        cfg.identity_providers.push(IdentityProviderConfig {
            name: "local".to_string(),
            kind: IdentityProviderKind::Oidc,
            issuer: "http://127.0.0.1:9000".to_string(),
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            client_secret_file: None,
            // Fetched by the server, so it has to obey the outbound policy.
            discovery_url: Some("http://127.0.0.1:9000/.well-known/openid-configuration".into()),
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
            userinfo_endpoint: None,
            redirect_uri: "http://127.0.0.1:8080/auth/callback".to_string(),
            scopes: vec!["openid".to_string()],
        });
        assert!(!cfg.tls.allow_loopback);
        let error = validate(&cfg).expect_err("loopback http without the switch");
        assert!(error.to_string().contains("allow_loopback"), "{error}");

        // With the switch on, the same config is accepted.
        cfg.tls.allow_loopback = true;
        validate(&cfg).expect("loopback http with tls.allow_loopback");
    }

    fn connector_oauth() -> ConnectorOAuthConfig {
        ConnectorOAuthConfig {
            authorization_endpoint: "https://upstream.example.com/authorize".into(),
            token_endpoint: "https://upstream.example.com/token".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            client_secret_file: String::new(),
            scopes: vec!["read".into()],
            userinfo_endpoint: "https://upstream.example.com/user".into(),
            subject_field: "id".into(),
        }
    }

    fn config_with_connector_oauth(oauth: ConnectorOAuthConfig) -> Config {
        let mut cfg = example();
        cfg.connectors.push(ConnectorConfig {
            id: "phigros".into(),
            base_url: "https://api.example.com".into(),
            allow_private_net: false,
            allow_link_local_metadata: false,
            resources: Vec::new(),
            oauth: Some(oauth),
        });
        cfg
    }

    /// A bind reads the upstream account after the exchange. Without a declared
    /// place to read it, every binding it creates would be unaddressable.
    #[test]
    fn a_connector_bind_requires_a_userinfo_endpoint() {
        let mut oauth = connector_oauth();
        oauth.userinfo_endpoint = String::new();
        let error = validate(&config_with_connector_oauth(oauth)).expect_err("missing userinfo");
        assert!(error.to_string().contains("userinfo_endpoint"), "{error}");
    }

    /// An unknown subject field is a configuration error, not a runtime
    /// surprise: the field name decides which upstream account a binding is
    /// addressed by.
    #[test]
    fn a_connector_bind_rejects_an_undeclared_subject_field() {
        let mut oauth = connector_oauth();
        oauth.subject_field = "sub".into();
        let error = validate(&config_with_connector_oauth(oauth)).expect_err("undeclared field");
        assert!(error.to_string().contains("subject_field"), "{error}");
    }

    /// The token and userinfo endpoints are fetched by the server, so they have
    /// to satisfy the same rule the outbound guard enforces. The authorization
    /// endpoint is only navigated to by a browser and is exempt.
    #[test]
    fn a_connector_token_endpoint_obeys_the_outbound_policy() {
        let mut oauth = connector_oauth();
        oauth.token_endpoint = "http://127.0.0.1:9000/token".into();
        let mut cfg = config_with_connector_oauth(oauth);
        assert!(!cfg.tls.allow_loopback);
        let error = validate(&cfg).expect_err("loopback token endpoint without the switch");
        assert!(error.to_string().contains("allow_loopback"), "{error}");

        cfg.tls.allow_loopback = true;
        validate(&cfg).expect("loopback token endpoint with the switch");

        // The browser-facing endpoint stays exempt even with the switch off.
        cfg.tls.allow_loopback = false;
        let oauth = cfg.connectors[0].oauth.as_mut().expect("oauth");
        oauth.token_endpoint = "https://upstream.example.com/token".into();
        oauth.authorization_endpoint = "http://127.0.0.1:9000/authorize".into();
        validate(&cfg).expect("the authorization endpoint is not fetched by us");
    }

    #[test]
    fn a_lookalike_issuer_is_rejected_by_validate() {
        let mut cfg = example();
        cfg.server.issuer = "http://localhost.evil.com".to_string();
        let error = validate(&cfg).expect_err("lookalike issuer");
        assert!(error.to_string().contains("server.issuer"), "{error}");
    }

    #[test]
    fn a_lookalike_redirect_uri_is_rejected_by_validate() {
        let mut cfg = two_providers();
        cfg.identity_providers[0].redirect_uri =
            "http://127.0.0.1.evil.com/auth/callback".to_string();
        let error = validate(&cfg).expect_err("lookalike redirect");
        assert!(error.to_string().contains("redirect_uri"), "{error}");
    }

    #[test]
    fn a_lookalike_idp_endpoint_is_rejected_by_validate() {
        let mut cfg = two_providers();
        cfg.identity_providers[0].token_endpoint =
            Some("http://localhost.evil.com/oauth2/token".to_string());
        let error = validate(&cfg).expect_err("lookalike endpoint");
        assert!(error.to_string().contains("endpoints"), "{error}");
    }
}
