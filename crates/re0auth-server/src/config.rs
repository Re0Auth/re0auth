use std::borrow::Cow;
use std::path::Path;

use figment::Figment;
use figment::providers::{Env, Format, Toml};
use re0auth_adapters::storage::{DatabaseOptions, SqliteSynchronous};
use serde::Deserialize;

use connector::validate_connector_oauth;
pub use connector::{ConnectorConfig, ConnectorOAuthConfig};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Prometheus exposition. Off by default; when enabled it is still gated
    /// to loopback or an admin session.
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// 绑定凭证的惰性推断阈值。
    #[serde(default)]
    pub binding_probe: BindingProbeConfig,
    /// Retention windows (Q-032). Defaults are the decided policy.
    #[serde(default)]
    pub retention: RetentionConfig,
    /// 入站请求与上游调用的超时上限。
    #[serde(default)]
    pub timeouts: TimeoutsConfig,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: String,
    pub issuer: String,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub url: String,
    /// SQLite 同步模式，默认 normal。
    #[serde(default)]
    pub synchronous: SqliteSynchronous,
    /// SQLite 页缓存大小（MB）。
    #[serde(default = "default_cache_size_mb")]
    pub cache_size_mb: u32,
    /// SQLite 内存映射大小（MB）；0 表示关闭。
    #[serde(default = "default_mmap_size_mb")]
    pub mmap_size_mb: u32,
    /// 连接池上限。
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
}

impl DatabaseConfig {
    #[must_use]
    pub fn options(&self) -> DatabaseOptions {
        DatabaseOptions {
            synchronous: self.synchronous,
            cache_size_mb: self.cache_size_mb,
            mmap_size_mb: self.mmap_size_mb,
            pool_size: self.pool_size,
        }
    }
}

fn default_cache_size_mb() -> u32 {
    16
}

fn default_mmap_size_mb() -> u32 {
    64
}

fn default_pool_size() -> u32 {
    5
}

/// 超时上限；限流另由 `[rate_limit]` 负责。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutsConfig {
    /// 单个入站请求的处理上限（秒）。
    #[serde(default = "default_request_secs")]
    pub request_secs: u64,
    /// 单次上游调用的上限（秒）。
    #[serde(default = "default_upstream_secs")]
    pub upstream_secs: u64,
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        Self {
            request_secs: default_request_secs(),
            upstream_secs: default_upstream_secs(),
        }
    }
}

fn default_request_secs() -> u64 {
    30
}

fn default_upstream_secs() -> u64 {
    10
}

fn default_master_key_version() -> u32 {
    1
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoConfig {
    pub master_key_file: String,
    /// Version stamped on newly sealed records and client-secret hashes.
    ///
    /// Rotation is expressed by raising this, pointing `master_key_file` at the
    /// new key, and listing the old key under `retired_master_key_files`.
    #[serde(default = "default_master_key_version")]
    pub master_key_version: u32,
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
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    pub upstream_response_bytes: u64,
    pub upstream_inflight_bytes: u64,
    pub inbound_body_bytes: u64,
}

/// Prometheus exposition settings.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
}

/// Response cache (INV-CACHE-01..03).
///
/// Off unless `enabled = true`: caching changes what callers observe during an
/// outage, so it is an explicit operator decision rather than a default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// 绑定凭证的惰性推断阈值。
/// 不探测上游，只按未刷新时长推断
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingProbeConfig {
    /// 超过该天数未刷新即视为失效
    #[serde(default = "default_binding_probe_after_days")]
    pub after_days: u64,
}

impl Default for BindingProbeConfig {
    fn default() -> Self {
        Self {
            after_days: default_binding_probe_after_days(),
        }
    }
}

fn default_binding_probe_after_days() -> u64 {
    // 0 disables the inference. With rotating refresh tokens, a real 401 is the
    // authoritative signal; a six-day idle period is not.
    0
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct TlsSettings {
    #[serde(default)]
    pub extra_ca_file: Option<String>,
    /// Global ceiling and IdP loopback. Connectors need their own flag.
    #[serde(default)]
    pub allow_loopback: bool,
    /// Global ceiling for private-network connectors (BYOC). Default off.
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

    /// Global ceiling for one connector's per-connector policy.
    ///
    /// A public-only global can only tighten; a connector cannot widen it.
    /// Metadata still needs the connector-level explicit flag; the global
    /// private/local switches only decide whether non-public egress is allowed
    /// at all.
    #[must_use]
    pub fn allows_connector(&self, policy: re0auth_api::connector::EgressPolicy) -> bool {
        use re0auth_api::connector::EgressPolicy;
        match policy {
            EgressPolicy::Public => true,
            EgressPolicy::PrivateNet | EgressPolicy::LinkLocalMetadata => {
                self.allow_private_net || self.allow_loopback
            }
            EgressPolicy::Loopback => self.allow_loopback,
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
    /// Human-readable label shown in the login selector. Defaults to `name`.
    #[serde(default)]
    pub display_name: String,
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
    /// The label the login selector shows, falling back to the selector name.
    #[must_use]
    pub fn effective_display_name(&self) -> Cow<'_, str> {
        if !self.display_name.trim().is_empty() {
            return Cow::Borrowed(self.display_name.trim());
        }
        self.effective_name()
    }

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
            .field("display_name", &self.display_name)
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
        "http" => allow_loopback && is_loopback_host(&url),
        _ => false,
    }
}

/// Loopback means the address, not one spelling of it: `127.0.0.0/8` and
/// `::1` are both loopback, and `Url` has already parsed the host form.
fn is_loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// Oidc 无适配器，返回 None
pub fn oauth2_kind(kind: IdentityProviderKind) -> Option<re0auth_idp::oauth2::OAuth2Kind> {
    match kind {
        IdentityProviderKind::Github => Some(re0auth_idp::oauth2::OAuth2Kind::GitHub),
        IdentityProviderKind::Qq => Some(re0auth_idp::oauth2::OAuth2Kind::Qq),
        IdentityProviderKind::Oidc => None,
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
            let oauth2 = oauth2_kind(idp.kind).ok_or_else(|| {
                anyhow::anyhow!("{label}.kind {:?} has no oauth2 adapter", idp.kind)
            })?;
            let expected = oauth2.namespace();
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
    if cfg.crypto.master_key_version == 0 {
        anyhow::bail!("crypto.master_key_version must be greater than zero");
    }
    let mut retired_versions = std::collections::HashSet::new();
    for retired in &cfg.crypto.retired_master_key_files {
        if retired.version == 0 {
            anyhow::bail!("crypto.retired_master_key_files[].version must be greater than zero");
        }
        if retired.version >= cfg.crypto.master_key_version {
            anyhow::bail!(
                "crypto.retired_master_key_files[].version {} must be lower than master_key_version {}",
                retired.version,
                cfg.crypto.master_key_version
            );
        }
        if retired.file.trim().is_empty() {
            anyhow::bail!("crypto.retired_master_key_files[].file is required");
        }
        if !retired_versions.insert(retired.version) {
            anyhow::bail!(
                "crypto.retired_master_key_files contains version {} twice",
                retired.version
            );
        }
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
    // One request reserves the whole response cap before the upstream is
    // contacted. A budget below that cap admits nothing, so every fetch would
    // fail with `upstream_capacity_exhausted`.
    if cfg.limits.upstream_inflight_bytes < cfg.limits.upstream_response_bytes {
        anyhow::bail!(
            "limits.upstream_inflight_bytes ({}) must be >= limits.upstream_response_bytes ({}); \
             a single fetch reserves the whole response cap",
            cfg.limits.upstream_inflight_bytes,
            cfg.limits.upstream_response_bytes
        );
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
        let range = re0auth_http::ProxyRange::parse(proxy).ok_or_else(|| {
            anyhow::anyhow!("server.trusted_proxies contains an invalid range {proxy:?}")
        })?;
        if range.prefix_len() == 0 {
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
        if connector.allow_loopback && connector.allow_link_local_metadata {
            anyhow::bail!(
                "connector {}: allow_loopback and allow_link_local_metadata are mutually exclusive",
                connector.id
            );
        }
        if !cfg.tls.allows_connector(connector.egress_policy()) {
            anyhow::bail!(
                "connector {}: egress policy exceeds the global [tls] ceiling;                  enable tls.allow_private_net or tls.allow_loopback as appropriate",
                connector.id
            );
        }
        let scheme = url.scheme();
        let loopback = is_loopback_host(&url);
        if scheme != "https" && !(scheme == "http" && loopback && connector.allow_loopback) {
            anyhow::bail!(
                "connector {}: base_url must be https (http only for loopback with                  connector allow_loopback and the global tls ceiling)",
                connector.id
            );
        }
        for resource in &connector.resources {
            resource
                .to_spec()
                .map_err(|error| anyhow::anyhow!("connector {}: {error}", connector.id))?;
        }
        if let Some(oauth) = &connector.oauth {
            validate_connector_oauth(connector, oauth)?;
        }
    }
    Ok(())
}

mod connector;

#[cfg(test)]
mod tests;
