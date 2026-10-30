#![forbid(unsafe_code)]

//! Composition root: config, wiring, and nothing else.

mod cli;
mod config;
mod config_env;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use config::load_config;
use config::{IdentityProviderKind, oauth2_kind};
use re0auth_adapters::client_secret::HmacClientSecretHasher;
use re0auth_adapters::clock::SystemClock;
use re0auth_adapters::crypto::RsaTokenSigner;
use re0auth_adapters::moka_cache::MokaCache;
use re0auth_adapters::random::OsRandom;
use re0auth_adapters::sealer::AesGcmSealer;
use re0auth_adapters::storage::SqliteStore;
use re0auth_api::Clock;
use re0auth_api::SecretString;
use re0auth_api::idp::IdpClient;
use re0auth_api::ports::Storage;
use re0auth_api::schedule::ScheduledTask;
use re0auth_app::auth::{AuthService, NamedIdp};
use re0auth_app::binding::BindingService;
use re0auth_app::circuit::{CircuitPolicy, CircuitTracker};
use re0auth_app::gateway::GatewayService;
use re0auth_app::oauth::OAuthService;
use re0auth_connectors::connector::{HttpBroker, StaticRegistry};
use re0auth_connectors::connector_secret::EncryptedFileSecretStore;
use re0auth_connectors::inflight::ByteBudget;
use re0auth_idp::oauth2::{OAuth2Config, OAuth2Provider};
use re0auth_idp::{OidcConfig, OidcProvider};
use re0auth_runtime::http_client::GuardedClient;
use zeroize::Zeroizing;

/// How often the housekeeping sweep runs. Expired rows are retained for an
/// hour past expiry, so a ten-minute cadence keeps the tables small without
/// touching them constantly.
const HOUSEKEEPING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// How often idle rate-limit keys are dropped.
///
/// A key quiet for longer than a full window is indistinguishable from a fresh
/// one, so there is no point checking more often than the window itself. The
/// default lanes are all 60 s.
const RATE_PRUNE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// How often retention is enforced. Its windows are measured in months, so a
/// frequent sweep would only add write pressure for no benefit.
const RETENTION_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(21_600);

/// Bounded access-telemetry queue (ADR-0025). Full means drop-and-count, so the
/// gateway's hot path never waits on the database.
const TELEMETRY_CHANNEL_CAPACITY: usize = 1_024;

/// How often the telemetry queue is drained into `audit_logs`. One second keeps
/// the ledger close to real time without a write per request.
const TELEMETRY_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Debug, Parser)]
#[command(name = "re0auth-server", version)]
struct Args {
    /// Path to config.toml.
    #[arg(long, default_value = "config.toml", global = true)]
    config: PathBuf,

    /// Validate the config and exit.
    #[arg(long, global = true)]
    check_config: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the HTTP server (default).
    Serve,
    /// Administrative shell commands.
    Admin(cli::AdminArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = load_config(&args.config)?;

    if args.check_config {
        println!(
            "config ok: issuer={} bind={}",
            cfg.server.issuer, cfg.server.bind
        );
        return Ok(());
    }

    match args.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            init_tracing();
            serve(cfg).await
        }
        Command::Admin(admin) => cli::run(&cfg, admin.command).await,
    }
}

/// Installs the global subscriber exactly once.
///
/// No ANSI: container log collectors treat escape codes as data, and a colour
/// restart in the middle of a line corrupts the record. JSON is the default so
/// fields stay machine-readable; `RUST_LOG` selects verbosity, and operators can
/// ask for plain text with `RE0AUTH_LOG_FORMAT=pretty` while debugging locally.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("RE0AUTH_LOG_FORMAT").as_deref() != Ok("pretty");

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(std::io::stdout);

    // `try_init` rather than `init`: a second call (tests, embedding) must not
    // panic the process.
    if json {
        let _ = builder.json().try_init();
    } else {
        let _ = builder.try_init();
    }
}

/// Mirrors the configured connectors into the database.
///
/// The config file stays authoritative: this only makes the table match it, so
/// connector-level secrets have a row to hang off and the portal can list what
/// exists. Connectors removed from the config are removed here too, which is
/// what makes the FK cascade clean up their secrets.
async fn sync_connectors(cfg: &config::Config, store: &SqliteStore) -> anyhow::Result<()> {
    let now = SystemClock.now();
    let existing = store.connectors().list().await?;
    let mut configured = std::collections::HashSet::new();

    for connector in &cfg.connectors {
        let id = re0auth_app::gateway::connector_id_for_name(&connector.id);
        configured.insert(id);
        let resources = connector
            .resources
            .iter()
            .map(|resource| resource.to_spec())
            .collect::<Result<Vec<_>, _>>()?;
        store
            .connectors()
            .upsert(
                &re0auth_api::ports::ConnectorRecord {
                    id,
                    name: connector.id.clone(),
                    base_url: connector.base_url.clone(),
                    allow_private_net: connector.allow_private_net,
                    allow_link_local_metadata: connector.allow_link_local_metadata,
                    created_at: now,
                    updated_at: now,
                },
                &resources,
                now,
            )
            .await?;
    }

    for stale in existing {
        if !configured.contains(&stale.id) {
            store.connectors().delete(&stale.id).await?;
            tracing::warn!(connector = %stale.name, "connector removed: no longer in config");
        }
    }
    Ok(())
}

/// Builds the shared response cache.
///
/// One instance is used by both the gateway (reads/writes) and `AuthService`
/// (sweeps on revoke). Two instances would mean a revoke silently left the
/// gateway's copy intact, so the sharing is the invariant, not an optimisation.
fn build_cache(
    cfg: &config::Config,
    clock: Arc<SystemClock>,
) -> Arc<dyn re0auth_api::cache::Cache> {
    if !cfg.cache.enabled {
        return Arc::new(re0auth_api::cache::NoCache);
    }
    tracing::info!(
        ttl_secs = cfg.cache.ttl_secs,
        max_bytes = cfg.cache.max_bytes,
        "response cache enabled"
    );
    Arc::new(MokaCache::new(cfg.cache.max_bytes, clock))
}

/// Builds the registry entries, one per configured connector.
///
/// One construction shared by the gateway and the consent screen's hints: two
/// call sites deriving scopes separately is how the hint and the read path start
/// disagreeing about which scope reaches which upstream.
fn connector_endpoints(
    cfg: &config::Config,
) -> anyhow::Result<Vec<re0auth_api::connector::ConnectorEndpoint>> {
    let mut endpoints = Vec::with_capacity(cfg.connectors.len());
    for connector in &cfg.connectors {
        let resources = connector
            .resources
            .iter()
            .map(|resource| resource.to_spec())
            .collect::<Result<Vec<_>, _>>()?;
        endpoints.push(re0auth_api::connector::ConnectorEndpoint {
            id: re0auth_app::gateway::connector_id_for_name(&connector.id),
            name: connector.id.clone(),
            base_url: connector.base_url.clone(),
            egress: connector.egress_policy(),
            resources,
        });
    }
    Ok(endpoints)
}

/// Inverts the registry into scope → connectors, for the consent screen's hints.
fn scope_index(
    endpoints: &[re0auth_api::connector::ConnectorEndpoint],
) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut index: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for endpoint in endpoints {
        for resource in &endpoint.resources {
            let names = index.entry(resource.required_scope.clone()).or_default();
            if !names.contains(&endpoint.name) {
                names.push(endpoint.name.clone());
            }
        }
    }
    index
}

async fn build_data_plane(
    cfg: &config::Config,
    store: Arc<SqliteStore>,
    clock: Arc<SystemClock>,
    random: Arc<OsRandom>,
    cache: Arc<dyn re0auth_api::cache::Cache>,
    endpoints: Vec<re0auth_api::connector::ConnectorEndpoint>,
    telemetry: Arc<dyn re0auth_api::ports::TelemetrySink>,
) -> anyhow::Result<(GatewayService, Option<BindingService>)> {
    // One client per connector; the global [tls] flags were already checked as
    // a ceiling in `config::validate`, so they cannot widen a connector here.
    let clients =
        re0auth_connectors::connector::ConnectorClients::new(&endpoints, cfg.tls.trust_config()?)?;
    for endpoint in &endpoints {
        tracing::info!(
            connector = %endpoint.name,
            egress = ?endpoint.egress,
            "connector egress policy"
        );
    }
    let registry = Arc::new(StaticRegistry::new(endpoints));
    // INV-RES-01: the aggregate cap. `max_body` bounds one response; this bounds
    // the sum across concurrent fetches to the same connector.
    let inflight = Arc::new(ByteBudget::new(cfg.limits.upstream_inflight_bytes));
    let broker = Arc::new(
        HttpBroker::new(
            clients.clone(),
            usize::try_from(cfg.limits.upstream_response_bytes).unwrap_or(usize::MAX),
        )
        .with_inflight_budget(inflight),
    );
    // The master key is required once the gateway runs: sub-credentials are
    // sealed at rest and there is no plaintext fallback. `master_keys` enforces
    // the "env only" empty-path form through the shared resolver.
    // The gateway seals with the same current/retired key set as the CLI; using
    // the legacy single-key constructor here would ignore `master_key_version`.
    let sealer = Arc::new(open_sealer(cfg)?);

    // Binding is opt-in per connector: a connector without endpoints can still
    // serve data for bindings issued elsewhere, but the routes stay 404 rather
    // than sending a user to an authorization page we cannot redeem.
    let binding = build_binding(
        cfg,
        store.clone(),
        registry.clone(),
        sealer.clone(),
        &clock,
        &random,
        clients,
        Arc::clone(&cache),
    )?;

    let gateway = GatewayService::new(
        store,
        registry,
        broker,
        sealer,
        clock,
        Arc::new(CircuitTracker::new(CircuitPolicy::default())),
        usize::try_from(cfg.limits.upstream_response_bytes).unwrap_or(usize::MAX),
    )
    // INV-CACHE-01..03. The same instance is handed to `AuthService`, which
    // sweeps it on revoke; sharing is what makes INV-CACHE-02 hold.
    .with_cache(cache, std::time::Duration::from_secs(cfg.cache.ttl_secs))
    .with_telemetry(telemetry);
    Ok((gateway, binding))
}

/// Builds the binding service when at least one connector declares endpoints.
#[allow(clippy::too_many_arguments)]
fn build_binding(
    cfg: &config::Config,
    store: Arc<SqliteStore>,
    registry: Arc<StaticRegistry>,
    sealer: Arc<AesGcmSealer>,
    clock: &Arc<SystemClock>,
    random: &Arc<OsRandom>,
    clients: re0auth_connectors::connector::ConnectorClients,
    cache: Arc<dyn re0auth_api::cache::Cache>,
) -> anyhow::Result<Option<BindingService>> {
    let mut configs = std::collections::HashMap::new();
    for connector in &cfg.connectors {
        let Some(oauth) = &connector.oauth else {
            continue;
        };
        let (id, oauth) = binding_config(&connector.id, oauth)?;
        configs.insert(id, oauth);
    }
    if configs.is_empty() {
        return Ok(None);
    }

    // The only place that can enumerate bindable upstreams: the registry resolves
    // by id and cannot list. Sorted so the portal renders a stable order.
    let mut bindable: Vec<String> = configs.keys().cloned().collect();
    bindable.sort();

    let auth = Arc::new(re0auth_connectors::oauth::ConfiguredConnectorAuth::new(
        clients, configs,
    ));
    Ok(Some(
        BindingService::new(
            store,
            registry,
            auth,
            sealer,
            clock.clone(),
            random.clone(),
            format!(
                "{}/api/me/bindings/callback",
                cfg.server.issuer.trim_end_matches('/')
            ),
        )
        .with_bindable_upstreams(bindable)
        .with_cache(cache),
    ))
}

/// Converts one connector's config into the adapter's, reading every field.
///
/// The parameter is typed rather than reached through `connector.oauth` at the
/// call site: the config-read gate tracks a receiver's type through its
/// bindings, and `Option<..>` unwrapped in a `let-else` is not one of the forms
/// it follows.
fn binding_config(
    id: &str,
    oauth: &config::ConnectorOAuthConfig,
) -> anyhow::Result<(String, re0auth_connectors::oauth::ConnectorOAuthConfig)> {
    let secret =
        resolve_connector_secret(oauth).with_context(|| format!("connector {id} oauth secret"))?;
    Ok((
        id.to_string(),
        re0auth_connectors::oauth::ConnectorOAuthConfig {
            authorization_endpoint: oauth.authorization_endpoint.clone(),
            token_endpoint: oauth.token_endpoint.clone(),
            client_id: oauth.client_id.clone(),
            client_secret: secret,
            scopes: oauth.scopes.clone(),
            userinfo_endpoint: oauth.userinfo_endpoint.clone(),
            revocation_endpoint: oauth.revocation_endpoint.clone(),
            subject_field: oauth.subject_field.clone(),
        },
    ))
}

/// Exactly one source for a connector's OAuth client secret.
///
/// Mirrors the identity-provider rule: inline and file are mutually exclusive,
/// and a blank file path counts as absent. A secret left blank is refused here
/// rather than at the token endpoint, where the failure is a 401 from the
/// upstream and reads as "wrong credentials" rather than "not configured".
fn resolve_connector_secret(oauth: &config::ConnectorOAuthConfig) -> anyhow::Result<SecretString> {
    let inline = oauth.client_secret.trim();
    let file = oauth.client_secret_file.trim();
    match (inline.is_empty(), file.is_empty()) {
        (false, false) => {
            anyhow::bail!("sets both client_secret and client_secret_file; keep exactly one")
        }
        (false, true) => Ok(SecretString::from(inline.to_string())),
        (true, false) => {
            let raw = std::fs::read_to_string(file)
                .with_context(|| format!("read client_secret_file {file}"))?;
            Ok(SecretString::from(
                raw.trim_end_matches(['\r', '\n']).to_string(),
            ))
        }
        (true, true) => anyhow::bail!("sets neither client_secret nor client_secret_file"),
    }
}

/// Opens the connector root-credential vault and verifies it is separate from
/// the core database (ADR-0039). Returns `None` when no path is configured.
fn connector_vault(
    cfg: &config::Config,
    random: Arc<dyn re0auth_api::Random>,
) -> anyhow::Result<Option<Arc<EncryptedFileSecretStore>>> {
    let path = cfg.crypto.connector_secret_file.trim();
    if path.is_empty() {
        return Ok(None);
    }
    let (current_version, keys) = master_keys(cfg)?;
    let pairs: Vec<(u32, &str)> = keys.iter().map(|(v, k)| (*v, k.as_str())).collect();
    let vault = EncryptedFileSecretStore::with_keys(path, current_version, pairs, random)?;
    // Defence in depth: `validate` already rejects the same string, this catches
    // two spellings that resolve to one file.
    vault.reject_core_database_path(
        re0auth_adapters::sqlite_path::database_file_path(&cfg.database.url).as_deref(),
    )?;
    // INV-NOLOG-01: the path is not a secret; the entries are, and none are read.
    tracing::info!(path = %vault.path().display(), "connector secret vault ready");
    Ok(Some(Arc::new(vault)))
}

/// The pepper and the AEAD key come from one configured source.
pub(crate) fn client_secret_hasher(cfg: &config::Config) -> anyhow::Result<HmacClientSecretHasher> {
    let (current_version, keys) = master_keys(cfg)?;
    let pairs: Vec<(u32, &str)> = keys.iter().map(|(v, k)| (*v, k.as_str())).collect();
    HmacClientSecretHasher::with_keys(current_version, pairs)
}

/// 主密钥版本与其十六进制材料
type MasterKeys = (u32, Vec<(u32, Zeroizing<String>)>);

/// Resolves the configured current and retired master keys.
///
/// The sealer, client-secret pepper, and connector vault share this set: a
/// rotation that teaches one but not the others leaves credentials unreadable.
/// The checks here are deliberately repeated from `config::validate`; the CLI
/// and embedded callers can construct a `Config` without going through the file
/// loader, and this is the last boundary before keys are used.
fn master_keys(cfg: &config::Config) -> anyhow::Result<MasterKeys> {
    let current_version = cfg.crypto.master_key_version;
    if current_version == 0 {
        anyhow::bail!("crypto.master_key_version must be greater than zero");
    }
    let current = AesGcmSealer::master_key_hex(master_key_path(cfg))?;
    let mut keys = vec![(current_version, current)];
    let mut seen = std::collections::HashSet::from([current_version]);
    for retired in &cfg.crypto.retired_master_key_files {
        if retired.version == 0 || retired.version >= current_version {
            anyhow::bail!(
                "retired key version {} must be greater than zero and lower than the current version {}",
                retired.version,
                current_version
            );
        }
        if !seen.insert(retired.version) {
            anyhow::bail!(
                "retired key version {} was configured twice",
                retired.version
            );
        }
        let path = std::path::Path::new(&retired.file);
        // A retired key always comes from its file: letting `RE0AUTH_ENCRYPTION_KEY`
        // stand in for it would make the rotation read the current key twice and
        // report success while leaving every old record unreadable.
        let hex = re0auth_runtime::master_key::resolve_master_key(None, Some(path))?;
        keys.push((retired.version, hex));
    }
    Ok((current_version, keys))
}

fn master_key_path(cfg: &config::Config) -> Option<&std::path::Path> {
    let path = cfg.crypto.master_key_file.trim();
    if path.is_empty() {
        None
    } else {
        Some(std::path::Path::new(path))
    }
}

/// The sealer holding the current key plus every retired key the operator declared.
///
/// Built through `with_keys` rather than `from_env_or_file` so a rotation can open
/// records written under an older key. Declaring none is the normal steady state:
/// the map then holds only the current key, and any record claiming another
/// version fails loudly instead of being skipped.
pub(crate) fn open_sealer(cfg: &config::Config) -> anyhow::Result<AesGcmSealer> {
    let (current_version, keys) = master_keys(cfg)?;
    let pairs: Vec<(u32, &str)> = keys.iter().map(|(v, k)| (*v, k.as_str())).collect();
    AesGcmSealer::with_keys(
        current_version,
        pairs,
        std::sync::Arc::new(re0auth_adapters::random::OsRandom),
    )
}

/// INV-RATE-01: parses `server.trusted_proxies` into ranges.
///
/// config validation already rejects junk, so a failure here means the two
/// pieces of code disagree — that is worth failing startup over, not ignoring.
fn trusted_proxies(cfg: &config::Config) -> anyhow::Result<Vec<re0auth_http::ProxyRange>> {
    cfg.server
        .trusted_proxies
        .iter()
        .map(|entry| {
            re0auth_http::ProxyRange::parse(entry)
                .ok_or_else(|| anyhow::anyhow!("invalid trusted_proxies entry {entry:?}"))
        })
        .collect()
}

fn build_rate_limiter(
    cfg: &config::Config,
    clock: Arc<SystemClock>,
) -> Arc<dyn re0auth_api::rate::RateLimiter> {
    // `disabled` is an explicit, logged choice rather than the absence of a
    // budget: silently running without a limiter is the failure mode that makes
    // "why did we get hammered" unanswerable after the fact.
    if cfg.rate_limit.disabled {
        tracing::warn!("rate limiting is disabled by configuration; do not run this in production");
        return Arc::new(re0auth_api::rate::Unlimited);
    }
    let policy = re0auth_adapters::rate_limit::RateLimitPolicy {
        unauthenticated: re0auth_adapters::rate_limit::LaneQuota {
            burst: cfg.rate_limit.unauthenticated_burst,
            period_secs: cfg.rate_limit.unauthenticated_period_secs,
        },
        authenticated: re0auth_adapters::rate_limit::LaneQuota {
            burst: cfg.rate_limit.authenticated_burst,
            period_secs: cfg.rate_limit.authenticated_period_secs,
        },
        per_user: re0auth_adapters::rate_limit::LaneQuota {
            burst: cfg.rate_limit.per_user_burst,
            period_secs: cfg.rate_limit.per_user_period_secs,
        },
    };
    tracing::info!(
        unauthenticated_burst = policy.unauthenticated.burst,
        unauthenticated_period_secs = policy.unauthenticated.period_secs,
        authenticated_burst = policy.authenticated.burst,
        authenticated_period_secs = policy.authenticated.period_secs,
        per_user_burst = policy.per_user.burst,
        per_user_period_secs = policy.per_user.period_secs,
        "rate limiting enabled"
    );
    Arc::new(re0auth_adapters::rate_limit::GovernorLimiter::new(
        policy, clock,
    ))
}

/// Loads the signing key set from disk and publishes the current key.
///
/// The database is read first: keys retired in a previous run are still needed to
/// verify tokens issued before the rotation (OPERATIONS.md §5.2). Dropping them
/// would turn every unexpired token into a verification failure at once.
async fn load_signer(
    cfg: &config::Config,
    store: &SqliteStore,
    clock: &SystemClock,
) -> anyhow::Result<RsaTokenSigner> {
    let known = store.signing_keys().published().await?;
    let now = clock.now();
    let signer = RsaTokenSigner::load_or_generate(
        std::path::Path::new(&cfg.crypto.signing_key_file),
        &cfg.server.issuer,
        now,
        &known,
    )?;
    // Publishing every loaded key keeps the table in step with what the JWKS
    // actually serves; a key that verifies but is not published would be
    // invisible to clients.
    for record in signer.records() {
        store.signing_keys().publish(&record).await?;
    }
    tracing::info!(keys = signer.records().len(), "signing key set loaded");
    Ok(signer)
}

async fn serve(cfg: config::Config) -> anyhow::Result<()> {
    let store = Arc::new(SqliteStore::connect(&cfg.database.url).await?);
    sync_connectors(&cfg, &store).await?;
    let clock = Arc::new(SystemClock);
    let signer = Arc::new(load_signer(&cfg, &store, clock.as_ref()).await?);
    let random = Arc::new(OsRandom);
    // INV-CONN-02 / ADR-0039: the connector vault is opened only when a path is
    // configured, and never shares a file with the core database. Nothing reads
    // it yet — connectors are blocked on OPEN-014 — so this only proves the
    // configured path is usable and correctly separated.
    connector_vault(&cfg, random.clone())?;
    // Built once and shared: the gateway's registry and the consent screen's hints
    // must be derived from the same entries, or the hint can name a scope the read
    // path does not require, or miss one it does.
    let endpoints = connector_endpoints(&cfg)?;
    let oauth = OAuthService::new(
        store.clone(),
        signer.clone(),
        clock.clone(),
        random.clone(),
        Arc::new(client_secret_hasher(&cfg)?),
        &cfg.server.issuer,
    )
    .with_binding_hints(Arc::new(re0auth_app::hints::ScopeBindingHints::new(
        store.clone(),
        scope_index(&endpoints),
    )));
    // INV-IDP-01: one provider per configured entry, each bound to its name.
    // Built in configuration order so a single-provider setup needs no selector.
    let mut idps = Vec::with_capacity(cfg.identity_providers.len());
    for idp in &cfg.identity_providers {
        // Used verbatim: `validate` has already required a non-empty list, because
        // there is no provider-neutral default (see `validate_provider_kind`).
        let scopes = idp.scopes.clone();
        let http = GuardedClient::with_tls(
            cfg.tls.policy(),
            cfg.tls.allow_loopback,
            cfg.tls.trust_config()?,
        )?;
        tracing::info!(trust = %http.trust().describe(), "outbound TLS trust");
        // INV-NOLOG-01: startup logging prints counts and issuer names only, never
        // tokens, cookies, passwords or sub-credential plaintext.
        let client: Arc<dyn IdpClient> = match idp.kind {
            IdentityProviderKind::Oidc => Arc::new(
                OidcProvider::discover(
                    OidcConfig {
                        issuer: idp.issuer.clone(),
                        client_id: idp.client_id.clone(),
                        client_secret: idp.client_secret.clone(),
                        redirect_uri: idp.redirect_uri.clone(),
                        scopes,
                        discovery_url: idp.discovery_url.clone(),
                        authorization_endpoint: idp.authorization_endpoint.clone(),
                        token_endpoint: idp.token_endpoint.clone(),
                        jwks_uri: idp.jwks_uri.clone(),
                    },
                    http,
                    clock.clone(),
                )
                .await?,
            ),
            // Exhaustive on purpose: a new kind must be wired here explicitly
            // rather than silently falling into the OAuth2 branch.
            IdentityProviderKind::Github | IdentityProviderKind::Qq => {
                Arc::new(OAuth2Provider::new(
                    OAuth2Config {
                        kind: oauth2_kind(idp.kind).ok_or_else(|| {
                            anyhow::anyhow!(
                                "provider {} is not an oauth2 kind",
                                idp.effective_name()
                            )
                        })?,
                        client_id: idp.client_id.clone(),
                        client_secret: idp.client_secret.clone(),
                        redirect_uri: idp.redirect_uri.clone(),
                        scopes,
                        // `validate` has already required all three for this kind.
                        authorization_endpoint: idp
                            .authorization_endpoint
                            .clone()
                            .expect("validated authorization_endpoint"),
                        token_endpoint: idp
                            .token_endpoint
                            .clone()
                            .expect("validated token_endpoint"),
                        userinfo_endpoint: idp
                            .userinfo_endpoint
                            .clone()
                            .expect("validated userinfo_endpoint"),
                    },
                    http,
                )?)
            }
        };
        tracing::info!(provider = %idp.effective_name(), kind = ?idp.kind, "identity provider ready");
        idps.push(NamedIdp {
            name: idp.effective_name().to_string(),
            display_name: idp.effective_display_name().to_string(),
            client,
        });
    }
    let cache = build_cache(&cfg, clock.clone());
    let auth = AuthService::new(
        store.clone(),
        idps,
        signer,
        clock.clone(),
        random.clone(),
        &cfg.server.issuer,
    )
    .with_cache(Arc::clone(&cache));
    let mut state = re0auth_http::AppState::new(oauth, auth)
        .with_rate_limiter(build_rate_limiter(&cfg, clock.clone()))
        // INV-RES-02: the router caps bodies at the configured value. Wiring this
        // is what makes `limits.inbound_body_bytes` real rather than decorative.
        .with_inbound_body_bytes(
            usize::try_from(cfg.limits.inbound_body_bytes).unwrap_or(usize::MAX),
        )
        // INV-RATE-01: an empty list means the header is never trusted, which is
        // the only safe default for a directly exposed instance.
        .with_trusted_proxies(trusted_proxies(&cfg)?);

    // B1: the admin surface shares the storage, clock and hasher with the rest
    // of the server, and gets the same cache so a killswitch revoke can
    // invalidate what the gateway might serve (INV-CACHE-02).
    state = state.with_admin(Arc::new(
        re0auth_app::admin_service::AdminService::new(
            store.clone(),
            clock.clone(),
            random.clone(),
            Arc::new(client_secret_hasher(&cfg)?),
        )
        .with_cache(Arc::clone(&cache)),
    ));

    // Built before the gateway so both halves exist even when no connector is
    // configured: a deployment with no producer simply drains an empty queue.
    let (telemetry_sink, telemetry_receiver, telemetry_dropped) =
        re0auth_runtime::telemetry::channel(TELEMETRY_CHANNEL_CAPACITY);

    if !cfg.connectors.is_empty() {
        let (gateway, binding) = build_data_plane(
            &cfg,
            store.clone(),
            clock.clone(),
            random.clone(),
            cache,
            endpoints,
            telemetry_sink,
        )
        .await?;
        // INV-NOLOG-01: connector names and counts only, never credentialed URLs.
        tracing::info!(
            connectors = cfg.connectors.len(),
            names = %cfg
                .connectors
                .iter()
                .map(|connector| connector.id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            binding = binding.is_some(),
            "gateway enabled"
        );
        state = state.with_gateway(Arc::new(gateway));
        if let Some(binding) = binding {
            state = state.with_binding(Arc::new(binding));
        }
    } else {
        tracing::info!("gateway disabled: no connectors configured");
    }

    let listener = tokio::net::TcpListener::bind(&cfg.server.bind).await?;
    tracing::info!(
        version = re0auth_app::build_info(),
        bind = %cfg.server.bind,
        issuer = %cfg.server.issuer,
        "re0auth-server listening"
    );

    // INV-SPAWN-01 / ADR-0026: the scheduler is the only place that spawns
    // background work. The composition root builds the tasks and registers
    // them; it does not define them and does not run them itself.
    let shutdown = tokio_util::sync::CancellationToken::new();
    let sweep = Arc::new(re0auth_app::housekeeping::HousekeepingSweepJob::new(
        store.clone(),
        clock.clone(),
        HOUSEKEEPING_INTERVAL,
    ));
    // Kept for the retention job: the scheduler takes ownership of `clock`.
    let retention_clock = clock.clone();
    let scheduler = re0auth_runtime::Scheduler::new(clock, shutdown.clone());
    // The limiter's keyed store is the one piece of state that grows with every
    // distinct IP and client id and never shrinks on its own, so it is swept
    // here rather than left to accumulate for the life of the process.
    let prune = Arc::new(re0auth_app::housekeeping::RateLimiterPruneJob::new(
        state.rate.clone(),
        RATE_PRUNE_INTERVAL,
    ));
    let retention = Arc::new(re0auth_app::housekeeping::RetentionSweepJob::new(
        store.clone(),
        retention_clock,
        RETENTION_SWEEP_INTERVAL,
        re0auth_app::housekeeping::RetentionPolicy::from_days(
            cfg.retention.audit_fact_days,
            cfg.retention.access_telemetry_days,
            cfg.retention.revoked_binding_anonymize_days,
        ),
    ));
    // The access ledger's writer. Draining here (not in the gateway) is what
    // keeps the request path free of database writes and INV-SPAWN-01 intact.
    let telemetry = Arc::new(re0auth_runtime::telemetry::TelemetryFlushJob::new(
        telemetry_receiver,
        store.clone(),
        TELEMETRY_FLUSH_INTERVAL,
        telemetry_dropped,
    ));
    let scheduler_handle = scheduler.start(vec![
        sweep as Arc<dyn ScheduledTask>,
        prune as Arc<dyn ScheduledTask>,
        retention as Arc<dyn ScheduledTask>,
        telemetry as Arc<dyn ScheduledTask>,
    ]);

    axum::serve(
        listener,
        re0auth_http::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(shutdown.clone()))
    .await?;

    // Stop the scheduler and wait for the in-flight sweep to finish, so a
    // shutdown never leaves a half-written cleanup behind.
    shutdown.cancel();
    let _ = scheduler_handle.await;
    tracing::info!("re0auth-server stopped");
    Ok(())
}

/// Resolves on Ctrl+C or SIGTERM, then cancels the shutdown token so every
/// background task observes the same signal.
async fn shutdown_signal(shutdown: tokio_util::sync::CancellationToken) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            // Without a handler the process simply keeps running; Ctrl+C still
            // works, so this is a degraded signal path rather than a failure.
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    shutdown.cancel();
}
