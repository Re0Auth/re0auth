use super::connector::{ParamConfig, ResourceConfig, ViewConfig};
use super::*;
use re0auth_adapters::storage::SqliteSynchronous;
use re0auth_api::view::ViewOutput;

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
fn database_defaults_are_tuned_for_wal() {
    let cfg = example();
    assert_eq!(cfg.database.synchronous, SqliteSynchronous::Normal);
    assert_eq!(cfg.database.cache_size_mb, 16);
    assert_eq!(cfg.database.mmap_size_mb, 64);
    assert_eq!(cfg.database.pool_size, 5);
}

#[test]
fn timeout_defaults_are_conservative() {
    let cfg = example();
    assert_eq!(cfg.timeouts.request_secs, 30);
    assert_eq!(cfg.timeouts.upstream_secs, 10);
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
    for proxy in ["0.0.0.0/0", " 0.0.0.0/0", "0.0.0.1/0", "0.0.0.0/00", "::/0"] {
        let mut cfg = example();
        cfg.server.trusted_proxies = vec![proxy.to_string()];
        assert!(validate(&cfg).is_err(), "{proxy:?} must be rejected");
    }
}

#[test]
fn an_invalid_trusted_proxy_is_rejected_before_startup() {
    let mut cfg = example();
    cfg.server.trusted_proxies = vec!["not-a-range".to_string()];
    assert!(validate(&cfg).is_err());
}

#[test]
fn loopback_classification_uses_address_semantics() {
    for url in [
        "http://127.0.0.1:9000",
        "http://127.0.0.2:9000",
        "http://[::1]:9000",
        "http://localhost:9000",
    ] {
        assert!(is_https_or_local_http(url, true), "{url} must be loopback");
    }
    assert!(!is_https_or_local_http("http://localhost.evil.com", true));
    assert!(!is_https_or_local_http("http://127.0.0.1:9000", false));
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
        display_name: String::new(),
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
        display_name: String::new(),
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
    cfg.crypto.connector_secret_file = cfg.database.url.trim_start_matches("sqlite://").to_string();
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
        display_name: String::new(),
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
        refresh_endpoint: None,
        client_id: "client".into(),
        client_secret: "secret".into(),
        client_secret_file: String::new(),
        scopes: vec!["read".into()],
        userinfo_endpoint: "https://upstream.example.com/user".into(),
        subject_field: "id".into(),
        revocation_endpoint: None,
    }
}

fn config_with_connector_oauth(oauth: ConnectorOAuthConfig) -> Config {
    let mut cfg = example();
    cfg.connectors.push(ConnectorConfig {
        id: "phigros".into(),
        display_name: "Phigros Query".into(),
        base_url: "https://api.example.com".into(),
        allow_private_net: false,
        allow_link_local_metadata: false,
        allow_loopback: false,
        expose_in_openapi: true,
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

/// A path is a configuration error, not a runtime surprise: the field name
/// decides which upstream account a binding is addressed by, and a path would
/// mean digging through an undeclared document (INV-CONN-01).
#[test]
fn a_connector_bind_rejects_a_subject_path() {
    let mut oauth = connector_oauth();
    oauth.subject_field = "user.id".into();
    let error = validate(&config_with_connector_oauth(oauth)).expect_err("path field");
    assert!(error.to_string().contains("subject_field"), "{error}");

    let mut oauth = connector_oauth();
    oauth.subject_field = "sub[0]".into();
    assert!(validate(&config_with_connector_oauth(oauth)).is_err());
}

/// Standard OIDC and most upstreams use a flat name that is not in any
/// vendor list; the rule is the shape, not a set of known names.
#[test]
fn a_connector_bind_accepts_any_flat_subject_field() {
    for field in ["sub", "uid", "user_id", "player-id"] {
        let mut oauth = connector_oauth();
        oauth.subject_field = field.into();
        validate(&config_with_connector_oauth(oauth))
            .unwrap_or_else(|error| panic!("{field}: {error}"));
    }
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
    cfg.connectors[0].allow_loopback = true;
    validate(&cfg).expect("loopback token endpoint with the connector switch");

    // The browser-facing endpoint stays exempt even with the switch off.
    cfg.tls.allow_loopback = false;
    cfg.connectors[0].allow_loopback = false;
    let oauth = cfg.connectors[0].oauth.as_mut().expect("oauth");
    oauth.token_endpoint = "https://upstream.example.com/token".into();
    oauth.authorization_endpoint = "http://127.0.0.1:9000/authorize".into();
    validate(&cfg).expect("the authorization endpoint is not fetched by us");
}

/// The revocation endpoint is fetched by us, so it is held to the same policy
/// as the token endpoint rather than being treated as a browser-facing URL.
#[test]
fn a_connector_revocation_endpoint_obeys_the_outbound_policy() {
    let mut oauth = connector_oauth();
    oauth.revocation_endpoint = Some("http://127.0.0.1:9000/revoke".into());
    let mut cfg = config_with_connector_oauth(oauth);
    assert!(!cfg.tls.allow_loopback);
    let error = validate(&cfg).expect_err("loopback revocation endpoint");
    assert!(error.to_string().contains("revocation_endpoint"), "{error}");

    cfg.tls.allow_loopback = true;
    cfg.connectors[0].allow_loopback = true;
    validate(&cfg).expect("loopback revocation endpoint with the switch");
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
    cfg.identity_providers[0].redirect_uri = "http://127.0.0.1.evil.com/auth/callback".to_string();
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
#[test]
fn connector_egress_policy_maps_flags() {
    let mut cfg = config_with_connector_oauth(connector_oauth());
    let connector = &mut cfg.connectors[0];
    assert_eq!(
        connector.egress_policy(),
        re0auth_api::connector::EgressPolicy::Public
    );
    connector.allow_private_net = true;
    assert_eq!(
        connector.egress_policy(),
        re0auth_api::connector::EgressPolicy::PrivateNet
    );
    connector.allow_loopback = true;
    assert_eq!(
        connector.egress_policy(),
        re0auth_api::connector::EgressPolicy::Loopback
    );
    connector.allow_loopback = false;
    connector.allow_link_local_metadata = true;
    assert_eq!(
        connector.egress_policy(),
        re0auth_api::connector::EgressPolicy::LinkLocalMetadata
    );
}

#[test]
fn connector_egress_cannot_exceed_the_global_ceiling() {
    let mut cfg = config_with_connector_oauth(connector_oauth());
    cfg.connectors[0].allow_private_net = true;
    cfg.tls.allow_private_net = false;
    let error = validate(&cfg).expect_err("private egress exceeds ceiling");
    assert!(
        error.to_string().contains("egress policy exceeds"),
        "{error}"
    );

    cfg.tls.allow_private_net = true;
    validate(&cfg).expect("private egress under ceiling");

    cfg.connectors[0].allow_loopback = true;
    cfg.tls.allow_loopback = false;
    let error = validate(&cfg).expect_err("loopback egress exceeds ceiling");
    assert!(
        error.to_string().contains("egress policy exceeds"),
        "{error}"
    );
    cfg.tls.allow_loopback = true;
    validate(&cfg).expect("loopback egress under ceiling");
}

#[test]
fn connector_loopback_http_needs_the_connector_flag() {
    let mut cfg = config_with_connector_oauth(connector_oauth());
    cfg.connectors[0].base_url = "http://127.0.0.1:8080".to_string();
    cfg.tls.allow_loopback = true;
    let error = validate(&cfg).expect_err("global loopback must not widen a connector");
    assert!(error.to_string().contains("allow_loopback"), "{error}");

    cfg.connectors[0].allow_loopback = true;
    validate(&cfg).expect("explicit connector loopback");
}

#[test]
fn connector_loopback_and_metadata_are_mutually_exclusive() {
    let mut cfg = config_with_connector_oauth(connector_oauth());
    cfg.connectors[0].allow_loopback = true;
    cfg.connectors[0].allow_link_local_metadata = true;
    cfg.tls.allow_loopback = true;
    let error = validate(&cfg).expect_err("incompatible policies");
    assert!(error.to_string().contains("mutually exclusive"), "{error}");
}

#[test]
fn metadata_egress_still_needs_a_non_public_global_ceiling() {
    let mut cfg = config_with_connector_oauth(connector_oauth());
    cfg.connectors[0].allow_link_local_metadata = true;
    cfg.tls.allow_private_net = false;
    let error = validate(&cfg).expect_err("metadata exceeds public ceiling");
    assert!(
        error.to_string().contains("egress policy exceeds"),
        "{error}"
    );
    cfg.tls.allow_private_net = true;
    validate(&cfg).expect("metadata under private ceiling");
}

#[test]
fn master_key_version_defaults_to_one() {
    let cfg = example();
    assert_eq!(cfg.crypto.master_key_version, 1);
}

#[test]
fn a_retired_key_must_be_lower_than_the_current_version() {
    let mut cfg = example();
    cfg.crypto.master_key_version = 2;
    cfg.crypto.retired_master_key_files = vec![RetiredKeyConfig {
        version: 1,
        file: "data/master.old.key".to_string(),
    }];
    validate(&cfg).expect("v1 retired under current v2");

    for version in [0, 2, 3] {
        cfg.crypto.retired_master_key_files = vec![RetiredKeyConfig {
            version,
            file: "data/master.old.key".to_string(),
        }];
        let error = validate(&cfg).expect_err("invalid retired version");
        assert!(
            error.to_string().contains("must be"),
            "version {version}: {error}"
        );
    }
}

#[test]
fn duplicate_retired_versions_are_rejected() {
    let mut cfg = example();
    cfg.crypto.master_key_version = 3;
    cfg.crypto.retired_master_key_files = vec![
        RetiredKeyConfig {
            version: 1,
            file: "data/master.old1.key".to_string(),
        },
        RetiredKeyConfig {
            version: 1,
            file: "data/master.old2.key".to_string(),
        },
    ];
    let error = validate(&cfg).expect_err("duplicate retired version");
    assert!(error.to_string().contains("twice"), "{error}");
}

#[test]
fn current_master_key_version_cannot_be_zero() {
    let mut cfg = example();
    cfg.crypto.master_key_version = 0;
    let error = validate(&cfg).expect_err("zero current version");
    assert!(error.to_string().contains("greater than zero"), "{error}");
}

#[test]
fn provider_display_name_defaults_to_its_selector_name() {
    let mut provider = oauth2_provider(IdentityProviderKind::Github, "https://github.com");
    assert_eq!(provider.effective_display_name(), "external");
    provider.display_name = "  GitHub  ".to_string();
    assert_eq!(provider.effective_display_name(), "GitHub");
}

fn resource_with_view(view: Option<ViewConfig>) -> ResourceConfig {
    ResourceConfig {
        name: "scores".to_string(),
        path: "/v1/scores/{subject}".to_string(),
        scope: None,
        method: None,
        idempotent: None,
        body: None,
        view,
        params: Vec::new(),
    }
}

#[test]
fn a_resource_view_parses_into_a_spec() {
    let resource = resource_with_view(Some(ViewConfig {
        data_path: Some("$.data".to_string()),
        items_path: None,
        fields: Some(std::collections::BTreeMap::from([(
            "score".to_string(),
            "$.score".to_string(),
        )])),
    }));
    let spec = resource.to_spec().expect("viewed resource");
    let view = spec.view.expect("view is attached");
    assert_eq!(view.fields.len(), 1);
    assert!(view.items_path.is_none());
}

#[test]
fn data_and_items_paths_are_mutually_exclusive() {
    let resource = resource_with_view(Some(ViewConfig {
        data_path: Some("$.data".to_string()),
        items_path: Some("$.data.items".to_string()),
        fields: None,
    }));
    let error = resource.to_spec().expect_err("conflicting roots");
    assert!(error.to_string().contains("mutually exclusive"), "{error}");
}

#[test]
fn an_invalid_view_path_is_rejected_at_load() {
    let resource = resource_with_view(Some(ViewConfig {
        data_path: Some("$.data.".to_string()),
        items_path: None,
        fields: None,
    }));
    let error = resource.to_spec().expect_err("bad path");
    assert!(error.to_string().contains("invalid view path"), "{error}");
}

fn phihub_resource(name: &str, path: &str, fields: &[(&str, &str)]) -> ResourceConfig {
    ResourceConfig {
        name: name.to_string(),
        path: path.to_string(),
        scope: Some("phihub.save.read".to_string()),
        method: Some("post".to_string()),
        idempotent: Some(true),
        body: Some(std::collections::BTreeMap::from([(
            "delegation_token".to_string(),
            "{credential}".to_string(),
        )])),
        params: Vec::new(),
        view: Some(ViewConfig {
            data_path: Some("$.data".to_string()),
            items_path: None,
            fields: Some(
                fields
                    .iter()
                    .map(|(name, path)| ((*name).to_string(), (*path).to_string()))
                    .collect(),
            ),
        }),
    }
}

#[test]
fn phihub_save_info_view_maps_documented_fields() {
    let resource = phihub_resource(
        "save_info",
        "/get/cloud/saveInfo",
        &[
            ("player_id", "$.PlayerId"),
            ("updated_at", "$.updatedAt"),
            ("rks", "$.summary.rankingScore"),
            ("challenge_mode_rank", "$.summary.challengeModeRank"),
            ("avatar", "$.summary.avatar"),
            ("game_version", "$.summary.gameVersion"),
            ("save_version", "$.summary.saveVersion"),
        ],
    );
    let spec = resource.to_spec().expect("valid save_info resource");
    let body = serde_json::json!({
        "data": {
            "PlayerId": "1502788182",
            "updatedAt": "2026-11-09T00:00:00.000Z",
            "summary": {
                "rankingScore": 15.1234,
                "challengeModeRank": 1234,
                "avatar": "avatar.png",
                "gameVersion": 3,
                "saveVersion": 5
            }
        }
    });
    assert_eq!(
        spec.view.expect("view").apply(&body).expect("view applies"),
        ViewOutput::Single(serde_json::json!({
            "player_id": "1502788182",
            "updated_at": "2026-11-09T00:00:00.000Z",
            "rks": 15.1234,
            "challenge_mode_rank": 1234,
            "avatar": "avatar.png",
            "game_version": 3,
            "save_version": 5
        }))
    );
}

#[test]
fn phihub_save_view_maps_profile_and_records() {
    let resource = phihub_resource(
        "save",
        "/get/cloud/saves",
        &[
            ("player_id", "$.saveInfo.PlayerId"),
            ("updated_at", "$.saveInfo.updatedAt"),
            ("rks", "$.saveInfo.summary.rankingScore"),
            (
                "challenge_mode_rank",
                "$.saveInfo.summary.challengeModeRank",
            ),
            ("avatar", "$.saveInfo.summary.avatar"),
            ("game_user", "$.gameuser"),
            ("records", "$.gameRecord"),
        ],
    );
    let spec = resource.to_spec().expect("valid save resource");
    let body = serde_json::json!({
        "data": {
            "saveInfo": {
                "PlayerId": "1502788182",
                "updatedAt": "2026-11-09T00:00:00.000Z",
                "summary": {
                    "rankingScore": 15.1234,
                    "challengeModeRank": 1234,
                    "avatar": "avatar.png"
                }
            },
            "gameuser": {"name": "player", "avatar": "avatar.png"},
            "gameRecord": {"song.0": [{"score": 1000000, "acc": 100, "fc": true}]}
        }
    });
    assert_eq!(
        spec.view.expect("view").apply(&body).expect("view applies"),
        ViewOutput::Single(serde_json::json!({
            "player_id": "1502788182",
            "updated_at": "2026-11-09T00:00:00.000Z",
            "rks": 15.1234,
            "challenge_mode_rank": 1234,
            "avatar": "avatar.png",
            "game_user": {"name": "player", "avatar": "avatar.png"},
            "records": {"song.0": [{"score": 1000000, "acc": 100, "fc": true}]}
        }))
    );
}

#[test]
fn phihub_history_view_maps_v4_sections() {
    let resource = phihub_resource(
        "history",
        "/get/history/historyV4",
        &[
            ("version", "$.version"),
            ("timezone", "$.timezone"),
            ("rks", "$.rks"),
            ("data", "$.data"),
            ("challenge_mode_rank", "$.challengeModeRank"),
            ("score_history", "$.scoreHistory"),
        ],
    );
    let spec = resource.to_spec().expect("valid history resource");
    let body = serde_json::json!({
        "data": {
            "version": 4,
            "timezone": "+08:00",
            "rks": [[2026, [11, [9, [0, 15.1234]]]]],
            "data": [[2026, [11, [9, [0, [1, 2, 3, 4, 5]]]]]],
            "challengeModeRank": [[2026, [11, [9, [0, 1234]]]]],
            "scoreHistory": {"song.0": {"IN": [[2026, [11, [9, [0, [100, 1000000, 1]]]]]]}}
        }
    });
    assert_eq!(
        spec.view.expect("view").apply(&body).expect("view applies"),
        ViewOutput::Single(serde_json::json!({
            "version": 4,
            "timezone": "+08:00",
            "rks": [[2026, [11, [9, [0, 15.1234]]]]],
            "data": [[2026, [11, [9, [0, [1, 2, 3, 4, 5]]]]]],
            "challenge_mode_rank": [[2026, [11, [9, [0, 1234]]]]],
            "score_history": {"song.0": {"IN": [[2026, [11, [9, [0, [100, 1000000, 1]]]]]]}}
        }))
    );
}

#[test]
fn s10_unknown_config_keys_are_rejected() {
    let dir = std::env::temp_dir().join(format!("re0auth-unknown-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let base = std::fs::read_to_string(example_path()).expect("example");

    let top = dir.join("top.toml");
    std::fs::write(&top, format!("unknown_key = 1\n{base}")).expect("write");
    assert!(
        load_config(&top).is_err(),
        "an unknown top-level key must not be silently ignored"
    );

    let nested = dir.join("nested.toml");
    std::fs::write(
        &nested,
        base.replace("[server]", "[server]\ntrusehd_proxies = []"),
    )
    .expect("write");
    assert!(
        load_config(&nested).is_err(),
        "an unknown nested key must not be silently ignored"
    );
}

#[test]
fn s25_connector_oauth_http_uses_its_own_loopback_flag() {
    fn connector(allow_loopback: bool) -> ConnectorConfig {
        let toml = format!(
            r#"
id = "local"
base_url = "https://api.example.com"
allow_loopback = {allow_loopback}
[oauth]
authorization_endpoint = "https://idp.example/authorize"
token_endpoint = "http://127.0.0.1:9000/token"
userinfo_endpoint = "https://idp.example/userinfo"
client_id = "client"
client_secret = "secret"
scopes = ["openid"]
subject_field = "id"
"#
        );
        Figment::new()
            .merge(figment::providers::Toml::string(&toml))
            .extract()
            .expect("connector")
    }

    let closed = connector(false);
    let oauth = closed.oauth.as_ref().expect("oauth");
    assert!(
        validate_connector_oauth(&closed, oauth).is_err(),
        "a connector without allow_loopback must not accept an http token endpoint"
    );

    let open = connector(true);
    let oauth = open.oauth.as_ref().expect("oauth");
    validate_connector_oauth(&open, oauth).expect("connector-loopback http is allowed");
}

#[test]
fn s26_inflight_budget_must_cover_one_response() {
    let dir = std::env::temp_dir().join(format!("re0auth-budget-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let base = std::fs::read_to_string(example_path()).expect("example");
    let patched = base.replace(
        "upstream_inflight_bytes = 67108864",
        "upstream_inflight_bytes = 1024",
    );
    assert_ne!(patched, base, "the example must contain the budget line");
    let path = dir.join("config.toml");
    std::fs::write(&path, patched).expect("write");
    let error = load_config(&path).expect_err("budget below one response");
    assert!(error.to_string().contains("inflight"), "{error}");
}

fn resource_with_params(params: Vec<ParamConfig>, method: &str) -> ResourceConfig {
    let body = std::collections::BTreeMap::from([(
        "delegation_token".to_string(),
        "{credential}".to_string(),
    )]);
    ResourceConfig {
        name: "scores".to_string(),
        path: "/scores".to_string(),
        scope: None,
        method: Some(method.to_string()),
        idempotent: None,
        body: Some(body),
        view: None,
        params,
    }
}

fn string_param(name: &str, location: &str) -> ParamConfig {
    ParamConfig {
        name: name.to_string(),
        location: Some(location.to_string()),
        upstream: Some(name.to_string()),
        kind: Some("string".to_string()),
        required: true,
        min_len: None,
        max_len: Some(64),
        min: None,
        max: None,
        values: Vec::new(),
        array: false,
        max_items: None,
    }
}

#[test]
fn connector_parameters_are_validated_and_typed() {
    let params = vec![
        string_param("song_id", "body"),
        ParamConfig {
            name: "rank".to_string(),
            location: Some("body".to_string()),
            upstream: Some("rank".to_string()),
            kind: Some("enum".to_string()),
            required: true,
            min_len: None,
            max_len: None,
            min: None,
            max: None,
            values: vec!["EZ".into(), "HD".into(), "IN".into(), "AT".into()],
            array: false,
            max_items: None,
        },
        ParamConfig {
            name: "b30_limit".to_string(),
            location: Some("body".to_string()),
            upstream: Some("limit".to_string()),
            kind: Some("integer".to_string()),
            required: false,
            min_len: None,
            max_len: None,
            min: Some(serde_json::Number::from(1)),
            max: Some(serde_json::Number::from(100)),
            values: Vec::new(),
            array: false,
            max_items: None,
        },
        ParamConfig {
            name: "is_full_combo".to_string(),
            location: Some("body".to_string()),
            upstream: Some("is_full_combo".to_string()),
            kind: Some("boolean".to_string()),
            required: false,
            min_len: None,
            max_len: None,
            min: None,
            max: None,
            values: Vec::new(),
            array: false,
            max_items: None,
        },
    ];
    let spec = resource_with_params(params, "post")
        .to_spec()
        .expect("valid params");
    assert_eq!(spec.params.len(), 4);
    assert_eq!(spec.params[0].name, "song_id");
    assert_eq!(spec.params[1].values.len(), 4);
    assert_eq!(
        spec.params[2]
            .min
            .as_ref()
            .and_then(serde_json::Number::as_i64),
        Some(1)
    );
    assert_eq!(
        spec.params[3].kind,
        re0auth_api::connector::ParamKind::Boolean
    );
}

#[test]
fn connector_parameters_support_repeatable_arrays() {
    let mut sections = string_param("request", "body");
    sections.kind = Some("enum".to_string());
    sections.max_len = None;
    sections.values = vec!["data".into(), "rks".into(), "scoreHistory".into()];
    sections.array = true;
    sections.max_items = Some(3);
    let spec = resource_with_params(vec![sections], "post")
        .to_spec()
        .expect("array param");
    assert!(spec.params[0].array);
    assert_eq!(spec.params[0].max_items, Some(3));

    let mut misplaced = string_param("tag", "query");
    misplaced.max_items = Some(3);
    assert!(
        resource_with_params(vec![misplaced], "post")
            .to_spec()
            .is_err(),
        "max_items without array is a declaration mistake"
    );

    let mut too_many = string_param("tag", "query");
    too_many.array = true;
    too_many.max_items = Some(re0auth_api::connector::MAX_ARRAY_ITEMS + 1);
    assert!(
        resource_with_params(vec![too_many], "post")
            .to_spec()
            .is_err(),
        "the member cap cannot exceed the gateway ceiling"
    );
}

#[test]
fn a_post_resource_may_declare_an_empty_body() {
    let mut empty = resource_with_params(Vec::new(), "post");
    empty.body = Some(std::collections::BTreeMap::new());
    let spec = empty.to_spec().expect("an explicit empty body is allowed");
    assert!(spec.body.is_empty());

    let mut absent = resource_with_params(Vec::new(), "post");
    absent.body = None;
    assert!(
        absent.to_spec().is_err(),
        "an absent body is still a misconfiguration"
    );
}

#[test]
fn connector_parameters_reject_bad_declarations() {
    let mut reserved = string_param("limit", "body");
    reserved.name = "limit".to_string();
    assert!(
        resource_with_params(vec![reserved], "post")
            .to_spec()
            .is_err()
    );

    assert!(
        resource_with_params(vec![string_param("song_id", "body")], "get")
            .to_spec()
            .is_err()
    );

    let mut collision = string_param("token", "query");
    collision.upstream = Some("delegation_token".to_string());
    assert!(
        resource_with_params(vec![collision], "post")
            .to_spec()
            .is_err()
    );

    let mut too_long = string_param("song_id", "body");
    too_long.max_len = Some(300);
    assert!(
        resource_with_params(vec![too_long], "post")
            .to_spec()
            .is_err()
    );

    let mut empty_enum = string_param("rank", "body");
    empty_enum.kind = Some("enum".to_string());
    assert!(
        resource_with_params(vec![empty_enum], "post")
            .to_spec()
            .is_err()
    );

    let mut float_bound = string_param("count", "body");
    float_bound.kind = Some("integer".to_string());
    float_bound.min = Some(serde_json::Number::from_f64(1.5).expect("finite"));
    assert!(
        resource_with_params(vec![float_bound], "post")
            .to_spec()
            .is_err()
    );

    let mut boolean_len = string_param("flag", "body");
    boolean_len.kind = Some("boolean".to_string());
    boolean_len.max_len = Some(1);
    assert!(
        resource_with_params(vec![boolean_len], "post")
            .to_spec()
            .is_err()
    );

    assert!(
        resource_with_params(
            vec![
                string_param("song_id", "body"),
                string_param("song_id", "body"),
            ],
            "post",
        )
        .to_spec()
        .is_err()
    );

    let mut inverted = string_param("count", "body");
    inverted.kind = Some("integer".to_string());
    inverted.min = Some(serde_json::Number::from(10));
    inverted.max = Some(serde_json::Number::from(1));
    assert!(
        resource_with_params(vec![inverted], "post")
            .to_spec()
            .is_err()
    );

    let mut duplicate_enum = string_param("rank", "body");
    duplicate_enum.kind = Some("enum".to_string());
    duplicate_enum.values = vec!["HD".into(), "HD".into()];
    assert!(
        resource_with_params(vec![duplicate_enum], "post")
            .to_spec()
            .is_err()
    );
}

#[test]
fn resource_params_parse_from_toml() {
    let toml = r#"
[[params]]
name = "song_id"
in = "query"
upstream = "songId"
kind = "string"
required = true
min_len = 1
max_len = 64

[[params]]
name = "rank"
in = "body"
kind = "enum"
values = ["EZ", "HD"]
"#;
    #[derive(serde::Deserialize)]
    struct Root {
        params: Vec<ParamConfig>,
    }
    let root: Root = Figment::new()
        .merge(figment::providers::Toml::string(toml))
        .extract()
        .expect("param table parses");
    assert_eq!(root.params.len(), 2);
    assert_eq!(root.params[0].location.as_deref(), Some("query"));
    assert_eq!(root.params[0].upstream.as_deref(), Some("songId"));
    assert_eq!(
        root.params[1].values,
        vec!["EZ".to_string(), "HD".to_string()]
    );
}
