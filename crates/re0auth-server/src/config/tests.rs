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
        base_url: "https://api.example.com".into(),
        allow_private_net: false,
        allow_link_local_metadata: false,
        allow_loopback: false,
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
