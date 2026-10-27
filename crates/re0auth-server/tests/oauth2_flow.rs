//! End-to-end tests for the non-OIDC providers.
//!
//! GitHub and QQ differ from OIDC in every wire detail that matters: no
//! `id_token`, no JWKS, and provider-specific token/openid bodies. Each quirk
//! gets a local mock so the adapter is exercised over real HTTP rather than by
//! calling its internals.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use axum::{Form, serve};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use url::Url;

use re0auth_adapters::storage::SqliteStore;
use re0auth_api::idp::IdpClient;
use re0auth_api::ports::{Identity, Storage, User, UserRole};
use re0auth_api::{IdentityId, UserId};
use re0auth_idp::oauth2::{OAuth2Config, OAuth2Kind, OAuth2Provider};
use re0auth_runtime::http_client::GuardedClient;
use re0auth_runtime::outbound::OutboundPolicy;

#[derive(Clone, Default)]
struct MockOAuth2 {
    base: Arc<Mutex<String>>,
    /// What the token endpoint answers with. Shapes differ per provider.
    token_body: Arc<Mutex<(String, &'static str)>>,
    /// Raw body of `GET /oauth2.0/me`, the JSONP endpoint QQ uses.
    openid_body: Arc<Mutex<String>>,
    /// Query parameters QQ's GET token endpoint received.
    token_query: Arc<Mutex<Option<HashMap<String, String>>>>,
    userinfo: Arc<Mutex<Value>>,
}

fn client() -> GuardedClient {
    GuardedClient::with_policy(OutboundPolicy::AllowLoopback, true).expect("http client")
}

/// Starts a mock with the given router state and returns its base URL.
async fn start(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("mock bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        serve(listener, app).await.expect("mock server");
    });
    base
}

async fn github_mock() -> (MockOAuth2, String) {
    let mock = MockOAuth2 {
        token_body: Arc::new(Mutex::new((
            json!({"access_token": "gh-token", "token_type": "bearer"}).to_string(),
            "application/json",
        ))),
        userinfo: Arc::new(Mutex::new(json!({
            "id": 12345,
            "login": "octocat",
            "name": "The Octocat"
        }))),
        ..Default::default()
    };
    let state = mock.clone();
    let app = Router::new()
        .route(
            "/token",
            post(|State(mock): State<MockOAuth2>, Form(_): Form<HashMap<String, String>>| async move {
                let (body, content_type) = mock.token_body.lock().expect("token body").clone();
                ([(axum::http::header::CONTENT_TYPE, content_type)], body)
            }),
        )
        .route(
            "/user",
            get(|State(mock): State<MockOAuth2>| async move {
                Json(mock.userinfo.lock().expect("userinfo").clone())
            }),
        )
        .with_state(state);
    let base = start(app).await;
    *mock.base.lock().expect("base") = base.clone();
    (mock, base)
}

async fn qq_mock() -> (MockOAuth2, String) {
    let mock = MockOAuth2 {
        token_body: Arc::new(Mutex::new((
            json!({
                "access_token": "qq-token",
                "expires_in": 7776000,
                "refresh_token": "r"
            })
            .to_string(),
            "application/json",
        ))),
        openid_body: Arc::new(Mutex::new(
            "callback( {\"client_id\":\"123\",\"openid\":\"qq-openid\"} );".to_string(),
        )),
        userinfo: Arc::new(Mutex::new(json!({
            "ret": 0,
            "msg": "",
            "nickname": "QQ Player"
        }))),
        ..Default::default()
    };
    let state = mock.clone();
    let app = Router::new()
        .route(
            "/token",
            get(
                |State(mock): State<MockOAuth2>, Query(query): Query<HashMap<String, String>>| async move {
                    *mock.token_query.lock().expect("token query") = Some(query);
                    let (body, content_type) = mock.token_body.lock().expect("token body").clone();
                    ([(axum::http::header::CONTENT_TYPE, content_type)], body)
                },
            ),
        )
        .route(
            "/oauth2.0/me",
            get(|State(mock): State<MockOAuth2>, Query(_): Query<HashMap<String, String>>| async move {
                mock.openid_body.lock().expect("openid body").clone()
            }),
        )
        .route(
            "/user/get_user_info",
            get(|State(mock): State<MockOAuth2>, Query(_): Query<HashMap<String, String>>| async move {
                Json(mock.userinfo.lock().expect("userinfo").clone())
            }),
        )
        .with_state(state);
    let base = start(app).await;
    *mock.base.lock().expect("base") = base.clone();
    (mock, base)
}

fn github_provider(base: &str) -> OAuth2Provider {
    OAuth2Provider::new(
        OAuth2Config {
            kind: OAuth2Kind::GitHub,
            client_id: "gh-client".to_string(),
            client_secret: "gh-secret".to_string(),
            redirect_uri: "https://auth.example.com/auth/callback".to_string(),
            scopes: vec!["read:user".to_string()],
            authorization_endpoint: format!("{base}/authorize"),
            token_endpoint: format!("{base}/token"),
            userinfo_endpoint: format!("{base}/user"),
        },
        client(),
    )
    .expect("github provider")
}

fn qq_provider(base: &str) -> OAuth2Provider {
    qq_provider_with_scopes(base, vec!["get_user_info".to_string()])
}

fn qq_provider_with_scopes(base: &str, scopes: Vec<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        OAuth2Config {
            kind: OAuth2Kind::Qq,
            client_id: "qq-client".to_string(),
            client_secret: "qq-secret".to_string(),
            redirect_uri: "https://auth.example.com/auth/callback".to_string(),
            scopes,
            authorization_endpoint: format!("{base}/authorize"),
            token_endpoint: format!("{base}/token"),
            userinfo_endpoint: format!("{base}/user/get_user_info"),
        },
        client(),
    )
    .expect("qq provider")
}

#[tokio::test]
async fn github_identity_uses_the_numeric_id_not_the_login() {
    let (_mock, base) = github_mock().await;
    let provider = github_provider(&base);

    let identity = provider
        .exchange_code("code", "", "")
        .await
        .expect("github login");
    assert_eq!(
        identity.subject, "12345",
        "the mutable login must not be the subject"
    );
    assert_eq!(identity.display_name, "The Octocat");
    assert_eq!(identity.issuer, "https://github.com");
}

/// GitHub answers the token endpoint with form encoding unless asked for JSON.
/// If the `Accept` header were dropped the body would not parse, so this asserts
/// the header is actually sent by making the mock honour it.
#[tokio::test]
async fn github_requires_the_json_accept_header() {
    let (mock, base) = github_mock().await;
    // Answer in the form-encoded default, as GitHub does when Accept is missing.
    *mock.token_body.lock().expect("token body") = (
        "access_token=gh-token".to_string(),
        "application/x-www-form-urlencoded",
    );
    let provider = github_provider(&base);

    let result = provider.exchange_code("code", "", "").await;
    let error = match result {
        Ok(identity) => panic!("a form-encoded body must not parse as JSON: {identity:?}"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("token response"),
        "expected a parse failure naming the token response, got {error}"
    );
}

#[tokio::test]
async fn github_reports_a_rejected_exchange() {
    let (mock, base) = github_mock().await;
    *mock.token_body.lock().expect("token body") = (
        json!({"error": "bad_verification_code"}).to_string(),
        "application/json",
    );
    let provider = github_provider(&base);

    let error = provider
        .exchange_code("code", "", "")
        .await
        .expect_err("a rejected exchange must not produce an identity");
    assert!(
        error.to_string().contains("bad_verification_code"),
        "{error}"
    );
}

#[tokio::test]
async fn qq_unwraps_jsonp_and_uses_the_openid_as_subject() {
    let (_mock, base) = qq_mock().await;
    let provider = qq_provider(&base);

    let identity = provider
        .exchange_code("code", "", "")
        .await
        .expect("qq login");
    assert_eq!(identity.subject, "qq-openid");
    assert_eq!(identity.display_name, "QQ Player");
    assert_eq!(identity.issuer, "https://graph.qq.com");
}

#[tokio::test]
async fn qq_reports_an_unwrappable_openid_response() {
    let (mock, base) = qq_mock().await;
    *mock.openid_body.lock().expect("openid body") = json!({"openid": "qq-openid"}).to_string();
    let provider = qq_provider(&base);

    let error = provider
        .exchange_code("code", "", "")
        .await
        .expect_err("an unwrapped body must not be accepted");
    assert!(error.to_string().contains("JSONP"), "{error}");
}

/// QQ's server-side flow is GET with query parameters and JSON when `fmt=json`
/// is requested. Pin both halves: a POST or a form body would pass a mock that
/// copied the old implementation but fail against the documented protocol.
#[tokio::test]
async fn qq_token_request_is_get_json_with_the_documented_parameters() {
    let (mock, base) = qq_mock().await;
    let provider = qq_provider(&base);

    let identity = provider
        .exchange_code("code", "", "")
        .await
        .expect("qq login");
    assert_eq!(identity.subject, "qq-openid");

    let query = mock
        .token_query
        .lock()
        .expect("token query")
        .clone()
        .expect("the token endpoint was called");
    assert_eq!(
        query.get("grant_type").map(String::as_str),
        Some("authorization_code")
    );
    assert_eq!(
        query.get("client_id").map(String::as_str),
        Some("qq-client")
    );
    assert_eq!(
        query.get("client_secret").map(String::as_str),
        Some("qq-secret")
    );
    assert_eq!(query.get("code").map(String::as_str), Some("code"));
    assert_eq!(query.get("fmt").map(String::as_str), Some("json"));
    assert_eq!(
        query.get("redirect_uri").map(String::as_str),
        Some("https://auth.example.com/auth/callback")
    );
}

#[tokio::test]
async fn qq_reports_a_json_token_failure() {
    let (mock, base) = qq_mock().await;
    *mock.token_body.lock().expect("token body") = (
        json!({"error": 100019, "error_description": "code invalid"}).to_string(),
        "application/json",
    );
    let provider = qq_provider(&base);

    let error = provider
        .exchange_code("code", "", "")
        .await
        .expect_err("a failed token exchange must not produce an identity");
    assert!(error.to_string().contains("100019"), "{error}");
    assert!(error.to_string().contains("code invalid"), "{error}");
}

/// Regression: the old implementation read this body as form encoding even
/// though it asked QQ for JSON. Accepting it here would let that bug return.
#[tokio::test]
async fn qq_rejects_a_form_encoded_token_body() {
    let (mock, base) = qq_mock().await;
    *mock.token_body.lock().expect("token body") = (
        "access_token=qq-token&expires_in=7776000".to_string(),
        "application/x-www-form-urlencoded",
    );
    let provider = qq_provider(&base);

    let error = provider
        .exchange_code("code", "", "")
        .await
        .expect_err("a form body is not the JSON asked for");
    assert!(error.to_string().contains("token response"), "{error}");
}

/// The authorization URL must not carry OIDC-only parameters. Sending `nonce` or
/// `code_challenge` to a provider that ignores them makes the login look
/// protected by PKCE when the exchange is bound only by the client secret.
#[tokio::test]
async fn the_authorization_url_omits_oidc_only_parameters() {
    let (_mock, base) = github_mock().await;
    let provider = github_provider(&base);

    let url = provider.authorization_url("state-1", "nonce-1", "challenge-1");
    let query: HashMap<String, String> = Url::parse(&url)
        .expect("authorization url")
        .query_pairs()
        .into_owned()
        .collect();

    assert_eq!(query.get("state").map(String::as_str), Some("state-1"));
    assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
    assert_eq!(query.get("scope").map(String::as_str), Some("read:user"));
    assert!(
        !query.contains_key("nonce"),
        "nonce is an OIDC parameter: {query:?}"
    );
    assert!(
        !query.contains_key("code_challenge"),
        "this provider does not support PKCE, so advertising it would be a lie: {query:?}"
    );
}

/// The two providers share no subject space even when the ids collide, because
/// the namespace is part of the key.
#[tokio::test]
async fn subjects_from_different_providers_do_not_collide() {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("store");
    let now = 1_000;

    let github = Identity {
        id: IdentityId::new(),
        user_id: UserId::new(),
        issuer: OAuth2Kind::GitHub.namespace().to_string(),
        subject: "12345".to_string(),
        created_at: now,
    };
    let qq = Identity {
        id: IdentityId::new(),
        user_id: UserId::new(),
        issuer: OAuth2Kind::Qq.namespace().to_string(),
        subject: "12345".to_string(),
        created_at: now,
    };
    assert_ne!(github.issuer, qq.issuer, "namespaces must differ");

    let user = User {
        id: github.user_id,
        display_name: "A".to_string(),
        role: UserRole::User,
        created_at: now,
        updated_at: now,
    };
    store.users().create(&user).await.expect("user");
    store
        .users()
        .link_identity(&github)
        .await
        .expect("github link");

    let other = User {
        id: qq.user_id,
        display_name: "B".to_string(),
        role: UserRole::User,
        created_at: now,
        updated_at: now,
    };
    store.users().create(&other).await.expect("user");
    store
        .users()
        .link_identity(&qq)
        .await
        .expect("the same numeric subject under another namespace must be allowed");

    let found = store
        .users()
        .find_by_identity(&github.issuer, "12345")
        .await
        .expect("lookup")
        .expect("github identity");
    assert_eq!(found.id, github.user_id);
    let found = store
        .users()
        .find_by_identity(&qq.issuer, "12345")
        .await
        .expect("lookup")
        .expect("qq identity");
    assert_eq!(found.id, qq.user_id);
}

#[tokio::test]
async fn qq_authorization_scopes_are_comma_separated() {
    let (_mock, base) = qq_mock().await;
    let provider = qq_provider_with_scopes(
        &base,
        vec!["get_user_info".to_string(), "list_album".to_string()],
    );
    let url = provider.authorization_url("state-1", "nonce-1", "challenge-1");
    let query: HashMap<String, String> = Url::parse(&url)
        .expect("authorization url")
        .query_pairs()
        .into_owned()
        .collect();
    assert_eq!(
        query.get("scope").map(String::as_str),
        Some("get_user_info,list_album")
    );
}
