use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use re0auth_adapters::clock::SystemClock;
use re0auth_adapters::crypto::RsaTokenSigner;
use re0auth_adapters::random::OsRandom;
use re0auth_adapters::storage::SqliteStore;
use re0auth_api::oauth::ConsentVersion;
use re0auth_api::ports::{Client, ClientStatus, Session, Storage, User, UserRole};
use re0auth_api::{ClientId, Clock, SessionId, UserId};
use re0auth_app::admin;
use re0auth_app::auth::AuthService;
use re0auth_app::oauth::{OAuthService, hash_secret};
use re0auth_domain::pkce;
use re0auth_http::{AppState, router};
use serde_json::Value;
use tower::ServiceExt;
use url::form_urlencoded;

const ISSUER: &str = "https://auth.example.com";
const TEST_MASTER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const REDIRECT_URI: &str = "https://client.example/callback";
const VERIFIER: &str = "verifier-0123456789-0123456789-0123456789-0123456789";
const SESSION_RAW: &str = "test-session-raw";

struct KeyGuard(PathBuf);

impl Drop for KeyGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct TestApp {
    router: axum::Router,
    store: SqliteStore,
    client_id: ClientId,
    user_id: UserId,
    key: KeyGuard,
}

async fn setup() -> TestApp {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("SQLite store");
    let key_path = std::env::temp_dir().join(format!("re0auth-flow-{}.pem", uuid::Uuid::now_v7()));
    let key = KeyGuard(key_path.clone());
    let signer =
        Arc::new(RsaTokenSigner::load_or_generate(&key_path, ISSUER, 1_000, &[]).expect("signer"));
    let clock = Arc::new(SystemClock);
    let random = Arc::new(OsRandom);
    let oauth = OAuthService::new(
        Arc::new(store.clone()),
        signer.clone(),
        clock.clone(),
        random.clone(),
        Arc::new(
            re0auth_adapters::client_secret::HmacClientSecretHasher::new(TEST_MASTER)
                .expect("hasher"),
        ),
        ISSUER,
    );
    let auth = AuthService::new(
        Arc::new(store.clone()),
        vec![],
        signer,
        clock,
        random,
        ISSUER,
    );

    let now = SystemClock.now();
    let user_id = UserId::new();
    store
        .users()
        .create(&User {
            id: user_id,
            display_name: "Alice".to_string(),
            role: UserRole::User,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("user");
    store
        .sessions()
        .create(&Session {
            id: SessionId::new(),
            id_hash: hash_secret(SESSION_RAW),
            user_id,
            csrf_hash: hash_secret("csrf"),
            created_at: now,
            last_seen_at: now,
            idle_expires_at: now + 3_600,
            absolute_expires_at: now + 7_200,
            revoked_at: None,
        })
        .await
        .expect("session");

    let client_id = ClientId::new();
    store
        .clients()
        .insert(
            &Client {
                id: client_id,
                name: "flow-client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                allowed_scopes: vec!["openid".to_string(), "profile".to_string()],
                raw_access: false,
                status: ClientStatus::Approved,
                secret_hash: None,
                created_at: now,
                updated_at: now,
            },
            &re0auth_api::audit::SecurityFact::new(
                re0auth_api::audit::AuditAction::ClientCreated,
                1_000,
                "client",
            ),
        )
        .await
        .expect("client");

    TestApp {
        router: router(AppState::new(oauth, auth)).layer(
            axum::extract::connect_info::MockConnectInfo(std::net::SocketAddr::from((
                [203, 0, 113, 10],
                4444,
            ))),
        ),
        store,
        client_id,
        user_id,
        key,
    }
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("JSON")
}

fn token_form(pairs: &[(&str, &str)]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

async fn post_form(app: &TestApp, form: String) -> axum::response::Response {
    post_form_path(app, "/oauth/token", form).await
}

async fn post_form_path(app: &TestApp, path: &str, form: String) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("request"),
        )
        .await
        .expect("response")
}

async fn post_json(
    app: &TestApp,
    uri: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    for (key, value) in headers {
        builder = builder.header(*key, *value);
    }
    app.router
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).expect("request"))
        .await
        .expect("response")
}

#[tokio::test]
async fn authorization_code_flow_reaches_userinfo_and_refresh() {
    let app = setup().await;
    let challenge = pkce::challenge_s256(VERIFIER);
    let mut authorize = url::Url::parse(&format!("{ISSUER}/oauth/authorize")).expect("URL");
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &app.client_id.0.to_string())
        .append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("scope", "openid profile")
        .append_pair("state", "state-123")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("nonce", "nonce-123");

    let authorize_uri = match authorize.query() {
        Some(query) => format!("{}?{query}", authorize.path()),
        None => authorize.path().to_string(),
    };
    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(authorize_uri)
                .header(header::COOKIE, format!("re0auth_session={SESSION_RAW}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("authorize");
    assert!(
        response.status().is_redirection(),
        "status={}",
        response.status()
    );
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location")
        .to_str()
        .expect("location utf8");
    let consent_url =
        url::Url::parse(&format!("{ISSUER}{location}")).expect("consent redirect URL");
    assert_eq!(consent_url.path(), "/consent");
    let request_id = consent_url
        .query_pairs()
        .find(|(key, _)| key == "request")
        .map(|(_, value)| value.to_string())
        .expect("consent request id");

    let pending = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/oauth/pending?{}",
                    token_form(&[("request", request_id.as_str())])
                ))
                .header(header::COOKIE, format!("re0auth_session={SESSION_RAW}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("pending");
    assert_eq!(pending.status(), StatusCode::OK);
    let pending_body = body_json(pending).await;
    assert_eq!(pending_body["client_name"], "flow-client");
    assert_eq!(pending_body["scopes"][0], "openid");

    let consent = post_json(
        &app,
        "/api/oauth/consent",
        serde_json::json!({
            "request_id": request_id,
            "decision": "approve",
        }),
        &[
            ("cookie", &format!("re0auth_session={SESSION_RAW}")),
            ("x-csrf-token", "csrf"),
        ],
    )
    .await;
    assert_eq!(consent.status(), StatusCode::OK);
    let consent_body = body_json(consent).await;
    let redirect = url::Url::parse(consent_body["redirect_to"].as_str().expect("redirect_to"))
        .expect("redirect URL");
    let code = redirect
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .expect("code");
    assert_eq!(
        redirect
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.to_string()),
        Some("state-123".to_string())
    );

    let response = post_form(
        &app,
        token_form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &app.client_id.0.to_string()),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", VERIFIER),
        ]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = body_json(response).await;
    let access_token = tokens["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    let id_token = tokens["id_token"].as_str().expect("id token").to_string();
    let refresh_token = tokens["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_string();

    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("userinfo");
    assert_eq!(response.status(), StatusCode::OK);
    let userinfo = body_json(response).await;
    assert_eq!(userinfo["name"], "Alice");

    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {id_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("id token userinfo");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "id_token must not be an access token"
    );

    let response = post_form(
        &app,
        token_form(&[
            ("grant_type", "refresh_token"),
            ("client_id", &app.client_id.0.to_string()),
            ("refresh_token", &refresh_token),
        ]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let refreshed = body_json(response).await;
    assert_ne!(refreshed["refresh_token"], refresh_token);

    let response = post_form(
        &app,
        token_form(&[
            ("grant_type", "refresh_token"),
            ("client_id", &app.client_id.0.to_string()),
            ("refresh_token", &refresh_token),
        ]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = body_json(response).await;
    assert_eq!(error["error"], "invalid_grant");

    drop(app.key);
}

fn authorize_uri(app: &TestApp, state: &str) -> String {
    let challenge = pkce::challenge_s256(VERIFIER);
    let mut authorize = url::Url::parse(&format!("{ISSUER}/oauth/authorize")).expect("URL");
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &app.client_id.0.to_string())
        .append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("scope", "openid profile")
        .append_pair("state", state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("nonce", "nonce-123");
    match authorize.query() {
        Some(query) => format!("{}?{query}", authorize.path()),
        None => authorize.path().to_string(),
    }
}

async fn authorize_request(app: &TestApp, state: &str) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::builder()
                .uri(authorize_uri(app, state))
                .header(header::COOKIE, format!("re0auth_session={SESSION_RAW}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("authorize")
}

fn consent_request_id(response: &axum::response::Response) -> String {
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location")
        .to_str()
        .expect("location utf8");
    assert!(
        location.starts_with("/consent?request="),
        "consent redirect must be /consent?request=..., got {location}"
    );
    let url = url::Url::parse(&format!("{ISSUER}{location}")).expect("consent URL");
    url.query_pairs()
        .find(|(key, _)| key == "request")
        .map(|(_, value)| value.to_string())
        .expect("request id")
}

async fn approve_authorization(app: &TestApp, state: &str) -> String {
    let response = authorize_request(app, state).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let request_id = consent_request_id(&response);
    let consent = post_json(
        app,
        "/api/oauth/consent",
        serde_json::json!({
            "request_id": request_id,
            "decision": "approve",
        }),
        &[
            ("cookie", &format!("re0auth_session={SESSION_RAW}")),
            ("x-csrf-token", "csrf"),
        ],
    )
    .await;
    assert_eq!(consent.status(), StatusCode::OK);
    let body = body_json(consent).await;
    let redirect =
        url::Url::parse(body["redirect_to"].as_str().expect("redirect_to")).expect("redirect URL");
    redirect
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .expect("code")
}

async fn revoke_authorization(app: &TestApp) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/me/authorizations/{}", app.client_id.0))
                .header(header::COOKIE, format!("re0auth_session={SESSION_RAW}"))
                .header("x-csrf-token", "csrf")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("revoke authorization")
}

async fn list_authorizations(app: &TestApp) -> Value {
    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/me/authorizations")
                .header(header::COOKIE, format!("re0auth_session={SESSION_RAW}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("authorizations");
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

async fn exchange_code(app: &TestApp, code: &str) -> axum::response::Response {
    post_form(
        app,
        token_form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &app.client_id.0.to_string()),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", VERIFIER),
        ]),
    )
    .await
}

async fn refresh_tokens(app: &TestApp, refresh_token: &str) -> axum::response::Response {
    post_form(
        app,
        token_form(&[
            ("grant_type", "refresh_token"),
            ("client_id", &app.client_id.0.to_string()),
            ("refresh_token", refresh_token),
        ]),
    )
    .await
}

async fn revoke_token(app: &TestApp, token: &str) -> axum::response::Response {
    post_form_path(
        app,
        "/oauth/revoke",
        token_form(&[
            ("token", token),
            ("client_id", &app.client_id.0.to_string()),
        ]),
    )
    .await
}

async fn start_device(app: &TestApp) -> Value {
    let response = post_form_path(
        app,
        "/oauth/device_authorization",
        token_form(&[
            ("client_id", &app.client_id.0.to_string()),
            ("scope", "openid profile"),
        ]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

async fn poll_device(app: &TestApp, device_code: &str) -> axum::response::Response {
    post_form_path(
        app,
        "/oauth/token",
        token_form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", &app.client_id.0.to_string()),
            ("device_code", device_code),
        ]),
    )
    .await
}

async fn userinfo(app: &TestApp, access_token: &str) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("userinfo")
}

#[tokio::test]
async fn consent_denial_and_existing_consent_shortcut() {
    let app = setup().await;

    let response = authorize_request(&app, "state-deny").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let request_id = consent_request_id(&response);

    let missing_csrf = post_json(
        &app,
        "/api/oauth/consent",
        serde_json::json!({
            "request_id": request_id,
            "decision": "deny",
        }),
        &[("cookie", &format!("re0auth_session={SESSION_RAW}"))],
    )
    .await;
    assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);

    let denied = post_json(
        &app,
        "/api/oauth/consent",
        serde_json::json!({
            "request_id": request_id,
            "decision": "deny",
        }),
        &[
            ("cookie", &format!("re0auth_session={SESSION_RAW}")),
            ("x-csrf-token", "csrf"),
        ],
    )
    .await;
    assert_eq!(denied.status(), StatusCode::OK);
    let denied_body = body_json(denied).await;
    let denied_redirect =
        url::Url::parse(denied_body["redirect_to"].as_str().expect("redirect_to"))
            .expect("deny redirect");
    assert_eq!(
        denied_redirect
            .query_pairs()
            .find(|(key, _)| key == "error")
            .map(|(_, value)| value.to_string()),
        Some("access_denied".to_string())
    );
    assert_eq!(
        denied_redirect
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.to_string()),
        Some("state-deny".to_string())
    );

    let response = authorize_request(&app, "state-approve").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let request_id = consent_request_id(&response);
    let approved = post_json(
        &app,
        "/api/oauth/consent",
        serde_json::json!({
            "request_id": request_id,
            "decision": "approve",
        }),
        &[
            ("cookie", &format!("re0auth_session={SESSION_RAW}")),
            ("x-csrf-token", "csrf"),
        ],
    )
    .await;
    assert_eq!(approved.status(), StatusCode::OK);

    let response = authorize_request(&app, "state-reuse").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location")
        .to_str()
        .expect("location utf8");
    let redirect = url::Url::parse(location).expect("client redirect");
    assert_eq!(redirect.host_str(), Some("client.example"));
    assert!(redirect.query_pairs().any(|(key, _)| key == "code"));

    drop(app.key);
}

#[tokio::test]
async fn revoking_consent_removes_authorization_from_the_list() {
    let app = setup().await;
    let _code = approve_authorization(&app, "state-list").await;

    let before = list_authorizations(&app).await;
    assert_eq!(before[0]["client_name"], "flow-client");

    let revoked = revoke_authorization(&app).await;
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

    let after = list_authorizations(&app).await;
    assert!(after.as_array().expect("list").is_empty());

    drop(app.key);
}

#[tokio::test]
async fn revoking_consent_requires_csrf() {
    let app = setup().await;
    let _code = approve_authorization(&app, "state-csrf").await;

    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/me/authorizations/{}", app.client_id.0))
                .header(header::COOKIE, format!("re0auth_session={SESSION_RAW}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("revoke without csrf");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    drop(app.key);
}

#[tokio::test]
async fn revoking_consent_invalidates_outstanding_code() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-code").await;

    let revoked = revoke_authorization(&app).await;
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

    let response = exchange_code(&app, &code).await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a code issued before consent revocation must not mint tokens"
    );
    let error = body_json(response).await;
    assert_eq!(error["error"], "invalid_grant");

    drop(app.key);
}

#[tokio::test]
async fn revoking_consent_stops_refresh() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-refresh").await;
    let response = exchange_code(&app, &code).await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = body_json(response).await;
    let refresh_token = tokens["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_string();

    let revoked = revoke_authorization(&app).await;
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

    let response = refresh_tokens(&app, &refresh_token).await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "revoking consent must stop the refresh family"
    );
    let error = body_json(response).await;
    assert_eq!(error["error"], "invalid_grant");

    drop(app.key);
}

#[tokio::test]
async fn revoking_consent_blocks_userinfo() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-userinfo").await;
    let response = exchange_code(&app, &code).await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = body_json(response).await;
    let access_token = tokens["access_token"]
        .as_str()
        .expect("access token")
        .to_string();

    let revoked = revoke_authorization(&app).await;
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

    let response = userinfo(&app, &access_token).await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "revoking consent must invalidate outstanding access tokens"
    );

    drop(app.key);
}

#[tokio::test]
async fn revoking_consent_denies_an_already_approved_device_code() {
    let app = setup().await;

    // 先建立有效 consent，否则没有可撤销对象
    let code = approve_authorization(&app, "state-device-existing").await;
    let response = exchange_code(&app, &code).await;
    assert_eq!(response.status(), StatusCode::OK);

    let authorization = start_device(&app).await;
    let device_code = authorization["device_code"].as_str().expect("device code");
    let user_code = authorization["user_code"].as_str().expect("user code");
    admin::approve_device(&app.store, &SystemClock, user_code, app.user_id)
        .await
        .expect("approve device");

    let revoked = revoke_authorization(&app).await;
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

    // D2=A 在换 token 时写 consent；这里必须挡住重建
    let response = poll_device(&app, device_code).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "access_denied");
    assert!(
        app.store
            .consents()
            .find(&app.user_id, &app.client_id)
            .await
            .expect("consent lookup")
            .is_none(),
        "the revoked authorization must not be recreated by the device poll"
    );

    drop(app.key);
}

#[tokio::test]
async fn device_login_reuses_an_existing_consent_without_bumping_version() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-device-reuse").await;
    let response = exchange_code(&app, &code).await;
    assert_eq!(response.status(), StatusCode::OK);
    let first_access = body_json(response).await["access_token"]
        .as_str()
        .expect("first access token")
        .to_string();

    let before = app
        .store
        .consents()
        .find(&app.user_id, &app.client_id)
        .await
        .expect("consent lookup")
        .expect("consent exists");
    assert_eq!(before.version, ConsentVersion(1));

    let authorization = start_device(&app).await;
    let device_code = authorization["device_code"].as_str().expect("device code");
    let user_code = authorization["user_code"].as_str().expect("user code");
    admin::approve_device(&app.store, &SystemClock, user_code, app.user_id)
        .await
        .expect("approve device");
    let response = poll_device(&app, device_code).await;
    assert_eq!(response.status(), StatusCode::OK);

    let after = app
        .store
        .consents()
        .find(&app.user_id, &app.client_id)
        .await
        .expect("consent lookup")
        .expect("consent still exists");
    assert_eq!(
        after.version, before.version,
        "a device login that already has consent must not bump the version"
    );
    let response = userinfo(&app, &first_access).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "an unrelated device login must not invalidate existing access tokens"
    );

    drop(app.key);
}

#[tokio::test]
async fn regranting_consent_keeps_old_access_tokens_invalid() {
    let app = setup().await;
    let old_code = approve_authorization(&app, "state-old").await;
    let response = exchange_code(&app, &old_code).await;
    assert_eq!(response.status(), StatusCode::OK);
    let old_access = body_json(response).await["access_token"]
        .as_str()
        .expect("old access token")
        .to_string();

    let revoked = revoke_authorization(&app).await;
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

    // Re-granting creates a new consent version. The old token must stay dead;
    // otherwise the version check would only be an "is there any consent"
    // check and re-authorizing would resurrect tokens the user already killed.
    let new_code = approve_authorization(&app, "state-new").await;
    let response = userinfo(&app, &old_access).await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "re-granting must not resurrect an access token from the old version"
    );

    let response = exchange_code(&app, &new_code).await;
    assert_eq!(response.status(), StatusCode::OK);
    let new_access = body_json(response).await["access_token"]
        .as_str()
        .expect("new access token")
        .to_string();
    let response = userinfo(&app, &new_access).await;
    assert_eq!(response.status(), StatusCode::OK);

    drop(app.key);
}

#[tokio::test]
async fn revoking_a_refresh_token_revokes_the_family() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-revoke-refresh").await;
    let response = exchange_code(&app, &code).await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = body_json(response).await;
    let refresh_token = tokens["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_string();

    let revoked = revoke_token(&app, &refresh_token).await;
    assert_eq!(revoked.status(), StatusCode::OK);

    let response = refresh_tokens(&app, &refresh_token).await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "revoking a refresh token must revoke its family"
    );
    let error = body_json(response).await;
    assert_eq!(error["error"], "invalid_grant");

    drop(app.key);
}

#[tokio::test]
async fn revoking_an_unknown_token_returns_200() {
    let app = setup().await;
    let response = revoke_token(&app, "not-a-real-token").await;
    assert_eq!(response.status(), StatusCode::OK);

    drop(app.key);
}

#[tokio::test]
async fn discovery_and_jwks_are_public() {
    let app = setup().await;

    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("discovery");
    assert_eq!(response.status(), StatusCode::OK);
    let discovery = body_json(response).await;
    assert_eq!(discovery["issuer"], ISSUER);
    assert_eq!(discovery["jwks_uri"], format!("{ISSUER}/jwks.json"));

    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/jwks.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("jwks");
    assert_eq!(response.status(), StatusCode::OK);
    let jwks = body_json(response).await;
    assert!(jwks["keys"][0]["kid"].as_str().is_some());
    assert_eq!(jwks["keys"][0]["alg"], "RS256");

    drop(app.key);
}

/// The binding routes, exercised through the real router.
///
/// The JSON success path needs a configured connector and is covered by the
/// app-level flow tests and the cross-language field gate; what must not
/// regress here is the guard wiring, which a route rename or a method change
/// would silently break.
#[tokio::test]
async fn binding_routes_keep_their_guards() {
    let app = setup().await;

    // The upstream list is session-only: no session, no answer.
    let anonymous = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/me/bindings/upstreams")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    // Starting a flow is state-changing, so it keeps the CSRF header check even
    // though it now answers JSON instead of redirecting.
    let no_csrf = post_json(
        &app,
        "/api/me/bindings/begin",
        serde_json::json!({ "upstream": "phigros" }),
        &[("cookie", &format!("re0auth_session={SESSION_RAW}"))],
    )
    .await;
    assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(no_csrf).await["code"], "invalid_csrf");

    // With CSRF but no connector configured in this deployment, the honest
    // answer is 404, not an authorization URL we could never redeem.
    let unconfigured = post_json(
        &app,
        "/api/me/bindings/begin",
        serde_json::json!({ "upstream": "phigros" }),
        &[
            ("cookie", &format!("re0auth_session={SESSION_RAW}")),
            ("x-csrf-token", "csrf"),
        ],
    )
    .await;
    assert_eq!(unconfigured.status(), StatusCode::NOT_FOUND);

    // The binding killswitch is a write, so it keeps the CSRF check too.
    let killswitch_no_csrf = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/me/bindings")
                .header(header::COOKIE, format!("re0auth_session={SESSION_RAW}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(killswitch_no_csrf.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(killswitch_no_csrf).await["code"], "invalid_csrf");

    // With CSRF and no bindings it is a successful no-op, not an error: a
    // killswitch has to be safe to press twice.
    let killswitch = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/me/bindings")
                .header(header::COOKIE, format!("re0auth_session={SESSION_RAW}"))
                .header("x-csrf-token", "csrf")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(killswitch.status(), StatusCode::OK);
    assert_eq!(body_json(killswitch).await["revoked"], 0);
}
