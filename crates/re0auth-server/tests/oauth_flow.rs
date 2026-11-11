use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine;
use re0auth_adapters::clock::SystemClock;
use re0auth_adapters::crypto::RsaTokenSigner;
use re0auth_adapters::random::OsRandom;
use re0auth_adapters::storage::SqliteStore;
use re0auth_api::oauth::{
    AccessTokenClaims, ApprovalTicketClaims, ConsentVersion, IdTokenClaims, TokenSigner,
};
use re0auth_api::ports::{
    Client, ClientStatus, Consent, RefreshToken, Session, Storage, User, UserRole, UserStatus,
};
use re0auth_api::{ClientId, Clock, FamilyId, RefreshTokenId, SessionId, UserId};
use re0auth_app::admin;
use re0auth_app::auth::AuthService;
use re0auth_app::oauth::{OAuthError, OAuthService, hash_secret};
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
            status: re0auth_api::ports::UserStatus::Active,
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
        router: router(AppState::new(oauth, auth).with_metrics(true)).layer(
            axum::extract::connect_info::MockConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
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
                .header(
                    header::COOKIE,
                    format!("__Host-re0auth_session={SESSION_RAW}"),
                )
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
                .header(
                    header::COOKIE,
                    format!("__Host-re0auth_session={SESSION_RAW}"),
                )
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
            ("cookie", &format!("__Host-re0auth_session={SESSION_RAW}")),
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
    let claims = jwt_payload(&id_token);
    assert!(claims["auth_time"].as_i64().expect("auth_time") > 0);
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
                .header(
                    header::COOKIE,
                    format!("__Host-re0auth_session={SESSION_RAW}"),
                )
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
            ("cookie", &format!("__Host-re0auth_session={SESSION_RAW}")),
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
                .header(
                    header::COOKIE,
                    format!("__Host-re0auth_session={SESSION_RAW}"),
                )
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
                .header(
                    header::COOKIE,
                    format!("__Host-re0auth_session={SESSION_RAW}"),
                )
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
        &[("cookie", &format!("__Host-re0auth_session={SESSION_RAW}"))],
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
            ("cookie", &format!("__Host-re0auth_session={SESSION_RAW}")),
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
            ("cookie", &format!("__Host-re0auth_session={SESSION_RAW}")),
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
                .header(
                    header::COOKIE,
                    format!("__Host-re0auth_session={SESSION_RAW}"),
                )
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

    let stored = app
        .store
        .refresh_tokens()
        .find(&hash_secret(&refresh_token))
        .await
        .expect("find refresh token")
        .expect("refresh token exists");
    assert!(
        stored.revoked_at.is_some(),
        "consent revocation must revoke the refresh family row"
    );

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
async fn retrying_revocation_cleans_tokens_after_consent_is_already_revoked() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-retry-revoke").await;
    let response = exchange_code(&app, &code).await;
    assert_eq!(response.status(), StatusCode::OK);
    let refresh_token = body_json(response).await["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_string();

    // Simulate the first attempt committing the consent revoke and then
    // crashing before the refresh-family cleanup.
    let now = SystemClock.now();
    app.store
        .consents()
        .revoke(
            &app.user_id,
            &app.client_id,
            &re0auth_api::audit::SecurityFact::new(
                re0auth_api::audit::AuditAction::ConsentRevoked,
                now,
                "consent:test",
            ),
            now,
        )
        .await
        .expect("first consent revoke");

    let retry = revoke_authorization(&app).await;
    assert_eq!(retry.status(), StatusCode::NOT_FOUND);
    let stored = app
        .store
        .refresh_tokens()
        .find(&hash_secret(&refresh_token))
        .await
        .expect("find refresh token")
        .expect("refresh token exists");
    assert!(
        stored.revoked_at.is_some(),
        "a retry must still clean the family even when consent is already revoked"
    );

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
    let first_refresh = tokens["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_string();

    let response = refresh_tokens(&app, &first_refresh).await;
    assert_eq!(response.status(), StatusCode::OK);
    let second_refresh = body_json(response).await["refresh_token"]
        .as_str()
        .expect("rotated refresh token")
        .to_string();

    let revoked = revoke_token(&app, &first_refresh).await;
    assert_eq!(revoked.status(), StatusCode::OK);

    let response = refresh_tokens(&app, &second_refresh).await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "revoking one family member must revoke the whole family"
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
        &[("cookie", &format!("__Host-re0auth_session={SESSION_RAW}"))],
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
            ("cookie", &format!("__Host-re0auth_session={SESSION_RAW}")),
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
                .header(
                    header::COOKIE,
                    format!("__Host-re0auth_session={SESSION_RAW}"),
                )
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
                .header(
                    header::COOKIE,
                    format!("__Host-re0auth_session={SESSION_RAW}"),
                )
                .header("x-csrf-token", "csrf")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(killswitch.status(), StatusCode::OK);
    assert_eq!(body_json(killswitch).await["revoked"], 0);
}

#[tokio::test]
async fn a_replayed_authorization_code_revokes_what_it_issued() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-replay").await;

    let first = exchange_code(&app, &code).await;
    assert_eq!(first.status(), StatusCode::OK);
    let issued = body_json(first).await;
    let access = issued["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    let refresh = issued["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_string();

    let replayed = exchange_code(&app, &code).await;
    assert_eq!(replayed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(replayed).await["error"], "invalid_grant");

    let refreshed = post_form(
        &app,
        token_form(&[
            ("grant_type", "refresh_token"),
            ("client_id", &app.client_id.0.to_string()),
            ("refresh_token", &refresh),
        ]),
    )
    .await;
    assert_eq!(
        refreshed.status(),
        StatusCode::BAD_REQUEST,
        "the family issued by the replayed code must be revoked"
    );
    assert_eq!(body_json(refreshed).await["error"], "invalid_grant");

    let info = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {access}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("userinfo");
    assert_eq!(
        info.status(),
        StatusCode::UNAUTHORIZED,
        "the access token must die with its family"
    );
}

// --------------------------------------------------------- security guards

/// 自定义 redirect_uri 的授权 URI，不动 `authorize_uri`
fn authorize_uri_with(app: &TestApp, redirect_uri: &str, scope: &str) -> String {
    let challenge = pkce::challenge_s256(VERIFIER);
    let mut authorize = url::Url::parse(&format!("{ISSUER}/oauth/authorize")).expect("URL");
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &app.client_id.0.to_string())
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", scope)
        .append_pair("state", "state-security")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("nonce", "nonce-123");
    match authorize.query() {
        Some(query) => format!("{}?{query}", authorize.path()),
        None => authorize.path().to_string(),
    }
}

async fn authorize_with_redirect(
    app: &TestApp,
    redirect_uri: &str,
    scope: &str,
) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::builder()
                .uri(authorize_uri_with(app, redirect_uri, scope))
                .header(
                    header::COOKIE,
                    format!("__Host-re0auth_session={SESSION_RAW}"),
                )
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("authorize")
}

/// 测试内自带第二个 client，不碰 `setup`
async fn insert_second_client(app: &TestApp) -> ClientId {
    let client_id = ClientId::new();
    let now = SystemClock.now();
    app.store
        .clients()
        .insert(
            &Client {
                id: client_id,
                name: "second-client".to_string(),
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
        .expect("second client");
    client_id
}

async fn exchange_code_with(
    app: &TestApp,
    client_id: &ClientId,
    code: &str,
    verifier: &str,
) -> axum::response::Response {
    post_form(
        app,
        token_form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client_id.0.to_string()),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", verifier),
        ]),
    )
    .await
}

#[tokio::test]
async fn authorize_rejects_a_redirect_uri_with_a_suffix() {
    let app = setup().await;
    let response =
        authorize_with_redirect(&app, "https://client.example/callback.evil.com", "openid").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_request");
}

#[tokio::test]
async fn authorize_rejects_a_redirect_uri_with_traversal() {
    let app = setup().await;
    let response =
        authorize_with_redirect(&app, "https://client.example/callback/../evil", "openid").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_request");
}

#[tokio::test]
async fn a_code_is_not_redeemable_by_another_client() {
    let app = setup().await;
    let other_client = insert_second_client(&app).await;
    let code = approve_authorization(&app, "state-cross-client").await;

    let stolen = exchange_code_with(&app, &other_client, &code, VERIFIER).await;
    assert_eq!(stolen.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(stolen).await["error"], "invalid_grant");

    // 失败的兑换不得烧掉 code
    let original = exchange_code(&app, &code).await;
    assert_eq!(original.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_pkce_bound_code_cannot_be_redeemed_with_a_verifier_mismatch() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-pkce").await;
    let wrong = "wrong-verifier-0123456789-0123456789-0123456789-0123";

    let response = exchange_code_with(&app, &app.client_id, &code, wrong).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_grant");

    // 错误 verifier 不得触发重放回收
    let original = exchange_code(&app, &code).await;
    assert_eq!(original.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_scope_outside_the_client_registration_is_invalid_scope() {
    let app = setup().await;
    let response = authorize_with_redirect(&app, REDIRECT_URI, "openid secrets").await;
    // RFC 6749 §4.1.2.1: a valid redirect_uri means the error goes back to the client.
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect");
    assert!(location.contains("error=invalid_scope"), "{location}");
}

async fn ban_user(app: &TestApp) {
    let now = SystemClock.now();
    let fact = re0auth_api::audit::SecurityFact::new(
        re0auth_api::audit::AuditAction::UserBanned,
        now,
        format!("user:{}", app.user_id.0),
    );
    app.store
        .users()
        .set_status(
            &app.user_id,
            re0auth_api::ports::UserStatus::Banned,
            &fact,
            now,
        )
        .await
        .expect("ban user");
}

/// B15: a ban must reach the token issuance paths, not just the session.
#[tokio::test]
async fn a_banned_account_cannot_refresh_or_use_userinfo() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-ban-tokens").await;
    let response = exchange_code(&app, &code).await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = body_json(response).await;
    let refresh = tokens["refresh_token"].as_str().expect("refresh token");
    let access = tokens["access_token"].as_str().expect("access token");

    ban_user(&app).await;

    let refreshed = refresh_tokens(&app, refresh).await;
    assert_eq!(refreshed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(refreshed).await["error"], "invalid_grant");

    let info = userinfo(&app, access).await;
    assert_eq!(info.status(), StatusCode::UNAUTHORIZED);
}

/// B15: an approved device code must not be exchanged after the ban.
#[tokio::test]
async fn a_banned_account_cannot_exchange_an_approved_device_code() {
    let app = setup().await;
    let authorization = start_device(&app).await;
    let user_code = authorization["user_code"].as_str().expect("user code");
    let device_code = authorization["device_code"].as_str().expect("device code");
    admin::approve_device(&app.store, &SystemClock, user_code, app.user_id)
        .await
        .expect("approve device");

    ban_user(&app).await;

    let response = poll_device(&app, device_code).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_grant");
}

/// B15: the admin ban path must cut the existing grants, not just the session.
#[tokio::test]
async fn banning_revokes_the_refresh_family_and_consent() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-ban-revoke").await;
    let tokens = body_json(exchange_code(&app, &code).await).await;
    let refresh = tokens["refresh_token"].as_str().expect("refresh token");

    let now = SystemClock.now();
    let admin_id = UserId::new();
    app.store
        .users()
        .create(&User {
            id: admin_id,
            display_name: "root".to_string(),
            role: UserRole::Admin,
            status: UserStatus::Active,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("admin user");
    let service = re0auth_app::admin_service::AdminService::new(
        Arc::new(app.store.clone()),
        Arc::new(SystemClock),
        Arc::new(OsRandom),
        Arc::new(
            re0auth_adapters::client_secret::HmacClientSecretHasher::new(TEST_MASTER)
                .expect("hasher"),
        ),
    );
    service
        .set_user_status(admin_id, app.user_id, UserStatus::Banned, None)
        .await
        .expect("ban");

    let stored = app
        .store
        .refresh_tokens()
        .find(&hash_secret(refresh))
        .await
        .expect("find refresh token")
        .expect("the refresh row must survive until purge");
    assert!(
        stored.revoked_at.is_some(),
        "the refresh family must be revoked by the ban"
    );
    let consent = app
        .store
        .consents()
        .find(&app.user_id, &app.client_id)
        .await
        .expect("find consent");
    assert!(consent.is_none(), "the consent must be revoked by the ban");
}

/// RFC 6749 §4.1.2 semantics for the device flow: a consumed code replayed by
/// another poller revokes the family the first exchange issued.
#[tokio::test]
async fn replaying_a_device_code_revokes_the_family_it_issued() {
    let app = setup().await;
    let authorization = start_device(&app).await;
    let user_code = authorization["user_code"].as_str().expect("user code");
    let device_code = authorization["device_code"].as_str().expect("device code");
    admin::approve_device(&app.store, &SystemClock, user_code, app.user_id)
        .await
        .expect("approve device");

    let first = poll_device(&app, device_code).await;
    assert_eq!(first.status(), StatusCode::OK);
    let tokens = body_json(first).await;
    let refresh = tokens["refresh_token"].as_str().expect("refresh token");

    let replay = poll_device(&app, device_code).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(replay).await["error"], "invalid_grant");

    let refreshed = refresh_tokens(&app, refresh).await;
    assert_eq!(refreshed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(refreshed).await["error"], "invalid_grant");
}

/// A client that never received the code cannot revoke the family it issued.
#[tokio::test]
async fn a_foreign_client_cannot_revoke_another_clients_family_by_replaying_its_code() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-foreign-replay").await;
    let first = exchange_code(&app, &code).await;
    assert_eq!(first.status(), StatusCode::OK);
    let tokens = body_json(first).await;
    let refresh = tokens["refresh_token"].as_str().expect("refresh token");

    let other = insert_second_client(&app).await;
    let replay = exchange_code_with(&app, &other, &code, VERIFIER).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(replay).await["error"], "invalid_grant");

    // The replay came from a client that never owned the code: the original
    // family must still be alive.
    let refreshed = refresh_tokens(&app, refresh).await;
    assert_eq!(refreshed.status(), StatusCode::OK);
}

/// Deleting an account must not silently drop a live upstream credential when
/// no revocation service is wired (F-6 / INV-ATTACH-05).
#[tokio::test]
async fn deleting_an_account_with_a_live_binding_is_refused() {
    let app = setup().await;
    let now = SystemClock.now();
    app.store
        .bindings()
        .upsert(
            &re0auth_api::ports::Binding {
                id: re0auth_api::BindingId::new(),
                user_id: app.user_id,
                upstream_id: "phigros".to_string(),
                upstream_user_id: "upstream-user".to_string(),
                status: re0auth_api::ports::BindingStatus::Active,
                created_at: now,
                updated_at: now,
                last_refreshed_at: None,
                last_error_code: None,
            },
            &re0auth_api::audit::SecurityFact::new(
                re0auth_api::audit::AuditAction::BindingCreated,
                now,
                "binding",
            ),
        )
        .await
        .expect("binding");

    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/me")
                .header(
                    header::COOKIE,
                    format!("__Host-re0auth_session={SESSION_RAW}"),
                )
                .header("x-csrf-token", "csrf")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("delete account");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = body_json(response).await;
    assert_eq!(body["code"], "bindings_not_revocable");
}

async fn refresh_tokens_with_scope(
    app: &TestApp,
    refresh_token: &str,
    scope: &str,
) -> axum::response::Response {
    post_form(
        app,
        token_form(&[
            ("grant_type", "refresh_token"),
            ("client_id", &app.client_id.0.to_string()),
            ("refresh_token", refresh_token),
            ("scope", scope),
        ]),
    )
    .await
}

/// RFC 6749 §6: an omitted scope keeps the grant, a subset narrows it.
#[tokio::test]
async fn refreshing_with_a_narrower_scope_narrows_the_token() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-refresh-narrow").await;
    let tokens = body_json(exchange_code(&app, &code).await).await;
    let refresh = tokens["refresh_token"].as_str().expect("refresh token");
    assert!(
        tokens["scope"]
            .as_str()
            .unwrap_or_default()
            .contains("profile"),
        "{tokens}"
    );

    let narrowed = refresh_tokens_with_scope(&app, refresh, "openid").await;
    assert_eq!(narrowed.status(), StatusCode::OK);
    let body = body_json(narrowed).await;
    assert_eq!(body["scope"], "openid");

    // The rotated refresh token must carry the narrowed scope too.
    let next = body["refresh_token"]
        .as_str()
        .expect("rotated refresh token");
    let again = body_json(refresh_tokens(&app, next).await).await;
    assert_eq!(again["scope"], "openid");
}

/// RFC 6749 §6: the requested scope must not exceed the original grant.
#[tokio::test]
async fn refreshing_with_a_wider_scope_is_invalid_scope() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-refresh-wide").await;
    let tokens = body_json(exchange_code(&app, &code).await).await;
    let refresh = tokens["refresh_token"].as_str().expect("refresh token");

    let response = refresh_tokens_with_scope(&app, refresh, "openid profile secrets").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_scope");
}

/// OIDC Core §5.3.1: the UserInfo endpoint must accept POST, with the token in
/// the form body (RFC 6750 §2.2).
#[tokio::test]
async fn userinfo_accepts_a_form_token_on_post() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-userinfo-post").await;
    let tokens = body_json(exchange_code(&app, &code).await).await;
    let access = tokens["access_token"].as_str().expect("access token");

    let response = post_form_path(&app, "/userinfo", token_form(&[("access_token", access)])).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert!(
        body["sub"].as_str().is_some_and(|sub| !sub.is_empty()),
        "{body}"
    );
}

/// RFC 6750 §2: a request must not carry the token in more than one place.
#[tokio::test]
async fn userinfo_post_rejects_two_bearer_methods() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-userinfo-both").await;
    let tokens = body_json(exchange_code(&app, &code).await).await;
    let access = tokens["access_token"].as_str().expect("access token");

    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {access}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(token_form(&[("access_token", access)])))
                .expect("request"),
        )
        .await
        .expect("userinfo post");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_request");
}

/// A POST without any token is an authentication failure, not a form error.
#[tokio::test]
async fn userinfo_post_without_a_token_is_unauthorized() {
    let app = setup().await;
    let response = post_form_path(&app, "/userinfo", token_form(&[("access_token", "")])).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(response).await["error"], "invalid_token");
}

/// OIDC Core §3.1.2.1: the authorization endpoint must accept POST as well as GET.
#[tokio::test]
async fn authorize_accepts_a_post_form() {
    let app = setup().await;
    let challenge = pkce::challenge_s256(VERIFIER);
    let form = token_form(&[
        ("response_type", "code"),
        ("client_id", &app.client_id.0.to_string()),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "openid profile"),
        ("state", "state-post"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("nonce", "nonce-123"),
    ]);
    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/authorize")
                .header(
                    header::COOKIE,
                    format!("__Host-re0auth_session={SESSION_RAW}"),
                )
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("request"),
        )
        .await
        .expect("authorize post");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("location");
    assert!(location.starts_with("/consent?"), "{location}");
}

/// An explicitly empty `scope` is malformed, not "no scopes".
#[tokio::test]
async fn refreshing_with_an_empty_scope_is_invalid_scope() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-refresh-empty").await;
    let tokens = body_json(exchange_code(&app, &code).await).await;
    let refresh = tokens["refresh_token"].as_str().expect("refresh token");

    let response = refresh_tokens_with_scope(&app, refresh, "").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_scope");
}

/// OIDC Core §5.4: `name` is a `profile` claim, so an `openid`-only grant must
/// not disclose it.
#[tokio::test]
async fn userinfo_omits_name_without_the_profile_scope() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-userinfo-scope").await;
    let tokens = body_json(exchange_code(&app, &code).await).await;
    let refresh = tokens["refresh_token"].as_str().expect("refresh token");

    let narrowed = refresh_tokens_with_scope(&app, refresh, "openid").await;
    assert_eq!(narrowed.status(), StatusCode::OK);
    let narrowed = body_json(narrowed).await;
    let access_token = narrowed["access_token"].as_str().expect("access token");

    let response = userinfo(&app, access_token).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert!(body.get("sub").is_some(), "{body}");
    assert!(
        body.get("name").is_none(),
        "openid alone must not disclose the profile name: {body}"
    );

    drop(app.key);
}

/// A suspended client must lose its tokens immediately, not at their 15 minute
/// TTL: the status is authoritative on every use.
#[tokio::test]
async fn suspending_a_client_stops_userinfo_and_refresh() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-suspend").await;
    let tokens = body_json(exchange_code(&app, &code).await).await;
    let access_token = tokens["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    let refresh_token = tokens["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_string();

    let response = userinfo(&app, &access_token).await;
    assert_eq!(response.status(), StatusCode::OK);

    app.store
        .clients()
        .set_status(&app.client_id, ClientStatus::Suspended, SystemClock.now())
        .await
        .expect("suspend client");

    let response = userinfo(&app, &access_token).await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "a suspended client's access token must stop working"
    );
    assert_eq!(body_json(response).await["error"], "invalid_token");

    // `refresh` authenticates the client first, so the rejection is
    // `unauthorized_client` rather than `invalid_grant`.
    let response = refresh_tokens(&app, &refresh_token).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "unauthorized_client");

    drop(app.key);
}

struct FailingSigner;

impl TokenSigner for FailingSigner {
    fn sign_access(&self, _: &AccessTokenClaims) -> re0auth_api::Re0Result<String> {
        Err(re0auth_api::Re0Error::Internal(
            "signing failed".to_string(),
        ))
    }
    fn sign_id(&self, _: &IdTokenClaims) -> re0auth_api::Re0Result<String> {
        Err(re0auth_api::Re0Error::Internal(
            "signing failed".to_string(),
        ))
    }
    fn sign_approval_ticket(&self, _: &ApprovalTicketClaims) -> re0auth_api::Re0Result<String> {
        panic!("not used")
    }
    fn verify_access(&self, _: &str) -> re0auth_api::Re0Result<AccessTokenClaims> {
        panic!("not used")
    }
    fn verify_approval_ticket(&self, _: &str) -> re0auth_api::Re0Result<ApprovalTicketClaims> {
        panic!("not used")
    }
    fn jwks(&self) -> String {
        panic!("not used")
    }
}

/// The real store and the failing signer, so a test can prove what the signer
/// failure left behind in durable state.
fn failing_service(app: &TestApp) -> OAuthService {
    OAuthService::new(
        Arc::new(app.store.clone()),
        Arc::new(FailingSigner),
        Arc::new(SystemClock),
        Arc::new(OsRandom),
        Arc::new(
            re0auth_adapters::client_secret::HmacClientSecretHasher::new(TEST_MASTER)
                .expect("hasher"),
        ),
        ISSUER,
    )
}

/// Signing is fallible, so it must run before the rotation claims the old token.
#[tokio::test]
async fn a_signing_failure_does_not_consume_the_refresh_token() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-signer-refresh").await;
    let tokens = body_json(exchange_code(&app, &code).await).await;
    let refresh = tokens["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_string();

    let service = failing_service(&app);
    let result = service
        .refresh(app.client_id, None, &refresh, None, None)
        .await;
    assert!(matches!(result, Err(OAuthError::Internal)), "{result:?}");

    let stored = app
        .store
        .refresh_tokens()
        .find(&hash_secret(&refresh))
        .await
        .expect("find refresh token")
        .expect("refresh token exists");
    assert!(
        stored.consumed_at.is_none(),
        "a signing failure must leave the old refresh token usable"
    );

    // And the real path still rotates it, which it could not if the failed
    // attempt had consumed it or lost its replacement.
    let response = refresh_tokens(&app, &refresh).await;
    assert_eq!(response.status(), StatusCode::OK);

    drop(app.key);
}

/// The code is already consumed at this point, but no unreachable refresh row
/// may be left behind.
#[tokio::test]
async fn a_signing_failure_on_code_exchange_inserts_no_refresh_token() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-signer-code").await;

    let service = failing_service(&app);
    let result = service
        .exchange_code(app.client_id, None, &code, REDIRECT_URI, VERIFIER)
        .await;
    assert!(matches!(result, Err(OAuthError::Internal)), "{result:?}");

    drop(app.key);
}

fn jwt_payload(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("jwt payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64 payload");
    serde_json::from_slice(&bytes).expect("json payload")
}

#[tokio::test]
async fn refresh_family_older_than_absolute_lifetime_is_rejected() {
    let app = setup().await;
    let now = SystemClock.now();
    let long_ago = now - 91 * 24 * 60 * 60;
    app.store
        .consents()
        .grant(
            &Consent {
                id: re0auth_api::ConsentId::new(),
                user_id: app.user_id,
                client_id: app.client_id,
                scopes: vec!["openid".to_string()],
                created_at: long_ago,
                updated_at: long_ago,
                revoked_at: None,
                version: ConsentVersion(0),
            },
            &re0auth_api::audit::SecurityFact::new(
                re0auth_api::audit::AuditAction::ConsentGranted,
                long_ago,
                "consent:absolute-ttl",
            ),
        )
        .await
        .expect("consent");

    let raw = "refresh-family-too-old";
    app.store
        .refresh_tokens()
        .insert(&RefreshToken {
            id: RefreshTokenId::new(),
            token_hash: hash_secret(raw),
            family_id: FamilyId::new(),
            client_id: app.client_id,
            user_id: app.user_id,
            scopes: vec!["openid".to_string()],
            created_at: long_ago,
            family_created_at: long_ago,
            auth_time: long_ago,
            expires_at: now + 3_600,
            consumed_at: None,
            revoked_at: None,
            replaced_by: None,
        })
        .await
        .expect("refresh token");

    let response = refresh_tokens_with_scope(&app, raw, "openid").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_grant");
}

#[tokio::test]
async fn introspection_reports_active_access_and_refresh_tokens() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-introspect").await;
    let tokens = body_json(exchange_code(&app, &code).await).await;
    let access = tokens["access_token"].as_str().expect("access");
    let refresh = tokens["refresh_token"].as_str().expect("refresh");
    let client = app.client_id.0.to_string();

    for (token, expected_type) in [(access, "Bearer"), (refresh, "refresh_token")] {
        let response = post_form_path(
            &app,
            "/oauth/introspect",
            token_form(&[("client_id", &client), ("token", token)]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["active"], true, "{body}");
        assert_eq!(body["token_type"], expected_type, "{body}");
        assert_eq!(body["client_id"], client, "{body}");
        assert_eq!(body["scope"], "openid profile", "{body}");
    }

    // Revoking the refresh family makes both tokens inactive.
    let response = post_form_path(
        &app,
        "/oauth/revoke",
        token_form(&[("client_id", &client), ("token", refresh)]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = post_form_path(
        &app,
        "/oauth/introspect",
        token_form(&[("client_id", &client), ("token", access)]),
    )
    .await;
    assert_eq!(body_json(response).await["active"], false);
}

#[tokio::test]
async fn introspection_requires_a_client_and_hides_foreign_tokens() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-introspect-foreign").await;
    let tokens = body_json(exchange_code(&app, &code).await).await;
    let access = tokens["access_token"].as_str().expect("access");

    let response =
        post_form_path(&app, "/oauth/introspect", token_form(&[("token", access)])).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = post_form_path(
        &app,
        "/oauth/introspect",
        token_form(&[("client_id", "not-a-uuid"), ("token", access)]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn metrics_counts_http_and_token_requests() {
    let app = setup().await;
    let code = approve_authorization(&app, "state-metrics").await;
    let tokens = body_json(exchange_code(&app, &code).await).await;
    assert!(tokens["access_token"].is_string());

    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("metrics");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body = String::from_utf8(body.to_vec()).expect("utf8");
    assert!(body.contains("oauth_token_issued_total"), "{body}");
    assert!(body.contains("grant_type=\"authorization_code\""), "{body}");
    assert!(body.contains("http_requests_total"), "{body}");
    assert!(body.contains("route=\"/oauth/token\""), "{body}");
}
