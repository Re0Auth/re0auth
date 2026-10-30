//! The admin HTTP surface (B1).
//!
//! Covers the rules that make the surface safe — admin-only, CSRF on every
//! write, one-time secrets — plus the audit correlation, because those are the
//! properties a refactor is most likely to quietly drop.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::body::{Body, to_bytes};
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use re0auth_adapters::client_secret::HmacClientSecretHasher;
use re0auth_adapters::clock::SystemClock;
use re0auth_adapters::crypto::RsaTokenSigner;
use re0auth_adapters::random::OsRandom;
use re0auth_adapters::storage::SqliteStore;
use re0auth_api::ports::{Storage, User, UserRole};
use re0auth_api::secret::ClientSecretHasher;
use re0auth_api::{Clock, UserId};
use re0auth_app::admin_service::AdminService;
use re0auth_app::auth::AuthService;
use re0auth_app::oauth::OAuthService;
use re0auth_http::{AppState, router};
use serde_json::{Value, json};
use tower::ServiceExt;

const ISSUER: &str = "https://auth.example.com";
const TEST_MASTER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Clone)]
struct TestClock(Arc<AtomicI64>);

impl Clock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct KeyGuard(PathBuf);

impl Drop for KeyGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct App {
    router: axum::Router,
    admin_id: UserId,
    user_id: UserId,
    admin_cookie: String,
    admin_csrf: String,
    user_cookie: String,
    _key: KeyGuard,
}

async fn app() -> App {
    let clock = TestClock(Arc::new(AtomicI64::new(SystemClock.now())));
    let key_path = std::env::temp_dir().join(format!("re0auth-admin-{}.pem", uuid::Uuid::now_v7()));
    let key = KeyGuard(key_path.clone());
    let signer =
        Arc::new(RsaTokenSigner::load_or_generate(&key_path, ISSUER, 1_000, &[]).expect("signer"));
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("store");
    let now = clock.now();

    let admin_id = UserId::new();
    store
        .users()
        .create(&User {
            id: admin_id,
            display_name: "Root".to_string(),
            role: UserRole::Admin,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("admin");
    let user_id = UserId::new();
    store
        .users()
        .create(&User {
            id: user_id,
            display_name: "Member".to_string(),
            role: UserRole::User,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("user");

    // The same hasher serves the OAuth engine and client-secret creation, so a
    // rotated secret verifies against exactly what issued it.
    let hasher: Arc<dyn ClientSecretHasher> =
        Arc::new(HmacClientSecretHasher::new(TEST_MASTER).expect("hasher"));
    let oauth = OAuthService::new(
        Arc::new(store.clone()),
        signer.clone(),
        Arc::new(clock.clone()),
        Arc::new(OsRandom),
        Arc::clone(&hasher),
        ISSUER,
    );
    let auth = AuthService::new(
        Arc::new(store.clone()),
        vec![],
        signer,
        Arc::new(clock.clone()),
        Arc::new(OsRandom),
        ISSUER,
    );
    let admin = AdminService::new(
        Arc::new(store.clone()),
        Arc::new(clock.clone()),
        Arc::new(OsRandom),
        hasher,
    );

    let (admin_cookie, admin_csrf) = session(&store, &clock, admin_id).await;
    let (user_cookie, _) = session(&store, &clock, user_id).await;

    let state = AppState::new(oauth, auth).with_admin(Arc::new(admin));
    App {
        router: router(state).layer(MockConnectInfo(SocketAddr::from(([203, 0, 113, 7], 4444)))),
        admin_id,
        user_id,
        admin_cookie,
        admin_csrf,
        user_cookie,
        _key: key,
    }
}

async fn session(store: &SqliteStore, clock: &TestClock, user: UserId) -> (String, String) {
    let created = re0auth_app::admin::create_session(store, clock, &OsRandom, user)
        .await
        .expect("session");
    (
        format!(
            "__Host-re0auth_session={}; __Host-re0auth_csrf={}",
            created.cookie, created.csrf_token
        ),
        created.csrf_token,
    )
}

async fn send(
    app: &App,
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    csrf: Option<&str>,
    request_id: Option<&str>,
    body: Option<&Value>,
) -> (StatusCode, Value, HeaderMap) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-csrf-token", csrf);
    }
    if let Some(id) = request_id {
        builder = builder.header("x-request-id", id);
    }
    let body = match body {
        None => Body::empty(),
        Some(value) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(value).expect("json"))
        }
    };
    let response = app
        .router
        .clone()
        .oneshot(builder.body(body).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let text = String::from_utf8_lossy(&bytes).to_string();
    let value = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, value, headers)
}

async fn get(app: &App, uri: &str, cookie: &str) -> (StatusCode, Value) {
    let (status, body, _) = send(app, Method::GET, uri, Some(cookie), None, None, None).await;
    (status, body)
}

async fn write(
    app: &App,
    method: Method,
    uri: &str,
    csrf: Option<&str>,
    request_id: Option<&str>,
    body: Option<&Value>,
) -> (StatusCode, Value, HeaderMap) {
    send(
        app,
        method,
        uri,
        Some(&app.admin_cookie),
        csrf,
        request_id,
        body,
    )
    .await
}

#[tokio::test]
async fn admin_routes_require_an_admin_session() {
    let app = app().await;

    // No session at all: 401, so a client knows to log in.
    let (status, body, _) = send(
        &app,
        Method::GET,
        "/api/admin/clients",
        None,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "login_required");

    // A logged-in member is refused with 403: logging in again cannot help.
    let (status, body) = get(&app, "/api/admin/clients", &app.user_cookie).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "forbidden");

    // Authentication runs before CSRF, so an anonymous write is still a 401.
    let (status, body, _) = send(
        &app,
        Method::POST,
        "/api/admin/clients",
        None,
        None,
        None,
        Some(&json!({"name": "bot"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "login_required");
}

#[tokio::test]
async fn writes_require_csrf_and_bad_queries_are_bad_requests() {
    let app = app().await;

    let (status, body, _) = write(
        &app,
        Method::POST,
        "/api/admin/clients",
        None,
        None,
        Some(&json!({"name": "bot"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "invalid_csrf");

    let (status, body, _) = send(
        &app,
        Method::GET,
        "/api/admin/audit?cursor=not-a-uuid",
        Some(&app.admin_cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_request");

    let (status, body, _) = send(
        &app,
        Method::GET,
        "/api/admin/audit?action=nonsense",
        Some(&app.admin_cookie),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_request");
}

#[tokio::test]
async fn creating_a_client_returns_the_secret_once_and_links_it() {
    let app = app().await;
    let (status, created, headers) = write(
        &app,
        Method::POST,
        "/api/admin/clients",
        Some(&app.admin_csrf),
        Some("test-create-1"),
        Some(&json!({
            "name": "bot",
            "redirect_uris": ["https://bot.example/cb"],
            "allowed_scopes": ["openid"],
            "confidential": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {created}");
    let id = created["id"].as_str().expect("id").to_string();
    let secret = created["secret"].as_str().expect("secret").to_string();
    assert!(!secret.is_empty());
    let location = headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("Location");
    assert_eq!(location, format!("/api/admin/clients/{id}"));

    // The list shows the secret exists, never the secret.
    let (status, list) = get(&app, "/api/admin/clients", &app.admin_cookie).await;
    assert_eq!(status, StatusCode::OK);
    let item = &list["items"][0];
    assert_eq!(item["id"], id);
    assert_eq!(item["has_secret"], true);
    assert_eq!(
        item["status"], "pending",
        "a fresh client is not usable yet"
    );
    assert!(
        item.get("secret").is_none(),
        "the list must never carry the secret: {item}"
    );

    // Rotation returns a different secret, exactly once.
    let (status, rotated, _) = write(
        &app,
        Method::POST,
        &format!("/api/admin/clients/{id}/rotate-secret"),
        Some(&app.admin_csrf),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(rotated["secret"], secret);

    // The create fact carries the request id the caller sent.
    let (status, audit) = get(
        &app,
        "/api/admin/audit?action=client_created",
        &app.admin_cookie,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let fact = &audit["items"][0];
    assert_eq!(fact["action"], "client_created");
    assert_eq!(fact["request_id"], "test-create-1");
    assert_eq!(fact["actor_user_id"], app.admin_id.0.to_string());
}

#[tokio::test]
async fn the_last_admin_cannot_be_demoted_but_a_member_can_be_promoted() {
    let app = app().await;

    let (status, body, _) = write(
        &app,
        Method::PATCH,
        &format!("/api/admin/users/{}", app.admin_id.0),
        Some(&app.admin_csrf),
        None,
        Some(&json!({"role": "user"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "conflict");

    let (status, body, _) = write(
        &app,
        Method::PATCH,
        &format!("/api/admin/users/{}", app.user_id.0),
        Some(&app.admin_csrf),
        None,
        Some(&json!({"role": "admin"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["role"], "admin");
}

#[tokio::test]
async fn connectors_are_read_only_and_use_the_shared_envelope() {
    let app = app().await;

    let (status, body) = get(&app, "/api/admin/connectors", &app.admin_cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"], json!([]));
    assert!(body["next_cursor"].is_null());

    // No write route exists: configuration is the source of truth.
    let (status, _, _) = write(
        &app,
        Method::POST,
        "/api/admin/connectors",
        Some(&app.admin_csrf),
        None,
        Some(&json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}
