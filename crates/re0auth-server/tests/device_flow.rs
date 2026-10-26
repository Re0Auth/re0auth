use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use re0auth_adapters::clock::SystemClock;
use re0auth_adapters::crypto::RsaTokenSigner;
use re0auth_adapters::random::OsRandom;
use re0auth_adapters::storage::SqliteStore;
use re0auth_api::ports::{Client, ClientStatus, Storage, User, UserRole};
use re0auth_api::{ClientId, Clock, UserId};
use re0auth_app::admin;
use re0auth_app::auth::AuthService;
use re0auth_app::oauth::OAuthService;
use re0auth_http::{AppState, router};
use serde_json::Value;
use tower::ServiceExt;
use url::form_urlencoded;

const ISSUER: &str = "https://auth.example.com";
const TEST_MASTER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

#[derive(Clone)]
struct TestClock(Arc<AtomicI64>);

impl TestClock {
    fn new(now: i64) -> Self {
        Self(Arc::new(AtomicI64::new(now)))
    }

    fn advance(&self, seconds: i64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

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

struct TestApp {
    router: axum::Router,
    store: SqliteStore,
    clock: TestClock,
    client_id: ClientId,
    user_id: UserId,
    _key: KeyGuard,
}

async fn setup() -> TestApp {
    setup_with_random(Arc::new(OsRandom)).await
}

/// Builds the same app, but with the randomness under the test's control.
///
/// The user code is drawn from the random source, so the only way to reach the
/// collision path on purpose is to script which bytes come back.
async fn setup_with_random(random: Arc<dyn re0auth_api::Random>) -> TestApp {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("SQLite store");
    let clock = TestClock::new(SystemClock.now());
    let key_path =
        std::env::temp_dir().join(format!("re0auth-device-{}.pem", uuid::Uuid::now_v7()));
    let key = KeyGuard(key_path.clone());
    let signer =
        Arc::new(RsaTokenSigner::load_or_generate(&key_path, ISSUER, 1_000, &[]).expect("signer"));
    let clock_arc = Arc::new(clock.clone());
    let oauth = OAuthService::new(
        Arc::new(store.clone()),
        signer.clone(),
        clock_arc.clone(),
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
        clock_arc,
        random,
        ISSUER,
    );

    let now = clock.now();
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
    let client_id = ClientId::new();
    store
        .clients()
        .insert(
            &Client {
                id: client_id,
                name: "device-client".to_string(),
                redirect_uris: vec!["https://client.example/callback".to_string()],
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
                [203, 0, 113, 9],
                4444,
            ))),
        ),
        store,
        clock,
        client_id,
        user_id,
        _key: key,
    }
}

/// Returns one scripted block per `bytes` call, then repeats the last one.
///
/// `device_authorization` draws in a fixed order — 32 bytes for the device code,
/// then 8 per user-code attempt — so scripting the blocks is the only way to
/// reach a collision on purpose. Repeating the last block is what expresses
/// "every further draw produces the same code"; a separate fallback would have
/// silently produced a *different* code and hidden the path under test.
struct ScriptedState {
    queue: std::collections::VecDeque<Vec<u8>>,
    last: Option<Vec<u8>>,
}

struct ScriptedRandom(std::sync::Mutex<ScriptedState>);

impl ScriptedRandom {
    fn shared(blocks: Vec<Vec<u8>>) -> Arc<dyn re0auth_api::Random> {
        Arc::new(Self(std::sync::Mutex::new(ScriptedState {
            queue: blocks.into(),
            last: None,
        })))
    }
}

impl re0auth_api::Random for ScriptedRandom {
    fn bytes(&self, len: usize) -> Vec<u8> {
        let mut state = self.0.lock().expect("lock");
        if let Some(block) = state.queue.pop_front() {
            state.last = Some(block);
        }
        let block = state
            .last
            .as_ref()
            .expect("the script must start with a block");
        (0..len).map(|index| block[index % block.len()]).collect()
    }
}

/// The user code a byte block produces, computed the way production does.
fn code_from(bytes: &[u8]) -> String {
    use re0auth_domain::device::{USER_CODE_ALPHABET, format_user_code};
    let raw: String = bytes
        .iter()
        .map(|byte| USER_CODE_ALPHABET[(byte & 31) as usize] as char)
        .collect();
    format_user_code(&raw)
}

fn stored_user_code(bytes: &[u8]) -> Vec<u8> {
    use re0auth_app::oauth::hash_secret;
    use re0auth_domain::device::normalize_user_code;
    hash_secret(&normalize_user_code(&code_from(bytes)))
}

async fn device_request(app: &TestApp) -> StatusCode {
    let client_id = app.client_id.0.to_string();
    post_form(
        app,
        "/oauth/device_authorization",
        form(&[("client_id", &client_id), ("scope", "openid")]),
    )
    .await
    .status()
}

/// A user code is drawn from a small space and `user_code_hash` is UNIQUE, so a
/// collision is a refused insert. Reporting it as `invalid_request` blamed the
/// client for our bad luck; the code is ours to choose, so it is redrawn.
#[tokio::test]
async fn a_user_code_collision_is_redrawn_rather_than_reported() {
    let first = vec![0x05_u8; 8];
    let second = vec![0x09_u8; 8];
    let random = ScriptedRandom::shared(vec![
        vec![0x11; 32],
        first.clone(),
        vec![0x22; 32],
        // The first draw of the second request repeats the first request's code,
        // which is exactly the collision; the next draw is fresh.
        first.clone(),
        second.clone(),
    ]);
    let app = setup_with_random(random).await;

    assert_eq!(device_request(&app).await, StatusCode::OK);
    assert_eq!(
        device_request(&app).await,
        StatusCode::OK,
        "a collision is ours to absorb, not the client's to see"
    );

    let first_hash = stored_user_code(&first);
    let second_hash = stored_user_code(&second);
    assert_ne!(first_hash, second_hash, "the mock must draw two codes");
    assert!(
        app.store
            .device_codes()
            .find_by_user_code_hash(&first_hash)
            .await
            .expect("lookup")
            .is_some(),
        "the first request's code must still be stored"
    );
    assert!(
        app.store
            .device_codes()
            .find_by_user_code_hash(&second_hash)
            .await
            .expect("lookup")
            .is_some(),
        "the second request must have stored its redrawn code"
    );
}

/// If the code space will not yield, that is our fault. It must not be dressed up
/// as a client error, which is what "exhausted code space" as a 400 used to do.
#[tokio::test]
async fn an_exhausted_code_space_is_a_server_error_not_a_client_error() {
    let collides = vec![0x05_u8; 8];
    // After the first two blocks every draw repeats the colliding code, so all
    // five attempts of the second request collide.
    let random = ScriptedRandom::shared(vec![vec![0x11; 32], collides]);
    let app = setup_with_random(random).await;

    assert_eq!(device_request(&app).await, StatusCode::OK);
    assert_eq!(
        device_request(&app).await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

async fn post_form(app: &TestApp, path: &str, body: String) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("JSON")
}

async fn start_device(app: &TestApp) -> Value {
    let client_id = app.client_id.0.to_string();
    let response = post_form(
        app,
        "/oauth/device_authorization",
        form(&[("client_id", &client_id), ("scope", "openid profile")]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

async fn poll_device(app: &TestApp, device_code: &str) -> axum::response::Response {
    let client_id = app.client_id.0.to_string();
    post_form(
        app,
        "/oauth/token",
        form(&[
            ("grant_type", DEVICE_GRANT),
            ("client_id", &client_id),
            ("device_code", device_code),
        ]),
    )
    .await
}

#[tokio::test]
async fn device_flow_pending_slow_down_approval_and_reuse() {
    let app = setup().await;
    let authorization = start_device(&app).await;
    let device_code = authorization["device_code"].as_str().unwrap();
    let user_code = authorization["user_code"].as_str().unwrap();
    assert_eq!(authorization["interval"], 5);
    assert!(
        authorization["verification_uri_complete"]
            .as_str()
            .unwrap()
            .contains(user_code)
    );

    let pending = poll_device(&app, device_code).await;
    assert_eq!(pending.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(pending).await["error"], "authorization_pending");

    let slow = poll_device(&app, device_code).await;
    assert_eq!(slow.status(), StatusCode::BAD_REQUEST);
    let slow_body = body_json(slow).await;
    assert_eq!(slow_body["error"], "slow_down");
    assert_eq!(slow_body["interval"], 10);

    app.clock.advance(11);
    admin::approve_device(&app.store, &app.clock, user_code, app.user_id)
        .await
        .expect("approve");

    let approved = poll_device(&app, device_code).await;
    assert_eq!(approved.status(), StatusCode::OK);
    let tokens = body_json(approved).await;
    let access_token = tokens["access_token"].as_str().unwrap();
    assert!(!access_token.is_empty());
    assert!(tokens["refresh_token"].as_str().is_some());

    let consent = app
        .store
        .consents()
        .find(&app.user_id, &app.client_id)
        .await
        .expect("consent lookup")
        .expect("a device token must create a consent record");
    assert_eq!(
        consent.scopes,
        vec!["openid".to_string(), "profile".to_string()]
    );
    assert_eq!(consent.version, re0auth_api::oauth::ConsentVersion(1));

    let userinfo = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(userinfo.status(), StatusCode::OK);
    assert_eq!(body_json(userinfo).await["name"], "Alice");

    let reused = poll_device(&app, device_code).await;
    assert_eq!(reused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(reused).await["error"], "invalid_grant");
}

#[tokio::test]
async fn device_flow_denied_and_expired() {
    let app = setup().await;

    let denied = start_device(&app).await;
    let denied_device = denied["device_code"].as_str().unwrap();
    let denied_user = denied["user_code"].as_str().unwrap();
    admin::deny_device(&app.store, &app.clock, denied_user)
        .await
        .expect("deny");
    let response = poll_device(&app, denied_device).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "access_denied");

    let expired = start_device(&app).await;
    let expired_device = expired["device_code"].as_str().unwrap();
    app.clock.advance(601);
    let response = poll_device(&app, expired_device).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "expired_token");
}
