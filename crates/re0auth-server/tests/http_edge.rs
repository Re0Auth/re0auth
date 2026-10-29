//! Malformed-input coverage for the HTTP edge.
//!
//! Every request here is deliberately wrong: missing fields, non-UUID ids,
//! wrong grant types, replayed or absent CSRF tokens, unknown device codes. The
//! point is to pin down *which* refusal each one gets, so an error path cannot
//! silently degrade into a 500 or, worse, a success.

use std::net::SocketAddr;

use std::path::PathBuf;

use std::sync::Arc;

use std::sync::atomic::{AtomicI64, Ordering};

use axum::body::{Body, to_bytes};

use axum::extract::connect_info::MockConnectInfo;

use axum::http::{Method, Request, StatusCode, header};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use re0auth_adapters::client_secret::HmacClientSecretHasher;
use re0auth_adapters::clock::SystemClock;
use re0auth_api::secret::ClientSecretHasher;

use re0auth_adapters::crypto::RsaTokenSigner;

use re0auth_adapters::random::OsRandom;

use re0auth_adapters::storage::SqliteStore;

use re0auth_api::ports::{Client, ClientStatus, Storage, User, UserRole};

use re0auth_api::{ClientId, Clock, UserId};

use re0auth_app::auth::AuthService;

use re0auth_app::oauth::OAuthService;

use re0auth_http::{AppState, router};
use serde_json::Value;

use tower::ServiceExt;

use url::form_urlencoded;

const ISSUER: &str = "https://auth.example.com";

const TEST_MASTER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const GOOD_SCOPE: &str = "openid";

#[derive(Clone)]
struct TestClock(Arc<AtomicI64>);

impl TestClock {
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

struct App {
    router: axum::Router,
    store: SqliteStore,
    clock: TestClock,
    client_id: ClientId,
    user_id: UserId,
    /// A confidential client, plus the raw secret (never stored).
    confidential: ConfidentialClient,
    _key: KeyGuard,
}

struct ConfidentialClient {
    id: ClientId,
    secret: String,
}

impl ConfidentialClient {
    fn basic_header(&self) -> String {
        let raw = format!("{}:{}", self.id.0, self.secret);
        format!("Basic {}", BASE64.encode(raw))
    }
}

const CONFIDENTIAL_SECRET: &str = "confidential-secret-value";

async fn app() -> App {
    build_app(1024 * 1024).await
}

/// Seeds the consent a directly-inserted auth code would have received from the
/// real approval flow. The edge tests skip the consent page on purpose; without
/// this row the code exchange is correctly refused by the consent gate.
async fn grant_consent(app: &App, client_id: ClientId, scopes: &[&str]) {
    let now = app.clock.now();
    app.store
        .consents()
        .grant(
            &re0auth_api::ports::Consent {
                id: re0auth_api::ConsentId::new(),
                user_id: app.user_id,
                client_id,
                scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
                created_at: now,
                updated_at: now,
                revoked_at: None,
                version: re0auth_api::oauth::ConsentVersion(0),
            },
            &re0auth_api::audit::SecurityFact::new(
                re0auth_api::audit::AuditAction::ConsentGranted,
                now,
                "consent:test",
            ),
        )
        .await
        .expect("grant consent");
}

async fn build_app(inbound_body: usize) -> App {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("SQLite store");
    build(store, inbound_body).await
}

/// Builds a fresh app over an existing store. The in-memory per-IP buckets live
/// in `AuthService`, so this models a restart: the database survives, the
/// in-memory counters do not. That difference is what the persistent per-code
/// counter exists for.
async fn build(store: SqliteStore, inbound_body: usize) -> App {
    build_with_limiter(store, inbound_body, Arc::new(re0auth_api::rate::Unlimited)).await
}

/// Builds the same app but with a real limiter, so the 429 path is exercised
/// end to end rather than by calling the limiter directly.
async fn build_with_limiter(
    store: SqliteStore,
    inbound_body: usize,
    rate: Arc<dyn re0auth_api::rate::RateLimiter>,
) -> App {
    build_with(store, inbound_body, move |_| Arc::clone(&rate)).await
}

fn strict_limiter(clock: &TestClock, burst: u32) -> Arc<dyn re0auth_api::rate::RateLimiter> {
    Arc::new(re0auth_adapters::rate_limit::GovernorLimiter::new(
        re0auth_adapters::rate_limit::RateLimitPolicy {
            unauthenticated: re0auth_adapters::rate_limit::LaneQuota {
                burst,
                period_secs: 60,
            },
            authenticated: re0auth_adapters::rate_limit::LaneQuota {
                burst,
                period_secs: 60,
            },
            // Same budget as the client lane: the client lane is charged first,
            // so a single caller still trips that ceiling first and the existing
            // expectations are unchanged.
            per_user: re0auth_adapters::rate_limit::LaneQuota {
                burst,
                period_secs: 60,
            },
        },
        Arc::new(clock.clone()),
    ))
}

/// Builds an app whose limiter is created from the app's own clock and allows
/// `burst` requests per minute on every lane.
async fn app_with_strict_limits(burst: u32) -> App {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("SQLite store");
    build_with(store, 1024 * 1024, move |clock| {
        strict_limiter(clock, burst)
    })
    .await
}

/// The limiter is built from the app's own clock, which only exists inside this
/// function. Building it before that point would give the test a limiter on a
/// different clock, and the time-travel tests would pass for the wrong reason.
async fn build_with<F>(store: SqliteStore, inbound_body: usize, make_rate: F) -> App
where
    F: Fn(&TestClock) -> Arc<dyn re0auth_api::rate::RateLimiter>,
{
    let clock = TestClock(Arc::new(AtomicI64::new(SystemClock.now())));
    let key_path = std::env::temp_dir().join(format!("re0auth-edge-{}.pem", uuid::Uuid::now_v7()));
    let key = KeyGuard(key_path.clone());
    let signer =
        Arc::new(RsaTokenSigner::load_or_generate(&key_path, ISSUER, 1_000, &[]).expect("signer"));
    let now = clock.now();

    let user_id = UserId::new();
    store
        .users()
        .create(&User {
            id: user_id,
            display_name: "Edge".to_string(),
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
                name: "edge-client".to_string(),
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

    let hasher = HmacClientSecretHasher::new(TEST_MASTER).expect("hasher");
    let confidential = ConfidentialClient {
        id: ClientId::new(),
        secret: CONFIDENTIAL_SECRET.to_string(),
    };
    store
        .clients()
        .insert(
            &Client {
                id: confidential.id,
                name: "edge-confidential".to_string(),
                redirect_uris: vec!["https://client.example/callback".to_string()],
                allowed_scopes: vec!["openid".to_string(), "profile".to_string()],
                raw_access: false,
                status: ClientStatus::Approved,
                secret_hash: Some(hasher.hash(CONFIDENTIAL_SECRET).expect("hash")),
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
        .expect("confidential client");

    let oauth = OAuthService::new(
        Arc::new(store.clone()),
        signer.clone(),
        Arc::new(clock.clone()),
        Arc::new(OsRandom),
        Arc::new(
            re0auth_adapters::client_secret::HmacClientSecretHasher::new(TEST_MASTER).unwrap(),
        ),
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

    let state = AppState::new(oauth, auth)
        .with_rate_limiter(make_rate(&clock))
        .with_inbound_body_bytes(inbound_body);

    App {
        router: router(state).layer(MockConnectInfo(SocketAddr::from(([203, 0, 113, 7], 4444)))),
        store,
        clock,
        client_id,
        user_id,
        confidential,
        _key: key,
    }
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

async fn send(app: &App, request: Request<Body>) -> (StatusCode, String, Option<String>) {
    let response = app.router.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        String::from_utf8_lossy(&bytes).to_string(),
        location,
    )
}

async fn get(app: &App, uri: &str) -> (StatusCode, String, Option<String>) {
    send(
        app,
        Request::builder().uri(uri).body(Body::empty()).unwrap(),
    )
    .await
}

// ------------------------------------------------------------ request id (§9)

async fn request_id_of(app: &App, supplied: Option<&str>) -> String {
    let mut builder = Request::builder().uri("/healthz");
    if let Some(id) = supplied {
        builder = builder.header("x-request-id", id);
    }
    let response = app
        .router
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .expect("response");
    response
        .headers()
        .get("x-request-id")
        .expect("every response must carry x-request-id")
        .to_str()
        .expect("ascii")
        .to_string()
}

#[tokio::test]
async fn every_response_carries_a_request_id() {
    // `API-SURFACE.md` §9 promises this unconditionally; a response without it
    // cannot be correlated with the audit row.
    let app = app().await;
    let generated = request_id_of(&app, None).await;
    assert!(!generated.is_empty());
    // Two requests must not share an id, or correlation would be meaningless.
    let second = request_id_of(&app, None).await;
    assert_ne!(generated, second);
}

#[tokio::test]
async fn a_caller_supplied_request_id_is_echoed() {
    let app = app().await;
    assert_eq!(
        request_id_of(&app, Some("req-abc-123")).await,
        "req-abc-123"
    );
}

#[tokio::test]
async fn a_malformed_request_id_is_replaced_not_echoed() {
    // Echoing an unvalidated value would let a caller place arbitrary bytes in a
    // response header, which log collectors treat as data.
    let app = app().await;
    let echoed = request_id_of(&app, Some("bad id with spaces")).await;
    assert_ne!(echoed, "bad id with spaces");
    assert!(!echoed.is_empty(), "a replacement id must still be issued");
}

#[tokio::test]
async fn a_malformed_request_id_does_not_fail_the_request() {
    // The header is a diagnostic aid. Rejecting a request over it would turn
    // observability into an availability problem.
    let app = app().await;
    let (status, _, _) = send(
        &app,
        Request::builder()
            .uri("/healthz")
            .header("x-request-id", "bad id with spaces")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

async fn get_with_cookie(
    app: &App,
    uri: &str,
    cookie: &str,
) -> (StatusCode, String, Option<String>) {
    send(
        app,
        Request::builder()
            .uri(uri)
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

async fn post(app: &App, uri: &str, body: String) -> (StatusCode, String, Option<String>) {
    send(
        app,
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

async fn post_with_headers(
    app: &App,
    uri: &str,
    body: String,
    headers: &[(&str, &str)],
) -> (StatusCode, String, Option<String>) {
    let mut builder = Request::builder().method("POST").uri(uri);
    // A caller-supplied content type must replace the form default, not duplicate
    // it: axum reads the first value and would otherwise see a stale header.
    let has_content_type = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-type"));
    if !has_content_type {
        builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    send(app, builder.body(Body::from(body)).unwrap()).await
}

/// The stable error code, whichever shape the lane answers with.
///
/// RFC 6749 calls the member `error` and RFC 9457 carries it as the `code`
/// extension. Both lanes publish the same identifiers, so a helper that read one
/// spelling would read an empty string for the other lane's endpoints.
fn error_code(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            value["code"]
                .as_str()
                .or_else(|| value["error"].as_str())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| format!("<no error field: {body}>"))
}

/// The session and gateway lanes answer RFC 9457; the OAuth endpoints do not.
/// A 401 from `/api/me` is the cheapest way to see the session lane's shape.
#[tokio::test]
async fn the_session_lane_answers_problem_json() {
    let app = build_app(64 * 1024).await;
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/me")
        .body(Body::empty())
        .expect("request");
    let (status, body, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let json: Value = serde_json::from_str(&body).expect("a JSON body");
    assert_eq!(json["type"], "about:blank");
    assert_eq!(json["status"], 401);
    assert_eq!(json["code"], "login_required");
    assert!(
        json["title"].is_string() && json["detail"].is_string(),
        "the registered members must be present: {body}"
    );
}

fn assert_api(status: StatusCode, body: &str, expected_status: StatusCode, expected: &str) {
    assert_eq!(status, expected_status, "body: {body}");
    assert_eq!(error_code(body), expected, "body: {body}");
}

// ---------------------------------------------------------------- authorize

#[tokio::test]
async fn authorize_rejects_every_malformed_query() {
    let app = app().await;
    let client = app.client_id.0.to_string();
    let redirect = "https%3A%2F%2Fclient.example%2Fcallback";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    // response_type must be `code`.
    for response_type in ["", "token", "CODE"] {
        let uri = format!(
            "/oauth/authorize?response_type={response_type}&client_id={client}&redirect_uri={redirect}&scope=openid&code_challenge={challenge}&code_challenge_method=S256"
        );
        let (status, body, _) = get(&app, &uri).await;
        assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_request");
    }

    // code_challenge_method must be S256.
    for method in ["", "plain", "s256"] {
        let uri = format!(
            "/oauth/authorize?response_type=code&client_id={client}&redirect_uri={redirect}&scope=openid&code_challenge={challenge}&code_challenge_method={method}"
        );
        let (status, body, _) = get(&app, &uri).await;
        assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_request");
    }

    // client_id: absent, empty, and non-UUID all fail before any session work.
    for client_param in ["", "&client_id=", "&client_id=not-a-uuid"] {
        let uri = format!(
            "/oauth/authorize?response_type=code{client_param}&redirect_uri={redirect}&scope=openid&code_challenge={challenge}&code_challenge_method=S256"
        );
        let (status, body, _) = get(&app, &uri).await;
        assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_request");
    }

    // redirect_uri missing.
    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={client}&scope=openid&code_challenge={challenge}&code_challenge_method=S256"
    );
    let (status, body, _) = get(&app, &uri).await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_request");

    // code_challenge missing or empty.
    for challenge_param in ["", "&code_challenge="] {
        let uri = format!(
            "/oauth/authorize?response_type=code&client_id={client}&redirect_uri={redirect}&scope=openid{challenge_param}&code_challenge_method=S256"
        );
        let (status, body, _) = get(&app, &uri).await;
        assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_request");
    }

    // No scope at all is an invalid_scope, not an invalid_request.
    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={client}&redirect_uri={redirect}&code_challenge={challenge}&code_challenge_method=S256"
    );
    let (status, body, _) = get(&app, &uri).await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_scope");
}

#[tokio::test]
async fn authorize_without_a_session_redirects_to_login() {
    let app = app().await;
    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
        app.client_id.0
    );
    let (status, _, location) = get(&app, &uri).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("redirect");
    assert!(location.starts_with("/login?return_to="), "{location}");
    assert!(
        location.contains("scope%3Dopenid"),
        "query is preserved: {location}"
    );
}

#[tokio::test]
async fn authorize_with_a_bogus_session_cookie_redirects_to_login() {
    let app = app().await;
    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
        app.client_id.0
    );
    let (status, _, location) = get_with_cookie(&app, &uri, "re0auth_session=forged").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.expect("redirect").starts_with("/login?"));
}

// ------------------------------------------------------- device_authorization

#[tokio::test]
async fn device_authorization_rejects_malformed_forms() {
    let app = app().await;
    let client = app.client_id.0.to_string();

    for body in [
        form(&[("scope", GOOD_SCOPE)]),
        form(&[("client_id", ""), ("scope", GOOD_SCOPE)]),
        form(&[("client_id", "not-a-uuid"), ("scope", GOOD_SCOPE)]),
    ] {
        let (status, payload, _) = post(&app, "/oauth/device_authorization", body).await;
        assert_api(status, &payload, StatusCode::BAD_REQUEST, "invalid_request");
    }

    for body in [
        form(&[("client_id", &client)]),
        form(&[("client_id", &client), ("scope", "")]),
        form(&[("client_id", &client), ("scope", "   ")]),
    ] {
        let (status, payload, _) = post(&app, "/oauth/device_authorization", body).await;
        assert_api(status, &payload, StatusCode::BAD_REQUEST, "invalid_scope");
    }
}

// -------------------------------------------------------------------- token

#[tokio::test]
async fn token_rejects_unknown_and_incomplete_grants() {
    let app = app().await;
    let client = app.client_id.0.to_string();

    let (status, body, _) = post(&app, "/oauth/token", form(&[("client_id", &client)])).await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_request");

    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[("client_id", &client), ("grant_type", "magic")]),
    )
    .await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_request");

    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[("client_id", "not-a-uuid"), ("grant_type", "refresh_token")]),
    )
    .await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_request");

    // authorization_code: each required field is enforced independently.
    for missing in ["code", "redirect_uri", "code_verifier"] {
        let mut pairs = vec![
            ("client_id", client.as_str()),
            ("grant_type", "authorization_code"),
            ("code", "abc"),
            ("redirect_uri", "https://client.example/callback"),
            ("code_verifier", "verifier"),
        ];
        pairs.retain(|(key, _)| *key != missing);
        let (status, body, _) = post(&app, "/oauth/token", form(&pairs)).await;
        assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_request");
    }

    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[("client_id", &client), ("grant_type", "refresh_token")]),
    )
    .await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_request");

    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[
            ("client_id", client.as_str()),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ]),
    )
    .await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_request");
}

#[tokio::test]
async fn token_rejects_unknown_credentials_without_leaking_which_part_failed() {
    let app = app().await;
    let client = app.client_id.0.to_string();

    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[
            ("client_id", &client),
            ("grant_type", "refresh_token"),
            ("refresh_token", "not-a-real-token"),
        ]),
    )
    .await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_grant");

    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[
            ("client_id", &client),
            ("grant_type", "authorization_code"),
            ("code", "not-a-real-code"),
            ("redirect_uri", "https://client.example/callback"),
            (
                "code_verifier",
                "verifier-0123456789-0123456789-0123456789-0123456789",
            ),
        ]),
    )
    .await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_grant");

    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[
            ("client_id", &client),
            ("grant_type", "authorization_code"),
            ("code", "not-a-real-code"),
            ("redirect_uri", "https://client.example/callback"),
            ("code_verifier", "too-short"),
        ]),
    )
    .await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_request");

    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[
            ("client_id", &client),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", "not-a-real-device-code"),
        ]),
    )
    .await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_grant");
}

// ----------------------------------------------------------------- callback

#[tokio::test]
async fn callback_rejects_provider_errors_and_missing_parameters() {
    let app = app().await;

    for query in [
        "error=access_denied",
        "error=server_error&error_description=x",
    ] {
        let (status, body, _) = get(&app, &format!("/auth/callback?{query}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
        assert!(body.contains("登录未完成"), "{body}");
    }

    let (status, _, _) = get(&app, "/auth/callback?state=abc").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "code is required");

    let (status, _, _) = get(&app, "/auth/callback?code=abc").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "state is required");

    // With both parameters present and a matching intent cookie the request
    // reaches the exchange, and this fixture has no IdP: the refusal is honest
    // rather than a silent success.
    let (status, _, location) = get_with_cookie(
        &app,
        "/auth/callback?code=abc&state=unknown",
        "re0auth_login=unknown",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    // The callback must never hand out a session on a failed exchange.
    assert!(location.is_none());
}

// ------------------------------------------------------------- session APIs

#[tokio::test]
async fn session_endpoints_require_a_cookie_and_csrf() {
    let app = app().await;

    for uri in ["/api/me", "/api/me/authorizations"] {
        let (status, body, _) = get(&app, uri).await;
        assert_api(status, &body, StatusCode::UNAUTHORIZED, "login_required");
    }

    for uri in ["/api/logout", "/api/logout-all"] {
        let (status, body, _) = post(&app, uri, String::new()).await;
        assert_api(status, &body, StatusCode::UNAUTHORIZED, "login_required");
    }

    // A forged session cookie is not a session.
    let (status, body, _) = get_with_cookie(&app, "/api/me", "re0auth_session=forged").await;
    assert_api(status, &body, StatusCode::UNAUTHORIZED, "login_required");

    // Malformed cookies must not be parsed leniently into a session.
    for cookie in [
        "re0auth_session",
        "re0auth_session=",
        "=;re0auth_session",
        "foo=bar",
    ] {
        let (status, body, _) = get_with_cookie(&app, "/api/me", cookie).await;
        assert_api(status, &body, StatusCode::UNAUTHORIZED, "login_required");
    }
}

#[tokio::test]
async fn revoke_authorization_rejects_non_uuid_paths() {
    let app = app().await;
    for path in [
        "not-a-uuid",
        "..",
        "%2e%2e",
        "00000000-0000-0000-0000-00000000000",
    ] {
        let (status, body, _) = send(
            &app,
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/me/authorizations/{path}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        // No session: the auth check fires first, and that is the correct order.
        assert_api(status, &body, StatusCode::UNAUTHORIZED, "login_required");
    }
}

// --------------------------------------------------------------- device pages

#[tokio::test]
async fn device_start_and_qr_reject_missing_or_unknown_codes() {
    let app = app().await;

    // A missing parameter is refused before any lookup.
    for uri in ["/device/start", "/device/qr.svg"] {
        let (status, body, _) = get(&app, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert!(body.contains("无法处理设备授权"), "{uri}: {body}");
    }

    // An explicitly empty code is treated as present and reaches the lookup.
    for uri in ["/device/start?user_code=", "/device/qr.svg?user_code="] {
        let (status, body, _) = get(&app, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert!(body.contains("登录未完成"), "{uri}: {body}");
    }

    // A syntactically wrong code is rejected without revealing whether it exists.
    for code in [
        "ZZZZ-ZZZZ",
        "1234",
        "../../etc/passwd",
        "'; DROP TABLE users; --",
    ] {
        let uri = format!("/device/qr.svg?{}", form(&[("user_code", code)]));
        let (status, body, _) = get(&app, &uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{code}");
        assert!(body.contains("登录未完成"), "{code}: {body}");
    }
}

#[tokio::test]
async fn device_start_locks_out_repeated_failures() {
    let app = app().await;
    let bad = format!("/device/start?{}", form(&[("user_code", "ZZZZ-ZZZZ")]));

    let mut last = StatusCode::BAD_REQUEST;
    for _ in 0..6 {
        let (status, _, _) = get(&app, &bad).await;
        last = status;
    }
    assert_eq!(
        last,
        StatusCode::TOO_MANY_REQUESTS,
        "the sixth failed attempt must be rate limited"
    );

    // The lockout is scoped to the peer, so a correct code from the same peer is
    // also refused while the bucket is exhausted.
    let device = post(
        &app,
        "/oauth/device_authorization",
        form(&[
            ("client_id", &app.client_id.0.to_string()),
            ("scope", GOOD_SCOPE),
        ]),
    )
    .await;
    assert_eq!(device.0, StatusCode::OK);
    let payload: Value = serde_json::from_str(&device.1).expect("json");
    let user_code = payload["user_code"].as_str().expect("user code");
    let (status, _, _) = get(
        &app,
        &format!("/device/start?{}", form(&[("user_code", user_code)])),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "lockout is per peer");
}

#[tokio::test]
async fn device_decision_requires_a_live_ticket() {
    let app = app().await;

    for path in ["/device/approve", "/device/deny"] {
        let (status, body, _) = post(&app, path, form(&[("ticket", "")])).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        assert!(body.contains("登录未完成"), "{path}: {body}");

        let (status, body, _) = post(&app, path, form(&[("ticket", "forged-ticket")])).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        assert!(body.contains("登录未完成"), "{path}: {body}");

        let (status, _, _) = post(&app, path, String::new()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: no ticket field");
    }
}

#[tokio::test]
async fn device_ticket_cannot_be_replayed() {
    let app = app().await;
    let device = post(
        &app,
        "/oauth/device_authorization",
        form(&[
            ("client_id", &app.client_id.0.to_string()),
            ("scope", GOOD_SCOPE),
        ]),
    )
    .await;
    assert_eq!(device.0, StatusCode::OK);
    let payload: Value = serde_json::from_str(&device.1).expect("json");
    assert!(payload["user_code"].as_str().is_some());

    // Without an IdP there is no way to mint a real ticket, so this pins the
    // important half: a forged or replayed ticket never approves anything, and
    // the device code stays unapproved.
    for ticket in ["replayed", "replayed", "forged"] {
        let (status, _, _) = post(&app, "/device/approve", form(&[("ticket", ticket)])).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "ticket {ticket}");
    }
}

// ------------------------------------------------------------------ gateway

#[tokio::test]
async fn gateway_route_rejects_bad_bearer_tokens() {
    let app = app().await;
    let cases = [
        None,
        Some("Bearer "),
        Some("Bearer not-a-jwt"),
        Some("Bearer a.b.c"),
        Some("Basic abc"),
        Some("bearer lowercase"),
        Some("Bearer"),
    ];
    for header_value in cases {
        let mut builder = Request::builder().uri("/api/v1/upstreams/probe/scores");
        if let Some(value) = header_value {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        let (status, body, _) = send(&app, builder.body(Body::empty()).unwrap()).await;
        // No gateway configured in this fixture: it reports that honestly.
        let code = error_code(&body);
        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::UNAUTHORIZED,
            "unexpected {status} for {header_value:?}: {body}"
        );
        assert!(
            code == "unknown_connector" || code == "invalid_token",
            "unexpected {code} for {header_value:?}"
        );
    }
}

// ------------------------------------------------------------------ health

#[tokio::test]
async fn healthz_is_open_and_readyz_answers() {
    let app = app().await;
    let (status, body, _) = get(&app, "/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");

    let (status, body, _) = get(&app, "/readyz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ready");
}

/// INV-READY-01: readiness must report the backend, not just the process.
///
/// An orchestrator that only checks `/healthz` keeps routing traffic to an
/// instance whose database is gone; every request then fails at the storage
/// layer. The two probes must disagree in exactly this situation.
#[tokio::test]
async fn readyz_reports_unavailable_when_storage_is_gone() {
    let app = app().await;
    app.store.close().await;

    let (status, body, _) = get(&app, "/readyz").await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "readiness must fail when storage is unreachable"
    );
    assert_eq!(body, "storage unavailable");

    let (status, body, _) = get(&app, "/healthz").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "liveness must not depend on storage, or the orchestrator would restart a healthy process"
    );
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn unknown_paths_fall_through_to_static_assets() {
    let app = app().await;
    let (status, _, _) = get(&app, "/definitely-not-a-route").await;
    // The SPA fallback serves index.html; what matters is that it is not a 404
    // with a stack trace and that it is not a redirect loop.
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "unexpected {status}"
    );
}

#[tokio::test]
async fn expired_device_poll_is_reported_as_expired() {
    let app = app().await;
    let device = post(
        &app,
        "/oauth/device_authorization",
        form(&[
            ("client_id", &app.client_id.0.to_string()),
            ("scope", GOOD_SCOPE),
        ]),
    )
    .await;
    assert_eq!(device.0, StatusCode::OK);
    let payload: Value = serde_json::from_str(&device.1).expect("json");
    let device_code = payload["device_code"].as_str().expect("device code");

    app.clock.advance(3_600);
    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[
            ("client_id", &app.client_id.0.to_string()),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
        ]),
    )
    .await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "expired_token");
}

#[tokio::test]
async fn consent_endpoints_require_a_session() {
    let app = app().await;
    let (status, body, _) = get(&app, "/api/oauth/pending?request=x").await;
    assert_api(status, &body, StatusCode::UNAUTHORIZED, "login_required");

    // Without a JSON content type axum refuses at the extractor, before auth.
    let (status, _, _) = post(
        &app,
        "/api/oauth/consent",
        r#"{"request_id":"x","decision":"approve"}"#.to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let (status, body, _) = post_with_headers(
        &app,
        "/api/oauth/consent",
        r#"{"request_id":"x","decision":"approve"}"#.to_string(),
        &[("content-type", "application/json")],
    )
    .await;
    assert_api(status, &body, StatusCode::UNAUTHORIZED, "login_required");
}

#[tokio::test]
async fn userinfo_rejects_missing_and_malformed_tokens() {
    let app = app().await;
    for value in [
        None,
        Some("Bearer "),
        Some("Bearer nope"),
        Some("Basic abc"),
    ] {
        let mut builder = Request::builder().uri("/userinfo");
        if let Some(value) = value {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        let (status, body, _) = send(&app, builder.body(Body::empty()).unwrap()).await;
        assert_api(status, &body, StatusCode::UNAUTHORIZED, "invalid_token");
    }

    // RFC 6750 §3.1: the challenge names the scheme and the failure.
    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header(header::AUTHORIZATION, "Bearer nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer error=\"invalid_token\""),
        "a 401 without the bearer challenge is a client-interop bug"
    );
}

// ------------------------------------------------------- authenticated edges

/// Mints a real session through the admin path so the authenticated branches can
/// be exercised without an IdP.
async fn authenticated(app: &App) -> (String, String) {
    let created =
        re0auth_app::admin::create_session(&app.store, &app.clock, &OsRandom, app.user_id)
            .await
            .expect("session");
    (
        format!(
            "re0auth_session={}; re0auth_csrf={}",
            created.cookie, created.csrf_token
        ),
        created.csrf_token,
    )
}

#[tokio::test]
async fn me_requires_a_csrf_cookie_that_matches_the_session() {
    let app = app().await;
    let (cookie, csrf) = authenticated(&app).await;

    let (status, body, _) = get_with_cookie(&app, "/api/me", &cookie).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let payload: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(payload["csrf_token"], csrf);

    // A session cookie without the matching CSRF cookie is refused.
    let (status, body, _) =
        get_with_cookie(&app, "/api/me", cookie.split(';').next().unwrap()).await;
    assert_api(status, &body, StatusCode::UNAUTHORIZED, "login_required");

    // A CSRF cookie that does not match the session is refused, not ignored.
    let mismatched = format!("{}; re0auth_csrf=wrong", cookie.split(';').next().unwrap());
    let (status, body, _) = get_with_cookie(&app, "/api/me", &mismatched).await;
    assert_api(status, &body, StatusCode::UNAUTHORIZED, "login_required");
}

#[tokio::test]
async fn state_changes_require_the_csrf_header() {
    let app = app().await;

    // `logout` destroys the session, so each URI gets its own fresh session.
    for uri in ["/api/logout", "/api/logout-all"] {
        let (cookie, csrf) = authenticated(&app).await;

        let (status, body, _) = post_with_headers(
            &app,
            uri,
            String::new(),
            &[(header::COOKIE.as_str(), cookie.as_str())],
        )
        .await;
        assert_api(status, &body, StatusCode::FORBIDDEN, "invalid_csrf");

        let (status, body, _) = post_with_headers(
            &app,
            uri,
            String::new(),
            &[
                (header::COOKIE.as_str(), cookie.as_str()),
                ("x-csrf-token", "forged"),
            ],
        )
        .await;
        assert_api(status, &body, StatusCode::FORBIDDEN, "invalid_csrf");

        let (status, _, _) = post_with_headers(
            &app,
            uri,
            String::new(),
            &[
                (header::COOKIE.as_str(), cookie.as_str()),
                ("x-csrf-token", csrf.as_str()),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{uri}");
    }
}

#[tokio::test]
async fn logout_all_clears_cookies_and_marks_them_secure() {
    let app = app().await;
    let (cookie, csrf) = authenticated(&app).await;

    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/logout-all")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let cleared: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(ToString::to_string)
        .collect();
    assert_eq!(cleared.len(), 2, "both cookies are cleared");
    for value in &cleared {
        assert!(value.contains("Max-Age=0"), "{value}");
        assert!(value.contains("Path=/"), "{value}");
    }
    // The session cookie is HttpOnly; the CSRF cookie deliberately is not, since
    // the SPA has to read it to echo the header.
    assert!(
        cleared
            .iter()
            .any(|value| value.starts_with("re0auth_session=;") && value.contains("HttpOnly")),
        "{cleared:?}"
    );

    // The session really is gone afterwards.
    let (status, body, _) = get_with_cookie(&app, "/api/me", &cookie).await;
    assert_api(status, &body, StatusCode::UNAUTHORIZED, "login_required");
}

#[tokio::test]
async fn authorizations_listing_is_empty_and_revoke_rejects_bad_ids() {
    let app = app().await;
    let (cookie, csrf) = authenticated(&app).await;

    let (status, body, _) = get_with_cookie(&app, "/api/me/authorizations", &cookie).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let payload: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(payload.as_array().expect("array").len(), 0);

    let (status, body, _) = send(
        &app,
        Request::builder()
            .method("DELETE")
            .uri("/api/me/authorizations/not-a-uuid")
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_request");

    // A well-formed but unknown client id is a 404: revocation is not silently
    // idempotent, so a typo in the SPA surfaces instead of looking successful.
    let unknown = uuid::Uuid::now_v7();
    let (status, body, _) = send(
        &app,
        Request::builder()
            .method("DELETE")
            .uri(format!("/api/me/authorizations/{unknown}"))
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_api(status, &body, StatusCode::NOT_FOUND, "not_found");
}

#[tokio::test]
async fn per_code_counter_survives_a_restart_and_locks_the_code() {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("SQLite store");
    let first = build(store.clone(), 1024 * 1024).await;

    // Five misses from one peer exhaust the in-memory bucket too, so this run
    // ends with both counters saturated. The point is what survives the restart.
    let code = "ABCD-EFGH";
    let uri = format!("/device/start?{}", form(&[("user_code", code)]));
    for attempt in 1..=5 {
        let (status, _, _) = get(&first, &uri).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "attempt {attempt} should miss, not lock"
        );
    }
    let (status, _, _) = get(&first, &uri).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the IP bucket trips first"
    );

    // Restart: same database, brand-new in-memory buckets.
    drop(first);
    let second = build(store, 1024 * 1024).await;

    // The peer has no in-memory history now, so only the persistent per-code
    // counter stands between this request and a fresh guess.
    let (status, body, _) = get(&second, &uri).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the per-code counter must survive a restart: {body}"
    );
    assert!(body.contains("登录未完成"), "{body}");

    // A different code is unaffected: the lockout is scoped, not global.
    let other = format!("/device/start?{}", form(&[("user_code", "ZZZZ-ZZZZ")]));
    let (status, _, _) = get(&second, &other).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn device_start_with_a_valid_code_fails_when_no_idp_is_configured() {
    let app = app().await;
    let device = post(
        &app,
        "/oauth/device_authorization",
        form(&[
            ("client_id", &app.client_id.0.to_string()),
            ("scope", GOOD_SCOPE),
        ]),
    )
    .await;
    assert_eq!(device.0, StatusCode::OK);
    let payload: Value = serde_json::from_str(&device.1).expect("json");
    let user_code = payload["user_code"].as_str().expect("user code");

    // The code is real, so the lookup succeeds; the failure comes from having no
    // identity provider, and it must say so rather than redirect to a dead IdP.
    let (status, body, location) = get(
        &app,
        &format!("/device/start?{}", form(&[("user_code", user_code)])),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {body}");
    assert!(body.contains("登录未完成"), "{body}");
    assert!(location.is_none(), "no redirect without an IdP");

    // The QR code only needs the code to exist, so it still works.
    let (status, body, _) = get(
        &app,
        &format!("/device/qr.svg?{}", form(&[("user_code", user_code)])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.contains("<svg"));
}

#[tokio::test]
async fn consent_requires_a_matching_session_and_csrf() {
    let app = app().await;
    let (cookie, csrf) = authenticated(&app).await;

    // Unknown request id: 404 rather than a redirect to nowhere.
    let (status, body, _) = get_with_cookie(&app, "/api/oauth/pending?request=abc", &cookie).await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
        "body: {body}"
    );

    let (status, body, _) = post_with_headers(
        &app,
        "/api/oauth/consent",
        r#"{"request_id":"not-a-uuid","decision":"approve"}"#.to_string(),
        &[
            ("content-type", "application/json"),
            (header::COOKIE.as_str(), cookie.as_str()),
            ("x-csrf-token", csrf.as_str()),
        ],
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
        "body: {body}"
    );

    // Malformed JSON is refused at the extractor.
    let (status, _, _) = post_with_headers(
        &app,
        "/api/oauth/consent",
        "{not json".to_string(),
        &[
            ("content-type", "application/json"),
            (header::COOKIE.as_str(), cookie.as_str()),
            ("x-csrf-token", csrf.as_str()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Missing CSRF is refused before the body is even considered.
    let (status, body, _) = post_with_headers(
        &app,
        "/api/oauth/consent",
        r#"{"request_id":"x","decision":"approve"}"#.to_string(),
        &[
            ("content-type", "application/json"),
            (header::COOKIE.as_str(), cookie.as_str()),
        ],
    )
    .await;
    assert_api(status, &body, StatusCode::FORBIDDEN, "invalid_csrf");
}

// ---------------------------------------------------------------- bindings

/// Inserts a binding owned by `owner`. `upstream_id` holds the connector's
/// configured name, which is what the gateway looks up.
async fn seed_binding(
    app: &App,
    owner: re0auth_api::UserId,
    connector: &str,
    status: re0auth_api::ports::BindingStatus,
) -> re0auth_api::BindingId {
    let id = re0auth_api::BindingId::new();
    let now = app.clock.now();
    app.store
        .bindings()
        .upsert(
            &re0auth_api::ports::Binding {
                id,
                user_id: owner,
                upstream_id: connector.to_string(),
                upstream_user_id: "player-1".to_string(),
                status,
                created_at: now,
                updated_at: now,
                last_refreshed_at: None,
                last_error_code: None,
            },
            &re0auth_api::audit::SecurityFact::new(
                re0auth_api::audit::AuditAction::BindingCreated,
                now,
                format!("binding:{}", id.0),
            ),
        )
        .await
        .expect("seed binding");
    id
}

#[tokio::test]
async fn bindings_list_shows_only_the_callers_own() {
    let app = app().await;
    let (cookie, _csrf) = authenticated(&app).await;

    let mine = seed_binding(
        &app,
        app.user_id,
        "phigros",
        re0auth_api::ports::BindingStatus::Active,
    )
    .await;
    let stranger = re0auth_api::UserId::new();
    app.store
        .users()
        .create(&User {
            id: stranger,
            display_name: "Stranger".to_string(),
            role: UserRole::User,
            created_at: app.clock.now(),
            updated_at: app.clock.now(),
        })
        .await
        .expect("stranger");
    seed_binding(
        &app,
        stranger,
        "other",
        re0auth_api::ports::BindingStatus::Active,
    )
    .await;

    let (status, body, _) = get_with_cookie(&app, "/api/me/bindings", &cookie).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let payload: Value = serde_json::from_str(&body).expect("json");
    let list = payload.as_array().expect("array");
    assert_eq!(list.len(), 1, "only the caller's bindings: {body}");
    assert_eq!(list[0]["id"], mine.0.to_string());
    assert_eq!(list[0]["connector"], "phigros");
    assert_eq!(list[0]["status"], "active");
}

#[tokio::test]
async fn bindings_require_a_session() {
    let app = app().await;
    let (status, _, _) = get(&app, "/api/me/bindings").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoking_a_binding_requires_csrf_and_ownership() {
    let app = app().await;
    let (cookie, csrf) = authenticated(&app).await;
    let mine = seed_binding(
        &app,
        app.user_id,
        "phigros",
        re0auth_api::ports::BindingStatus::Active,
    )
    .await;
    let uri = format!("/api/me/bindings/{}", mine.0);

    // No CSRF header: refused before anything is touched.
    let (status, body, _) = send(
        &app,
        Request::builder()
            .method("DELETE")
            .uri(&uri)
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");

    // Malformed id.
    let (status, body, _) = send(
        &app,
        Request::builder()
            .method("DELETE")
            .uri("/api/me/bindings/not-a-uuid")
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");

    // Someone else's binding id: must look like it does not exist.
    let stranger = re0auth_api::UserId::new();
    app.store
        .users()
        .create(&User {
            id: stranger,
            display_name: "Stranger".to_string(),
            role: UserRole::User,
            created_at: app.clock.now(),
            updated_at: app.clock.now(),
        })
        .await
        .expect("stranger");
    let foreign = seed_binding(
        &app,
        stranger,
        "other",
        re0auth_api::ports::BindingStatus::Active,
    )
    .await;
    let (status, body, _) = send(
        &app,
        Request::builder()
            .method("DELETE")
            .uri(format!("/api/me/bindings/{}", foreign.0))
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a foreign binding must not be distinguishable from a missing one: {body}"
    );

    // Own binding succeeds and disappears from the list.
    let (status, body, _) = send(
        &app,
        Request::builder()
            .method("DELETE")
            .uri(&uri)
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "body: {body}");

    let (_, body, _) = get_with_cookie(&app, "/api/me/bindings", &cookie).await;
    let payload: Value = serde_json::from_str(&body).expect("json");
    assert!(payload.as_array().expect("array").is_empty());

    // The row survives as revoked: the audit trail must still resolve what the
    // binding was, and a re-bind must not resurrect the old credential.
    let stored = app
        .store
        .bindings()
        .find(&app.user_id, "phigros")
        .await
        .expect("find")
        .expect("row");
    assert_eq!(stored.status, re0auth_api::ports::BindingStatus::Revoked);
}

// ------------------------------------------------------------ rate limiting

#[tokio::test]
async fn the_unauthenticated_lane_returns_429_with_retry_after() {
    let app = app_with_strict_limits(2).await;
    let burst = 2;

    // Spend the budget. Each request is a well-formed device-authorization call
    // so the only reason to refuse is the limiter.
    for index in 0..burst {
        let (status, body, _) = post(
            &app,
            "/oauth/device_authorization",
            form(&[
                ("client_id", &app.client_id.0.to_string()),
                ("scope", GOOD_SCOPE),
            ]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "request {index} body: {body}");
    }

    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/device_authorization")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form(&[
                    ("client_id", &app.client_id.0.to_string()),
                    ("scope", GOOD_SCOPE),
                ])))
                .unwrap(),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    // The header is the point: a 429 without it leaves a client retrying blind.
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .expect("Retry-After")
        .to_str()
        .expect("ascii")
        .parse::<u64>()
        .expect("seconds");
    assert!(retry_after >= 1, "got {retry_after}");

    // The ceiling actually enforced must be published, otherwise a client
    // pacing itself from the header would be guessing.
    let limit = response
        .headers()
        .get("ratelimit-limit")
        .expect("RateLimit-Limit")
        .to_str()
        .expect("ascii");
    assert_eq!(limit, "2");
    let policy = response
        .headers()
        .get("ratelimit-policy")
        .expect("RateLimit-Policy")
        .to_str()
        .expect("ascii");
    assert_eq!(policy, "2;w=60");

    // `RateLimit-Remaining` is deliberately absent: GCRA's allowance lives in an
    // opaque atomic, so any value here would be a second counter that drifts.
    // Asserting the absence keeps someone from adding a plausible-looking lie.
    assert!(
        response.headers().get("ratelimit-remaining").is_none(),
        "a remaining count cannot be derived from GCRA state; do not invent one"
    );
}

#[tokio::test]
async fn login_is_on_the_unauthenticated_lane() {
    let app = app_with_strict_limits(1).await;

    // The first call spends the bucket. This fixture has no IdP, so the honest
    // answer is 503 — which proves the request reached the handler.
    let (status, _, _) = get(&app, "/auth/login?return_to=%2F").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let (status, body, _) = get(&app, "/auth/login?return_to=%2F").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
}

#[tokio::test]
async fn advancing_the_clock_reopens_the_unauthenticated_lane() {
    let app = app_with_strict_limits(1).await;
    let burst = 1;
    for _ in 0..burst {
        let (status, _, _) = post(
            &app,
            "/oauth/device_authorization",
            form(&[
                ("client_id", &app.client_id.0.to_string()),
                ("scope", GOOD_SCOPE),
            ]),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, _, _) = post(
        &app,
        "/oauth/device_authorization",
        form(&[
            ("client_id", &app.client_id.0.to_string()),
            ("scope", GOOD_SCOPE),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // Past the window the budget is back. This only works because the limiter
    // reads the app's clock; with a hardware counter it would need a real sleep.
    app.clock.advance(120);
    let (status, body, _) = post(
        &app,
        "/oauth/device_authorization",
        form(&[
            ("client_id", &app.client_id.0.to_string()),
            ("scope", GOOD_SCOPE),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[tokio::test]
async fn the_token_endpoint_is_limited_too() {
    // The token endpoint is the most expensive anonymous call, so it must be on
    // the same lane rather than relying on device-authorization's budget.
    let app = app_with_strict_limits(1).await;
    let burst = 1;
    for _ in 0..burst {
        let (status, _, _) = post(
            &app,
            "/oauth/token",
            form(&[
                ("client_id", &app.client_id.0.to_string()),
                ("grant_type", "refresh_token"),
                ("refresh_token", "x"),
            ]),
        )
        .await;
        // Well-formed but unknown grant token: 400, not 429.
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[
            ("client_id", &app.client_id.0.to_string()),
            ("grant_type", "refresh_token"),
            ("refresh_token", "x"),
        ]),
    )
    .await;
    assert_api(status, &body, StatusCode::TOO_MANY_REQUESTS, "rate_limited");
}

// ------------------------------------------------------- client credentials

/// Builds a POST with both a body and an `Authorization` header.
async fn post_with_auth(
    app: &App,
    uri: &str,
    authorization: &str,
    body: String,
) -> (StatusCode, String, Option<String>) {
    send(
        app,
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::AUTHORIZATION, authorization)
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn a_confidential_client_must_present_its_secret() {
    let app = app().await;
    let client = app.confidential.id.0.to_string();

    // No secret at all: rejected before the grant is even looked at.
    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[
            ("client_id", &client),
            ("grant_type", "refresh_token"),
            ("refresh_token", "x"),
        ]),
    )
    .await;
    assert_api(status, &body, StatusCode::UNAUTHORIZED, "invalid_client");

    // A wrong secret: same answer, and it must not distinguish the two cases.
    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[
            ("client_id", &client),
            ("client_secret", "wrong"),
            ("grant_type", "refresh_token"),
            ("refresh_token", "x"),
        ]),
    )
    .await;
    assert_api(status, &body, StatusCode::UNAUTHORIZED, "invalid_client");

    // The right secret gets past authentication and fails on the grant instead,
    // which proves the secret was actually checked rather than ignored.
    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[
            ("client_id", &client),
            ("client_secret", CONFIDENTIAL_SECRET),
            ("grant_type", "refresh_token"),
            ("refresh_token", "x"),
        ]),
    )
    .await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_grant");
}

#[tokio::test]
async fn a_public_client_must_not_present_a_secret() {
    let app = app().await;
    let client = app.client_id.0.to_string();

    // Accepting this would let anyone bolt an arbitrary secret onto a public
    // client and hide a misconfiguration behind a "successful" call.
    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[
            ("client_id", &client),
            ("client_secret", "anything"),
            ("grant_type", "refresh_token"),
            ("refresh_token", "x"),
        ]),
    )
    .await;
    assert_api(status, &body, StatusCode::UNAUTHORIZED, "invalid_client");
}

#[tokio::test]
async fn invalid_client_names_the_basic_scheme() {
    let app = app().await;
    let client = app.confidential.id.0.to_string();

    let response = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form(&[
                    ("client_id", &client),
                    ("grant_type", "refresh_token"),
                    ("refresh_token", "x"),
                ])))
                .unwrap(),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // RFC 6749 §5.2 requires the challenge header, not just the code.
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("WWW-Authenticate")
        .to_str()
        .expect("ascii");
    assert!(
        challenge.starts_with("Basic"),
        "challenge was {challenge:?}"
    );
}

#[tokio::test]
async fn basic_authentication_is_honoured() {
    let app = app().await;
    let client = app.confidential.id.0.to_string();

    // Right credentials over Basic: past auth, fails on the unknown grant token.
    let (status, body, _) = post_with_auth(
        &app,
        "/oauth/token",
        &app.confidential.basic_header(),
        form(&[("grant_type", "refresh_token"), ("refresh_token", "x")]),
    )
    .await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_grant");

    // Matching body client_id plus Basic is fine; a *different* id is not.
    let (status, body, _) = post_with_auth(
        &app,
        "/oauth/token",
        &app.confidential.basic_header(),
        form(&[
            ("client_id", &client),
            ("grant_type", "refresh_token"),
            ("refresh_token", "x"),
        ]),
    )
    .await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_grant");

    let (status, body, _) = post_with_auth(
        &app,
        "/oauth/token",
        &app.confidential.basic_header(),
        form(&[
            ("client_id", &app.client_id.0.to_string()),
            ("grant_type", "refresh_token"),
            ("refresh_token", "x"),
        ]),
    )
    .await;
    assert_api(status, &body, StatusCode::BAD_REQUEST, "invalid_request");
}

#[tokio::test]
async fn a_malformed_basic_header_is_rejected_as_invalid_client() {
    let app = app().await;

    for header_value in [
        "Basic",
        "Basic !!!not-base64!!!",
        "Basic bm8tY29sb24=", // "no-colon"
        "Bearer abc",
        "Basic ",
    ] {
        let (status, body, _) = post_with_auth(
            &app,
            "/oauth/token",
            header_value,
            form(&[("grant_type", "refresh_token"), ("refresh_token", "x")]),
        )
        .await;
        assert_api(status, &body, StatusCode::UNAUTHORIZED, "invalid_client");
    }
}

#[tokio::test]
async fn discovery_advertises_the_auth_methods_it_actually_supports() {
    let app = app().await;
    let (status, body, _) = get(&app, "/.well-known/openid-configuration").await;
    assert_eq!(status, StatusCode::OK);

    let payload: Value = serde_json::from_str(&body).expect("json");
    let methods = payload["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        methods,
        vec!["client_secret_basic", "client_secret_post", "none"],
        "advertising `none` alone hid the confidential-client support"
    );
}

#[tokio::test]
async fn discovery_and_jwks_are_cacheable_for_an_hour() {
    let app = app().await;
    for uri in ["/.well-known/openid-configuration", "/jwks.json"] {
        let response = app
            .router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("public, max-age=3600"),
            "{uri}"
        );
    }
}

#[tokio::test]
async fn device_authorization_authenticates_confidential_clients() {
    let app = app().await;

    // RFC 8628 §3.1: a confidential client must authenticate here too. Without
    // the secret this would start a flow under a client it does not control.
    let body = form(&[
        ("client_id", app.confidential.id.0.to_string().as_str()),
        ("scope", "openid"),
    ]);
    let (status, body, _) = post(&app, "/oauth/device_authorization", body).await;
    assert_api(status, &body, StatusCode::UNAUTHORIZED, "invalid_client");

    let body = form(&[
        ("client_id", app.confidential.id.0.to_string().as_str()),
        ("client_secret", CONFIDENTIAL_SECRET),
        ("scope", "openid"),
    ]);
    let (status, body, _) = post(&app, "/oauth/device_authorization", body).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn token_rejects_two_client_authentication_methods() {
    let app = app().await;
    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", "x"),
        ("redirect_uri", "https://client.example/callback"),
        ("code_verifier", "v"),
        ("client_secret", CONFIDENTIAL_SECRET),
    ]);
    let (status, body, _) = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::AUTHORIZATION, app.confidential.basic_header())
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.contains("use only one client authentication method"),
        "{body}"
    );
}

#[tokio::test]
async fn revoking_a_token_requires_it_to_belong_to_the_caller() {
    let app = app().await;
    let code = "revoke-owner-code";
    let verifier = "verifier-abcdefghijklmnopqrstuvwxyz-0123456789";
    let challenge = re0auth_domain::pkce::challenge_s256(verifier);
    let now = app.clock.now();
    app.store
        .auth_codes()
        .insert(
            &re0auth_api::ports::AuthCode {
                id: re0auth_api::AuthCodeId::new(),
                code_hash: re0auth_app::oauth::hash_secret(code),
                client_id: app.confidential.id,
                user_id: app.user_id,
                redirect_uri: "https://client.example/callback".to_string(),
                scopes: vec!["openid".to_string()],
                code_challenge: Some(challenge),
                code_challenge_method: Some("S256".to_string()),
                nonce: None,
                created_at: now,
                expires_at: now + 600,
                consumed_at: None,
                family_id: None,
            },
            &re0auth_api::audit::SecurityFact::new(
                re0auth_api::audit::AuditAction::AuthCodeIssued,
                now,
                format!("client:{}", app.confidential.id.0),
            ),
        )
        .await
        .expect("seed code");

    grant_consent(&app, app.confidential.id, &["openid"]).await;

    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[
            ("client_id", app.confidential.id.0.to_string().as_str()),
            ("client_secret", CONFIDENTIAL_SECRET),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", "https://client.example/callback"),
            ("code_verifier", verifier),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let payload: Value = serde_json::from_str(&body).expect("token json");
    let access = payload["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    let refresh = payload["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_string();

    let userinfo = |token: &str| {
        Request::builder()
            .uri("/userinfo")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    let (status, _, _) = send(&app, userinfo(&access)).await;
    assert_eq!(status, StatusCode::OK);

    // RFC 7009 §2.1: another client may not revoke it. The answer stays 200 so
    // the endpoint is not an oracle, but the token must remain usable.
    let (status, _, _) = post(
        &app,
        "/oauth/revoke",
        form(&[
            ("token", access.as_str()),
            ("client_id", app.client_id.0.to_string().as_str()),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = send(&app, userinfo(&access)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a foreign client must not be able to revoke this token"
    );

    let (status, _, _) = post(
        &app,
        "/oauth/revoke",
        form(&[
            ("token", access.as_str()),
            ("client_id", app.confidential.id.0.to_string().as_str()),
            ("client_secret", CONFIDENTIAL_SECRET),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = send(&app, userinfo(&access)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The same ownership rule applies to the opaque refresh-token branch.
    let (status, _, _) = post(
        &app,
        "/oauth/revoke",
        form(&[
            ("token", refresh.as_str()),
            ("client_id", app.client_id.0.to_string().as_str()),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
            ("client_id", app.confidential.id.0.to_string().as_str()),
            ("client_secret", CONFIDENTIAL_SECRET),
        ]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a foreign client must not revoke the refresh token"
    );
    let rotated: Value = serde_json::from_str(&body).expect("rotated token json");
    let rotated = rotated["refresh_token"]
        .as_str()
        .expect("rotated refresh token")
        .to_string();

    let (status, _, _) = post(
        &app,
        "/oauth/revoke",
        form(&[
            ("token", rotated.as_str()),
            ("client_id", app.confidential.id.0.to_string().as_str()),
            ("client_secret", CONFIDENTIAL_SECRET),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body, _) = post(
        &app,
        "/oauth/token",
        form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rotated.as_str()),
            ("client_id", app.confidential.id.0.to_string().as_str()),
            ("client_secret", CONFIDENTIAL_SECRET),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.contains("invalid_grant"),
        "revoked refresh token must fail as invalid_grant: {body}"
    );
}

#[tokio::test]
async fn a_wrong_secret_does_not_burn_the_authorization_code() {
    let app = app().await;

    // Seed a real, consumable code for the confidential client.
    let code = "confidential-code";
    let verifier = "verifier-0123456789-0123456789-0123456789-0123456789";
    let challenge = re0auth_domain::pkce::challenge_s256(verifier);
    let now = app.clock.now();
    app.store
        .auth_codes()
        .insert(
            &re0auth_api::ports::AuthCode {
                id: re0auth_api::AuthCodeId::new(),
                code_hash: re0auth_app::oauth::hash_secret(code),
                client_id: app.confidential.id,
                user_id: app.user_id,
                redirect_uri: "https://client.example/callback".to_string(),
                scopes: vec!["openid".to_string()],
                code_challenge: Some(challenge),
                code_challenge_method: Some("S256".to_string()),
                nonce: None,
                created_at: now,
                expires_at: now + 600,
                consumed_at: None,
                family_id: None,
            },
            &re0auth_api::audit::SecurityFact::new(
                re0auth_api::audit::AuditAction::AuthCodeIssued,
                now,
                format!("client:{}", app.confidential.id.0),
            ),
        )
        .await
        .expect("seed code");

    grant_consent(&app, app.confidential.id, &["openid"]).await;

    let exchange = |secret: &str| {
        form(&[
            ("client_id", &app.confidential.id.0.to_string()),
            ("client_secret", secret),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", "https://client.example/callback"),
            ("code_verifier", verifier),
        ])
    };

    // Wrong secret: refused, and the code must still be there afterwards.
    let (status, body, _) = post(&app, "/oauth/token", exchange("wrong")).await;
    assert_api(status, &body, StatusCode::UNAUTHORIZED, "invalid_client");

    // The same code, with the right secret, must still exchange. If the failed
    // attempt had consumed it, this would be `invalid_grant`.
    let (status, body, _) = post(&app, "/oauth/token", exchange(CONFIDENTIAL_SECRET)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a failed client authentication must not consume the code; body: {body}"
    );
}

// ------------------------------------------------- request id in the audit trail

#[tokio::test]
async fn the_request_id_reaches_the_audit_row() {
    // A correlation header that only appears on the response is decoration. The
    // point of §9 is that an operator can take an id from a client report and
    // find the matching security fact.
    let app = app().await;
    let (cookie, csrf) = authenticated(&app).await;

    let binding = re0auth_api::ports::Binding {
        id: re0auth_api::BindingId::new(),
        user_id: app.user_id,
        upstream_id: "phigros".to_string(),
        upstream_user_id: "player-1".to_string(),
        status: re0auth_api::ports::BindingStatus::Active,
        created_at: 1_000,
        updated_at: 1_000,
        last_refreshed_at: None,
        last_error_code: None,
    };
    app.store
        .bindings()
        .upsert(
            &binding,
            &re0auth_api::audit::SecurityFact::new(
                re0auth_api::audit::AuditAction::BindingCreated,
                1_000,
                "binding:setup",
            ),
        )
        .await
        .expect("binding");

    let correlation = "corr-0123456789";
    let (status, body, _) = send(
        &app,
        Request::builder()
            .method("DELETE")
            .uri(format!("/api/me/bindings/{}", binding.id.0))
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .header("x-request-id", correlation)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "body: {body}");

    let audits = app.store.audits().recent(100).await.expect("audit rows");
    let revoked = audits
        .iter()
        .find(|record| record.action == re0auth_api::audit::AuditAction::BindingRevoked)
        .expect("the revocation must be audited");
    assert_eq!(
        revoked.request_id.as_deref(),
        Some(correlation),
        "the audit row must carry the correlation id from the request"
    );
}

/// INV-RES-02: the cap must come from configuration, not from axum's default.
/// The bug this catches is a knob that parses, validates, and changes nothing.
#[tokio::test]
async fn the_inbound_body_cap_is_the_configured_value() {
    // 64 bytes is far below axum's 2 MiB default, so an unwired limit accepts this.
    let app = build_app(64).await;
    let payload = "x".repeat(2048);
    let body = form(&[
        ("client_id", app.client_id.0.to_string().as_str()),
        ("scope", "openid"),
        ("padding", payload.as_str()),
    ]);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/oauth/device_authorization")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .expect("request");
    let (status, _, _) = send(&app, request).await;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "a body over the configured cap must be rejected before extraction"
    );
}

#[tokio::test]
async fn a_body_within_the_cap_still_reaches_the_handler() {
    let app = build_app(64 * 1024).await;
    let body = form(&[
        ("client_id", app.client_id.0.to_string().as_str()),
        ("scope", "openid"),
    ]);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/oauth/device_authorization")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .expect("request");
    let (status, _, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::OK);
}

/// INV-RATE-01: a peer outside `trusted_proxies` cannot choose its own bucket.
/// Without this, per-IP limiting is trivially defeated by rotating a header.
#[tokio::test]
async fn a_forged_forwarded_header_does_not_create_a_new_rate_bucket() {
    // burst = 1, and the peer address never changes.
    let app = app_with_strict_limits(1).await;
    let body = form(&[
        ("client_id", app.client_id.0.to_string().as_str()),
        ("scope", "openid"),
    ]);
    let mut statuses = Vec::new();
    for forwarded in ["1.2.3.4", "5.6.7.8", "9.10.11.12"] {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/oauth/device_authorization")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("x-forwarded-for", forwarded)
            .body(Body::from(body.clone()))
            .expect("request");
        let (status, _, _) = send(&app, request).await;
        statuses.push(status);
    }
    assert_eq!(statuses[0], StatusCode::OK);
    assert_eq!(
        statuses[1],
        StatusCode::TOO_MANY_REQUESTS,
        "a header must not hand the caller a fresh bucket"
    );
    assert_eq!(statuses[2], StatusCode::TOO_MANY_REQUESTS);
}
