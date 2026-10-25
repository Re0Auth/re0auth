use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::connect_info::MockConnectInfo;

use aws_lc_rs::signature::KeyPair as _;
use axum::body::{Body, to_bytes};
use axum::extract::{Form, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::Json;
use axum::routing::{get, post};
use axum::{Router, serve};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tower::ServiceExt;
use url::Url;
use url::form_urlencoded;

use re0auth_adapters::clock::SystemClock;
use re0auth_adapters::crypto::RsaTokenSigner;
use re0auth_adapters::random::OsRandom;
use re0auth_adapters::storage::SqliteStore;
use re0auth_api::idp::IdpClient;
use re0auth_api::ports::{Client, ClientStatus, Storage};
use re0auth_api::{ClientId, Clock};
use re0auth_app::auth::AuthService;
use re0auth_app::oauth::OAuthService;
use re0auth_http::{AppState, router};
use re0auth_idp::{OidcConfig, OidcProvider};
use re0auth_runtime::http_client::GuardedClient;
use re0auth_runtime::outbound::OutboundPolicy;

const ISSUER: &str = "http://127.0.0.1:19090";
const TEST_MASTER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const CLIENT_ID: &str = "test-client";
const REDIRECT_URI: &str = "http://client.example/callback";

struct KeyGuard(PathBuf);

impl Drop for KeyGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[derive(Clone)]
struct TestKey {
    encoding: EncodingKey,
    kid: String,
    jwk: Value,
}

impl TestKey {
    fn generate(kid: &str) -> Self {
        let key_pair =
            aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).expect("rsa key");
        let private_der =
            aws_lc_rs::encoding::AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&key_pair)
                .expect("pkcs8 der");
        let encoding = EncodingKey::from_rsa_pem(pkcs8_pem(private_der.as_ref()).as_bytes())
            .expect("encoding key");
        let public = key_pair.public_key();
        let spki = aws_lc_rs::rsa::PublicKey::from_der(public.as_ref()).expect("public key");
        Self {
            encoding,
            kid: kid.to_string(),
            jwk: json!({
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": URL_SAFE_NO_PAD.encode(
                    spki.modulus().big_endian_without_leading_zero()
                ),
                "e": URL_SAFE_NO_PAD.encode(
                    spki.exponent().big_endian_without_leading_zero()
                ),
            }),
        }
    }
}

fn pkcs8_pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

#[derive(Clone)]
struct MockIdp {
    base: String,
    nonce: Arc<Mutex<String>>,
    /// Replaceable so a test can model an IdP key rotation mid-run.
    key: Arc<Mutex<Arc<TestKey>>>,
    /// Counts JWKS fetches, which is how the refresh cooldown is proven.
    jwks_fetches: Arc<std::sync::atomic::AtomicUsize>,
    /// When set, the token endpoint stamps this `kid` while still signing with
    /// the real key — an unknown kid that survives a JWKS refresh.
    forced_kid: Arc<Mutex<Option<String>>>,
    /// Replaces the `aud` claim, so a test can mint a multi-audience token.
    audience: Arc<Mutex<Option<Value>>>,
    /// Replaces the JOSE `typ` header, so a test can present a non-id token.
    header_typ: Arc<Mutex<Option<String>>>,
    /// Publishes the signing key twice under the same `kid` in JWKS.
    duplicate_kid: Arc<Mutex<bool>>,
    /// Replaces one endpoint in the discovery document, so the same-origin guard
    /// can be pushed on one field at a time.
    discovery_override: Arc<Mutex<Option<(&'static str, String)>>>,
    /// What the last token request authenticated with. Pins how we authenticate:
    /// a form field, never `Authorization: Basic` (`IDP-SETUP.md` §2, ADR-0047).
    last_token_auth: Arc<Mutex<Option<TokenAuth>>>,
    client_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TokenAuth {
    basic: bool,
    form_secret: bool,
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    #[allow(dead_code)]
    code: Option<String>,
    client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: Value,
    exp: i64,
    iat: i64,
    nonce: String,
    name: String,
}

impl MockIdp {
    fn current_key(&self) -> Arc<TestKey> {
        Arc::clone(&self.key.lock().expect("key"))
    }

    fn rotate(&self, kid: &str) -> Arc<TestKey> {
        let key = Arc::new(TestKey::generate(kid));
        *self.key.lock().expect("key") = Arc::clone(&key);
        key
    }

    fn sign(&self) -> String {
        let now = SystemClock.now();
        let nonce = self.nonce.lock().expect("nonce").clone();
        let key = self.current_key();
        let audience = self
            .audience
            .lock()
            .expect("audience")
            .clone()
            .unwrap_or_else(|| json!(self.client_id));
        let typ = self.header_typ.lock().expect("header typ").clone();
        let kid = match self.forced_kid.lock().expect("forced kid").clone() {
            Some(kid) => kid,
            None => key.kid.clone(),
        };
        sign_token_shaped(
            &key,
            &kid,
            &self.base,
            audience,
            typ.as_deref(),
            &nonce,
            now,
        )
    }

    fn force_kid(&self, kid: Option<&str>) {
        *self.forced_kid.lock().expect("forced kid") = kid.map(str::to_string);
    }

    fn force_audience(&self, audience: Option<Value>) {
        *self.audience.lock().expect("audience") = audience;
    }

    fn force_header_typ(&self, typ: Option<&str>) {
        *self.header_typ.lock().expect("header typ") = typ.map(str::to_string);
    }

    fn publish_duplicate_kid(&self, duplicate: bool) {
        *self.duplicate_kid.lock().expect("duplicate kid") = duplicate;
    }

    fn force_discovered_endpoint(&self, field: &'static str, value: &str) {
        *self.discovery_override.lock().expect("override") = Some((field, value.to_string()));
    }

    fn jwks_fetch_count(&self) -> usize {
        self.jwks_fetches.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Builds an id token with the claims and header a test needs to deviate from
/// the well-formed one, so the verifier can be pushed on one axis at a time.
fn sign_token_shaped(
    key: &TestKey,
    kid: &str,
    issuer: &str,
    audience: Value,
    typ: Option<&str>,
    nonce: &str,
    now: i64,
) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    if let Some(typ) = typ {
        header.typ = Some(typ.to_string());
    }
    encode(
        &header,
        &IdTokenClaims {
            iss: issuer.to_string(),
            sub: "idp-user-1".to_string(),
            aud: audience,
            exp: now + 300,
            iat: now,
            nonce: nonce.to_string(),
            name: "Alice".to_string(),
        },
        &key.encoding,
    )
    .expect("sign id token")
}

async fn discovery(State(mock): State<MockIdp>) -> Json<Value> {
    let mut document = json!({
        "issuer": mock.base,
        "authorization_endpoint": format!("{}/authorize", mock.base),
        "token_endpoint": format!("{}/token", mock.base),
        "jwks_uri": format!("{}/jwks", mock.base),
    });
    let forced = mock.discovery_override.lock().expect("override").clone();
    if let Some((field, value)) = forced {
        document[field] = json!(value);
    }
    Json(document)
}

async fn jwks(State(mock): State<MockIdp>) -> Json<Value> {
    mock.jwks_fetches
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let jwk = mock.current_key().jwk.clone();
    if *mock.duplicate_kid.lock().expect("duplicate kid") {
        return Json(json!({ "keys": [jwk.clone(), jwk] }));
    }
    Json(json!({ "keys": [jwk] }))
}

async fn token(
    State(mock): State<MockIdp>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Json<Value> {
    *mock.last_token_auth.lock().expect("token auth") = Some(TokenAuth {
        basic: headers.contains_key(header::AUTHORIZATION),
        form_secret: form.client_secret.is_some(),
    });
    Json(json!({ "id_token": mock.sign() }))
}

async fn start_mock() -> MockIdp {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("mock bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let mock = MockIdp {
        base,
        nonce: Arc::new(Mutex::new(String::new())),
        key: Arc::new(Mutex::new(Arc::new(TestKey::generate("test-key")))),
        jwks_fetches: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        forced_kid: Arc::new(Mutex::new(None)),
        audience: Arc::new(Mutex::new(None)),
        header_typ: Arc::new(Mutex::new(None)),
        duplicate_kid: Arc::new(Mutex::new(false)),
        discovery_override: Arc::new(Mutex::new(None)),
        last_token_auth: Arc::new(Mutex::new(None)),
        client_id: CLIENT_ID.to_string(),
    };
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(mock.clone());
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("mock runtime");
        runtime.block_on(async move {
            serve(listener, app).await.expect("mock server");
        });
    });
    mock
}

struct TestApp {
    router: Router,
    client_id: ClientId,
    mock: MockIdp,
    _key: KeyGuard,
}

/// A clock the test advances by hand, so the refresh cooldown can be proven
/// without sleeping a real minute.
#[derive(Clone)]
struct ManualClock(Arc<std::sync::atomic::AtomicI64>);

impl ManualClock {
    fn new(start: i64) -> Self {
        Self(Arc::new(std::sync::atomic::AtomicI64::new(start)))
    }

    fn advance(&self, seconds: i64) {
        self.0
            .fetch_add(seconds, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> i64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Builds a provider over the mock's discovery document with a chosen clock.
async fn try_provider_for(mock: &MockIdp, clock: Arc<dyn Clock>) -> anyhow::Result<OidcProvider> {
    OidcProvider::discover(
        OidcConfig {
            issuer: mock.base.clone(),
            client_id: CLIENT_ID.to_string(),
            client_secret: "secret".to_string(),
            redirect_uri: format!("{ISSUER}/auth/callback"),
            scopes: vec!["openid".to_string()],
            discovery_url: Some(format!("{}/.well-known/openid-configuration", mock.base)),
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
        },
        GuardedClient::with_policy(OutboundPolicy::AllowLoopback, true).expect("http client"),
        clock,
    )
    .await
}

async fn provider_for(mock: &MockIdp, clock: Arc<dyn Clock>) -> OidcProvider {
    try_provider_for(mock, clock).await.expect("discover idp")
}

/// ADR-0036 / INV-SSRF-01: an outbound target must come from configuration, not
/// from a response body. A discovered endpoint on another origin is refused, and
/// the refusal happens before we send anything to it.
#[tokio::test]
async fn a_discovered_endpoint_off_the_issuers_origin_is_refused() {
    for field in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
        let mock = start_mock().await;
        mock.force_discovered_endpoint(field, "https://cdn.example.net/elsewhere");

        let error = match try_provider_for(&mock, Arc::new(SystemClock)).await {
            Ok(_) => panic!("a foreign origin must be refused"),
            Err(error) => error,
        };
        let message = format!("{error:#}");
        assert!(
            message.contains(field),
            "the error must name the field: {message}"
        );
        assert!(
            message.contains("origin"),
            "the error must say why it was refused: {message}"
        );
        assert_eq!(
            mock.jwks_fetch_count(),
            0,
            "the refusal must precede any outbound request"
        );
    }
}

/// The escape hatch: a provider whose JWKS lives on a CDN is supported by naming
/// that URL in configuration. An explicit value is the operator's statement, so
/// it is not origin-checked — the point of the guard is the *document*, not the
/// operator.
#[tokio::test]
async fn an_explicitly_configured_endpoint_is_taken_as_is() {
    let mock = start_mock().await;
    // Same loopback address, different port: a different origin, still reachable.
    let jwks_host = start_mock().await;
    let provider = OidcProvider::discover(
        OidcConfig {
            issuer: mock.base.clone(),
            client_id: CLIENT_ID.to_string(),
            client_secret: "secret".to_string(),
            redirect_uri: format!("{ISSUER}/auth/callback"),
            scopes: vec!["openid".to_string()],
            discovery_url: Some(format!("{}/.well-known/openid-configuration", mock.base)),
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: Some(format!("{}/jwks", jwks_host.base)),
        },
        GuardedClient::with_policy(OutboundPolicy::AllowLoopback, true).expect("http client"),
        Arc::new(SystemClock),
    )
    .await
    .expect("an explicitly configured endpoint is not origin-checked");

    assert_eq!(provider.jwks_uri(), format!("{}/jwks", jwks_host.base));
    assert_eq!(
        jwks_host.jwks_fetch_count(),
        1,
        "the configured host was used"
    );
    assert_eq!(
        mock.jwks_fetch_count(),
        0,
        "the document's jwks_uri must not be used when config names one"
    );
}

async fn setup() -> TestApp {
    let mock = start_mock().await;
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("store");
    let key_path = std::env::temp_dir().join(format!("re0auth-auth-{}.pem", uuid::Uuid::now_v7()));
    let key = KeyGuard(key_path.clone());
    let signer =
        Arc::new(RsaTokenSigner::load_or_generate(&key_path, ISSUER, 1_000, &[]).expect("signer"));
    let clock = Arc::new(SystemClock);
    let random = Arc::new(OsRandom);
    let provider = Arc::new(
        OidcProvider::discover(
            OidcConfig {
                issuer: mock.base.clone(),
                client_id: CLIENT_ID.to_string(),
                client_secret: "secret".to_string(),
                redirect_uri: format!("{ISSUER}/auth/callback"),
                scopes: vec!["openid".to_string(), "profile".to_string()],
                discovery_url: Some(format!("{}/.well-known/openid-configuration", mock.base)),
                authorization_endpoint: None,
                token_endpoint: None,
                jwks_uri: None,
            },
            // Local mock IdP on 127.0.0.1: the only policy that admits loopback.
            GuardedClient::with_policy(OutboundPolicy::AllowLoopback, true).expect("http client"),
            clock.clone(),
        )
        .await
        .expect("discover idp"),
    );
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
        vec![re0auth_app::auth::NamedIdp {
            name: "test-idp".to_string(),
            client: provider,
        }],
        signer,
        clock,
        random,
        ISSUER,
    );
    let client_id = ClientId::new();
    store
        .clients()
        .insert(
            &Client {
                id: client_id,
                name: "Test client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                allowed_scopes: vec!["openid".to_string(), "profile".to_string()],
                raw_access: false,
                status: ClientStatus::Approved,
                secret_hash: None,
                created_at: SystemClock.now(),
                updated_at: SystemClock.now(),
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
        router: router(AppState::new(oauth, auth))
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345)))),
        client_id,
        mock,
        _key: key,
    }
}

async fn get_request(app: &TestApp, uri: &str, cookie: Option<&str>) -> axum::response::Response {
    let mut builder = Request::builder().uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    app.router
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

async fn post_form(
    app: &TestApp,
    uri: &str,
    body: String,
    headers: &[(&str, &str)],
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for (key, value) in headers {
        builder = builder.header(*key, *value);
    }
    app.router
        .clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

async fn response_text(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf8")
}

fn set_cookie_names(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or(value).to_string())
        .collect()
}

fn cookie_header(pairs: &[String]) -> String {
    pairs.join("; ")
}

fn cookie_value(pairs: &[String], name: &str) -> String {
    pairs
        .iter()
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
        .expect("cookie value")
        .to_string()
}

/// The login intent cookie set by `/auth/login` or `/device/start`.
///
/// The name depends on whether the issuer is https (`__Host-` prefix), so the
/// tests match on the suffix rather than hard-coding one of the two.
fn login_intent(headers: &HeaderMap) -> String {
    set_cookie_names(headers)
        .into_iter()
        .find(|pair| pair.contains("re0auth_login="))
        .expect("login intent cookie")
}

fn ticket_from_html(html: &str) -> String {
    let marker = "name=\"ticket\" value=\"";
    let start = html.find(marker).expect("ticket marker") + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("ticket end");
    rest[..end].to_string()
}

#[tokio::test]
async fn idp_login_creates_session_and_csrf_exchange() {
    let app = setup().await;
    let authorize_return = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile&code_challenge=abc&code_challenge_method=S256",
        app.client_id.0, REDIRECT_URI
    );
    let login_uri = format!(
        "/auth/login?{}",
        form(&[("return_to", authorize_return.as_str())])
    );
    let login_response = get_request(&app, &login_uri, None).await;
    assert_eq!(login_response.status(), StatusCode::SEE_OTHER);
    let intent = login_intent(login_response.headers());
    let location = login_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorization redirect");
    let authorization = Url::parse(location).expect("authorization url");
    let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
    *app.mock.nonce.lock().expect("nonce") = query["nonce"].clone();

    let callback_uri = format!(
        "/auth/callback?{}",
        form(&[("code", "test-code"), ("state", query["state"].as_str()),])
    );
    let callback = get_request(&app, &callback_uri, Some(&intent)).await;
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        callback
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some(authorize_return.as_str())
    );
    let cookies = set_cookie_names(callback.headers());
    assert_eq!(cookies.len(), 2);
    let cookie = cookie_header(&cookies);
    let csrf = cookie_value(&cookies, "re0auth_csrf");

    let replay = get_request(&app, &callback_uri, Some(&intent)).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

    let me = get_request(&app, "/api/me", Some(&cookie)).await;
    assert_eq!(me.status(), StatusCode::OK);
    let me_body: Value = serde_json::from_str(&response_text(me).await).expect("me json");
    assert_eq!(me_body["user"]["display_name"], "Alice");
    assert_eq!(me_body["csrf_token"], csrf);

    let wrong_csrf = post_form(
        &app,
        "/api/logout",
        String::new(),
        &[
            (header::COOKIE.as_str(), cookie.as_str()),
            ("x-csrf-token", "wrong"),
        ],
    )
    .await;
    assert_eq!(wrong_csrf.status(), StatusCode::FORBIDDEN);

    let logout = post_form(
        &app,
        "/api/logout",
        String::new(),
        &[
            (header::COOKIE.as_str(), cookie.as_str()),
            ("x-csrf-token", csrf.as_str()),
        ],
    )
    .await;
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    let me_after = get_request(&app, "/api/me", Some(&cookie)).await;
    assert_eq!(me_after.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_rejects_unknown_state_and_wrong_nonce() {
    let app = setup().await;
    let bad_state = get_request(
        &app,
        "/auth/callback?code=test-code&state=unknown",
        Some("re0auth_login=unknown"),
    )
    .await;
    assert_eq!(bad_state.status(), StatusCode::BAD_REQUEST);

    let login_uri = format!(
        "/auth/login?{}",
        form(&[("return_to", "/oauth/authorize?client_id=test")])
    );
    let login = get_request(&app, &login_uri, None).await;
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let intent = login_intent(login.headers());
    let location = login
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorization redirect");
    let authorization = Url::parse(location).expect("authorization url");
    let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
    *app.mock.nonce.lock().expect("nonce") = "wrong-nonce".to_string();

    let callback = get_request(
        &app,
        &format!(
            "/auth/callback?{}",
            form(&[("code", "test-code"), ("state", query["state"].as_str()),])
        ),
        Some(&intent),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::BAD_REQUEST);
    assert!(callback.headers().get(header::SET_COOKIE).is_none());
}
/// INV-LOGIN-05: a callback URL completed in another browser must not create a
/// session. Capturing such a URL is how login CSRF turns into an attacker-owned
/// session.
#[tokio::test]
async fn login_callback_from_another_browser_is_rejected() {
    let app = setup().await;
    let login = get_request(&app, "/auth/login?return_to=%2F", None).await;
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let location = login
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorization redirect");
    let authorization = Url::parse(location).expect("authorization url");
    let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
    *app.mock.nonce.lock().expect("nonce") = query["nonce"].clone();
    let callback_uri = format!(
        "/auth/callback?{}",
        form(&[("code", "test-code"), ("state", query["state"].as_str()),])
    );

    let missing = get_request(&app, &callback_uri, None).await;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    assert!(
        missing.headers().get(header::SET_COOKIE).is_none(),
        "a callback without the intent cookie must not issue a session"
    );

    let wrong = get_request(&app, &callback_uri, Some("re0auth_login=other")).await;
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
    assert!(
        wrong.headers().get(header::SET_COOKIE).is_none(),
        "a mismatched intent cookie must not issue a session"
    );
}

#[tokio::test]
async fn device_approval_ticket_is_one_time_and_has_no_session_cookie() {
    let app = setup().await;
    let device = post_form(
        &app,
        "/oauth/device_authorization",
        form(&[
            ("client_id", app.client_id.0.to_string().as_str()),
            ("scope", "openid profile"),
        ]),
        &[],
    )
    .await;
    assert_eq!(device.status(), StatusCode::OK);
    let device_body: Value =
        serde_json::from_str(&response_text(device).await).expect("device json");
    let user_code = device_body["user_code"].as_str().expect("user code");
    let device_code = device_body["device_code"].as_str().expect("device code");

    let qr = get_request(
        &app,
        &format!("/device/qr.svg?{}", form(&[("user_code", user_code)])),
        None,
    )
    .await;
    assert_eq!(qr.status(), StatusCode::OK);
    assert_eq!(
        qr.headers().get(header::CONTENT_TYPE).unwrap(),
        "image/svg+xml"
    );
    assert!(response_text(qr).await.contains("<svg"));

    let device_page = get_request(
        &app,
        &format!("/device/start?{}", form(&[("user_code", user_code)])),
        None,
    )
    .await;
    assert_eq!(device_page.status(), StatusCode::SEE_OTHER);
    let intent = login_intent(device_page.headers());
    let location = device_page
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorization redirect");
    let authorization = Url::parse(location).expect("authorization url");
    let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
    *app.mock.nonce.lock().expect("nonce") = query["nonce"].clone();

    let callback = get_request(
        &app,
        &format!(
            "/auth/callback?{}",
            form(&[("code", "device-code"), ("state", query["state"].as_str()),])
        ),
        Some(&intent),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::OK);
    assert!(
        callback.headers().get(header::SET_COOKIE).is_none(),
        "device approval must not set a session cookie"
    );
    let html = response_text(callback).await;
    let ticket = ticket_from_html(&html);

    let approve = post_form(
        &app,
        "/device/approve",
        form(&[("ticket", ticket.as_str())]),
        &[],
    )
    .await;
    assert_eq!(approve.status(), StatusCode::OK);
    assert!(response_text(approve).await.contains("设备已批准"));

    let token = post_form(
        &app,
        "/oauth/token",
        form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", app.client_id.0.to_string().as_str()),
            ("device_code", device_code),
        ]),
        &[],
    )
    .await;
    assert_eq!(token.status(), StatusCode::OK);
    let token_body: Value = serde_json::from_str(&response_text(token).await).expect("token json");
    assert!(token_body["access_token"].as_str().is_some());

    let replay = post_form(
        &app,
        "/device/approve",
        form(&[("ticket", ticket.as_str())]),
        &[],
    )
    .await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

    for _ in 0..5 {
        let bad = get_request(
            &app,
            &format!("/device/start?{}", form(&[("user_code", "ZZZZ-ZZZZ")])),
            None,
        )
        .await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    }
    let limited = get_request(
        &app,
        &format!("/device/start?{}", form(&[("user_code", "ZZZZ-ZZZZ")])),
        None,
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
}

/// INV-TOKEN-02: an IdP that rotates its signing key must not require a restart.
/// Before the refresh path existed, this failed with "unknown kid" until the
/// process was restarted.
#[tokio::test]
async fn a_rotated_signing_key_is_picked_up_without_a_restart() {
    let mock = start_mock().await;
    let clock = ManualClock::new(1_000_000);
    let provider = provider_for(&mock, Arc::new(clock.clone())).await;

    // The pre-rotation key verifies.
    mock.nonce.lock().expect("nonce").clear();
    let first = provider.exchange_code("code", "verifier", "").await;
    assert!(first.is_ok(), "the original key must verify: {first:?}");

    let fetches_before = mock.jwks_fetch_count();

    // Rotate: the IdP now publishes a different kid. The clock is advanced past
    // the cooldown because the refresh is bounded by design — "picked up within
    // one cooldown window" is the real guarantee, not "picked up instantly".
    mock.rotate("rotated-key");
    clock.advance(61);
    let second = provider.exchange_code("code", "verifier", "").await;
    assert!(
        second.is_ok(),
        "a rotated key must verify without a restart: {second:?}"
    );
    assert!(
        mock.jwks_fetch_count() > fetches_before,
        "the unknown kid must trigger a JWKS refresh"
    );
}

/// INV-TOKEN-02: an unknown kid refreshes at most once per cooldown window.
/// Without the floor, a caller presenting random kids could make us hammer the
/// IdP on every request.
#[tokio::test]
async fn repeated_unknown_kids_do_not_hammer_the_idp() {
    let mock = start_mock().await;
    let clock = ManualClock::new(1_000_000);
    let provider = provider_for(&mock, Arc::new(clock.clone())).await;
    mock.force_kid(Some("never-published"));

    // Three attempts inside one cooldown window.
    for attempt in 0..3 {
        let result = provider.exchange_code("code", "verifier", "").await;
        assert!(
            result.is_err(),
            "attempt {attempt}: a kid the IdP never publishes must not verify"
        );
    }
    let during_cooldown = mock.jwks_fetch_count();
    assert_eq!(
        during_cooldown, 2,
        "the initial discover fetch plus exactly one refresh; got {during_cooldown}"
    );

    // Past the cooldown, another unknown kid is allowed one more fetch.
    clock.advance(61);
    let _ = provider.exchange_code("code", "verifier", "").await;
    assert_eq!(
        mock.jwks_fetch_count(),
        3,
        "the cooldown must expire, not disable refreshing"
    );
}

/// INV-IDP-01: an unknown provider name must be refused, not silently replaced
/// by the only configured one. Silent fallback is how a user ends up logged in
/// through a provider they did not pick.
#[tokio::test]
async fn login_rejects_an_unknown_provider_name() {
    let app = setup().await;
    for uri in [
        "/auth/login?idp=nope",
        "/auth/login?idp=test-idp-2",
        "/auth/login?idp=Test-Idp",
    ] {
        let response = get_request(&app, uri, None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    }
}

/// Runs the login far enough to exchange the code, and returns the callback
/// response. The nonce is copied into the mock from the authorization URL, which
/// is what a real provider does out of band.
async fn complete_login(app: &TestApp) -> axum::response::Response {
    let login = get_request(app, "/auth/login?return_to=%2F", None).await;
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let intent = login_intent(login.headers());
    let location = login
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorization redirect");
    let authorization = Url::parse(location).expect("authorization url");
    let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
    *app.mock.nonce.lock().expect("nonce") = query["nonce"].clone();
    let callback_uri = format!(
        "/auth/callback?{}",
        form(&[("code", "test-code"), ("state", query["state"].as_str()),])
    );
    get_request(app, &callback_uri, Some(&intent)).await
}

/// ADR-0047 / `IDP-SETUP.md` §2: PKCE is always sent, and the discovery document
/// is not consulted for it. The mock provider deliberately omits
/// `code_challenge_methods_supported`, so this asserts the unconditional send.
#[tokio::test]
async fn the_authorization_url_always_carries_a_pkce_challenge() {
    let app = setup().await;
    let login = get_request(&app, "/auth/login?return_to=%2F", None).await;
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let location = login
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorization redirect");
    let authorization = Url::parse(location).expect("authorization url");
    let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();

    assert_eq!(query["code_challenge_method"], "S256");
    // S256 sends base64url(SHA-256(verifier)): 32 bytes, no padding.
    assert_eq!(
        query["code_challenge"].len(),
        43,
        "{}",
        query["code_challenge"]
    );
}

/// ADR-0047 / `IDP-SETUP.md` §2: only `client_secret_post` is implemented.
#[tokio::test]
async fn the_token_exchange_authenticates_with_a_form_field() {
    let app = setup().await;
    let callback = complete_login(&app).await;
    assert_eq!(
        callback.status(),
        StatusCode::SEE_OTHER,
        "the login completes"
    );

    let auth = app
        .mock
        .last_token_auth
        .lock()
        .expect("token auth")
        .expect("the token endpoint was called");
    assert!(
        auth.form_secret,
        "client_secret must travel in the form: {auth:?}"
    );
    assert!(
        !auth.basic,
        "client_secret_basic is not implemented; sending it would be a new capability: {auth:?}"
    );
}

/// The configured name is selectable, and an empty `idp=` is treated as absent
/// so a stray query parameter does not turn a working link into an error.
#[tokio::test]
async fn login_accepts_the_configured_provider_and_an_empty_selector() {
    let app = setup().await;
    for uri in ["/auth/login?idp=test-idp", "/auth/login?idp="] {
        let response = get_request(&app, uri, None).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{uri}");
    }
}

/// The destination the login flow comes back to is a path on this origin.
///
/// `/%09//evil.example` decodes to `/\t//evil.example`, which a naive prefix
/// check accepts; a browser strips the tab while parsing and lands on
/// `//evil.example`, i.e. another host. The whole point of the guard.
#[tokio::test]
async fn login_refuses_a_destination_that_hides_another_origin() {
    let app = setup().await;
    for raw in [
        "//evil.example",
        "/\t/evil.example",
        "/\n/evil.example",
        "https://evil.example/",
        "/\\evil.example",
    ] {
        let uri = format!("/auth/login?{}", form(&[("return_to", raw)]));
        let response = get_request(&app, &uri, None).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{raw:?} must not become a redirect target"
        );
    }
    let accepted = get_request(&app, "/auth/login?return_to=%2Faccount", None).await;
    assert_eq!(accepted.status(), StatusCode::SEE_OTHER);
}

/// INV-IDP-01: the callback ignores `idp` from the query string. It must follow
/// the provider recorded when the login started, otherwise a caller could
/// present one IdP's code to another IdP's token endpoint.
#[tokio::test]
async fn the_callback_ignores_a_caller_supplied_provider() {
    let app = setup().await;
    let login = get_request(&app, "/auth/login?return_to=%2F", None).await;
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let location = login
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("authorization redirect");
    let authorization = Url::parse(location).expect("authorization url");
    let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
    *app.mock.nonce.lock().expect("nonce") = query["nonce"].clone();

    let intent = login_intent(login.headers());
    // A name that does not exist: honouring it would fail the whole callback.
    let callback_uri = format!(
        "/auth/callback?{}",
        form(&[
            ("code", "test-code"),
            ("state", query["state"].as_str()),
            ("idp", "does-not-exist"),
        ])
    );
    let callback = get_request(&app, &callback_uri, Some(&intent)).await;
    assert_eq!(
        callback.status(),
        StatusCode::SEE_OTHER,
        "the transaction's provider must win over the query parameter"
    );
}

/// OIDC Core 3.1.3.7: an `aud` that lists this client *and* another one is only
/// acceptable when `azp` is verified. This provider does not verify `azp`, so the
/// token must be refused rather than accepted on the intersection alone.
#[tokio::test]
async fn an_id_token_with_an_untrusted_extra_audience_is_rejected() {
    let mock = start_mock().await;
    let provider = provider_for(&mock, Arc::new(ManualClock::new(1_000_000))).await;
    mock.force_audience(Some(json!([CLIENT_ID, "some-other-client"])));

    let result = provider.exchange_code("code", "verifier", "").await;
    let error = result.expect_err("an extra audience must be refused");
    assert!(
        error.to_string().contains("audience"),
        "expected an audience rejection, got {error}"
    );
}

/// A single-element array naming this client is still a well-formed id token.
#[tokio::test]
async fn an_id_token_with_a_single_element_audience_array_is_accepted() {
    let mock = start_mock().await;
    let provider = provider_for(&mock, Arc::new(ManualClock::new(1_000_000))).await;
    mock.force_audience(Some(json!([CLIENT_ID])));

    let identity = provider
        .exchange_code("code", "verifier", "")
        .await
        .expect("a single-audience array must verify");
    assert_eq!(identity.subject, "idp-user-1");
}

/// RFC 7515 §4.1.6 and OIDC Core 3.1.3.7: the id token must be a JWT. An access
/// token (`at+jwt`) presented in its place must not be accepted.
#[tokio::test]
async fn an_id_token_with_a_foreign_typ_header_is_rejected() {
    let mock = start_mock().await;
    let provider = provider_for(&mock, Arc::new(ManualClock::new(1_000_000))).await;
    mock.force_header_typ(Some("at+jwt"));

    let result = provider.exchange_code("code", "verifier", "").await;
    let error = result.expect_err("a foreign typ must be refused");
    assert!(error.to_string().contains("typ"), "{error}");
}

/// Google/Discord serve a minimal discovery document; Microsoft serves one whose
/// issuer carries a tenant path. Both must configure and verify through the same
/// code path, so the issuer comparison cannot be host-only or path-insensitive.
#[tokio::test]
async fn an_issuer_with_a_tenant_path_is_compared_verbatim() {
    let mock = start_mock().await;
    let tenant_issuer = format!("{}/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0", mock.base);

    // The mock signs with `mock.base`; configuring the tenant form must fail
    // rather than pass on a shared host.
    let provider = OidcProvider::discover(
        OidcConfig {
            issuer: tenant_issuer.clone(),
            client_id: CLIENT_ID.to_string(),
            client_secret: "secret".to_string(),
            redirect_uri: format!("{ISSUER}/auth/callback"),
            scopes: vec!["openid".to_string()],
            discovery_url: Some(format!("{}/.well-known/openid-configuration", mock.base)),
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
        },
        GuardedClient::with_policy(OutboundPolicy::AllowLoopback, true).expect("http client"),
        Arc::new(ManualClock::new(1_000_000)),
    )
    .await;
    let error = match provider {
        Ok(_) => panic!("a discovery issuer mismatch must fail at startup"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("issuer mismatch"),
        "expected an issuer mismatch, got {error}"
    );
}

/// Discord's discovery omits `scopes_supported`, `claims_supported` and
/// `token_endpoint_auth_methods_supported`. None of them may be required, or a
/// provider would be rejected for a field it never needed.
///
/// This also covers the branch that skips discovery entirely: when all three
/// endpoints are configured, the document is never fetched.
#[tokio::test]
async fn explicit_endpoints_work_without_a_discovery_document() {
    let mock = start_mock().await;
    let provider = OidcProvider::discover(
        OidcConfig {
            issuer: mock.base.clone(),
            client_id: CLIENT_ID.to_string(),
            client_secret: "secret".to_string(),
            redirect_uri: format!("{ISSUER}/auth/callback"),
            scopes: vec!["openid".to_string()],
            // A discovery URL that would 404 if it were ever requested.
            discovery_url: Some(format!("{}/does-not-exist", mock.base)),
            authorization_endpoint: Some(format!("{}/authorize", mock.base)),
            token_endpoint: Some(format!("{}/token", mock.base)),
            jwks_uri: Some(format!("{}/jwks", mock.base)),
        },
        GuardedClient::with_policy(OutboundPolicy::AllowLoopback, true).expect("http client"),
        Arc::new(ManualClock::new(1_000_000)),
    )
    .await
    .expect("explicit endpoints must not need discovery");

    let identity = provider
        .exchange_code("code", "verifier", "")
        .await
        .expect("the token endpoint is configured, so login must work");
    assert_eq!(identity.subject, "idp-user-1");
}

/// An IdP publishing two keys under one `kid` is malformed. Picking the first
/// would verify against an arbitrary one of them, so the set is refused.
///
/// The flag is set before `discover` because that call already fetches the JWKS;
/// setting it afterwards would leave the cached set well-formed.
#[tokio::test]
async fn duplicate_kids_in_the_jwks_are_rejected() {
    let mock = start_mock().await;
    mock.publish_duplicate_kid(true);
    let provider = provider_for(&mock, Arc::new(ManualClock::new(1_000_000))).await;

    let result = provider.exchange_code("code", "verifier", "").await;
    let error = result.expect_err("an ambiguous kid must be refused");
    assert!(error.to_string().contains("ambiguous"), "{error}");
}
