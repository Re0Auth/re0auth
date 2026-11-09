//! End-to-end data-plane route test.
//!
//! Exercises the real HTTP router, the real gateway use case, a real SQLite
//! store and a real `AesGcmSealer`. Only the upstream itself is mocked, which is
//! the point: it proves the whole chain is wired, not just the units.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use re0auth_adapters::clock::SystemClock;
use re0auth_adapters::crypto::RsaTokenSigner;
use re0auth_adapters::random::OsRandom;
use re0auth_adapters::sealer::AesGcmSealer;
use re0auth_adapters::storage::SqliteStore;
use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::connector::{ConnectorEndpoint, EgressPolicy, ResourceSpec, UpstreamPayload};
use re0auth_api::oauth::{AccessTokenClaims, ConsentVersion, TokenSigner};
use re0auth_api::ports::{
    Binding, BindingStatus, Client, ClientStatus, Consent, Storage, User, UserRole,
};
use re0auth_api::secret::SecretSealer;
use re0auth_api::view::{FieldMapping, JsonPath, ViewSpec};
use re0auth_api::{BindingId, ClientId, Clock, ConsentId, SecretString, UserId};
use re0auth_app::auth::AuthService;
use re0auth_app::circuit::{CircuitPolicy, CircuitTracker};
use re0auth_app::gateway::GatewayService;
use re0auth_app::oauth::OAuthService;
use re0auth_contract::{ConnectorFixture, MockConnector};
use tower::ServiceExt;

const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const ISSUER: &str = "https://issuer.test";
const TEST_MASTER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SCOPE: &str = "probe.records.read";

struct Fixture {
    router: axum::Router,
    signer: Arc<RsaTokenSigner>,
    user: UserId,
    client_id: ClientId,
    store: Arc<SqliteStore>,
    connector: Arc<MockConnector>,
}

async fn fixture() -> Fixture {
    fixture_with_rate(Arc::new(re0auth_api::rate::Unlimited)).await
}

async fn fixture_with_rate(rate: Arc<dyn re0auth_api::rate::RateLimiter>) -> Fixture {
    let store = Arc::new(
        SqliteStore::connect("sqlite::memory:")
            .await
            .expect("in-memory store"),
    );
    let clock = Arc::new(SystemClock);
    let random = Arc::new(OsRandom);
    let key_path = std::env::temp_dir().join(format!("route-test-{}.pem", uuid::Uuid::now_v7()));
    let signer = Arc::new(
        RsaTokenSigner::load_or_generate(key_path.as_path(), ISSUER, 1_000, &[]).expect("signer"),
    );

    let user = UserId::new();
    let now = clock.now();
    store
        .users()
        .create(&User {
            id: user,
            display_name: "probe".to_string(),
            role: UserRole::User,
            status: re0auth_api::ports::UserStatus::Active,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("insert user");

    let client_id = ClientId::new();
    let allowed_scopes = vec![SCOPE.to_string(), "openid".to_string()];
    store
        .clients()
        .insert(
            &Client {
                id: client_id,
                name: "test-client".to_string(),
                redirect_uris: vec![],
                allowed_scopes: allowed_scopes.clone(),
                raw_access: false,
                status: ClientStatus::Approved,
                secret_hash: None,
                created_at: now,
                updated_at: now,
            },
            &SecurityFact::new(AuditAction::ClientCreated, now, "client:test"),
        )
        .await
        .expect("insert client");
    store
        .consents()
        .grant(
            &Consent {
                id: ConsentId::new(),
                user_id: user,
                client_id,
                scopes: allowed_scopes,
                created_at: now,
                updated_at: now,
                revoked_at: None,
                version: ConsentVersion(0),
            },
            &SecurityFact::new(AuditAction::ConsentGranted, now, "consent:test"),
        )
        .await
        .expect("insert consent");

    let connector = Arc::new(MockConnector::new());
    let connector_id = re0auth_app::gateway::connector_id_for_name("probe");
    connector.register(ConnectorEndpoint {
        id: connector_id,
        name: "probe".to_string(),
        base_url: "https://upstream.test".to_string(),
        egress: EgressPolicy::Public,

        resources: vec![
            ResourceSpec::new("scores", "/v1/scores/{subject}")
                .expect("spec")
                .with_scope(SCOPE)
                .expect("scope"),
            // A single-object view: renames upstream fields (ADR-0049).
            ResourceSpec::new("profile", "/v1/profile/{subject}")
                .expect("spec")
                .with_scope(SCOPE)
                .expect("scope")
                .with_view(ViewSpec {
                    data_path: JsonPath::parse("$.data").expect("path"),
                    items_path: None,
                    fields: vec![FieldMapping {
                        name: "player".to_string(),
                        path: JsonPath::parse("$.user.id").expect("path"),
                    }],
                }),
            // A list view: the only shape that accepts limit/cursor.
            ResourceSpec::new("records", "/v1/records/{subject}")
                .expect("spec")
                .with_scope(SCOPE)
                .expect("scope")
                .with_view(ViewSpec {
                    data_path: JsonPath::parse("$").expect("path"),
                    items_path: Some(JsonPath::parse("$.data.items").expect("path")),
                    fields: vec![FieldMapping {
                        name: "id".to_string(),
                        path: JsonPath::parse("$.id").expect("path"),
                    }],
                }),
        ],
    });

    let sealer = Arc::new(AesGcmSealer::new(KEY, random.clone()).expect("sealer"));
    let binding_id = BindingId::new();
    store
        .bindings()
        .upsert(
            &Binding {
                id: binding_id,
                user_id: user,
                upstream_id: "probe".to_string(),
                upstream_user_id: "player-1".to_string(),
                status: BindingStatus::Active,
                created_at: now,
                updated_at: now,
                last_refreshed_at: None,
                last_error_code: None,
            },
            &SecurityFact::new(
                AuditAction::BindingCreated,
                now,
                format!("binding:{}", binding_id.0),
            ),
        )
        .await
        .expect("insert binding");
    let sealed = sealer
        .seal(
            &binding_id,
            &SecretString::from("sub-token-abc".to_string()),
        )
        .expect("seal");
    store
        .bindings()
        .store_sub_credential(&binding_id, &sealed, now)
        .await
        .expect("store credential");

    let oauth = OAuthService::new(
        store.clone(),
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
        store.clone(),
        vec![],
        signer.clone(),
        clock.clone(),
        random,
        ISSUER,
    );
    let gateway = GatewayService::new(
        store.clone(),
        connector.clone() as Arc<dyn re0auth_api::connector::ConnectorRegistry>,
        connector.clone() as Arc<dyn re0auth_api::connector::ConnectorBroker>,
        sealer,
        clock,
        Arc::new(CircuitTracker::new(CircuitPolicy::default())),
        4 * 1024 * 1024,
    );
    let state = re0auth_http::AppState::new(oauth, auth)
        .with_gateway(Arc::new(gateway))
        .with_rate_limiter(rate);

    Fixture {
        router: re0auth_http::router(state).layer(MockConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            1234,
        )))),
        signer,
        user,
        client_id,
        store,
        connector,
    }
}

/// Mints a real access token through the real signer, so the route verifies a
/// genuine JWT rather than a stub.
fn access_token(fixture: &Fixture, scope: &str) -> String {
    access_token_with_version(fixture, scope, ConsentVersion(1))
}

fn access_token_with_version(fixture: &Fixture, scope: &str, version: ConsentVersion) -> String {
    let now = chrono_like_now();
    fixture
        .signer
        .sign_access(&AccessTokenClaims {
            iss: ISSUER.to_string(),
            sub: fixture.user.0.to_string(),
            aud: format!("{ISSUER}/api/v1"),
            client_id: fixture.client_id.0.to_string(),
            scope: scope.to_string(),
            exp: now + 900,
            iat: now,
            jti: "test-jti".to_string(),
            token_use: "access".to_string(),
            family_id: "00000000-0000-0000-0000-000000000000".to_string(),
            consent_version: version,
        })
        .expect("sign access token")
}

fn chrono_like_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

async fn get(fixture: &Fixture, uri: &str, token: Option<&str>) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder().uri(uri);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = fixture
        .router
        .clone()
        .oneshot(request.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, body.to_vec())
}

#[tokio::test]
async fn missing_token_is_rejected_before_any_upstream_call() {
    let fixture = fixture().await;
    let (status, _) = get(&fixture, "/api/v1/upstreams/probe/scores", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(fixture.connector.calls().is_empty());
}

#[tokio::test]
async fn unknown_connector_is_not_found_without_calling_upstream() {
    let fixture = fixture().await;
    let token = access_token(&fixture, SCOPE);
    let (status, _) = get(&fixture, "/api/v1/upstreams/nope/scores", Some(&token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(fixture.connector.calls().is_empty());
}

#[tokio::test]
async fn unregistered_resource_is_not_found_without_calling_upstream() {
    let fixture = fixture().await;
    let token = access_token(&fixture, SCOPE);
    let (status, _) = get(&fixture, "/api/v1/upstreams/probe/unknown", Some(&token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(fixture.connector.calls().is_empty());
}

#[tokio::test]
async fn missing_scope_is_forbidden_and_never_reaches_upstream() {
    let fixture = fixture().await;
    let token = access_token(&fixture, "openid");
    let (status, _) = get(&fixture, "/api/v1/upstreams/probe/scores", Some(&token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(fixture.connector.calls().is_empty());
}

#[tokio::test]
async fn successful_fetch_reaches_the_connector_with_the_binding_subject() {
    let fixture = fixture().await;
    fixture.connector.set_response(
        "scores",
        Ok(UpstreamPayload {
            content_type: "application/json".to_string(),
            body: br#"{"rks":15.2}"#.to_vec(),
        }),
    );
    let token = access_token(&fixture, SCOPE);
    let (status, body) = get(&fixture, "/api/v1/upstreams/probe/scores", Some(&token)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&body)
    );
    // The normalized lane answers with the envelope (ADR-0049).
    let envelope: serde_json::Value = serde_json::from_slice(&body).expect("envelope is JSON");
    assert_eq!(envelope["data"], serde_json::json!({"rks": 15.2}));
    assert_eq!(envelope["upstream"], "probe");
    assert_eq!(envelope["endpoint"], "scores");
    assert_eq!(envelope["stability"], "declared");

    let calls = fixture.connector.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].resource, "scores");
    // The subject comes from the binding, never from the request.
    assert_eq!(calls[0].subject, "player-1");
}

#[tokio::test]
async fn the_gateway_charges_the_user_lane_not_just_the_client_lane() {
    // The client lane is deliberately generous and the user lane is one. If the
    // route only charged the client lane, every request here would succeed and
    // this test would pass for the wrong reason.
    let clock = Arc::new(re0auth_adapters::clock::SystemClock);
    let rate = Arc::new(re0auth_adapters::rate_limit::GovernorLimiter::new(
        re0auth_adapters::rate_limit::RateLimitPolicy {
            unauthenticated: re0auth_adapters::rate_limit::LaneQuota {
                burst: 100,
                period_secs: 60,
            },
            authenticated: re0auth_adapters::rate_limit::LaneQuota {
                burst: 100,
                period_secs: 60,
            },
            per_user: re0auth_adapters::rate_limit::LaneQuota {
                burst: 1,
                period_secs: 60,
            },
        },
        clock,
    ));
    let fixture = fixture_with_rate(rate).await;
    fixture.connector.set_response(
        "scores",
        Ok(UpstreamPayload {
            content_type: "application/json".to_string(),
            body: br#"{"rks":15.2}"#.to_vec(),
        }),
    );
    let token = access_token(&fixture, SCOPE);

    let (first, _) = get(&fixture, "/api/v1/upstreams/probe/scores", Some(&token)).await;
    assert_eq!(first, StatusCode::OK, "the user budget must admit one");

    let (second, body) = get(&fixture, "/api/v1/upstreams/probe/scores", Some(&token)).await;
    assert_eq!(
        second,
        StatusCode::TOO_MANY_REQUESTS,
        "the user lane was never charged: {}",
        String::from_utf8_lossy(&body)
    );
    // Only the first call reached the upstream; the second was refused before it.
    assert_eq!(fixture.connector.calls().len(), 1);
}

#[tokio::test]
async fn revoked_consent_blocks_the_gateway_before_the_upstream() {
    let fixture = fixture().await;
    fixture.connector.set_response(
        "scores",
        Ok(UpstreamPayload {
            content_type: "application/json".to_string(),
            body: br#"{"rks":15.2}"#.to_vec(),
        }),
    );
    let token = access_token(&fixture, SCOPE);
    let uri = "/api/v1/upstreams/probe/scores";

    let (status, _) = get(&fixture, uri, Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fixture.connector.calls().len(), 1);

    let now = SystemClock.now();
    fixture
        .store
        .consents()
        .revoke(
            &fixture.user,
            &fixture.client_id,
            &SecurityFact::new(AuditAction::ConsentRevoked, now, "consent:test"),
            now,
        )
        .await
        .expect("revoke consent");

    let (status, _) = get(&fixture, uri, Some(&token)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a revoked consent must fail before the gateway is reached"
    );
    assert_eq!(
        fixture.connector.calls().len(),
        1,
        "the revoked token must not reach the upstream"
    );
}

#[tokio::test]
async fn an_old_access_token_version_is_rejected_before_the_upstream() {
    let fixture = fixture().await;
    fixture.connector.set_response(
        "scores",
        Ok(UpstreamPayload {
            content_type: "application/json".to_string(),
            body: br#"{"rks":15.2}"#.to_vec(),
        }),
    );
    // Version 0 is what a pre-consent-version token decodes to.
    let token = access_token_with_version(&fixture, SCOPE, ConsentVersion(0));

    let (status, _) = get(&fixture, "/api/v1/upstreams/probe/scores", Some(&token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        fixture.connector.calls().len(),
        0,
        "an old token must not reach the upstream"
    );
}

// ---- normalized views and pagination (ADR-0049) --------------------------

#[tokio::test]
async fn a_single_view_renames_fields_inside_the_envelope() {
    let fixture = fixture().await;
    fixture.connector.set_response(
        "profile",
        Ok(UpstreamPayload {
            content_type: "application/json".to_string(),
            body: br#"{"data":{"user":{"id":"player-1"},"extra":1}}"#.to_vec(),
        }),
    );
    let token = access_token(&fixture, SCOPE);
    let (status, body) = get(&fixture, "/api/v1/upstreams/probe/profile", Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let envelope: serde_json::Value = serde_json::from_slice(&body).expect("envelope");
    assert_eq!(envelope["data"], serde_json::json!({"player": "player-1"}));
    assert_eq!(envelope["upstream"], "probe");
    assert_eq!(envelope["endpoint"], "profile");
    assert_eq!(envelope["stability"], "declared");
}

#[tokio::test]
async fn a_list_view_paginates_with_an_opaque_cursor() {
    let fixture = fixture().await;
    fixture.connector.set_response(
        "records",
        Ok(UpstreamPayload {
            content_type: "application/json".to_string(),
            body: br#"{"data":{"items":[{"id":"a"},{"id":"b"},{"id":"c"},{"id":"d"},{"id":"e"}]}}"#
                .to_vec(),
        }),
    );
    let token = access_token(&fixture, SCOPE);

    let (status, body) = get(
        &fixture,
        "/api/v1/upstreams/probe/records?limit=2",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let first: serde_json::Value = serde_json::from_slice(&body).expect("envelope");
    assert_eq!(
        first["data"]["items"],
        serde_json::json!([{"id": "a"}, {"id": "b"}])
    );
    let cursor = first["data"]["next_cursor"]
        .as_str()
        .expect("more pages")
        .to_string();

    let path = format!("/api/v1/upstreams/probe/records?limit=2&cursor={cursor}");
    let (status, body) = get(&fixture, &path, Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let second: serde_json::Value = serde_json::from_slice(&body).expect("envelope");
    assert_eq!(
        second["data"]["items"],
        serde_json::json!([{"id": "c"}, {"id": "d"}])
    );
    let cursor = second["data"]["next_cursor"]
        .as_str()
        .expect("more pages")
        .to_string();

    let path = format!("/api/v1/upstreams/probe/records?limit=2&cursor={cursor}");
    let (status, body) = get(&fixture, &path, Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let last: serde_json::Value = serde_json::from_slice(&body).expect("envelope");
    assert_eq!(last["data"]["items"], serde_json::json!([{"id": "e"}]));
    assert!(
        last["data"]["next_cursor"].is_null(),
        "the last page has no cursor"
    );
}

#[tokio::test]
async fn pagination_belongs_only_to_list_views() {
    let fixture = fixture().await;
    let token = access_token(&fixture, SCOPE);
    let (status, body) = get(
        &fixture,
        "/api/v1/upstreams/probe/profile?limit=2",
        Some(&token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let error: serde_json::Value = serde_json::from_slice(&body).expect("problem body");
    assert_eq!(error["code"], "invalid_request");
    assert!(
        fixture.connector.calls().is_empty(),
        "a bad page must not cost an upstream call"
    );
}

#[tokio::test]
async fn an_out_of_range_limit_is_a_client_error() {
    let fixture = fixture().await;
    let token = access_token(&fixture, SCOPE);
    for limit in ["0", "101", "abc"] {
        let path = format!("/api/v1/upstreams/probe/records?limit={limit}");
        let (status, body) = get(&fixture, &path, Some(&token)).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "limit {limit}: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

#[tokio::test]
async fn a_missing_view_path_is_upstream_contract_changed() {
    let fixture = fixture().await;
    fixture.connector.set_response(
        "profile",
        Ok(UpstreamPayload {
            content_type: "application/json".to_string(),
            body: br#"{"data":{"user":{}}}"#.to_vec(),
        }),
    );
    let token = access_token(&fixture, SCOPE);
    let (status, body) = get(&fixture, "/api/v1/upstreams/probe/profile", Some(&token)).await;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let error: serde_json::Value = serde_json::from_slice(&body).expect("problem body");
    assert_eq!(error["code"], "upstream_contract_changed");
}

/// The anonymous budget must be charged before the JWT is verified; otherwise a
/// caller over quota still costs a signature check plus three queries.
struct DenyAll;

impl re0auth_api::rate::RateLimiter for DenyAll {
    fn check(&self, _lane: re0auth_api::rate::Lane, _key: &str) -> re0auth_api::rate::RateDecision {
        re0auth_api::rate::RateDecision::Deny {
            retry_after_secs: 7,
            limit: 1,
            window_secs: 60,
        }
    }

    fn prune(&self) -> usize {
        0
    }
}

#[tokio::test]
async fn s12_over_quota_callers_are_rejected_before_token_verification() {
    let fixture = fixture_with_rate(Arc::new(DenyAll)).await;
    // A forged token would normally be rejected as 401; the point is that the
    // limiter answers first.
    let (status, _) = get(
        &fixture,
        "/api/v1/upstreams/probe/scores",
        Some("not-a-real-token"),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(fixture.connector.calls().is_empty());
}
