use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use futures_util::StreamExt as _;
use re0auth_api::audit::{AccessSource, AccessTelemetry};
use re0auth_api::cache::Cache;
use re0auth_api::connector::{
    AssetStream, BodyField, BodyValue, ConnectorBroker, ConnectorEndpoint, EgressPolicy,
    FaultClass, ResourceMethod, ResourceRequest, ResourceSpec, UpstreamError, UpstreamPayload,
};
use re0auth_api::ports::{
    Binding, BindingStatus, GatewayObserver, Storage, TelemetrySink, User, UserRole, UserStatus,
};
use re0auth_api::secret::SecretSealer;
use re0auth_api::{BindingId, Clock, ConnectorId, Re0Error, SecretString, UserId};
use re0auth_app::circuit::{CircuitPolicy, CircuitTracker};
use re0auth_app::credentials::{CredentialError, CredentialSource};
use re0auth_app::gateway::{GatewayError, GatewayRequest, GatewayService, Pagination};
use re0auth_contract::{
    ClockedCache, ConnectorFixture, MemoryCache, MemoryStore, MockConnector, MockSealer,
};
use secrecy::ExposeSecret;

struct FixedClock(std::sync::Mutex<i64>);

impl FixedClock {
    fn new(now: i64) -> Self {
        Self(std::sync::Mutex::new(now))
    }
}

impl Clock for FixedClock {
    fn now(&self) -> i64 {
        *self.0.lock().expect("clock")
    }
}

struct Harness {
    store: Arc<MemoryStore>,
    connector: Arc<MockConnector>,
    service: GatewayService,
    clock: Arc<FixedClock>,
    user: User,
    binding: Binding,
    connector_id: ConnectorId,
    endpoint: ConnectorEndpoint,
}

async fn harness() -> Harness {
    harness_with_cache(Arc::new(re0auth_api::cache::NoCache)).await
}

async fn harness_with_cache(cache: Arc<dyn re0auth_api::cache::Cache>) -> Harness {
    let now = 1_000;
    let store = Arc::new(MemoryStore::new());
    let user = User {
        id: UserId::new(),
        display_name: "gateway-user".to_string(),
        role: UserRole::User,
        status: re0auth_api::ports::UserStatus::Active,
        created_at: now,
        updated_at: now,
    };
    store.users().create(&user).await.expect("create user");

    let connector = Arc::new(MockConnector::new());
    let connector_id = ConnectorId::new();
    let endpoint = ConnectorEndpoint {
        id: connector_id,
        name: "phigros".to_string(),
        base_url: "https://connector.example".to_string(),
        egress: EgressPolicy::Public,

        resources: vec![
            ResourceSpec::new("scores", "/v1/scores/{subject}")
                .expect("spec")
                .with_scope("scores.read")
                .expect("scope"),
        ],
    };
    connector.register(endpoint.clone());

    let binding = Binding {
        id: BindingId::new(),
        user_id: user.id,
        upstream_id: "phigros".to_string(),
        upstream_user_id: "player-1".to_string(),
        status: BindingStatus::Active,
        created_at: now,
        updated_at: now,
        last_refreshed_at: None,
        last_error_code: None,
    };
    store
        .bindings()
        .upsert(&binding, &fact_binding())
        .await
        .expect("binding");

    let sealer = Arc::new(MockSealer::new());
    let sealed = sealer
        .seal(&binding.id, &SecretString::from("sub-token".to_string()))
        .expect("seal");
    store
        .bindings()
        .store_sub_credential(&binding.id, &sealed, now)
        .await
        .expect("store sub credential");

    let circuit = Arc::new(CircuitTracker::new(CircuitPolicy {
        failure_threshold: 2,
        open_for_secs: 60,
        probe_retry_secs: 1,
    }));
    let clock = Arc::new(FixedClock::new(now));
    let service = GatewayService::new(
        store.clone(),
        connector.clone(),
        connector.clone(),
        sealer,
        clock.clone(),
        circuit,
        1024,
    )
    .with_cache(cache, std::time::Duration::from_secs(300));

    Harness {
        store,
        connector,
        service,
        clock,
        user,
        binding,
        connector_id,
        endpoint,
    }
}

fn empty_params() -> &'static BTreeMap<String, Vec<String>> {
    static EMPTY: std::sync::LazyLock<BTreeMap<String, Vec<String>>> =
        std::sync::LazyLock::new(BTreeMap::new);
    &EMPTY
}

impl Harness {
    fn set_now(&self, now: i64) {
        *self.clock.0.lock().expect("clock") = now;
    }
}

fn request<'a>(
    user: UserId,
    connector_id: ConnectorId,
    scopes: &'a [String],
    resource: &'a str,
) -> GatewayRequest<'a> {
    GatewayRequest {
        user_id: user,
        // Only consulted when `raw` is true; the non-raw path never looks it up.
        client_id: "00000000-0000-0000-0000-000000000000",
        granted_scopes: scopes,
        connector_id,
        resource,
        raw: false,
        correlation_id: None,
        pagination: Pagination::default(),
        params: empty_params(),
    }
}

fn scopes() -> Vec<String> {
    vec!["openid".to_string(), "scores.read".to_string()]
}

fn payload(body: &[u8]) -> UpstreamPayload {
    UpstreamPayload {
        content_type: "application/json".to_string(),
        body: body.to_vec(),
    }
}

#[tokio::test]
async fn missing_scope_is_business_and_never_calls_the_upstream() {
    let app = harness().await;
    let granted = vec!["openid".to_string()];
    let error = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("scope must be enforced");
    assert!(matches!(error, GatewayError::InsufficientScope));
    assert_eq!(error.fault_class(), FaultClass::Business);
    assert!(app.connector.calls().is_empty());
}

#[tokio::test]
async fn traversal_is_rejected_before_the_upstream() {
    let app = harness().await;
    let granted = scopes();
    for resource in ["../scores", "https://evil.example", "scores%2f.."] {
        let error = app
            .service
            .fetch(request(app.user.id, app.connector_id, &granted, resource))
            .await
            .expect_err("resource must be validated");
        assert!(matches!(error, GatewayError::InvalidResource(_)));
        assert_eq!(error.fault_class(), FaultClass::Business);
    }
    assert!(app.connector.calls().is_empty());
}

#[tokio::test]
async fn subject_comes_from_the_binding_never_from_the_caller() {
    let app = harness().await;
    let granted = scopes();
    app.connector
        .set_response("scores", Ok(payload(br#"{"score":1}"#)));
    app.service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect("fetch");

    // The broker saw exactly the binding's upstream id.
    let calls = app.connector.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].subject, "player-1");
    assert_eq!(calls[0].subject, app.binding.upstream_user_id);
}

#[tokio::test]
async fn binding_with_an_unsafe_upstream_id_is_rejected_before_the_upstream() {
    let app = harness().await;
    let granted = scopes();
    let mut hostile = app.binding.clone();
    hostile.upstream_user_id = "../other-player".to_string();
    app.store
        .bindings()
        .upsert(&hostile, &fact_binding())
        .await
        .expect("binding");

    let error = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("unsafe upstream id must never reach the broker");
    assert!(matches!(error, GatewayError::InvalidResource(_)));
    assert_eq!(error.fault_class(), FaultClass::Business);
    assert!(app.connector.calls().is_empty());
}

#[tokio::test]
async fn unregistered_resource_is_business_and_never_calls_the_upstream() {
    let app = harness().await;
    let granted = scopes();
    let error = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "history"))
        .await
        .expect_err("unregistered resource");
    assert!(matches!(error, GatewayError::UnknownResource));
    assert_eq!(error.code(), "endpoint_not_found");
    assert_eq!(error.fault_class(), FaultClass::Business);
    assert!(app.connector.calls().is_empty());
}

#[tokio::test]
async fn missing_binding_is_business_and_writes_no_circuit_state() {
    let app = harness().await;
    let other = app.endpoint.id;
    let stranger = UserId::new();
    // A token always names a real user; the missing thing under test is the
    // binding, not the account.
    app.store
        .users()
        .create(&User {
            id: stranger,
            display_name: "stranger".to_string(),
            role: UserRole::User,
            status: UserStatus::Active,
            created_at: 1_000,
            updated_at: 1_000,
        })
        .await
        .expect("stranger");
    let granted = scopes();
    let error = app
        .service
        .fetch(request(stranger, other, &granted, "scores"))
        .await
        .expect_err("binding required");
    assert!(matches!(error, GatewayError::BindingRequired));
    assert_eq!(error.code(), "binding_required");
    assert_eq!(error.fault_class(), FaultClass::Business);
    assert!(app.connector.calls().is_empty());
    assert_eq!(app.service.retry_after(other, 1_000), None);
}

#[tokio::test]
async fn unknown_connector_is_business() {
    let app = harness().await;
    let granted = scopes();
    let missing = ConnectorId::new();
    let error = app
        .service
        .fetch(request(app.user.id, missing, &granted, "scores"))
        .await
        .expect_err("unknown connector");
    assert!(matches!(error, GatewayError::ConnectorNotFound));
    assert_eq!(error.fault_class(), FaultClass::Business);
    assert_eq!(app.service.retry_after(missing, 1_000), None);
}

#[tokio::test]
async fn upstream_401_marks_needs_reauth_without_tripping_the_breaker() {
    let app = harness().await;
    app.connector
        .set_response("scores", Err(UpstreamError::CredentialExpired));
    let granted = scopes();
    let error = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("401");
    assert!(matches!(
        error,
        GatewayError::Upstream(UpstreamError::CredentialExpired)
    ));
    assert_eq!(error.code(), "upstream_needs_reauth");
    assert_eq!(error.fault_class(), FaultClass::Business);

    let stored = app
        .store
        .bindings()
        .find(&app.user.id, "phigros")
        .await
        .expect("find")
        .expect("binding");
    assert_eq!(stored.status, BindingStatus::NeedsReauth);
    assert_eq!(stored.last_error_code.as_deref(), Some("upstream_401"));
    assert_eq!(app.service.retry_after(app.connector_id, 1_000), None);
}

#[tokio::test]
async fn upstream_403_keeps_the_binding_active() {
    let app = harness().await;
    app.connector
        .set_response("scores", Err(UpstreamError::InsufficientScope));
    let granted = scopes();
    let error = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("403");
    assert!(matches!(
        error,
        GatewayError::Upstream(UpstreamError::InsufficientScope)
    ));
    assert_eq!(error.fault_class(), FaultClass::Business);
    assert_eq!(error.code(), "insufficient_scope");

    let stored = app
        .store
        .bindings()
        .find(&app.user.id, "phigros")
        .await
        .expect("find")
        .expect("binding");
    assert_eq!(stored.status, BindingStatus::Active);
    assert_eq!(stored.last_error_code, None);
    assert_eq!(app.service.retry_after(app.connector_id, 1_000), None);
}

#[tokio::test]
async fn upstream_400_is_a_business_error_and_keeps_the_breaker_closed() {
    let app = harness().await;
    app.connector
        .set_response("scores", Err(UpstreamError::Rejected));
    let granted = scopes();
    let error = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("400");
    assert!(matches!(
        error,
        GatewayError::Upstream(UpstreamError::Rejected)
    ));
    assert_eq!(error.code(), "invalid_parameter");
    assert_eq!(error.fault_class(), FaultClass::Business);

    // Business faults must never count toward the breaker; otherwise one
    // misconfigured resource would take the whole connector down for everyone.
    let stored = app
        .store
        .bindings()
        .find(&app.user.id, "phigros")
        .await
        .expect("find")
        .expect("binding");
    assert_eq!(stored.status, BindingStatus::Active);
    assert_eq!(app.service.retry_after(app.connector_id, 1_000), None);
}

#[tokio::test]
async fn rate_limit_is_internal_and_opens_the_breaker() {
    let app = harness().await;
    app.connector.set_response(
        "scores",
        Err(UpstreamError::RateLimited {
            retry_after_secs: Some(10),
        }),
    );
    let granted = scopes();
    for _ in 0..2 {
        let error = app
            .service
            .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
            .await
            .expect_err("429");
        assert_eq!(error.fault_class(), FaultClass::Internal);
    }
    assert_eq!(app.service.retry_after(app.connector_id, 1_000), Some(60));
    assert_eq!(
        app.service
            .binding_retry_after(app.connector_id, app.binding.id, 1_000),
        Some(60),
        "429 counts at both connector and binding level"
    );

    let error = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("circuit open");
    assert!(matches!(error, GatewayError::CircuitOpen { .. }));
    assert_eq!(
        app.connector.calls().len(),
        2,
        "open circuit stops upstream calls"
    );

    let stored = app
        .store
        .bindings()
        .find(&app.user.id, "phigros")
        .await
        .expect("find")
        .expect("binding");
    assert_eq!(stored.status, BindingStatus::Active);
}

#[tokio::test]
async fn half_open_admits_one_probe_then_closes_on_success() {
    let app = harness().await;
    // Threshold 2, cooldown 60s, per the harness policy.
    // A 500 (Internal) still counts against the breaker but is not retried,
    // so the call count below measures breaker behaviour only.
    app.connector
        .set_response("scores", Err(UpstreamError::Internal));
    let granted = scopes();
    for _ in 0..2 {
        let _ = app
            .service
            .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
            .await
            .expect_err("5xx opens the breaker");
    }
    let calls_when_open = app.connector.calls().len();
    assert_eq!(calls_when_open, 2);

    // Move the clock past the cooldown: the first caller becomes the probe.
    app.set_now(1_061);
    app.connector.set_response(
        "scores",
        Ok(UpstreamPayload {
            content_type: "application/json".to_string(),
            body: br#"{"score":1}"#.to_vec(),
        }),
    );
    app.service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect("probe is admitted");

    // A successful probe closes the breaker: traffic flows again.
    app.service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect("closed after probe");
    assert_eq!(app.connector.calls().len(), 4);
    assert_eq!(app.service.retry_after(app.connector_id, 1_061), None);
}

#[tokio::test]
async fn upstream_5xx_is_internal() {
    let app = harness().await;
    app.connector
        .set_response("scores", Err(UpstreamError::Unavailable));
    let granted = scopes();
    let error = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("5xx");
    assert_eq!(error.fault_class(), FaultClass::Internal);
    assert_eq!(error.code(), "upstream_unavailable");
}

#[tokio::test]
async fn a_plain_failure_during_a_probe_does_not_strand_the_binding_breaker() {
    // `admit` has a side effect: it moves Open -> HalfOpen and claims the single
    // probe slot. Two keys are admitted per request (connector, then binding).
    // But `apply_failure` settles the binding only for 429; a plain 5xx settles
    // the connector alone. The binding therefore stays HalfOpen with its probe
    // slot taken forever, and every later request for that binding is rejected
    // until the process restarts.
    let app = harness().await;
    let granted = scopes();

    // 429 opens both keys (it counts at both levels) until 1000 + 60.
    app.connector.set_response(
        "scores",
        Err(UpstreamError::RateLimited {
            retry_after_secs: Some(10),
        }),
    );
    for _ in 0..2 {
        let _ = app
            .service
            .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
            .await;
    }

    // Past the cooldown both keys become half-open. The probe reaches the
    // upstream and fails with a plain 5xx, which settles only the connector.
    app.set_now(1_061);
    app.connector
        .set_response("scores", Err(UpstreamError::Unavailable));
    let _ = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await;

    // The upstream recovers and enough time passes for the connector to probe
    // again. The binding's breaker was never settled, so it is still holding a
    // probe that will never finish.
    app.set_now(2_000);
    app.connector.set_response(
        "scores",
        Ok(UpstreamPayload {
            content_type: "application/json".to_string(),
            body: br#"{"score":1}"#.to_vec(),
        }),
    );
    let before = app.connector.calls().len();
    for _ in 0..5 {
        let _ = app
            .service
            .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
            .await;
    }
    assert!(
        app.connector.calls().len() > before,
        "the binding breaker never released its probe slot: every request is \
         rejected with 503 even though the upstream is healthy"
    );
}

#[tokio::test]
async fn oversized_payload_is_truncated_and_internal() {
    let app = harness().await;
    app.connector
        .set_response("scores", Ok(payload(&vec![b'x'; 2048])));
    let granted = scopes();
    let error = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("oversized payload");
    assert!(matches!(
        error,
        GatewayError::Upstream(UpstreamError::Truncated)
    ));
    assert_eq!(error.fault_class(), FaultClass::Internal);

    let stored = app
        .store
        .bindings()
        .find(&app.user.id, "phigros")
        .await
        .expect("find")
        .expect("binding");
    assert_eq!(stored.status, BindingStatus::Active);
}

#[tokio::test]
async fn success_returns_the_payload_and_uses_the_sealed_credential() {
    let app = harness().await;
    let body = br#"{"score": 42}"#;
    app.connector.set_response("scores", Ok(payload(body)));
    let granted = scopes();
    let response = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect("fetch");
    // The normalized lane answers with the envelope (ADR-0049), not the raw body.
    let envelope: serde_json::Value =
        serde_json::from_slice(&response.body).expect("envelope is JSON");
    assert_eq!(envelope["data"], serde_json::json!({"score": 42}));
    assert_eq!(envelope["upstream"], "phigros");
    assert_eq!(envelope["endpoint"], "scores");
    assert_eq!(envelope["stability"], "declared");
    assert_eq!(response.content_type, "application/json");
    assert_eq!(
        app.connector.calls(),
        vec![re0auth_api::connector::ResourceRequest::new(
            "scores", "player-1"
        )]
    );
}

#[tokio::test]
async fn revoked_binding_is_rejected_before_the_upstream() {
    let app = harness().await;
    app.store
        .bindings()
        .mark_needs_reauth(&app.binding.id, "upstream_401", &fact_binding(), 1_100)
        .await
        .expect("mark needs reauth");
    let granted = scopes();
    let error = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("needs reauth");
    assert!(matches!(error, GatewayError::BindingNeedsReauth));
    assert_eq!(error.code(), "upstream_needs_reauth");
    assert!(app.connector.calls().is_empty());
}

#[tokio::test]
async fn registry_errors_are_split_by_class() {
    struct Failing(bool);
    #[async_trait::async_trait]
    impl re0auth_api::connector::ConnectorRegistry for Failing {
        async fn resolve(&self, _id: &ConnectorId) -> re0auth_api::Re0Result<ConnectorEndpoint> {
            if self.0 {
                Err(Re0Error::Business("missing".to_string()))
            } else {
                Err(Re0Error::Internal("broken".to_string()))
            }
        }
    }

    let app = harness().await;
    let granted = scopes();
    let business = GatewayService::new(
        app.store.clone(),
        Arc::new(Failing(true)),
        app.connector.clone(),
        Arc::new(MockSealer::new()),
        Arc::new(FixedClock::new(1_000)),
        Arc::new(CircuitTracker::new(CircuitPolicy::default())),
        1024,
    );
    let error = business
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("business");
    assert!(matches!(error, GatewayError::ConnectorNotFound));

    let internal = GatewayService::new(
        app.store.clone(),
        Arc::new(Failing(false)),
        app.connector.clone(),
        Arc::new(MockSealer::new()),
        Arc::new(FixedClock::new(1_000)),
        Arc::new(CircuitTracker::new(CircuitPolicy::default())),
        1024,
    );
    let error = internal
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("internal");
    assert!(matches!(error, GatewayError::Internal));
}

fn fact_binding() -> re0auth_api::audit::SecurityFact {
    re0auth_api::audit::SecurityFact::new(
        re0auth_api::audit::AuditAction::BindingCreated,
        0,
        "binding".to_string(),
    )
}

// ------------------------------------------------------------- raw view (INV-RAW-01)

/// Registers a client with the given `raw_access` flag and returns its id.
async fn client(app: &Harness, raw_access: bool) -> re0auth_api::ClientId {
    use re0auth_api::ports::{Client, ClientStatus};
    let client = Client {
        id: re0auth_api::ClientId::new(),
        name: format!("raw-{raw_access}"),
        redirect_uris: vec!["https://example.test/cb".to_string()],
        allowed_scopes: vec!["scores.read".to_string(), "phigros.raw.read".to_string()],
        raw_access,
        status: ClientStatus::Approved,
        secret_hash: None,
        created_at: 1_000,
        updated_at: 1_000,
    };
    app.store
        .clients()
        .insert(
            &client,
            &re0auth_api::audit::SecurityFact::new(
                re0auth_api::audit::AuditAction::ClientCreated,
                1_000,
                "client",
            ),
        )
        .await
        .expect("client");
    client.id
}

fn raw_request<'a>(
    user: UserId,
    client_id: &'a str,
    connector_id: ConnectorId,
    scopes: &'a [String],
) -> GatewayRequest<'a> {
    GatewayRequest {
        user_id: user,
        client_id,
        granted_scopes: scopes,
        connector_id,
        resource: "scores",
        raw: true,
        correlation_id: None,
        pagination: Pagination::default(),
        params: empty_params(),
    }
}

fn raw_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "scores.read".to_string(),
        "phigros.raw.read".to_string(),
    ]
}

#[tokio::test]
async fn raw_needs_both_the_flag_and_the_scope() {
    // INV-RAW-01 is two independent gates. A test that only exercised the happy
    // path would not notice if one of them were dropped.
    let app = harness().await;
    let allowed = client(&app, true).await;
    let plain = client(&app, false).await;
    app.connector
        .set_response("scores", Ok(payload(br#"{"score":1}"#)));

    // Both gates pass.
    app.service
        .fetch(raw_request(
            app.user.id,
            &allowed.0.to_string(),
            app.connector_id,
            &raw_scopes(),
        ))
        .await
        .expect("raw with flag and scope");

    // Flag missing.
    let error = app
        .service
        .fetch(raw_request(
            app.user.id,
            &plain.0.to_string(),
            app.connector_id,
            &raw_scopes(),
        ))
        .await
        .expect_err("raw_access is off");
    assert!(matches!(error, GatewayError::RawNotAllowed));
    assert_eq!(error.code(), "raw_not_allowed");

    // Scope missing, flag present.
    let scopes_without_raw: Vec<String> = vec!["openid".to_string(), "scores.read".to_string()];
    let error = app
        .service
        .fetch(raw_request(
            app.user.id,
            &allowed.0.to_string(),
            app.connector_id,
            &scopes_without_raw,
        ))
        .await
        .expect_err("raw scope is missing");
    assert!(matches!(error, GatewayError::RawNotAllowed));
}

#[tokio::test]
async fn raw_refusal_is_business_class_and_never_reaches_the_upstream() {
    // A client that is not approved for raw must not be able to use retries to
    // discover anything, and must not trip the breaker on the way out.
    let app = harness().await;
    let plain = client(&app, false).await;
    let before = app.connector.calls().len();
    let error = app
        .service
        .fetch(raw_request(
            app.user.id,
            &plain.0.to_string(),
            app.connector_id,
            &raw_scopes(),
        ))
        .await
        .expect_err("denied");
    assert_eq!(error.fault_class(), FaultClass::Business);
    assert_eq!(app.connector.calls().len(), before);
}

#[tokio::test]
async fn the_non_raw_path_never_consults_the_client_record() {
    // `raw_access` must not leak into the ordinary lane: a client id that does
    // not exist at all still works for a normal fetch, because that path has no
    // reason to look at the client.
    let app = harness().await;
    let granted = scopes();
    app.connector
        .set_response("scores", Ok(payload(br#"{"score":1}"#)));
    app.service
        .fetch(GatewayRequest {
            user_id: app.user.id,
            client_id: "00000000-0000-0000-0000-000000000000",
            granted_scopes: &granted,
            connector_id: app.connector_id,
            resource: "scores",
            raw: false,
            correlation_id: None,
            pagination: Pagination::default(),
            params: empty_params(),
        })
        .await
        .expect("non-raw fetch must not need a client record");
}

// ---------------------------------------------------------------- cache

/// Builds a cache holding one fresh entry for the harness's binding.
///
/// Uses the harness's own clock so the entry is fresh in the same time frame the
/// gateway sees; a wall clock would make "fresh" depend on when the test runs.
/// Seeds the cache with the shape the gateway now writes:
/// `[fetched_at BE][data JSON]`.
async fn primed_cache(
    app: &Harness,
    data: serde_json::Value,
) -> Arc<dyn re0auth_api::cache::Cache> {
    let cache = re0auth_contract::ClockedCache::new(
        re0auth_contract::MemoryCache::new(),
        app.clock.clone() as Arc<dyn Clock>,
    );
    let mut body = app.clock.now().to_be_bytes().to_vec();
    body.extend_from_slice(&serde_json::to_vec(&data).expect("data"));
    cache
        .put(
            &re0auth_api::cache::key(&app.binding.id, "phigros", "scores"),
            &re0auth_api::cache::CachedResponse::new("application/json", body),
            std::time::Duration::from_secs(300),
        )
        .await;
    Arc::new(cache)
}

#[tokio::test]
async fn a_fresh_entry_is_served_without_calling_the_upstream() {
    // The baseline: the cache works at all. Without this, the refusal tests
    // below would pass merely because caching is broken.
    let app = harness().await;
    let cache = primed_cache(&app, serde_json::json!({"cached": true})).await;
    let app = Harness {
        service: GatewayService::new(
            app.store.clone(),
            app.connector.clone(),
            app.connector.clone(),
            Arc::new(MockSealer::new()),
            app.clock.clone(),
            Arc::new(CircuitTracker::new(CircuitPolicy::default())),
            1024,
        )
        .with_cache(cache, std::time::Duration::from_secs(300)),
        ..app
    };
    let granted = scopes();
    let payload = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect("cached fetch");
    let envelope: serde_json::Value =
        serde_json::from_slice(&payload.body).expect("envelope is JSON");
    assert_eq!(envelope["data"], serde_json::json!({"cached": true}));
    assert_eq!(
        envelope["fetched_at"].as_i64(),
        Some(1000),
        "a cache hit must keep the original fetch time"
    );
    assert!(
        app.connector.calls().is_empty(),
        "a fresh cache hit must not reach the upstream"
    );
}

/// INV-CACHE-01: the cache must not be read before the scope gate.
///
/// This is the privilege-escalation test. If the read moves above
/// `scope_allows`, a caller without `scores.read` receives another scope's
/// cached payload — a 200 where a 403 belongs.
#[tokio::test]
async fn a_caller_without_the_scope_never_receives_a_cached_payload() {
    let app = harness().await;
    let cache = primed_cache(&app, serde_json::json!({"cached": "for-someone-else"})).await;
    let app = Harness {
        service: GatewayService::new(
            app.store.clone(),
            app.connector.clone(),
            app.connector.clone(),
            Arc::new(MockSealer::new()),
            app.clock.clone(),
            Arc::new(CircuitTracker::new(CircuitPolicy::default())),
            1024,
        )
        .with_cache(cache, std::time::Duration::from_secs(300)),
        ..app
    };
    // Only `openid`: no `scores.read`.
    let granted = vec!["openid".to_string()];
    let error = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("the scope gate must run before the cache read");
    assert!(
        matches!(error, GatewayError::InsufficientScope),
        "got {error:?} instead of a scope refusal — the cache was read first"
    );
    assert!(app.connector.calls().is_empty());
}

/// INV-CACHE-01: the cache must not be read before the binding status check.
#[tokio::test]
async fn a_revoked_binding_never_receives_a_cached_payload() {
    let app = harness().await;
    let cache = primed_cache(&app, serde_json::json!({"cached": "revoked-user"})).await;
    // Revoke the binding in the store, leaving the cache untouched: this
    // simulates a reader that raced ahead of the sweep.
    app.store
        .bindings()
        .revoke(&app.binding.id, &fact_binding(), 1_100)
        .await
        .expect("revoke");
    let app = Harness {
        service: GatewayService::new(
            app.store.clone(),
            app.connector.clone(),
            app.connector.clone(),
            Arc::new(MockSealer::new()),
            app.clock.clone(),
            Arc::new(CircuitTracker::new(CircuitPolicy::default())),
            1024,
        )
        .with_cache(cache, std::time::Duration::from_secs(300)),
        ..app
    };
    let granted = scopes();
    let error = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("a revoked binding must not be served from cache");
    assert!(
        matches!(error, GatewayError::BindingRevoked),
        "got {error:?} instead of a binding refusal — the cache was read first"
    );
}

/// INV-CACHE-03: the raw view is never cached.
#[tokio::test]
async fn a_raw_request_is_never_served_from_the_cache() {
    let app = harness().await;
    let cache = primed_cache(&app, serde_json::json!({"cached": true})).await;
    let plain = client(&app, true).await;
    let app = Harness {
        service: GatewayService::new(
            app.store.clone(),
            app.connector.clone(),
            app.connector.clone(),
            Arc::new(MockSealer::new()),
            app.clock.clone(),
            Arc::new(CircuitTracker::new(CircuitPolicy::default())),
            1024,
        )
        .with_cache(
            Arc::clone(&cache) as Arc<dyn re0auth_api::cache::Cache>,
            std::time::Duration::from_secs(300),
        ),
        ..app
    };
    app.connector
        .set_response("scores", Ok(payload(br#"{"live":true}"#)));
    let payload = app
        .service
        .fetch(raw_request(
            app.user.id,
            &plain.0.to_string(),
            app.connector_id,
            &raw_scopes(),
        ))
        .await
        .expect("raw fetch");
    assert_eq!(
        payload.body, br#"{"live":true}"#,
        "a raw request must hit the upstream, not replay the cached body"
    );
    assert_eq!(app.connector.calls().len(), 1);
}

#[derive(Default)]
struct RecordingTelemetry {
    events: std::sync::Mutex<Vec<AccessTelemetry>>,
}

impl TelemetrySink for RecordingTelemetry {
    fn record(&self, event: AccessTelemetry) -> bool {
        self.events.lock().expect("telemetry").push(event);
        true
    }
}

/// A served read must appear in the access ledger with the binding's connector
/// and the caller's identity — never with the subject or a client-chosen value.
#[tokio::test]
async fn a_served_read_is_recorded_as_access_telemetry() {
    let app = harness().await;
    let granted = scopes();
    app.connector
        .set_response("scores", Ok(payload(br#"{"score":1}"#)));
    let recorder = Arc::new(RecordingTelemetry::default());
    let service = app.service.with_telemetry(recorder.clone());

    service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect("fetch");

    let events = recorder.events.lock().expect("telemetry");
    assert_eq!(events.len(), 1, "one read, one ledger row");
    let event = &events[0];
    assert_eq!(event.connector, "phigros");
    assert_eq!(event.resource, "scores");
    assert_eq!(event.actor_user_id, Some(app.user.id));
    assert_eq!(event.source, AccessSource::Upstream);
}

// ---- retry policy (F-4) --------------------------------------------------

/// Fails the first N calls with a transport error, then answers normally.
struct FlakyBroker {
    failures: usize,
    internal: bool,
    calls: AtomicUsize,
}

impl FlakyBroker {
    fn new(failures: usize) -> Self {
        Self {
            failures,
            internal: false,
            calls: AtomicUsize::new(0),
        }
    }

    fn internal() -> Self {
        Self {
            failures: usize::MAX,
            internal: true,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ConnectorBroker for FlakyBroker {
    async fn fetch_raw_data(
        &self,
        _endpoint: &ConnectorEndpoint,
        _token: &SecretString,
        _resource: &ResourceRequest,
    ) -> Result<UpstreamPayload, UpstreamError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call <= self.failures {
            return Err(if self.internal {
                UpstreamError::Internal
            } else {
                UpstreamError::Unavailable
            });
        }
        Ok(payload(br#"{"score":1}"#))
    }

    async fn fetch_asset_stream(
        &self,
        _endpoint: &ConnectorEndpoint,
        _token: &SecretString,
        _resource: &ResourceRequest,
        _accept: &str,
        _max_body: usize,
    ) -> Result<AssetStream, UpstreamError> {
        Err(UpstreamError::Unavailable)
    }
}

fn service_with_broker(app: &Harness, broker: Arc<dyn ConnectorBroker>) -> GatewayService {
    GatewayService::new(
        app.store.clone(),
        app.connector.clone(),
        broker,
        Arc::new(MockSealer::new()),
        app.clock.clone(),
        Arc::new(CircuitTracker::new(CircuitPolicy::default())),
        1024,
    )
}

#[tokio::test]
async fn an_idempotent_read_is_retried_and_then_succeeds() {
    let app = harness().await;
    let broker = Arc::new(FlakyBroker::new(1));
    let service = service_with_broker(&app, broker.clone());
    let granted = scopes();
    service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect("the second attempt succeeds");
    assert_eq!(broker.calls(), 2, "one retry, not a retry storm");
}

#[tokio::test]
async fn a_persistent_transport_failure_stops_after_three_attempts() {
    let app = harness().await;
    let broker = Arc::new(FlakyBroker::new(usize::MAX));
    let service = service_with_broker(&app, broker.clone());
    let granted = scopes();
    let error = service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("still failing");
    assert!(
        matches!(error, GatewayError::Upstream(UpstreamError::Unavailable)),
        "{error:?}"
    );
    assert_eq!(broker.calls(), 3, "bounded attempts");
}

#[tokio::test]
async fn an_upstream_500_is_not_retried() {
    // 500 is a broken upstream, not a transient one; retrying multiplies the
    // load that broke it.
    let app = harness().await;
    let broker = Arc::new(FlakyBroker::internal());
    let service = service_with_broker(&app, broker.clone());
    let granted = scopes();
    let error = service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("500 fails");
    assert!(
        matches!(error, GatewayError::Upstream(UpstreamError::Internal)),
        "{error:?}"
    );
    assert_eq!(broker.calls(), 1, "no retry for a non-transient failure");
}

#[tokio::test]
async fn a_non_idempotent_resource_is_never_retried() {
    let app = harness().await;
    let mut endpoint = app.endpoint.clone();
    endpoint.resources.push(
        ResourceSpec::new("write", "/v1/write/{subject}")
            .expect("spec")
            .with_scope("scores.read")
            .expect("scope")
            .with_transport(
                ResourceMethod::Post,
                vec![BodyField {
                    name: "probe".to_string(),
                    value: BodyValue::Literal(serde_json::Value::String("1".to_string())),
                }],
                false,
            )
            .expect("transport"),
    );
    app.connector.register(endpoint);
    let broker = Arc::new(FlakyBroker::new(1));
    let service = service_with_broker(&app, broker.clone());
    let granted = scopes();
    service
        .fetch(request(app.user.id, app.connector_id, &granted, "write"))
        .await
        .expect_err("a POST that may have taken effect must not be replayed");
    assert_eq!(broker.calls(), 1);
}

#[tokio::test]
async fn a_banned_account_is_refused_before_any_upstream_call() {
    let app = harness().await;
    app.store
        .users()
        .set_status(&app.user.id, UserStatus::Banned, &fact_binding(), 1_000)
        .await
        .expect("ban");
    let granted = scopes();
    let error = app
        .service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("banned accounts are refused");
    assert!(matches!(error, GatewayError::AccountBanned), "{error:?}");
    assert_eq!(error.code(), "account_banned");
    assert!(app.connector.calls().is_empty());
}

struct FakeCredentials {
    refresh_result: Result<&'static str, CredentialError>,
    refreshes: AtomicUsize,
}

#[async_trait]
impl CredentialSource for FakeCredentials {
    async fn access_token(&self, _binding: &Binding) -> Result<SecretString, CredentialError> {
        Ok(SecretString::from("stale-token"))
    }

    async fn refresh(
        &self,
        _binding: &Binding,
        stale_access: &str,
    ) -> Result<SecretString, CredentialError> {
        assert_eq!(stale_access, "stale-token");
        self.refreshes.fetch_add(1, Ordering::SeqCst);
        self.refresh_result
            .map(|token| SecretString::from(token.to_string()))
    }
}

struct TokenBroker {
    calls: AtomicUsize,
}

#[async_trait]
impl ConnectorBroker for TokenBroker {
    async fn fetch_raw_data(
        &self,
        _endpoint: &ConnectorEndpoint,
        sub_token: &SecretString,
        _resource: &ResourceRequest,
    ) -> Result<UpstreamPayload, UpstreamError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if sub_token.expose_secret() == "fresh-token" {
            Ok(payload(br#"{"ok":true}"#))
        } else {
            Err(UpstreamError::CredentialExpired)
        }
    }

    async fn fetch_asset_stream(
        &self,
        _endpoint: &ConnectorEndpoint,
        _sub_token: &SecretString,
        _resource: &ResourceRequest,
        _accept: &str,
        _max_body: usize,
    ) -> Result<AssetStream, UpstreamError> {
        Err(UpstreamError::Unavailable)
    }
}

fn service_with_credentials(
    app: &Harness,
    credentials: Arc<FakeCredentials>,
    broker: Arc<TokenBroker>,
) -> GatewayService {
    GatewayService::new(
        app.store.clone(),
        app.connector.clone(),
        broker,
        Arc::new(MockSealer::new()),
        app.clock.clone(),
        Arc::new(CircuitTracker::new(CircuitPolicy {
            failure_threshold: 2,
            open_for_secs: 60,
            probe_retry_secs: 1,
        })),
        1024,
    )
    .with_credentials(credentials)
}

#[tokio::test]
async fn a_401_refreshes_once_and_retries_the_read() {
    let app = harness().await;
    let credentials = Arc::new(FakeCredentials {
        refresh_result: Ok("fresh-token"),
        refreshes: AtomicUsize::new(0),
    });
    let broker = Arc::new(TokenBroker {
        calls: AtomicUsize::new(0),
    });
    let service = service_with_credentials(&app, credentials.clone(), broker.clone());

    let granted = scopes();
    let result = service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect("refresh retry succeeds");
    assert_eq!(broker.calls.load(Ordering::SeqCst), 2);
    assert_eq!(credentials.refreshes.load(Ordering::SeqCst), 1);
    assert!(String::from_utf8_lossy(&result.body).contains("\"ok\":true"));
}

#[tokio::test]
async fn invalid_refresh_marks_the_binding_needs_reauth() {
    let app = harness().await;
    let credentials = Arc::new(FakeCredentials {
        refresh_result: Err(CredentialError::NeedsReauth),
        refreshes: AtomicUsize::new(0),
    });
    let broker = Arc::new(TokenBroker {
        calls: AtomicUsize::new(0),
    });
    let service = service_with_credentials(&app, credentials, broker.clone());

    let granted = scopes();
    let error = service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("invalid refresh");
    assert!(matches!(
        error,
        GatewayError::Upstream(UpstreamError::CredentialExpired)
    ));
    assert_eq!(broker.calls.load(Ordering::SeqCst), 1);
    let binding = app
        .store
        .bindings()
        .get(&app.binding.id)
        .await
        .expect("get")
        .expect("binding");
    assert_eq!(binding.status, BindingStatus::NeedsReauth);
    assert_eq!(
        binding.last_error_code.as_deref(),
        Some("refresh_invalid_grant")
    );
}

#[tokio::test]
async fn transient_refresh_failure_keeps_the_binding_active() {
    let app = harness().await;
    let credentials = Arc::new(FakeCredentials {
        refresh_result: Err(CredentialError::Unavailable),
        refreshes: AtomicUsize::new(0),
    });
    let broker = Arc::new(TokenBroker {
        calls: AtomicUsize::new(0),
    });
    let service = service_with_credentials(&app, credentials, broker.clone());

    let granted = scopes();
    let error = service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect_err("transient refresh");
    assert!(matches!(
        error,
        GatewayError::Upstream(UpstreamError::Unavailable)
    ));
    assert_eq!(broker.calls.load(Ordering::SeqCst), 1);
    let binding = app
        .store
        .bindings()
        .get(&app.binding.id)
        .await
        .expect("get")
        .expect("binding");
    assert_eq!(binding.status, BindingStatus::Active);
}

#[tokio::test]
async fn pagination_on_a_non_list_resource_is_rejected_before_the_upstream() {
    let app = harness().await;
    let granted = scopes();
    let params = BTreeMap::from([
        ("limit".to_string(), vec!["1".to_string()]),
        ("cursor".to_string(), vec!["x".to_string()]),
    ]);
    let error = app
        .service
        .fetch(GatewayRequest {
            user_id: app.user.id,
            client_id: "00000000-0000-0000-0000-000000000000",
            granted_scopes: &granted,
            connector_id: app.connector_id,
            resource: "scores",
            raw: false,
            correlation_id: None,
            pagination: Pagination {
                limit: Some(1),
                cursor: Some("x".to_string()),
            },
            params: &params,
        })
        .await
        .expect_err("pagination on a non-list resource");
    assert!(matches!(error, GatewayError::InvalidRequest(_)));
    assert!(app.connector.calls().is_empty());
}

#[derive(Default)]
struct CountingObserver {
    hits: AtomicUsize,
    misses: AtomicUsize,
}

impl GatewayObserver for CountingObserver {
    fn cache_hit(&self, _connector: &str, _resource: &str) {
        self.hits.fetch_add(1, Ordering::SeqCst);
    }

    fn cache_miss(&self, _connector: &str, _resource: &str) {
        self.misses.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn cache_hits_and_misses_are_reported_to_the_observer() {
    let cache = Arc::new(ClockedCache::new(
        MemoryCache::new(),
        Arc::new(FixedClock::new(1_000)),
    ));
    let mut app = harness_with_cache(cache).await;
    let observer = Arc::new(CountingObserver::default());
    app.service = app.service.with_observer(observer.clone());
    app.connector
        .set_response("scores", Ok(payload(br#"{"score":1}"#)));

    let granted = scopes();
    app.service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect("first read misses and fills the cache");
    app.service
        .fetch(request(app.user.id, app.connector_id, &granted, "scores"))
        .await
        .expect("second read hits the cache");

    assert_eq!(observer.misses.load(Ordering::SeqCst), 1);
    assert_eq!(observer.hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        app.connector.calls().len(),
        1,
        "the hit never reached upstream"
    );
}

struct TestFailures {
    clock: Arc<FixedClock>,
    entries: std::sync::Mutex<std::collections::HashMap<String, (i64, UpstreamError)>>,
}

impl re0auth_api::cache::FailureCache for TestFailures {
    fn get(&self, key: &str) -> Option<UpstreamError> {
        self.entries
            .lock()
            .expect("failures")
            .get(key)
            .filter(|(expires, _)| self.clock.now() < *expires)
            .map(|(_, error)| error.clone())
    }

    fn put(&self, key: String, error: UpstreamError, ttl: std::time::Duration) {
        let expires = self.clock.now() + i64::try_from(ttl.as_secs()).expect("TTL");
        self.entries
            .lock()
            .expect("failures")
            .insert(key, (expires, error));
    }
}

struct AssetApp {
    harness: Harness,
    cache: Arc<ClockedCache>,
    failures: Arc<TestFailures>,
}

async fn asset_harness(shared: bool) -> AssetApp {
    asset_harness_with_limits(shared, 5, 4, 32, 45, 10).await
}

async fn asset_harness_with_limits(
    shared: bool,
    negative_ttl: u64,
    detached: usize,
    loaders: usize,
    deadline: u64,
    upstream_timeout: u64,
) -> AssetApp {
    use re0auth_api::connector::ResponseKind;

    let mut app = harness().await;
    let mut spec = ResourceSpec::new("jacket", "/v1/jacket")
        .expect("asset spec")
        .with_scope("scores.read")
        .expect("scope")
        .with_response(
            ResponseKind::Binary,
            vec!["image/png".to_string(), "image/avif".to_string()],
            None,
        );
    spec.shared = shared;
    app.endpoint.resources.push(spec);
    app.connector.register(app.endpoint.clone());
    let cache = Arc::new(ClockedCache::new(
        MemoryCache::new(),
        app.clock.clone() as Arc<dyn Clock>,
    ));
    let failures = Arc::new(TestFailures {
        clock: app.clock.clone(),
        entries: std::sync::Mutex::new(std::collections::HashMap::new()),
    });
    app.service = app
        .service
        .with_asset_support(
            cache.clone(),
            failures.clone(),
            std::time::Duration::from_secs(negative_ttl),
            detached,
            loaders,
            std::time::Duration::from_secs(deadline),
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(upstream_timeout),
        )
        .with_asset_spawner(Arc::new(|future| drop(tokio::spawn(future))));
    AssetApp {
        harness: app,
        cache,
        failures,
    }
}

fn png() -> &'static [u8] {
    b"\x89PNG\r\n\x1a\nbody"
}

async fn read_asset(response: re0auth_api::connector::AssetResponse) -> Vec<u8> {
    use futures_util::StreamExt;

    match response {
        re0auth_api::connector::AssetResponse::Buffered(payload) => payload.body.to_vec(),
        re0auth_api::connector::AssetResponse::Streaming(stream) => stream
            .body
            .map(|chunk| chunk.expect("asset stream"))
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect(),
    }
}

type ControlledAssetHandler =
    dyn Fn() -> Result<AssetStream, UpstreamError> + Send + Sync + 'static;

struct ControlledBroker {
    inner: Arc<MockConnector>,
    handlers: std::sync::Mutex<std::collections::HashMap<String, Arc<ControlledAssetHandler>>>,
    calls: AtomicUsize,
    call_count: tokio::sync::watch::Sender<usize>,
}

impl ControlledBroker {
    fn new(inner: Arc<MockConnector>) -> Self {
        let (call_count, _) = tokio::sync::watch::channel(0);
        Self {
            inner,
            handlers: std::sync::Mutex::new(std::collections::HashMap::new()),
            calls: AtomicUsize::new(0),
            call_count,
        }
    }

    fn set_asset_handler(
        &self,
        resource: &str,
        handler: impl Fn() -> Result<AssetStream, UpstreamError> + Send + Sync + 'static,
    ) {
        self.handlers
            .lock()
            .expect("asset handlers")
            .insert(resource.to_string(), Arc::new(handler));
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    async fn wait_for_calls(&self, expected: usize) {
        let mut calls = self.call_count.subscribe();
        while *calls.borrow_and_update() < expected {
            calls.changed().await.expect("call count sender");
        }
    }
}

#[async_trait]
impl re0auth_api::connector::ConnectorRegistry for ControlledBroker {
    async fn resolve(&self, id: &ConnectorId) -> re0auth_api::Re0Result<ConnectorEndpoint> {
        re0auth_api::connector::ConnectorRegistry::resolve(&*self.inner, id).await
    }
}

#[async_trait]
impl ConnectorBroker for ControlledBroker {
    async fn fetch_raw_data(
        &self,
        endpoint: &ConnectorEndpoint,
        sub_token: &SecretString,
        resource: &ResourceRequest,
    ) -> Result<UpstreamPayload, UpstreamError> {
        self.inner
            .fetch_raw_data(endpoint, sub_token, resource)
            .await
    }

    async fn fetch_asset_stream(
        &self,
        _endpoint: &ConnectorEndpoint,
        _sub_token: &SecretString,
        resource: &ResourceRequest,
        _accept: &str,
        _max_body: usize,
    ) -> Result<AssetStream, UpstreamError> {
        let calls = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.call_count.send_replace(calls);
        let handler = self
            .handlers
            .lock()
            .expect("asset handlers")
            .get(&resource.resource)
            .cloned()
            .ok_or(UpstreamError::NotFound)?;
        handler()
    }
}

async fn controlled_asset_harness(
    shared: bool,
    negative_ttl: u64,
    detached: usize,
    loaders: usize,
    deadline: u64,
    upstream_timeout: u64,
) -> (AssetApp, Arc<ControlledBroker>) {
    let mut app = asset_harness_with_limits(
        shared,
        negative_ttl,
        detached,
        loaders,
        deadline,
        upstream_timeout,
    )
    .await;
    let broker = Arc::new(ControlledBroker::new(app.harness.connector.clone()));
    app.harness.service = GatewayService::new(
        app.harness.store.clone(),
        app.harness.connector.clone(),
        broker.clone(),
        Arc::new(MockSealer::new()),
        app.harness.clock.clone(),
        Arc::new(CircuitTracker::new(CircuitPolicy {
            failure_threshold: 2,
            open_for_secs: 60,
            probe_retry_secs: 1,
        })),
        1024,
    )
    .with_asset_support(
        app.cache.clone(),
        app.failures.clone(),
        std::time::Duration::from_secs(negative_ttl),
        detached,
        loaders,
        std::time::Duration::from_secs(deadline),
        std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(upstream_timeout),
    )
    .with_asset_spawner(Arc::new(|future| drop(tokio::spawn(future))));
    (app, broker)
}

async fn try_read_asset(
    response: re0auth_api::connector::AssetResponse,
) -> Result<Vec<u8>, UpstreamError> {
    use futures_util::StreamExt;

    match response {
        re0auth_api::connector::AssetResponse::Buffered(payload) => Ok(payload.body.to_vec()),
        re0auth_api::connector::AssetResponse::Streaming(stream) => {
            let chunks = stream.body.collect::<Vec<_>>().await;
            let mut body = Vec::new();
            for chunk in chunks {
                body.extend_from_slice(&chunk?);
            }
            Ok(body)
        }
    }
}

async fn wait_for_asset_cache(cache: &ClockedCache, expected: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while cache.len() != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("asset loader finishes");
}

async fn wait_for_release(release: &mut tokio::sync::watch::Receiver<bool>) {
    while !*release.borrow_and_update() {
        release.changed().await.expect("release sender");
    }
}

fn gated_png_stream(release: &tokio::sync::watch::Sender<bool>) -> AssetStream {
    let mut released = release.subscribe();
    AssetStream {
        content_type: "image/png".to_string(),
        body: Box::pin(
            futures_util::stream::once(async move { Ok(bytes::Bytes::from_static(png())) }).chain(
                futures_util::stream::once(async move {
                    wait_for_release(&mut released).await;
                    Ok(bytes::Bytes::from_static(b""))
                }),
            ),
        ),
    }
}

#[tokio::test(start_paused = true)]
async fn global_asset_loader_cap_queues_the_third_distinct_key() {
    let (mut app, broker) = controlled_asset_harness(false, 5, 4, 2, 45, 0).await;
    for name in ["jacket_two", "jacket_three"] {
        app.harness.endpoint.resources.push(
            ResourceSpec::new(name, "/v1/jacket")
                .expect("asset spec")
                .with_scope("scores.read")
                .expect("scope")
                .with_response(
                    re0auth_api::connector::ResponseKind::Binary,
                    vec!["image/png".to_string()],
                    None,
                ),
        );
        broker.inner.register(app.harness.endpoint.clone());
    }
    let (release_tx, _) = tokio::sync::watch::channel(false);
    for name in ["jacket", "jacket_two", "jacket_three"] {
        let release = release_tx.clone();
        broker.set_asset_handler(name, move || Ok(gated_png_stream(&release)));
    }

    let granted = scopes();
    let mut tasks = Vec::new();
    for name in ["jacket", "jacket_two", "jacket_three"] {
        let service = app.harness.service.clone();
        let granted = granted.clone();
        let user = app.harness.user.id;
        let connector = app.harness.connector_id;
        tasks.push(tokio::spawn(async move {
            let response = service
                .fetch_asset(request(user, connector, &granted, name), Some("image/png"))
                .await
                .expect("asset response");
            read_asset(response).await
        }));
    }
    broker.wait_for_calls(2).await;
    tokio::task::yield_now().await;
    assert_eq!(broker.calls(), 2, "only two loaders hold global permits");
    assert!(!tasks[2].is_finished(), "the third key is still queued");

    release_tx.send(true).expect("release receivers");
    for task in tasks {
        assert_eq!(task.await.expect("asset task"), png());
    }
    assert_eq!(broker.calls(), 3);
    assert_eq!(app.cache.len(), 3);
}

#[tokio::test(start_paused = true)]
async fn orphan_without_detached_permit_aborts_and_permits_a_fresh_retry() {
    let (app, broker) = controlled_asset_harness(false, 5, 0, 2, 45, 0).await;
    let (release_tx, _) = tokio::sync::watch::channel(false);
    let release = release_tx.clone();
    broker.set_asset_handler("jacket", move || Ok(gated_png_stream(&release)));
    let granted = scopes();
    let response = app
        .harness
        .service
        .fetch_asset(
            request(
                app.harness.user.id,
                app.harness.connector_id,
                &granted,
                "jacket",
            ),
            Some("image/png"),
        )
        .await
        .expect("first asset response");
    drop(response);
    release_tx.send(true).expect("release receiver");
    tokio::task::yield_now().await;
    assert!(app.cache.is_empty(), "an aborted fill caches no prefix");

    broker.set_asset_handler("jacket", || {
        Ok(AssetStream {
            content_type: "image/png".to_string(),
            body: Box::pin(futures_util::stream::once(async {
                Ok(bytes::Bytes::from_static(png()))
            })),
        })
    });
    let response = app
        .harness
        .service
        .fetch_asset(
            request(
                app.harness.user.id,
                app.harness.connector_id,
                &granted,
                "jacket",
            ),
            Some("image/png"),
        )
        .await
        .expect("fresh flight after orphan abort");
    assert_eq!(read_asset(response).await, png());
    assert_eq!(broker.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn orphan_with_detached_permit_finishes_and_populates_cache() {
    let (app, broker) = controlled_asset_harness(false, 5, 1, 2, 45, 0).await;
    let (release_tx, _) = tokio::sync::watch::channel(false);
    let release = release_tx.clone();
    broker.set_asset_handler("jacket", move || Ok(gated_png_stream(&release)));
    let granted = scopes();
    let response = app
        .harness
        .service
        .fetch_asset(
            request(
                app.harness.user.id,
                app.harness.connector_id,
                &granted,
                "jacket",
            ),
            Some("image/png"),
        )
        .await
        .expect("first asset response");
    drop(response);
    release_tx.send(true).expect("release receiver");
    wait_for_asset_cache(&app.cache, 1).await;

    let response = app
        .harness
        .service
        .fetch_asset(
            request(
                app.harness.user.id,
                app.harness.connector_id,
                &granted,
                "jacket",
            ),
            Some("image/png"),
        )
        .await
        .expect("detached cache hit");
    assert_eq!(read_asset(response).await, png());
    assert_eq!(broker.calls(), 1, "the retry never reaches upstream");
}

#[tokio::test(start_paused = true)]
async fn asset_deadline_stops_slow_drip_with_attached_subscriber() {
    let (app, broker) = controlled_asset_harness(false, 5, 1, 2, 1, 0).await;
    broker.set_asset_handler("jacket", || {
        Ok(AssetStream {
            content_type: "image/png".to_string(),
            body: Box::pin(
                futures_util::stream::once(async { Ok(bytes::Bytes::from_static(png())) }).chain(
                    futures_util::stream::once(async {
                        tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                        Ok(bytes::Bytes::from_static(b""))
                    }),
                ),
            ),
        })
    });
    let granted = scopes();
    let response = app
        .harness
        .service
        .fetch_asset(
            request(
                app.harness.user.id,
                app.harness.connector_id,
                &granted,
                "jacket",
            ),
            Some("image/png"),
        )
        .await
        .expect("stream starts before the deadline");
    let pending = tokio::spawn(try_read_asset(response));
    tokio::task::yield_now().await;
    assert!(!pending.is_finished(), "subscriber remains attached");
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    let error = pending
        .await
        .expect("subscriber task")
        .expect_err("deadline rejects the slow drip");
    assert!(matches!(error, UpstreamError::Unavailable));
    assert!(app.cache.is_empty());
    assert!(app.failures.entries.lock().expect("failures").is_empty());
}

#[tokio::test(start_paused = true)]
async fn panic_mid_asset_stream_removes_flight_for_fresh_retry() {
    let (app, broker) = controlled_asset_harness(false, 5, 1, 2, 45, 0).await;
    broker.set_asset_handler("jacket", || {
        Ok(AssetStream {
            content_type: "image/png".to_string(),
            body: Box::pin(
                futures_util::stream::once(async { Ok(bytes::Bytes::from_static(png())) }).chain(
                    futures_util::stream::once(async { panic!("injected asset stream panic") }),
                ),
            ),
        })
    });
    let granted = scopes();
    let response = app
        .harness
        .service
        .fetch_asset(
            request(
                app.harness.user.id,
                app.harness.connector_id,
                &granted,
                "jacket",
            ),
            Some("image/png"),
        )
        .await
        .expect("panicking stream starts");
    let error = try_read_asset(response)
        .await
        .expect_err("panic becomes a terminal asset error");
    assert!(matches!(error, UpstreamError::Internal));
    assert!(app.cache.is_empty());

    broker.set_asset_handler("jacket", || {
        Ok(AssetStream {
            content_type: "image/png".to_string(),
            body: Box::pin(futures_util::stream::once(async {
                Ok(bytes::Bytes::from_static(png()))
            })),
        })
    });
    let response = app
        .harness
        .service
        .fetch_asset(
            request(
                app.harness.user.id,
                app.harness.connector_id,
                &granted,
                "jacket",
            ),
            Some("image/png"),
        )
        .await
        .expect("retry joins a fresh flight");
    assert_eq!(read_asset(response).await, png());
    assert_eq!(broker.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn open_asset_circuit_preflights_before_waiting_for_a_loader_permit() {
    let (app, broker) = controlled_asset_harness(false, 0, 1, 1, 45, 0).await;
    broker.set_asset_handler("jacket", || Err(UpstreamError::Unavailable));
    let granted = scopes();
    for _ in 0..2 {
        let error = app
            .harness
            .service
            .fetch_asset(
                request(
                    app.harness.user.id,
                    app.harness.connector_id,
                    &granted,
                    "jacket",
                ),
                Some("image/png"),
            )
            .await
            .expect_err("upstream failures open the connector circuit");
        assert!(matches!(
            error,
            GatewayError::Upstream(UpstreamError::Unavailable)
        ));
    }

    let healthy = ConnectorId::new();
    let mut slow_spec = ResourceSpec::new("slow_jacket", "/v1/jacket")
        .expect("slow asset spec")
        .with_scope("scores.read")
        .expect("scope")
        .with_response(
            re0auth_api::connector::ResponseKind::Binary,
            vec!["image/png".to_string()],
            None,
        );
    slow_spec.shared = true;
    app.harness.connector.register(ConnectorEndpoint {
        id: healthy,
        name: "healthy".to_string(),
        base_url: "https://healthy.example".to_string(),
        egress: EgressPolicy::Public,
        resources: vec![slow_spec],
    });
    let (release_tx, _) = tokio::sync::watch::channel(false);
    let release = release_tx.clone();
    broker.set_asset_handler("slow_jacket", move || Ok(gated_png_stream(&release)));
    let service = app.harness.service.clone();
    let slow_granted = granted.clone();
    let user = app.harness.user.id;
    let connector = healthy;
    let slow = tokio::spawn(async move {
        let response = service
            .fetch_asset(
                request(user, connector, &slow_granted, "slow_jacket"),
                Some("image/png"),
            )
            .await
            .expect("slow loader response");
        read_asset(response).await
    });
    broker.wait_for_calls(3).await;

    let error = app
        .harness
        .service
        .fetch_asset(
            request(
                app.harness.user.id,
                app.harness.connector_id,
                &granted,
                "jacket",
            ),
            Some("image/png"),
        )
        .await
        .expect_err("open circuit rejects before permit acquisition");
    assert!(matches!(error, GatewayError::CircuitOpen { .. }));
    assert_eq!(broker.calls(), 3, "the open circuit makes no broker call");
    assert!(!slow.is_finished(), "the other key still owns the loader");

    release_tx.send(true).expect("release receiver");
    assert_eq!(slow.await.expect("slow loader task"), png());
}

struct AssetActivity {
    active: Arc<AtomicUsize>,
}

impl AssetActivity {
    fn enter(active: Arc<AtomicUsize>, peak: Arc<AtomicUsize>) -> Self {
        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
        peak.fetch_max(current, Ordering::SeqCst);
        Self { active }
    }
}

impl Drop for AssetActivity {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

fn counted_detached_stream(
    release: &tokio::sync::watch::Sender<bool>,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
) -> AssetStream {
    struct State {
        release: tokio::sync::watch::Receiver<bool>,
        first: bool,
        finished: bool,
        counted: bool,
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        activity: Option<AssetActivity>,
    }
    let state = State {
        release: release.subscribe(),
        first: true,
        finished: false,
        counted: false,
        active,
        peak,
        activity: None,
    };
    AssetStream {
        content_type: "image/png".to_string(),
        body: Box::pin(futures_util::stream::unfold(
            state,
            |mut state| async move {
                if state.first {
                    state.first = false;
                    return Some((Ok(bytes::Bytes::from_static(png())), state));
                }
                if !state.finished {
                    wait_for_release(&mut state.release).await;
                    state.finished = true;
                    return Some((Ok(bytes::Bytes::from_static(b"")), state));
                }
                if !state.counted {
                    state.counted = true;
                    state.activity = Some(AssetActivity::enter(
                        state.active.clone(),
                        state.peak.clone(),
                    ));
                    tokio::task::yield_now().await;
                    return Some((Ok(bytes::Bytes::from_static(b"")), state));
                }
                state.activity.take();
                None
            },
        )),
    }
}

#[tokio::test(start_paused = true)]
async fn many_orphaned_asset_keys_obey_the_detached_fill_cap() {
    const KEYS: usize = 1000;
    const LOADERS: usize = KEYS;
    let (mut app, broker) = controlled_asset_harness(false, 5, 2, LOADERS, 45, 0).await;
    let names = std::iter::once("jacket".to_string())
        .chain((1..KEYS).map(|index| format!("jacket_{index}")))
        .collect::<Vec<_>>();
    for name in &names {
        app.harness.endpoint.resources.push(
            ResourceSpec::new(name, "/v1/jacket")
                .expect("extra asset spec")
                .with_scope("scores.read")
                .expect("scope")
                .with_response(
                    re0auth_api::connector::ResponseKind::Binary,
                    vec!["image/png".to_string()],
                    None,
                ),
        );
        app.harness.connector.register(app.harness.endpoint.clone());
    }
    let (release_tx, _) = tokio::sync::watch::channel(false);
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    for name in &names {
        let release = release_tx.clone();
        let active = active.clone();
        let peak = peak.clone();
        broker.set_asset_handler(name, move || {
            Ok(counted_detached_stream(
                &release,
                active.clone(),
                peak.clone(),
            ))
        });
    }

    let granted = scopes();
    let mut tasks = Vec::new();
    for name in &names {
        let service = app.harness.service.clone();
        let granted = granted.clone();
        let user = app.harness.user.id;
        let connector = app.harness.connector_id;
        let name = name.clone();
        tasks.push(tokio::spawn(async move {
            let response = service
                .fetch_asset(request(user, connector, &granted, &name), Some("image/png"))
                .await
                .expect("orphan candidate response");
            drop(response);
        }));
    }
    broker.wait_for_calls(LOADERS).await;
    for task in tasks {
        task.await.expect("orphan candidate task");
    }
    release_tx.send(true).expect("release receivers");
    wait_for_asset_cache(&app.cache, 2).await;
    assert_eq!(app.cache.len(), 2, "aborted fills leave no partial cache");
    assert_eq!(broker.calls(), KEYS);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert!(
        peak.load(Ordering::SeqCst) <= 2,
        "only two detached fills may hold body chunks concurrently"
    );
}

async fn add_asset_user(harness: &Harness, display_name: &str) -> UserId {
    let user = UserId::new();
    harness
        .store
        .users()
        .create(&User {
            id: user,
            display_name: display_name.to_string(),
            role: UserRole::User,
            status: UserStatus::Active,
            created_at: 1_000,
            updated_at: 1_000,
        })
        .await
        .expect("create asset user");
    user
}

async fn add_asset_binding(harness: &Harness, display_name: &str) -> (UserId, BindingId) {
    let user = add_asset_user(harness, display_name).await;
    let binding = Binding {
        id: BindingId::new(),
        user_id: user,
        upstream_id: "phigros".to_string(),
        upstream_user_id: display_name.to_string(),
        status: BindingStatus::Active,
        created_at: 1_000,
        updated_at: 1_000,
        last_refreshed_at: None,
        last_error_code: None,
    };
    harness
        .store
        .bindings()
        .upsert(&binding, &fact_binding())
        .await
        .expect("create asset binding");
    let sealed = MockSealer::new()
        .seal(&binding.id, &SecretString::from("other-token".to_string()))
        .expect("seal asset credential");
    harness
        .store
        .bindings()
        .store_sub_credential(&binding.id, &sealed, 1_000)
        .await
        .expect("store asset credential");
    (user, binding.id)
}

#[tokio::test]
async fn private_asset_cache_is_isolated_by_binding() {
    let app = asset_harness(false).await;
    app.harness.connector.set_asset_stream(
        "jacket",
        "image/png",
        [bytes::Bytes::from_static(png())],
    );
    let (other, other_binding) = add_asset_binding(&app.harness, "other-player").await;
    let granted = scopes();

    for _ in 0..2 {
        for user in [app.harness.user.id, other] {
            let response = app
                .harness
                .service
                .fetch_asset(
                    request(user, app.harness.connector_id, &granted, "jacket"),
                    Some("image/png"),
                )
                .await
                .expect("private asset");
            assert_eq!(read_asset(response).await, png());
        }
    }

    assert_eq!(app.harness.connector.calls().len(), 2);
    assert_eq!(app.cache.len(), 2);
    let first_key = re0auth_api::cache::key_asset(
        &app.harness.binding.id,
        &app.harness.binding.upstream_user_id,
        &app.harness.endpoint.name,
        "jacket",
        &BTreeMap::new(),
    );
    let second_key = re0auth_api::cache::key_asset(
        &other_binding,
        "other-player",
        &app.harness.endpoint.name,
        "jacket",
        &BTreeMap::new(),
    );
    assert!(app.cache.get(&first_key).await.is_some());
    assert!(app.cache.get(&second_key).await.is_some());
}

#[tokio::test]
async fn private_asset_cache_is_isolated_by_upstream_subject() {
    let app = asset_harness(false).await;
    app.harness.connector.set_asset_stream(
        "jacket",
        "image/png",
        [bytes::Bytes::from_static(png())],
    );
    let granted = scopes();
    let first = app
        .harness
        .service
        .fetch_asset(
            request(
                app.harness.user.id,
                app.harness.connector_id,
                &granted,
                "jacket",
            ),
            Some("image/png"),
        )
        .await
        .expect("first private asset");
    assert_eq!(read_asset(first).await, png());

    let rebound = Binding {
        upstream_user_id: "different-upstream-account".to_string(),
        ..app.harness.binding.clone()
    };
    app.harness
        .store
        .bindings()
        .upsert(&rebound, &fact_binding())
        .await
        .expect("rebind upstream account");
    let second = app
        .harness
        .service
        .fetch_asset(
            request(
                app.harness.user.id,
                app.harness.connector_id,
                &granted,
                "jacket",
            ),
            Some("image/png"),
        )
        .await
        .expect("rebound private asset");
    assert_eq!(read_asset(second).await, png());
    assert_eq!(app.harness.connector.calls().len(), 2);
    assert_eq!(app.cache.len(), 2);
}

#[tokio::test]
async fn shared_asset_users_share_one_upstream_call_and_cache_entry() {
    let app = asset_harness(true).await;
    app.harness.connector.set_asset_stream(
        "jacket",
        "image/png",
        [bytes::Bytes::from_static(png())],
    );
    let other = add_asset_user(&app.harness, "shared-without-binding").await;
    let granted = scopes();

    for _ in 0..2 {
        for user in [app.harness.user.id, other] {
            let response = app
                .harness
                .service
                .fetch_asset(
                    request(user, app.harness.connector_id, &granted, "jacket"),
                    Some("image/png"),
                )
                .await
                .expect("shared asset");
            assert_eq!(read_asset(response).await, png());
        }
    }

    assert_eq!(app.harness.connector.calls().len(), 1);
    assert_eq!(app.cache.len(), 1);
    let key =
        re0auth_api::cache::key_shared(&app.harness.endpoint.name, "jacket", &BTreeMap::new());
    assert!(app.cache.get(&key).await.is_some());
    assert!(!key.contains(&app.harness.binding.id.0.to_string()));
}

#[tokio::test]
async fn unavailable_assets_are_negative_cached_unless_ttl_is_zero() {
    let app = asset_harness(false).await;
    app.harness
        .connector
        .set_asset_error("jacket", UpstreamError::Unavailable);
    let granted = scopes();
    for _ in 0..2 {
        let error = app
            .harness
            .service
            .fetch_asset(
                request(
                    app.harness.user.id,
                    app.harness.connector_id,
                    &granted,
                    "jacket",
                ),
                Some("image/png"),
            )
            .await
            .expect_err("cached unavailability");
        assert!(matches!(
            error,
            GatewayError::Upstream(UpstreamError::Unavailable)
        ));
    }
    assert_eq!(app.harness.connector.calls().len(), 1);
    assert_eq!(app.failures.entries.lock().expect("failures").len(), 1);

    let disabled = asset_harness_with_limits(false, 0, 4, 32, 45, 10).await;
    disabled
        .harness
        .connector
        .set_asset_error("jacket", UpstreamError::Unavailable);
    for _ in 0..2 {
        let error = disabled
            .harness
            .service
            .fetch_asset(
                request(
                    disabled.harness.user.id,
                    disabled.harness.connector_id,
                    &granted,
                    "jacket",
                ),
                Some("image/png"),
            )
            .await
            .expect_err("uncached unavailability");
        assert!(matches!(
            error,
            GatewayError::Upstream(UpstreamError::Unavailable)
        ));
    }
    assert_eq!(disabled.harness.connector.calls().len(), 2);
    assert!(
        disabled
            .failures
            .entries
            .lock()
            .expect("failures")
            .is_empty()
    );
}

async fn assert_avif_box(body: &'static [u8], accepted: bool) {
    let app = asset_harness(false).await;
    app.harness.connector.set_asset_stream(
        "jacket",
        "image/avif",
        body.chunks(4)
            .map(bytes::Bytes::copy_from_slice)
            .collect::<Vec<_>>(),
    );
    let granted = scopes();
    let result = app
        .harness
        .service
        .fetch_asset(
            request(
                app.harness.user.id,
                app.harness.connector_id,
                &granted,
                "jacket",
            ),
            Some("image/avif"),
        )
        .await;
    if accepted {
        assert_eq!(read_asset(result.expect("valid AVIF")).await, body);
        assert_eq!(app.cache.len(), 1);
    } else {
        let error = result.expect_err("invalid AVIF");
        assert!(matches!(
            error,
            GatewayError::Upstream(UpstreamError::ContractChanged)
        ));
        assert!(app.cache.is_empty());
    }
}

#[tokio::test]
async fn avif_loader_waits_for_the_entire_ftyp_box() {
    let compatible_at_16: &'static [u8] = b"\0\0\0\x18ftypmif1\0\0\0\0aviftest";
    let compatible_at_20: &'static [u8] = b"\0\0\0\x18ftypmiaf\0\0\0\0testavif";
    assert_avif_box(compatible_at_16, true).await;
    assert_avif_box(compatible_at_20, true).await;
    assert_avif_box(b"\0\0\0\x18ftypmif1\0\0\0\0testtest", false).await;
    assert_avif_box(b"\0\0\0\x18ftypmif1\0\0\0\0avif", false).await;
    assert_avif_box(b"\0\0\0\x10ftypavif\0\0\0\0", true).await;
    assert_avif_box(b"\0\0\0\x0cftypavif\0\0\0\0", false).await;
    assert_avif_box(b"\0\0\x01\x01ftypavif\0\0\0\0aviftest", false).await;
}

#[tokio::test]
async fn ten_asset_requests_share_one_loader_and_start_at_chunk_zero() {
    let app = asset_harness(false).await;
    app.harness.connector.set_asset_stream(
        "jacket",
        "image/png",
        [
            bytes::Bytes::from_static(b"\x89PNG\r\n\x1a\nbo"),
            bytes::Bytes::from_static(b"d"),
            bytes::Bytes::from_static(b"y"),
        ],
    );
    let granted = scopes();
    let requests = (0..10).map(|_| {
        let service = app.harness.service.clone();
        let granted = granted.clone();
        let user = app.harness.user.id;
        let connector = app.harness.connector_id;
        async move {
            let response = service
                .fetch_asset(
                    request(user, connector, &granted, "jacket"),
                    Some("image/png"),
                )
                .await
                .expect("asset response");
            read_asset(response).await
        }
    });
    let bodies = futures_util::future::join_all(requests).await;
    assert!(bodies.iter().all(|body| body == png()));
    assert_eq!(app.harness.connector.calls().len(), 1);
    assert_eq!(app.cache.len(), 1);
}

#[tokio::test]
async fn shared_assets_need_no_binding_but_private_assets_still_do() {
    let app = asset_harness(true).await;
    app.harness.connector.set_asset_stream(
        "jacket",
        "image/png",
        [bytes::Bytes::from_static(png())],
    );
    let other = UserId::new();
    app.harness
        .store
        .users()
        .create(&User {
            id: other,
            display_name: "shared-user".to_string(),
            role: UserRole::User,
            status: UserStatus::Active,
            created_at: 1_000,
            updated_at: 1_000,
        })
        .await
        .expect("user");
    let granted = scopes();
    let response = app
        .harness
        .service
        .fetch_asset(
            request(other, app.harness.connector_id, &granted, "jacket"),
            Some("image/png"),
        )
        .await
        .expect("shared request without binding");
    assert_eq!(read_asset(response).await, png());

    let private = asset_harness(false).await;
    private
        .harness
        .store
        .users()
        .create(&User {
            id: other,
            display_name: "private-user".to_string(),
            role: UserRole::User,
            status: UserStatus::Active,
            created_at: 1_000,
            updated_at: 1_000,
        })
        .await
        .expect("user");
    let error = private
        .harness
        .service
        .fetch_asset(
            request(other, private.harness.connector_id, &granted, "jacket"),
            Some("image/png"),
        )
        .await
        .expect_err("private binding required");
    assert!(matches!(error, GatewayError::BindingRequired));
}

#[tokio::test]
async fn negative_assets_expire_on_the_injected_clock() {
    let app = asset_harness(false).await;
    app.harness
        .connector
        .set_asset_error("jacket", UpstreamError::NotFound);
    let granted = scopes();
    for _ in 0..2 {
        let error = app
            .harness
            .service
            .fetch_asset(
                request(
                    app.harness.user.id,
                    app.harness.connector_id,
                    &granted,
                    "jacket",
                ),
                Some("image/png"),
            )
            .await
            .expect_err("negative response");
        assert!(matches!(
            error,
            GatewayError::Upstream(UpstreamError::NotFound)
        ));
    }
    assert_eq!(app.harness.connector.calls().len(), 1);
    app.harness.set_now(1_006);
    app.harness
        .service
        .fetch_asset(
            request(
                app.harness.user.id,
                app.harness.connector_id,
                &granted,
                "jacket",
            ),
            Some("image/png"),
        )
        .await
        .expect_err("expired negative");
    assert_eq!(app.harness.connector.calls().len(), 2);
}

#[tokio::test]
async fn accept_magic_and_normalized_route_are_enforced() {
    let app = asset_harness(false).await;
    let granted = scopes();
    let error = app
        .harness
        .service
        .fetch_asset(
            request(
                app.harness.user.id,
                app.harness.connector_id,
                &granted,
                "jacket",
            ),
            Some("image/jpeg"),
        )
        .await
        .expect_err("unacceptable type");
    assert!(matches!(error, GatewayError::NotAcceptable));

    app.harness.connector.set_asset_stream(
        "jacket",
        "image/png",
        [bytes::Bytes::from_static(br#"{"not":"png"}"#)],
    );
    let error = app
        .harness
        .service
        .fetch_asset(
            request(
                app.harness.user.id,
                app.harness.connector_id,
                &granted,
                "jacket",
            ),
            Some("image/png"),
        )
        .await
        .expect_err("magic mismatch");
    assert!(matches!(
        error,
        GatewayError::Upstream(UpstreamError::ContractChanged)
    ));
    assert!(app.cache.is_empty());

    let error = app
        .harness
        .service
        .fetch(request(
            app.harness.user.id,
            app.harness.connector_id,
            &granted,
            "jacket",
        ))
        .await
        .expect_err("normalized fetch rejects binary");
    assert!(matches!(
        error,
        GatewayError::InvalidRequest("binary resource requires /api/v1/assets")
    ));
}

#[tokio::test]
async fn shared_json_fetch_skips_binding_and_subject() {
    let mut app = asset_harness(true).await;
    let mut spec = ResourceSpec::new("public_stats", "/v1/public")
        .expect("shared JSON spec")
        .with_scope("scores.read")
        .expect("scope");
    spec.shared = true;
    app.harness.endpoint.resources.push(spec);
    app.harness.connector.register(app.harness.endpoint.clone());
    app.harness
        .connector
        .set_response("public_stats", Ok(payload(br#"{"available":true}"#)));
    let user = add_asset_user(&app.harness, "shared-json").await;
    let granted = scopes();
    let payload = app
        .harness
        .service
        .fetch(request(
            user,
            app.harness.connector_id,
            &granted,
            "public_stats",
        ))
        .await
        .expect("shared JSON without binding");
    let document: serde_json::Value = serde_json::from_slice(&payload.body).expect("envelope");
    assert_eq!(document["data"], serde_json::json!({"available": true}));
    let calls = app.harness.connector.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].subject, "");
}
