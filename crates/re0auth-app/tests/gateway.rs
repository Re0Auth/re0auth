use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use re0auth_api::audit::{AccessSource, AccessTelemetry};
use re0auth_api::cache::Cache;
use re0auth_api::connector::{
    BodyField, BodyValue, ConnectorBroker, ConnectorEndpoint, EgressPolicy, FaultClass,
    ResourceMethod, ResourceRequest, ResourceSpec, UpstreamError, UpstreamPayload,
};
use re0auth_api::ports::{
    Binding, BindingStatus, Storage, TelemetrySink, User, UserRole, UserStatus,
};
use re0auth_api::secret::SecretSealer;
use re0auth_api::{BindingId, Clock, ConnectorId, Re0Error, SecretString, UserId};
use re0auth_app::circuit::{CircuitPolicy, CircuitTracker};
use re0auth_app::credentials::{CredentialError, CredentialSource};
use re0auth_app::gateway::{GatewayError, GatewayRequest, GatewayService, Pagination};
use re0auth_contract::{ConnectorFixture, MemoryStore, MockConnector, MockSealer};
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
            &re0auth_api::cache::CachedResponse {
                content_type: "application/json".to_string(),
                body,
                stale: false,
            },
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
                    value: BodyValue::Constant("1".to_string()),
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
