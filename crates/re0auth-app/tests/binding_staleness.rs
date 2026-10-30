//! 惰性推断：超时未刷新的绑定降级为需要重新授权。
//!
//! 不探测上游，只按未刷新时长推断。测试覆盖阈值两侧、
//! 从未刷新的回退到 created_at、阈值为 0 时禁用、以及已撤销
//! 的绑定不受影响。

use std::sync::Arc;

use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::oauth::{AccessTokenClaims, ApprovalTicketClaims, IdTokenClaims, TokenSigner};
use re0auth_api::ports::{Binding, BindingStatus, Storage, User, UserRole};
use re0auth_api::{BindingId, Clock, Random, Re0Result, UserId};
use re0auth_app::auth::AuthService;
use re0auth_contract::MemoryStore;

const DAY: i64 = 86_400;

struct FixedClock(i64);

impl Clock for FixedClock {
    fn now(&self) -> i64 {
        self.0
    }
}

struct ZeroRandom;

impl Random for ZeroRandom {
    fn bytes(&self, len: usize) -> Vec<u8> {
        vec![7; len]
    }
}

struct UnusedSigner;

impl TokenSigner for UnusedSigner {
    fn sign_access(&self, _: &AccessTokenClaims) -> Re0Result<String> {
        panic!("not used")
    }
    fn sign_id(&self, _: &IdTokenClaims) -> Re0Result<String> {
        panic!("not used")
    }
    fn sign_approval_ticket(&self, _: &ApprovalTicketClaims) -> Re0Result<String> {
        panic!("not used")
    }
    fn verify_access(&self, _: &str) -> Re0Result<AccessTokenClaims> {
        panic!("not used")
    }
    fn verify_approval_ticket(&self, _: &str) -> Re0Result<ApprovalTicketClaims> {
        panic!("not used")
    }
    fn jwks(&self) -> String {
        panic!("not used")
    }
}

fn service(store: Arc<MemoryStore>, now: i64, after_days: u64) -> AuthService {
    AuthService::new(
        store,
        vec![],
        Arc::new(UnusedSigner),
        Arc::new(FixedClock(now)),
        Arc::new(ZeroRandom),
        "https://issuer.test",
    )
    .with_binding_probe(after_days)
}

/// 建一个绑定，`last_refreshed_at` 由调用方决定。
async fn seed(
    store: &MemoryStore,
    now: i64,
    status: BindingStatus,
    last_refreshed_at: Option<i64>,
) -> (UserId, Binding) {
    let user = UserId::new();
    store
        .users()
        .create(&User {
            id: user,
            display_name: "stale-user".to_string(),
            role: UserRole::User,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("user");
    let binding = Binding {
        id: BindingId::new(),
        user_id: user,
        upstream_id: "phihub".to_string(),
        upstream_user_id: "player-1".to_string(),
        status,
        created_at: now,
        updated_at: now,
        last_refreshed_at,
        last_error_code: None,
    };
    store
        .bindings()
        .upsert(
            &binding,
            &SecurityFact::new(
                AuditAction::BindingCreated,
                now,
                format!("binding:{}", binding.id.0),
            ),
        )
        .await
        .expect("binding");
    (user, binding)
}

#[tokio::test]
async fn a_binding_past_the_threshold_is_downgraded() {
    let now = 1_000_000;
    let store = Arc::new(MemoryStore::new());
    let (user, binding) = seed(
        &store,
        now,
        BindingStatus::Active,
        Some(now - 7 * DAY),
    )
    .await;

    let views = service(store.clone(), now, 6)
        .list_bindings(user)
        .await
        .expect("list");

    assert_eq!(views.len(), 1);
    assert_eq!(views[0].status, "needs_reauth");
    assert_eq!(views[0].last_error_code.as_deref(), Some("stale_credential"));

    let stored = store
        .bindings()
        .find(&user, "phihub")
        .await
        .expect("find")
        .expect("binding");
    assert_eq!(
        stored.status,
        BindingStatus::NeedsReauth,
        "降级必须落库，否则下次访问会重新变回 active"
    );
    assert_eq!(stored.id, binding.id);
}

#[tokio::test]
async fn a_binding_within_the_threshold_stays_active() {
    let now = 1_000_000;
    let store = Arc::new(MemoryStore::new());
    let (user, _) = seed(
        &store,
        now,
        BindingStatus::Active,
        Some(now - 5 * DAY),
    )
    .await;

    let views = service(store.clone(), now, 6)
        .list_bindings(user)
        .await
        .expect("list");

    assert_eq!(views[0].status, "active");
    assert!(views[0].last_error_code.is_none());

    let stored = store
        .bindings()
        .find(&user, "phihub")
        .await
        .expect("find")
        .expect("binding");
    assert_eq!(stored.status, BindingStatus::Active, "阈值内不得改动");
}

#[tokio::test]
async fn a_binding_never_refreshed_falls_back_to_created_at() {
    let now = 1_000_000;
    let store = Arc::new(MemoryStore::new());
    let (user, _) = seed(&store, now - 7 * DAY, BindingStatus::Active, None).await;

    let views = service(store.clone(), now, 6)
        .list_bindings(user)
        .await
        .expect("list");

    assert_eq!(
        views[0].status, "needs_reauth",
        "从未刷新过时按 created_at 计算时长"
    );
}

#[tokio::test]
async fn a_zero_threshold_disables_the_inference() {
    let now = 1_000_000;
    let store = Arc::new(MemoryStore::new());
    let (user, _) = seed(
        &store,
        now,
        BindingStatus::Active,
        Some(now - 30 * DAY),
    )
    .await;

    let views = service(store.clone(), now, 0)
        .list_bindings(user)
        .await
        .expect("list");

    assert_eq!(views[0].status, "active", "阈值为 0 表示关闭推断");
}

#[tokio::test]
async fn a_revoked_binding_is_not_listed_nor_downgraded() {
    let now = 1_000_000;
    let store = Arc::new(MemoryStore::new());
    let (user, binding) = seed(
        &store,
        now,
        BindingStatus::Revoked,
        Some(now - 30 * DAY),
    )
    .await;

    let views = service(store.clone(), now, 6)
        .list_bindings(user)
        .await
        .expect("list");

    assert!(views.is_empty(), "已撤销的绑定不在列表中");

    let stored = store
        .bindings()
        .find(&user, "phihub")
        .await
        .expect("find")
        .expect("binding");
    assert_eq!(stored.status, BindingStatus::Revoked, "不得改写已撤销状态");
    assert_eq!(stored.id, binding.id);
}
