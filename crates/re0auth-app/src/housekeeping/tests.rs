use std::sync::Arc;
use std::time::Duration;

use re0auth_api::ports::{LoginTransaction, Session, Storage, User, UserRole};
use re0auth_api::{Clock, SessionId, Unix, UserId};
use re0auth_contract::memory::MemoryStore;

use super::*;

struct FixedClock(Unix);

impl Clock for FixedClock {
    fn now(&self) -> Unix {
        self.0
    }
}

fn session(
    user: UserId,
    hash: u8,
    now: Unix,
    idle_expires_at: Unix,
    absolute_expires_at: Unix,
) -> Session {
    Session {
        id: SessionId::new(),
        id_hash: vec![hash; 32],
        user_id: user,
        csrf_hash: vec![1u8; 32],
        created_at: now,
        last_seen_at: now,
        idle_expires_at,
        absolute_expires_at,
        revoked_at: None,
    }
}

async fn seed_user(store: &MemoryStore, now: Unix) -> UserId {
    let user = UserId::new();
    store
        .users()
        .create(&User {
            id: user,
            display_name: "probe".to_string(),
            role: UserRole::User,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("user");
    user
}

#[tokio::test]
async fn sweep_removes_rows_past_retention_and_keeps_live_ones() {
    let store = Arc::new(MemoryStore::new());
    let user = seed_user(&store, 1_000).await;

    // Expired long before the retention cutoff: must be deleted.
    store
        .sessions()
        .create(&session(user, 1, 1_000_000, 1_000_100, 1_000_200))
        .await
        .expect("expired session");
    // Expired, but inside the retention window: must survive this sweep.
    store
        .sessions()
        .create(&session(user, 2, 9_800_000, 9_827_200, 9_900_000))
        .await
        .expect("recently expired session");
    // Still valid: must survive.
    store
        .sessions()
        .create(&session(user, 3, 10_000_000, 99_000_000, 99_000_000))
        .await
        .expect("live session");

    let job = HousekeepingSweepJob::new(
        store.clone(),
        Arc::new(FixedClock(10_000_000)),
        Duration::from_secs(600),
    );
    job.run().await.expect("sweep succeeds");

    // The purged row is gone outright, not merely expired.
    assert!(
        store
            .sessions()
            .find_active(&[1u8; 32], 1_000_050)
            .await
            .expect("lookup")
            .is_none(),
        "the long-expired session must be deleted, not just filtered out"
    );
    // Retention keeps the recently expired row around.
    assert!(
        store
            .sessions()
            .find_active(&[2u8; 32], 9_827_199)
            .await
            .expect("lookup")
            .is_some(),
        "a row inside the retention window must survive"
    );
    assert!(
        store
            .sessions()
            .find_active(&[3u8; 32], 10_000_000)
            .await
            .expect("lookup")
            .is_some(),
        "the live session must survive"
    );
}

/// The point of per-table windows: two rows expired at the same instant are kept
/// for different lengths of time. A session gets a week to explain the failure;
/// a login transaction gets a day, because nothing can reference it after that.
#[tokio::test]
async fn each_table_keeps_its_own_window() {
    let store = Arc::new(MemoryStore::new());
    let user = seed_user(&store, 1_000).await;
    let now = 10 * DAY;
    // Both expired two days ago.
    let expired_at = now - 2 * DAY;

    store
        .sessions()
        .create(&session(user, 7, 1_000, expired_at, expired_at))
        .await
        .expect("session");
    store
        .login_transactions()
        .insert(&LoginTransaction {
            state_hash: vec![9u8; 32],
            nonce: "nonce".to_string(),
            pkce_verifier: "verifier".to_string(),
            return_to: "/".to_string(),
            provider: "test".to_string(),
            created_at: 1_000,
            expires_at: expired_at,
            consumed_at: None,
        })
        .await
        .expect("login transaction");

    HousekeepingSweepJob::new(
        store.clone(),
        Arc::new(FixedClock(now)),
        Duration::from_secs(600),
    )
    .run()
    .await
    .expect("sweep");

    assert!(
        store
            .sessions()
            .find_active(&[7u8; 32], expired_at - 1)
            .await
            .expect("lookup")
            .is_some(),
        "a session is kept for a week after expiry"
    );
    assert!(
        store
            .login_transactions()
            .consume(&[9u8; 32], now)
            .await
            .is_err(),
        "a login transaction is gone after a day"
    );
}

#[tokio::test]
async fn an_empty_database_is_a_successful_sweep() {
    let store = Arc::new(MemoryStore::new());
    let job = HousekeepingSweepJob::new(
        store,
        Arc::new(FixedClock(100_000)),
        Duration::from_secs(600),
    );
    // Nothing to delete is not a failure: the scheduler must not log errors for
    // a healthy but idle instance.
    job.run().await.expect("empty sweep succeeds");
}

#[test]
fn task_identity_is_stable_and_interval_is_passed_through() {
    let store = Arc::new(MemoryStore::new());
    let job = HousekeepingSweepJob::new(store, Arc::new(FixedClock(0)), Duration::from_secs(3_600));
    assert_eq!(job.name(), "housekeeping-sweep");
    assert_eq!(job.interval(), Duration::from_secs(3_600));
}

#[tokio::test]
async fn retention_sweep_ages_out_telemetry_before_facts_and_anonymizes_bindings() {
    use re0auth_api::audit::{
        AuditAction, AuditOutcome, AuditRecord, AuditTier, SecurityFact, Severity,
    };
    use re0auth_api::ports::{ANONYMIZED_UPSTREAM_USER_ID, Binding, BindingStatus};
    use re0auth_api::{AuditId, BindingId};

    const DAY: Unix = 86_400;
    let store = Arc::new(MemoryStore::new());
    let user = seed_user(&store, 1_000).await;

    // 400 days after the oldest event: past the 90-day telemetry and 30-day
    // binding windows but still inside the 365-day fact window for a fact that is
    // only 300 days old.
    let now = 1_000 + 400 * DAY;

    // A binding revoked 40 days ago: past its anonymization window.
    let revoked = Binding {
        id: BindingId::new(),
        user_id: user,
        upstream_id: "phigros".to_string(),
        upstream_user_id: "upstream-player".to_string(),
        status: BindingStatus::Active,
        created_at: now - 40 * DAY,
        updated_at: now - 40 * DAY,
        last_refreshed_at: None,
        last_error_code: None,
    };
    store
        .bindings()
        .upsert(
            &revoked,
            &SecurityFact::new(AuditAction::BindingCreated, now - 40 * DAY, "binding"),
        )
        .await
        .expect("binding");
    store
        .bindings()
        .revoke(
            &revoked.id,
            &SecurityFact::new(AuditAction::BindingRevoked, now - 40 * DAY, "binding"),
            now - 40 * DAY,
        )
        .await
        .expect("revoke");

    // A fact 300 days old, inside the year.
    let recent = Binding {
        id: BindingId::new(),
        upstream_id: "phihub".to_string(),
        ..revoked.clone()
    };
    store
        .bindings()
        .upsert(
            &recent,
            &SecurityFact::new(AuditAction::BindingCreated, now - 300 * DAY, "binding"),
        )
        .await
        .expect("recent fact");

    // Telemetry 100 days old: past its 90-day window.
    store
        .audits()
        .append(&AuditRecord {
            id: AuditId::new(),
            occurred_at: now - 100 * DAY,
            actor_user_id: Some(user),
            client_id: None,
            action: AuditAction::AuthCodeIssued,
            target: "telemetry".to_string(),
            outcome: AuditOutcome::Success,
            severity: Severity::Info,
            request_id: None,
            detail: "{}".to_string(),
            tier: AuditTier::Telemetry,
        })
        .await
        .expect("append telemetry");

    let job = RetentionSweepJob::new(
        store.clone(),
        Arc::new(FixedClock(now)),
        Duration::from_secs(600),
        RetentionPolicy::from_days(365, 90, 30),
    );
    job.run().await.expect("retention sweep succeeds");

    let records = store.audits().recent(100).await.expect("recent");
    assert!(
        records.iter().all(|record| record.tier == AuditTier::Fact),
        "access telemetry older than its window must be deleted"
    );
    assert!(
        records.iter().any(|record| record.target == "binding"),
        "a fact inside the year must survive"
    );

    let kept = store
        .bindings()
        .find(&user, "phigros")
        .await
        .expect("find")
        .expect("row kept");
    assert_eq!(
        kept.upstream_user_id, ANONYMIZED_UPSTREAM_USER_ID,
        "the revoked binding's row stays for audit but its identity is gone"
    );
}
