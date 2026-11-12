use re0auth_adapters::storage::SqliteStore;
use re0auth_api::AuditId;
use re0auth_api::audit::{AuditAction, AuditOutcome, AuditRecord, AuditTier, Severity};
use re0auth_api::ports::Storage;

fn record() -> AuditRecord {
    AuditRecord {
        id: AuditId::new(),
        occurred_at: 1_000,
        actor_user_id: None,
        client_id: None,
        action: AuditAction::DataAccessed,
        target: "phigros/scores".to_string(),
        outcome: AuditOutcome::Success,
        severity: Severity::Info,
        request_id: None,
        detail: "{}".to_string(),
        tier: AuditTier::Telemetry,
    }
}

#[tokio::test]
async fn a_bad_batch_row_does_not_roll_back_the_other_rows() {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("store");
    let duplicate = record();
    store
        .audits()
        .append(&duplicate)
        .await
        .expect("existing telemetry");
    let unique = record();

    let (appended, failures) = store
        .audits()
        .append_batch(&[duplicate, unique])
        .await
        .expect("batch");
    assert_eq!(appended, 1);
    assert_eq!(failures.len(), 1);
    assert_eq!(store.audits().count().await.expect("count"), 2);
}

#[tokio::test]
async fn retention_purges_every_expired_batch() {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("store");
    let records: Vec<_> = (0..1_001).map(|_| record()).collect();
    let (appended, failures) = store
        .audits()
        .append_batch(&records)
        .await
        .expect("seed telemetry");
    assert_eq!(appended, 1_001);
    assert!(failures.is_empty());

    let purged = store
        .audits()
        .purge_tier_before(AuditTier::Telemetry, 1_000)
        .await
        .expect("purge");
    assert_eq!(purged, 1_001);
    assert_eq!(store.audits().count().await.expect("count"), 0);
}
