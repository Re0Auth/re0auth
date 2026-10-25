//! Access telemetry reaches `audit_logs` with the right tier, and a full queue
//! drops instead of blocking (ADR-0025).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use re0auth_api::audit::{AccessSource, AccessTelemetry, AuditAction, AuditTier};
use re0auth_api::ports::{Storage, TelemetrySink};
use re0auth_api::schedule::ScheduledTask;
use re0auth_api::{AuditId, UserId};
use re0auth_contract::MemoryStore;
use re0auth_runtime::telemetry::{TelemetryFlushJob, channel};

fn event(occurred_at: i64) -> AccessTelemetry {
    AccessTelemetry {
        id: AuditId::new(),
        occurred_at,
        actor_user_id: Some(UserId::new()),
        client_id: None,
        connector: "phigros".to_string(),
        resource: "scores".to_string(),
        source: AccessSource::Upstream,
        latency_ms: 42,
        request_id: Some("req-1".to_string()),
    }
}

#[tokio::test]
async fn the_flush_job_writes_the_telemetry_tier_and_reports_drops() {
    let store = Arc::new(MemoryStore::new());
    let (sink, receiver, dropped) = channel(1);

    // One record fits; the next is dropped and counted rather than blocking.
    assert!(sink.record(event(1)));
    assert!(!sink.record(event(2)));
    assert_eq!(dropped.load(Ordering::Relaxed), 1);

    let job = TelemetryFlushJob::new(
        receiver,
        store.clone(),
        Duration::from_secs(1),
        Arc::clone(&dropped),
    );
    job.run().await.expect("flush");

    let rows = store.audits().recent(10).await.expect("recent");
    assert_eq!(
        rows.len(),
        1,
        "only the queued record lands; the dropped one is gone"
    );
    assert_eq!(rows[0].action, AuditAction::DataAccessed);
    assert_eq!(
        rows[0].tier,
        AuditTier::Telemetry,
        "access telemetry must not be written as a security fact"
    );

    // An empty queue is a healthy no-op, not a failure.
    job.run().await.expect("second flush");
}
