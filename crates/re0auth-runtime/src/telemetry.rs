//! Access-telemetry pipeline (ADR-0025): a bounded channel and its drain job.
//!
//! The gateway only ever `try_send`s; this module owns the receive side and the
//! drop counter. The drain is a [`ScheduledTask`] so INV-SPAWN-01 holds — the
//! composition root's scheduler is the only place that starts background work.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use re0auth_api::audit::{
    AccessTelemetry, AuditAction, AuditOutcome, AuditRecord, AuditTier, Severity,
};
use re0auth_api::ports::{Storage, TelemetrySink};
use re0auth_api::schedule::{ScheduledTask, TaskError};

/// The producer handle. `record` never blocks and never awaits.
pub struct ChannelTelemetrySink {
    sender: mpsc::Sender<AccessTelemetry>,
    dropped: Arc<AtomicU64>,
}

/// Builds a bounded telemetry channel: the sink for the producer, the receiver
/// for the drain job, and the counter they share.
///
/// Exactly one sink clone and one receiver exist by construction, so the drop
/// count has a single owner.
#[must_use]
pub fn channel(
    capacity: usize,
) -> (
    Arc<ChannelTelemetrySink>,
    mpsc::Receiver<AccessTelemetry>,
    Arc<AtomicU64>,
) {
    let (sender, receiver) = mpsc::channel(capacity);
    let dropped = Arc::new(AtomicU64::new(0));
    let sink = Arc::new(ChannelTelemetrySink {
        sender,
        dropped: Arc::clone(&dropped),
    });
    (sink, receiver, dropped)
}

impl TelemetrySink for ChannelTelemetrySink {
    fn record(&self, event: AccessTelemetry) -> bool {
        match self.sender.try_send(event) {
            Ok(()) => true,
            // A full queue and a closed one both mean the record is gone, and
            // neither is retryable by the caller, so both count as drops.
            Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }
}

/// Drains the channel into `audit_logs` as the telemetry tier.
pub struct TelemetryFlushJob {
    /// Behind a `Mutex` because [`ScheduledTask::run`] borrows `&self` while
    /// `try_recv` needs `&mut`. It is never held across an `await`; the batch is
    /// drained first and written afterwards.
    receiver: std::sync::Mutex<mpsc::Receiver<AccessTelemetry>>,
    storage: Arc<dyn Storage>,
    interval: Duration,
    dropped: Arc<AtomicU64>,
    /// Last drop count reported, so the warning fires once per increase rather
    /// than once per flush.
    reported_dropped: AtomicU64,
}

impl TelemetryFlushJob {
    #[must_use]
    pub fn new(
        receiver: mpsc::Receiver<AccessTelemetry>,
        storage: Arc<dyn Storage>,
        interval: Duration,
        dropped: Arc<AtomicU64>,
    ) -> Self {
        Self {
            receiver: std::sync::Mutex::new(receiver),
            storage,
            interval,
            dropped,
            reported_dropped: AtomicU64::new(0),
        }
    }

    /// Turns one event into the row that lands in `audit_logs`.
    ///
    /// The type split exists so the application layer never touches JSON: it
    /// sends an [`AccessTelemetry`], and the encoding lives here.
    #[must_use]
    pub fn to_record(event: &AccessTelemetry) -> AuditRecord {
        AuditRecord {
            id: event.id,
            occurred_at: event.occurred_at,
            actor_user_id: event.actor_user_id,
            client_id: event.client_id,
            action: AuditAction::DataAccessed,
            target: format!("{}/{}", event.connector, event.resource),
            outcome: AuditOutcome::Success,
            severity: Severity::Info,
            request_id: event.request_id.clone(),
            detail: serde_json::json!({
                "source": event.source.as_str(),
                "latency_ms": event.latency_ms,
            })
            .to_string(),
            // `append` forces this too; stating it here keeps the row honest
            // even if a future writer stops forcing it.
            tier: AuditTier::Telemetry,
        }
    }

    /// Reports the cumulative drop count once per increase.
    ///
    /// Q-036 keeps v1 on logs rather than metrics, so this warning is the only
    /// signal that the access ledger is incomplete — and saying so is the
    /// difference between "no reads happened" and "reads were not recorded".
    fn report_drops(&self) {
        let total = self.dropped.load(Ordering::Relaxed);
        let reported = self.reported_dropped.swap(total, Ordering::Relaxed);
        if total > reported {
            tracing::warn!(
                audit_dropped_total = total,
                "access telemetry dropped records; the access ledger is incomplete"
            );
        }
    }
}

#[async_trait]
impl ScheduledTask for TelemetryFlushJob {
    fn name(&self) -> &'static str {
        "telemetry-flush"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    async fn run(&self) -> Result<(), TaskError> {
        // Drain first, then write: the receiver lock must not be held across an
        // `await`, or the future stops being `Send`.
        let mut batch = Vec::new();
        {
            let mut receiver = self.receiver.lock().expect("telemetry receiver poisoned");
            while let Ok(event) = receiver.try_recv() {
                batch.push(event);
            }
        }

        let mut appended = 0u64;
        let mut failures = Vec::new();
        for event in &batch {
            match self.storage.audits().append(&Self::to_record(event)).await {
                Ok(()) => appended += 1,
                // One bad row must not drop the rest of the batch: the queue is
                // lossy by design, but losing a whole batch to one failure is not.
                Err(error) => failures.push(error.to_string()),
            }
        }
        self.report_drops();
        if failures.is_empty() {
            return Ok(());
        }
        Err(TaskError::failed(format!(
            "{appended} telemetry row(s) appended, {} failed: {}",
            failures.len(),
            failures.join("; ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use re0auth_api::audit::AccessSource;
    use re0auth_api::{AuditId, UserId};

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
    async fn a_full_queue_drops_and_counts() {
        // The receiver stays alive, or every send would fail as "closed" and the
        // drop would not be attributable to the queue being full.
        let (sink, _receiver, dropped) = channel(1);
        assert!(sink.record(event(1)));
        assert!(!sink.record(event(2)), "the second record has no room");
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn an_event_becomes_a_telemetry_row() {
        let record = TelemetryFlushJob::to_record(&event(7));
        assert_eq!(record.action, AuditAction::DataAccessed);
        assert_eq!(
            record.tier,
            AuditTier::Telemetry,
            "access telemetry is the lossy tier"
        );
        assert_eq!(record.target, "phigros/scores");
        assert_eq!(record.outcome, AuditOutcome::Success);
        assert!(record.detail.contains("upstream"));
        assert!(
            record.detail.contains("42"),
            "latency is kept: {}",
            record.detail
        );
    }
}
