//! Periodic cleanup of expired rows.
//!
//! Every repository exposes `purge_expired`, but nothing called them: the tables
//! would grow without bound. This job is the single caller, driven by the
//! scheduler so that no repository starts background work of its own.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use re0auth_api::audit::AuditTier;
use re0auth_api::ports::Storage;
use re0auth_api::rate::RateLimiter;
use re0auth_api::schedule::{ScheduledTask, TaskError};
use re0auth_api::{Clock, Unix};

/// One day, as the unit the windows below are written in.
const DAY: Unix = 86_400;

/// How long each table keeps a row after it expires (`DATA-MODEL.md` §6).
///
/// A single window was the first cut, and it made one requirement impossible: a
/// revoked refresh token has to survive 30 days so that replaying it is detected
/// as reuse rather than as "unknown token". Deleting too early turns a clean
/// "this code expired" into "code not found", so each window is generous for its
/// own reason rather than uniformly short.
mod grace {
    use super::DAY;
    use re0auth_api::Unix;

    /// Codes and sessions: long enough to explain the failure to the user.
    pub const SESSIONS: Unix = 7 * DAY;
    pub const AUTH_CODES: Unix = 7 * DAY;
    pub const DEVICE_CODES: Unix = 7 * DAY;
    /// Short-lived flows: a day after expiry nothing can reference them.
    pub const LOGIN_TRANSACTIONS: Unix = DAY;
    pub const APPROVAL_TICKETS: Unix = DAY;
    pub const PENDING_AUTHORIZATIONS: Unix = DAY;
    pub const DEVICE_ATTEMPTS: Unix = DAY;
    /// Reuse detection: a rotated token must stay comparable for a month.
    pub const REFRESH_TOKENS: Unix = 30 * DAY;
    /// Revocation rows matter only while the token could be presented.
    pub const ACCESS_REVOCATIONS: Unix = 0;
}

/// Deletes expired rows from every repository that has a purge method.
pub struct HousekeepingSweepJob {
    storage: Arc<dyn Storage>,
    clock: Arc<dyn Clock>,
    interval: Duration,
}

impl HousekeepingSweepJob {
    #[must_use]
    pub fn new(storage: Arc<dyn Storage>, clock: Arc<dyn Clock>, interval: Duration) -> Self {
        Self {
            storage,
            clock,
            interval,
        }
    }
}

#[async_trait]
impl ScheduledTask for HousekeepingSweepJob {
    fn name(&self) -> &'static str {
        "housekeeping-sweep"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    async fn run(&self) -> Result<(), TaskError> {
        let now = self.clock.now();
        let before = |grace: Unix| now.saturating_sub(grace);
        let storage = self.storage.as_ref();

        // Each purge is independent. One failing table must not stop the others
        // from being swept, so failures are collected and reported together.
        let mut sweep = Sweep::default();

        sweep.add(
            "sessions",
            storage
                .sessions()
                .purge_expired(before(grace::SESSIONS))
                .await,
        );
        sweep.add(
            "auth_codes",
            storage
                .auth_codes()
                .purge_expired(before(grace::AUTH_CODES))
                .await,
        );
        sweep.add(
            "refresh_tokens",
            storage
                .refresh_tokens()
                .purge_expired(before(grace::REFRESH_TOKENS))
                .await,
        );
        sweep.add(
            "login_transactions",
            storage
                .login_transactions()
                .purge_expired(before(grace::LOGIN_TRANSACTIONS))
                .await,
        );
        sweep.add(
            "approval_tickets",
            storage
                .approval_tickets()
                .purge_expired(before(grace::APPROVAL_TICKETS))
                .await,
        );
        sweep.add(
            "pending_authorizations",
            storage
                .pending_authorizations()
                .purge_expired(before(grace::PENDING_AUTHORIZATIONS))
                .await,
        );
        sweep.add(
            "device_codes",
            storage
                .device_codes()
                .purge_expired(before(grace::DEVICE_CODES))
                .await,
        );
        sweep.add(
            "device_attempts",
            storage
                .device_attempts()
                .purge_expired(before(grace::DEVICE_ATTEMPTS))
                .await,
        );
        sweep.add(
            "access_revocations",
            storage
                .access_tokens()
                .purge_expired(before(grace::ACCESS_REVOCATIONS))
                .await,
        );

        sweep.finish()
    }
}

/// How long each tier is kept, in seconds (Q-032 defaults: facts one year,
/// access telemetry 90 days, revoked-binding identity 30 days).
#[derive(Clone, Copy, Debug)]
pub struct RetentionPolicy {
    pub audit_fact_secs: Unix,
    pub access_telemetry_secs: Unix,
    pub revoked_binding_anonymize_secs: Unix,
}

impl RetentionPolicy {
    /// Builds a policy from the configured day counts.
    ///
    /// Saturating rather than wrapping: an absurd day count must mean "keep
    /// effectively forever", never a negative window that deletes everything.
    #[must_use]
    pub fn from_days(
        audit_fact_days: u64,
        access_telemetry_days: u64,
        revoked_binding_anonymize_days: u64,
    ) -> Self {
        const SECS_PER_DAY: u64 = 86_400;
        let seconds = |days: u64| {
            Unix::try_from(days)
                .unwrap_or(Unix::MAX / SECS_PER_DAY as Unix)
                .saturating_mul(SECS_PER_DAY as Unix)
        };
        Self {
            audit_fact_secs: seconds(audit_fact_days),
            access_telemetry_secs: seconds(access_telemetry_days),
            revoked_binding_anonymize_secs: seconds(revoked_binding_anonymize_days),
        }
    }
}

/// Enforces the retention policy: deletes audit rows past their tier's window and
/// anonymizes revoked bindings past theirs.
///
/// Deliberately separate from [`HousekeepingSweepJob`]: that job removes rows
/// that are *already expired* under one short grace period, while retention is a
/// compliance policy measured in months with a different window per tier.
/// Folding them together would force one semantic onto the other.
pub struct RetentionSweepJob {
    storage: Arc<dyn Storage>,
    clock: Arc<dyn Clock>,
    interval: Duration,
    policy: RetentionPolicy,
}

impl RetentionSweepJob {
    #[must_use]
    pub fn new(
        storage: Arc<dyn Storage>,
        clock: Arc<dyn Clock>,
        interval: Duration,
        policy: RetentionPolicy,
    ) -> Self {
        Self {
            storage,
            clock,
            interval,
            policy,
        }
    }
}

#[async_trait]
impl ScheduledTask for RetentionSweepJob {
    fn name(&self) -> &'static str {
        "retention-sweep"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    async fn run(&self) -> Result<(), TaskError> {
        let now = self.clock.now();
        let storage = self.storage.as_ref();

        // Each action is independent: one failing table must not stop the others
        // from being swept, so failures are collected and reported together.
        let mut sweep = Sweep::default();
        sweep.add(
            "audit_facts",
            storage
                .audits()
                .purge_tier_before(
                    AuditTier::Fact,
                    now.saturating_sub(self.policy.audit_fact_secs),
                )
                .await,
        );
        sweep.add(
            "access_telemetry",
            storage
                .audits()
                .purge_tier_before(
                    AuditTier::Telemetry,
                    now.saturating_sub(self.policy.access_telemetry_secs),
                )
                .await,
        );
        sweep.add(
            "revoked_bindings",
            storage
                .bindings()
                .anonymize_revoked_before(
                    now.saturating_sub(self.policy.revoked_binding_anonymize_secs),
                )
                .await,
        );
        sweep.finish()
    }
}

/// Drops rate-limiter keys that have gone quiet.
///
/// Kept separate from [`HousekeepingSweepJob`] because it touches no storage and
/// has a different interval: the limiter's state is bounded by the burst window
/// (seconds to a minute), while row retention is measured in hours. Sharing one
/// job would force one of the two to run at the wrong cadence.
pub struct RateLimiterPruneJob {
    limiter: Arc<dyn RateLimiter>,
    interval: Duration,
}

impl RateLimiterPruneJob {
    #[must_use]
    pub fn new(limiter: Arc<dyn RateLimiter>, interval: Duration) -> Self {
        Self { limiter, interval }
    }
}

#[async_trait]
impl ScheduledTask for RateLimiterPruneJob {
    fn name(&self) -> &'static str {
        "rate-limiter-prune"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    async fn run(&self) -> Result<(), TaskError> {
        // The count is discarded rather than logged: `re0auth-app` has no
        // `tracing` dependency and adding one just to emit a debug line would
        // widen the application layer's dependency surface. The scheduler
        // already logs failures, which is the signal that matters.
        let _ = self.limiter.prune();
        Ok(())
    }
}

/// Tallies one sweep. Separated from `run` so the borrow of `self` ends before
/// the result is assembled.
#[derive(Default)]
struct Sweep {
    rows: u64,
    failures: Vec<String>,
}

impl Sweep {
    fn add(&mut self, table: &str, result: Result<u64, re0auth_api::ports::RepoError>) {
        match result {
            Ok(rows) => self.rows += rows,
            Err(error) => self.failures.push(format!("{table}: {error}")),
        }
    }

    fn finish(self) -> Result<(), TaskError> {
        if self.failures.is_empty() {
            return Ok(());
        }
        Err(TaskError::failed(format!(
            "{} row(s) removed, {} table(s) failed: {}",
            self.rows,
            self.failures.len(),
            self.failures.join("; ")
        )))
    }
}

#[cfg(test)]
mod tests;
