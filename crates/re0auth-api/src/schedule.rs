//! Scheduling contract (ADR-0026).
//!
//! The scheduler *engine* lives in `re0auth-runtime`; the *task* contract lives
//! here so that use cases can define periodic work without depending on
//! infrastructure. `re0auth-app` produces tasks, `re0auth-runtime` drives them,
//! and the composition root only registers them.

use std::time::Duration;

use async_trait::async_trait;

/// Why one pass of a scheduled task failed.
///
/// Failures are logged and swallowed by the scheduler: a broken sweep must never
/// take down the process or stop the other tasks.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TaskError {
    #[error("task failed: {0}")]
    Failed(String),
}

impl TaskError {
    #[must_use]
    pub fn failed(reason: impl Into<String>) -> Self {
        Self::Failed(reason.into())
    }
}

/// A unit of periodic work driven by the single scheduler (INV-SPAWN-01).
///
/// Implementations must be idempotent and bounded. The scheduler runs them
/// serially on one task, so a slow task delays every task behind it.
#[async_trait]
pub trait ScheduledTask: Send + Sync {
    /// Stable name used in logs. Must never contain secrets (INV-NOLOG-01).
    fn name(&self) -> &'static str;

    /// How often `run` should execute.
    fn interval(&self) -> Duration;

    /// Performs one pass of work.
    async fn run(&self) -> Result<(), TaskError>;
}
