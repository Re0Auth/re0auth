#![forbid(unsafe_code)]

//! Runtime infrastructure: the process-wide scheduler engine (ADR-0026), plus
//! the outbound HTTP stack that both adapter crates share.
//!
//! The scheduler half deliberately holds almost nothing: the scheduling
//! primitive exists so that background work has exactly one legal home.
//!
//! The HTTP half (`http_client`, `outbound`, `tls`) is here because both
//! `re0auth-idp` and `re0auth-connectors` need it and neither may depend on the
//! other (ADR-0021). Putting it in either sibling would make the two planes meet
//! at the wrong layer; putting it here matches the rule that infrastructure is
//! shared and knows no business type.
//!
//! ## Invariant: one spawn point (INV-SPAWN-01)
//!
//! No adapter, use case or HTTP handler may start background work. Periodic work
//! is a [`ScheduledTask`] defined by a use case and registered with [`Scheduler`]
//! by the composition root; [`Scheduler::start`] is the only place in the
//! workspace that calls `tokio::spawn`. That is what keeps adapters replaceable
//! at runtime: an adapter that never spawns cannot leak a task when dropped.
//!
//! The scheduler knows a [`Clock`] and a shutdown token. It knows nothing about
//! storage, audit, connectors or any other business type.

pub mod http_client;
pub mod master_key;
pub mod outbound;
pub mod telemetry;
pub mod tls;

use std::sync::Arc;
use std::time::Duration;

use re0auth_api::schedule::ScheduledTask;
use re0auth_api::{Clock, Unix};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Drives every [`ScheduledTask`] on one task until shutdown is requested.
pub struct Scheduler {
    clock: Arc<dyn Clock>,
    shutdown: CancellationToken,
    tick: Option<Duration>,
}

impl Scheduler {
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, shutdown: CancellationToken) -> Self {
        Self {
            clock,
            shutdown,
            tick: None,
        }
    }

    /// Overrides the scan granularity. Production derives it from the shortest
    /// task interval; tests pin it to keep runs deterministic.
    #[must_use]
    pub fn with_tick(mut self, tick: Duration) -> Self {
        self.tick = Some(tick);
        self
    }

    /// Starts the scheduler on its own task and returns the handle.
    ///
    /// This is the only `tokio::spawn` in production code (INV-SPAWN-01).
    #[must_use]
    pub fn start(self, tasks: Vec<Arc<dyn ScheduledTask>>) -> JoinHandle<()> {
        tokio::spawn(self.run(tasks))
    }

    /// Runs the scheduling loop on the current task.
    ///
    /// Due-ness comes from the injected [`Clock`], not from tick counts, so a
    /// delayed tick cannot silently push the schedule out. The tokio timer only
    /// decides *when to look*, never *whether a task is due*.
    pub async fn run(self, tasks: Vec<Arc<dyn ScheduledTask>>) {
        if tasks.is_empty() {
            return;
        }
        let tick = self.tick.unwrap_or_else(|| scan_interval(&tasks));
        // Every task is due immediately: a freshly started process should not
        // wait a full interval before its first sweep.
        let mut next_due: Vec<Unix> = vec![self.clock.now(); tasks.len()];

        let mut timer = tokio::time::interval(tick);
        // `interval` fires immediately on the first tick, which is what makes the
        // "due at startup" schedule execute without a special case.
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                () = self.shutdown.cancelled() => break,
                _ = timer.tick() => {
                    let now = self.clock.now();
                    for (index, task) in tasks.iter().enumerate() {
                        if now < next_due[index] {
                            continue;
                        }
                        run_once(task.as_ref()).await;
                        // Schedule from `now`, not `next_due + interval`, so a long
                        // pause does not produce a burst of catch-up runs.
                        next_due[index] = self.clock.now() + seconds(task.interval());
                    }
                }
            }
        }
    }
}

async fn run_once(task: &dyn ScheduledTask) {
    if let Err(error) = task.run().await {
        // A broken sweep must be visible but must never take the scheduler down.
        // `task.name()` is documented to never contain secrets (INV-NOLOG-01).
        tracing::error!(
            task = task.name(),
            error = %error,
            "scheduled task failed; the scheduler keeps running"
        );
    }
}

/// Looks at the clock often enough that the shortest task is not noticeably
/// late, but never more than once a second and never less than once a minute.
fn scan_interval(tasks: &[Arc<dyn ScheduledTask>]) -> Duration {
    let shortest = tasks
        .iter()
        .map(|task| task.interval())
        .min()
        .unwrap_or(Duration::from_secs(60));
    (shortest / 4).clamp(Duration::from_secs(1), Duration::from_secs(60))
}

fn seconds(duration: Duration) -> Unix {
    Unix::try_from(duration.as_secs()).unwrap_or(Unix::MAX)
}

#[cfg(test)]
mod tests;
