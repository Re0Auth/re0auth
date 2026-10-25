//! The scheduler must actually drive the sweep against a real database.
//!
//! Unit tests prove the engine and the job separately; this proves the wiring
//! that only exists in the composition root.

use std::sync::Arc;
use std::time::Duration;

use re0auth_adapters::clock::SystemClock;
use re0auth_adapters::storage::SqliteStore;
use re0auth_api::ports::{Session, Storage, User, UserRole};
use re0auth_api::schedule::ScheduledTask;
use re0auth_api::{Clock, SessionId, UserId};
use re0auth_app::housekeeping::HousekeepingSweepJob;
use tokio_util::sync::CancellationToken;

async fn store_with_session(expired_secs_ago: i64) -> (Arc<SqliteStore>, Vec<u8>, i64) {
    let store = Arc::new(
        SqliteStore::connect("sqlite::memory:")
            .await
            .expect("in-memory store"),
    );
    let now = SystemClock.now();
    let user = UserId::new();
    store
        .users()
        .create(&User {
            id: user,
            display_name: "sweep".to_string(),
            role: UserRole::User,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("user");

    let hash = vec![7u8; 32];
    let expires_at = now - expired_secs_ago;
    store
        .sessions()
        .create(&Session {
            id: SessionId::new(),
            id_hash: hash.clone(),
            user_id: user,
            csrf_hash: vec![8u8; 32],
            created_at: expires_at - 100,
            last_seen_at: expires_at - 100,
            idle_expires_at: expires_at,
            absolute_expires_at: expires_at,
            revoked_at: None,
        })
        .await
        .expect("session");

    (store, hash, expires_at)
}

#[tokio::test]
async fn scheduler_runs_the_sweep_against_sqlite() {
    // Expired well past the session window (7 days), so the first pass must
    // delete it.
    let (store, hash, _) = store_with_session(8 * 86_400).await;
    let clock = Arc::new(SystemClock);
    let shutdown = CancellationToken::new();

    let sweep = Arc::new(HousekeepingSweepJob::new(
        store.clone(),
        clock.clone(),
        Duration::from_secs(3_600),
    ));
    let scheduler = re0auth_runtime::Scheduler::new(clock, shutdown.clone())
        .with_tick(Duration::from_millis(50));
    let handle = scheduler.start(vec![sweep as Arc<dyn ScheduledTask>]);

    // Give the immediate startup pass time to complete against the database.
    let mut purged = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if store
            .sessions()
            .find_active(&hash, 1)
            .await
            .expect("lookup")
            .is_none()
        {
            purged = true;
            break;
        }
    }

    shutdown.cancel();
    let _ = handle.await;
    assert!(purged, "the scheduler never drove the sweep");
}

#[tokio::test]
async fn a_session_inside_the_retention_window_survives_the_sweep() {
    // Expired one second ago: the sweep runs but must not delete it, because
    // the session window is measured in days.
    let (store, hash, expires_at) = store_with_session(1).await;
    let clock = Arc::new(SystemClock);
    let shutdown = CancellationToken::new();

    let sweep = Arc::new(HousekeepingSweepJob::new(
        store.clone(),
        clock.clone(),
        Duration::from_secs(3_600),
    ));
    let scheduler = re0auth_runtime::Scheduler::new(clock, shutdown.clone())
        .with_tick(Duration::from_millis(50));
    let handle = scheduler.start(vec![sweep as Arc<dyn ScheduledTask>]);

    tokio::time::sleep(Duration::from_millis(400)).await;
    shutdown.cancel();
    let _ = handle.await;

    // `find_active` filters by expiry, so probe with a timestamp inside the
    // session's lifetime to ask "is the row still in the table at all?".
    let row = store
        .sessions()
        .find_active(&hash, expires_at - 1)
        .await
        .expect("lookup");
    assert!(
        row.is_some(),
        "a row inside the retention window must not be purged"
    );
}

#[tokio::test]
async fn the_scheduler_drives_the_rate_limiter_sweep() {
    // The limiter's key table is the one structure that grows with every
    // distinct IP and never shrinks by itself. This drives the real job through
    // the real scheduler and proves `prune` is actually called.
    struct CountingLimiter {
        prunes: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl re0auth_api::rate::RateLimiter for CountingLimiter {
        fn check(
            &self,
            _lane: re0auth_api::rate::Lane,
            _key: &str,
        ) -> re0auth_api::rate::RateDecision {
            re0auth_api::rate::RateDecision::Allow
        }
        fn prune(&self) -> usize {
            self.prunes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            0
        }
    }

    let prunes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let clock = Arc::new(SystemClock);
    let shutdown = CancellationToken::new();
    let job = Arc::new(re0auth_app::housekeeping::RateLimiterPruneJob::new(
        Arc::new(CountingLimiter {
            prunes: Arc::clone(&prunes),
        }),
        Duration::from_secs(3_600),
    ));
    let scheduler = re0auth_runtime::Scheduler::new(clock, shutdown.clone())
        .with_tick(Duration::from_millis(50));
    let handle = scheduler.start(vec![job as Arc<dyn ScheduledTask>]);

    // One immediate pass at startup is the documented behaviour.
    let mut observed = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        if prunes.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            observed = true;
            break;
        }
    }

    shutdown.cancel();
    let _ = handle.await;
    assert!(observed, "the scheduler never ran the prune job");
}

#[tokio::test]
async fn shutdown_stops_the_composition_root_scheduler() {
    let (store, _hash, _) = store_with_session(8 * 86_400).await;
    let clock = Arc::new(SystemClock);
    let shutdown = CancellationToken::new();
    let sweep = Arc::new(HousekeepingSweepJob::new(
        store,
        clock.clone(),
        Duration::from_secs(3_600),
    ));
    let scheduler = re0auth_runtime::Scheduler::new(clock, shutdown.clone())
        .with_tick(Duration::from_millis(50));
    let handle = scheduler.start(vec![sweep as Arc<dyn ScheduledTask>]);

    tokio::time::sleep(Duration::from_millis(150)).await;
    shutdown.cancel();

    let finished = tokio::time::timeout(Duration::from_secs(5), handle).await;
    assert!(
        finished.is_ok(),
        "shutdown must stop the scheduler rather than leaving a dangling task"
    );
}
