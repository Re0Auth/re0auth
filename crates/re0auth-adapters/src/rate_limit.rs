//! GCRA rate limiting (INV-RATE-01).
//!
//! Backed by `governor`, with two deliberate departures from its defaults:
//!
//! 1. **`quanta` is disabled.** `governor`'s default clock reads a hardware
//!    timestamp counter, which no test can advance. `default-features = false`
//!    removes it; the clock below replaces it.
//! 2. **The clock is ours.** [`PortClock`] asks [`Clock`](re0auth_api::Clock),
//!    so `TestClock` drives the buckets exactly as it drives token expiry.
//!    Without this the rate limiter would be the one component whose behaviour
//!    tests cannot reproduce.
//!
//! `tower_governor` was rejected rather than configured: it depends on
//! `governor` without disabling default features, so `quanta` cannot be removed
//! from a downstream crate no matter which features are selected.

use std::num::NonZeroU32;
use std::ops::Add;
use std::sync::Arc;
use std::time::Duration;

use governor::clock::{Clock as GovernorClock, Reference};
use governor::middleware::NoOpMiddleware;
use governor::nanos::Nanos;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter as Governor};
use re0auth_api::Clock;
use re0auth_api::rate::{Lane, RateDecision, RateLimiter};

/// One budget per lane.
#[derive(Clone, Copy, Debug)]
pub struct LaneQuota {
    /// How many requests fit in `period_secs` before the bucket is empty.
    pub burst: u32,
    /// The window over which `burst` replenishes.
    pub period_secs: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct RateLimitPolicy {
    pub unauthenticated: LaneQuota,
    pub authenticated: LaneQuota,
    pub per_user: LaneQuota,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            unauthenticated: LaneQuota {
                burst: 30,
                period_secs: 60,
            },
            authenticated: LaneQuota {
                burst: 120,
                period_secs: 60,
            },
            // Half the client budget: many clients per user is normal, many
            // users per client is also normal, so a user should not be able to
            // spend as much as an entire integration.
            per_user: LaneQuota {
                burst: 60,
                period_secs: 60,
            },
        }
    }
}

/// A [`Nanos`] instant taken from the injected clock.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PortInstant(u64);

impl Add<Nanos> for PortInstant {
    type Output = Self;

    fn add(self, other: Nanos) -> Self {
        Self(self.0.saturating_add(other.as_u64()))
    }
}

impl Reference for PortInstant {
    fn duration_since(&self, earlier: Self) -> Nanos {
        Nanos::from(self.0.saturating_sub(earlier.0))
    }

    fn saturating_sub(&self, duration: Nanos) -> Self {
        Self(self.0.saturating_sub(duration.as_u64()))
    }
}

/// Bridges [`re0auth_api::Clock`] (seconds) into governor's nanosecond world.
///
/// Negative clock values clamp to zero: `Unix` before the epoch is not a
/// meaningful input for a monotonic budget, and saturating here keeps the
/// limiter total instead of panicking in production.
pub struct PortClock {
    clock: Arc<dyn Clock>,
}

impl PortClock {
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }
}

impl GovernorClock for PortClock {
    type Instant = PortInstant;

    fn now(&self) -> Self::Instant {
        let seconds = self.clock.now().max(0);
        PortInstant(
            u64::try_from(seconds)
                .unwrap_or(0)
                .saturating_mul(1_000_000_000),
        )
    }
}

/// Keyed GCRA limiters, one per lane.
pub struct GovernorLimiter {
    unauthenticated: LaneLimiter,
    authenticated: LaneLimiter,
    per_user: LaneLimiter,
    clock: PortClock,
}

/// A lane's limiter plus the burst it enforces.
///
/// The burst is kept beside the limiter rather than read back from it: GCRA
/// stores its state as an opaque theoretical-arrival-time counter, so the
/// remaining allowance is not recoverable without a parallel counter that would
/// drift. Reporting the ceiling is honest; inventing a remaining count is not.
struct LaneLimiter {
    limiter: KeyedLimiter,
    burst: u64,
    window_secs: u64,
}

type KeyedLimiter =
    Governor<String, DashMapStateStore<String>, PortClock, NoOpMiddleware<PortInstant>>;

impl GovernorLimiter {
    #[must_use]
    pub fn new(policy: RateLimitPolicy, clock: Arc<dyn Clock>) -> Self {
        Self {
            unauthenticated: build(policy.unauthenticated, clock.clone()),
            authenticated: build(policy.authenticated, clock.clone()),
            per_user: build(policy.per_user, clock.clone()),
            clock: PortClock::new(clock),
        }
    }

    fn limiter(&self, lane: Lane) -> &LaneLimiter {
        match lane {
            Lane::Unauthenticated => &self.unauthenticated,
            Lane::Authenticated => &self.authenticated,
            Lane::PerUser => &self.per_user,
        }
    }
}

fn build(quota: LaneQuota, clock: Arc<dyn Clock>) -> LaneLimiter {
    // A zero burst would reject every request including the first; clamp to one
    // so a misconfiguration degrades to "very strict" rather than "broken".
    let burst = NonZeroU32::new(quota.burst.max(1)).unwrap_or(NonZeroU32::MIN);
    let window_secs = quota.period_secs.max(1);
    let period = Duration::from_secs(window_secs);
    // `Quota::new(burst, period)` replenishes the whole burst over one period,
    // which is what `burst` per `period` is supposed to mean. `with_period`
    // would instead replenish a single cell per period: a 30/60 s budget would
    // refill at 1/minute, 30x stricter than configured, while the published
    // `RateLimit-Policy` header still claimed 30.
    //
    // The constructor is deprecated for being unintuitive, not incorrect; its
    // replacement (`with_period(...).allow_burst(...)`) is the one that does
    // not match the documented meaning here.
    #[allow(deprecated)]
    let quota = Quota::new(burst, period).expect("period is non-zero");
    LaneLimiter {
        limiter: Governor::new(quota, DashMapStateStore::default(), PortClock::new(clock)),
        burst: u64::from(burst.get()),
        window_secs,
    }
}

impl RateLimiter for GovernorLimiter {
    fn check(&self, lane: Lane, key: &str) -> RateDecision {
        let lane_limiter = self.limiter(lane);
        match lane_limiter.limiter.check_key(&key.to_string()) {
            Ok(()) => RateDecision::Allow,
            Err(not_until) => {
                let wait = not_until.wait_time_from(self.clock.now());
                RateDecision::Deny {
                    retry_after_secs: wait.as_secs().max(1),
                    limit: lane_limiter.burst,
                    window_secs: lane_limiter.window_secs,
                }
            }
        }
    }

    fn prune(&self) -> usize {
        // `retain_recent` drops every key whose theoretical arrival time is in
        // the past, i.e. one that would behave identically to a fresh entry.
        // That is exactly the safe set: a key still inside its window keeps its
        // remaining budget.
        let mut dropped = 0;
        for lane in [&self.unauthenticated, &self.authenticated, &self.per_user] {
            let before = lane.limiter.len();
            lane.limiter.retain_recent();
            dropped += before.saturating_sub(lane.limiter.len());
        }
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use re0auth_api::Unix;
    use std::sync::atomic::{AtomicI64, Ordering};

    struct TestClock(Arc<AtomicI64>);

    impl Clock for TestClock {
        fn now(&self) -> Unix {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn setup(policy: RateLimitPolicy) -> (Arc<TestClock>, GovernorLimiter) {
        let clock = Arc::new(TestClock(Arc::new(AtomicI64::new(1_000))));
        let limiter = GovernorLimiter::new(policy, clock.clone());
        (clock, limiter)
    }

    fn single(burst: u32) -> RateLimitPolicy {
        RateLimitPolicy {
            unauthenticated: LaneQuota {
                burst,
                period_secs: 60,
            },
            authenticated: LaneQuota {
                burst,
                period_secs: 60,
            },
            per_user: LaneQuota {
                burst,
                period_secs: 60,
            },
        }
    }

    #[test]
    fn the_burst_is_allowed_then_the_next_request_is_denied() {
        let (_clock, limiter) = setup(single(3));
        for _ in 0..3 {
            assert_eq!(
                limiter.check(Lane::Unauthenticated, "1.2.3.4"),
                RateDecision::Allow
            );
        }
        assert!(matches!(
            limiter.check(Lane::Unauthenticated, "1.2.3.4"),
            RateDecision::Deny { .. }
        ));
    }

    #[test]
    fn advancing_the_injected_clock_refills_the_bucket() {
        // This is the whole reason the port exists: with `quanta` this test
        // would need to sleep for a minute.
        let (_clock, limiter) = setup(single(2));
        assert_eq!(
            limiter.check(Lane::Authenticated, "client-a"),
            RateDecision::Allow
        );
        assert_eq!(
            limiter.check(Lane::Authenticated, "client-a"),
            RateDecision::Allow
        );
        assert!(matches!(
            limiter.check(Lane::Authenticated, "client-a"),
            RateDecision::Deny { .. }
        ));

        // Two minutes is past the 60 s window: the budget is back.
        _clock.0.fetch_add(120, Ordering::SeqCst);
        assert_eq!(
            limiter.check(Lane::Authenticated, "client-a"),
            RateDecision::Allow
        );
    }

    #[test]
    fn keys_are_independent_within_a_lane() {
        let (_clock, limiter) = setup(single(1));
        assert_eq!(
            limiter.check(Lane::Unauthenticated, "10.0.0.1"),
            RateDecision::Allow
        );
        assert!(matches!(
            limiter.check(Lane::Unauthenticated, "10.0.0.1"),
            RateDecision::Deny { .. }
        ));
        // A different address has its own budget; one attacker must not be able
        // to spend anybody else's.
        assert_eq!(
            limiter.check(Lane::Unauthenticated, "10.0.0.2"),
            RateDecision::Allow
        );
    }

    #[test]
    fn the_lanes_have_separate_budgets() {
        let (_, limiter) = setup(RateLimitPolicy {
            unauthenticated: LaneQuota {
                burst: 1,
                period_secs: 60,
            },
            authenticated: LaneQuota {
                burst: 5,
                period_secs: 60,
            },
            per_user: LaneQuota {
                burst: 3,
                period_secs: 60,
            },
        });
        assert_eq!(
            limiter.check(Lane::Unauthenticated, "k"),
            RateDecision::Allow
        );
        assert!(matches!(
            limiter.check(Lane::Unauthenticated, "k"),
            RateDecision::Deny { .. }
        ));
        // The authenticated lane for the same key is untouched.
        for _ in 0..5 {
            assert_eq!(limiter.check(Lane::Authenticated, "k"), RateDecision::Allow);
        }
        // Draining the client budget does not touch the user budget either.
        for _ in 0..3 {
            assert_eq!(limiter.check(Lane::PerUser, "k"), RateDecision::Allow);
        }
        assert!(matches!(
            limiter.check(Lane::PerUser, "k"),
            RateDecision::Deny { .. }
        ));
    }

    #[test]
    fn the_user_lane_bounds_one_player_across_shared_clients() {
        // The reason the lane exists: two bots with the same client id must not
        // be able to spend one player's budget twice over.
        let (_, limiter) = setup(RateLimitPolicy {
            unauthenticated: LaneQuota {
                burst: 100,
                period_secs: 60,
            },
            authenticated: LaneQuota {
                burst: 100,
                period_secs: 60,
            },
            per_user: LaneQuota {
                burst: 2,
                period_secs: 60,
            },
        });
        assert_eq!(limiter.check(Lane::PerUser, "user-a"), RateDecision::Allow);
        assert_eq!(limiter.check(Lane::PerUser, "user-a"), RateDecision::Allow);
        assert!(matches!(
            limiter.check(Lane::PerUser, "user-a"),
            RateDecision::Deny { .. }
        ));
        // Another player sharing the same client id keeps their own budget.
        assert_eq!(limiter.check(Lane::PerUser, "user-b"), RateDecision::Allow);
        // ...and the client budget is unaffected by the user being throttled.
        assert_eq!(
            limiter.check(Lane::Authenticated, "client-shared"),
            RateDecision::Allow
        );
    }

    #[test]
    fn a_denial_reports_a_retry_after_of_at_least_one_second() {
        let (_, limiter) = setup(single(1));
        assert_eq!(limiter.check(Lane::Authenticated, "k"), RateDecision::Allow);
        match limiter.check(Lane::Authenticated, "k") {
            RateDecision::Deny {
                retry_after_secs,
                limit,
                window_secs,
            } => {
                // A zero here would make clients retry immediately and turn the
                // limit into a busy loop.
                assert!(retry_after_secs >= 1, "got {retry_after_secs}");
                assert!(retry_after_secs <= 60, "got {retry_after_secs}");
                // The published ceiling must be the one actually enforced, or a
                // client sizing its pacing from the header would be misled.
                assert_eq!(limit, 1);
                assert_eq!(window_secs, 60);
            }
            RateDecision::Allow => panic!("the bucket should be empty"),
        }
    }

    #[test]
    fn a_zero_burst_does_not_reject_everything() {
        // Misconfiguration must degrade to "very strict", not "nothing works".
        let (_, limiter) = setup(single(0));
        assert_eq!(limiter.check(Lane::Authenticated, "k"), RateDecision::Allow);
    }

    #[test]
    fn the_bucket_refills_at_the_configured_rate() {
        // `burst` per `period` means the whole budget comes back over one period.
        // `Quota::with_period` alone refills one cell per period, which would
        // make a 30/60s budget behave like 30 per 30 minutes.
        let (clock, limiter) = setup(single(30));
        let mut allowed = 0;
        while limiter.check(Lane::Unauthenticated, "k") == RateDecision::Allow {
            allowed += 1;
            assert!(allowed <= 100, "the burst never ran out");
        }
        assert_eq!(allowed, 30, "the configured burst must be admitted at once");

        // One period later the same number must be available again.
        clock.0.fetch_add(60, Ordering::SeqCst);
        let mut refilled = 0;
        while limiter.check(Lane::Unauthenticated, "k") == RateDecision::Allow {
            refilled += 1;
            assert!(refilled <= 100, "refill is unbounded");
        }
        assert_eq!(
            refilled, 30,
            "a full period must restore the whole burst, not one cell"
        );
    }

    #[test]
    fn pruning_drops_idle_keys_and_keeps_busy_ones() {
        // The leak this exists for: every distinct IP the process ever saw left
        // an entry behind forever. A scanner sweeping fifty thousand addresses
        // would grow the table by fifty thousand rows and slow every lookup.
        let (clock, limiter) = setup(single(5));

        // A key that burns its budget, and one that is merely seen.
        assert_eq!(
            limiter.check(Lane::Unauthenticated, "busy"),
            RateDecision::Allow
        );
        for _ in 0..4 {
            assert_eq!(
                limiter.check(Lane::Unauthenticated, "busy"),
                RateDecision::Allow
            );
        }
        for index in 0..100 {
            assert_eq!(
                limiter.check(Lane::Unauthenticated, &format!("scanner-{index}")),
                RateDecision::Allow
            );
        }

        // Moving past the window makes the one-shot keys indistinguishable from
        // fresh. The busy key survives one more interval: `retain_recent` drops
        // keys whose theoretical arrival time is behind `now - t`, where `t` is
        // the per-request interval, so a key that arrived moments ago is kept
        // one round longer. That is conservative, not wrong: it only costs a
        // little memory and never hands back a spent budget.
        clock.0.fetch_add(61, Ordering::SeqCst);
        let dropped = limiter.prune();
        assert_eq!(
            dropped, 100,
            "every idle one-shot key must be dropped; the busy key is retained \
             one interval longer by GCRA's own rule"
        );

        // A dropped key behaves like a new one: the full burst is available.
        // That is what makes the sweep safe rather than a way to bypass a limit.
        let mut allowed = 0;
        while limiter.check(Lane::Unauthenticated, "busy") == RateDecision::Allow {
            allowed += 1;
            assert!(allowed <= 100, "the burst never ran out");
        }
        assert_eq!(allowed, 5, "a pruned key must start with its full burst");
    }

    #[test]
    fn a_key_retained_by_the_gcra_rule_is_eventually_dropped() {
        // The flip side of the conservative rule above: it must not retain a key
        // forever. After another full window even the busy key is gone, so the
        // table cannot drift upward by one entry per active key.
        let (clock, limiter) = setup(single(5));
        for _ in 0..5 {
            assert_eq!(limiter.check(Lane::PerUser, "busy"), RateDecision::Allow);
        }
        clock.0.fetch_add(61, Ordering::SeqCst);
        assert_eq!(limiter.prune(), 0, "retained by the interval rule");
        clock.0.fetch_add(60, Ordering::SeqCst);
        assert_eq!(
            limiter.prune(),
            1,
            "the busy key must not survive two windows"
        );
    }

    #[test]
    fn pruning_does_not_refill_a_key_that_is_still_inside_its_window() {
        // This is the property that makes pruning safe to run at all. If it
        // dropped a key whose window has not elapsed, a caller could escape its
        // budget by waiting for the sweep instead of for the window.
        let (clock, limiter) = setup(single(3));
        for _ in 0..3 {
            assert_eq!(
                limiter.check(Lane::Authenticated, "hot"),
                RateDecision::Allow
            );
        }
        assert!(matches!(
            limiter.check(Lane::Authenticated, "hot"),
            RateDecision::Deny { .. }
        ));

        // Still inside the 60 s window: the budget must stay spent.
        clock.0.fetch_add(10, Ordering::SeqCst);
        limiter.prune();
        assert!(
            matches!(
                limiter.check(Lane::Authenticated, "hot"),
                RateDecision::Deny { .. }
            ),
            "a prune inside the window handed back a spent budget"
        );
    }

    #[test]
    fn pruning_covers_every_lane() {
        let (clock, limiter) = setup(single(2));
        for key in ["a", "b", "c"] {
            let _ = limiter.check(Lane::Unauthenticated, key);
            let _ = limiter.check(Lane::Authenticated, key);
            let _ = limiter.check(Lane::PerUser, key);
        }
        clock.0.fetch_add(61, Ordering::SeqCst);
        let dropped = limiter.prune();
        assert!(
            dropped >= 9,
            "all three lanes must be swept, dropped {dropped}"
        );
    }
}
