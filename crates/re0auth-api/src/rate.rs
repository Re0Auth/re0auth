//! Rate limiting as a port (INV-RATE-01).
//!
//! Two lanes, because the two audiences fail differently:
//!
//! - **Unauthenticated** requests are keyed by client IP. Anyone can hit the
//!   login and device endpoints, so the budget has to stop a single address from
//!   grinding through codes.
//! - **Authenticated** data-plane requests are keyed by client id. A single bot
//!   holding a valid token must not be able to consume the instance.
//! - **Per-user** data-plane requests are keyed by user id. A bot fleet that
//!   shares one client id must not be able to exhaust that client's budget by
//!   hammering a single player's data.
//!
//! The client and user lanes are both charged on a gateway request. They answer
//! different questions: the client budget bounds one integration's share of the
//! instance, the user budget bounds one player's share of an integration.
//!
//! The limiter never decides *what* the budget is; that is configuration. It
//! only answers one question per call: may this key proceed now, and if not, how
//! long should the caller wait.
//!
//! Time comes from the injected [`Clock`](crate::Clock), never from a
//! hardware counter. Tests advance a fake clock and expect the buckets to
//! refill, which is only possible if the limiter asks the port.

/// Which budget a request is charged to.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Lane {
    /// Pre-authentication endpoints, keyed by client IP.
    Unauthenticated,
    /// Data-plane endpoints, keyed by client id.
    Authenticated,
    /// Data-plane endpoints, keyed by user id.
    ///
    /// Separate from [`Lane::Authenticated`] because the two ceilings protect
    /// different parties: the client budget protects the instance from one
    /// integration, the user budget protects one player from everybody using
    /// that same integration.
    PerUser,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateDecision {
    /// The request may proceed.
    Allow,
    /// The budget is spent; the caller should retry after `retry_after_secs`.
    Deny {
        retry_after_secs: u64,
        /// The lane's burst, so the response can state the ceiling it hit.
        ///
        /// Only denials carry it: GCRA keeps its remaining-count in an opaque
        /// atomic, so `RateLimit-Remaining` cannot be reported without keeping a
        /// second counter that would drift from the real one. Reporting a made-up
        /// number would be worse than reporting none.
        limit: u64,
        /// The lane's window in seconds, so the policy header states the real
        /// period instead of a hard-coded one.
        window_secs: u64,
    },
}

/// Decides whether a key may proceed on a lane.
pub trait RateLimiter: Send + Sync {
    /// Charges one unit to `key` on `lane`.
    ///
    /// No `now` parameter on purpose: the limiter owns the clock (through the
    /// same [`Clock`](crate::Clock) port everything else uses). Accepting a
    /// caller-supplied timestamp would let the two disagree about "now", which
    /// is exactly the bug that makes a limiter either too strict or useless.
    ///
    /// Implementations must not block and must be safe to call concurrently.
    fn check(&self, lane: Lane, key: &str) -> RateDecision;

    /// Drops state for keys that have been quiet long enough to be
    /// indistinguishable from a fresh one.
    ///
    /// Without this the keyed store grows with every distinct IP and client id
    /// the process ever saw and never shrinks: a scanner touching fifty thousand
    /// addresses leaves fifty thousand entries behind forever, and every lookup
    /// pays for the larger table. The scheduler drives this (INV-SPAWN-01), so
    /// the limiter itself never starts a background task.
    ///
    /// Returns how many keys were dropped, so the caller can log a real number
    /// instead of guessing.
    fn prune(&self) -> usize {
        0
    }
}

/// A limiter that allows everything. Used where no budget is configured, so the
/// call sites do not need an `Option`.
pub struct Unlimited;

impl RateLimiter for Unlimited {
    fn check(&self, _lane: Lane, _key: &str) -> RateDecision {
        RateDecision::Allow
    }
}
