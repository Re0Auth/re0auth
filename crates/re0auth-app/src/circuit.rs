//! In-memory circuit tracker with half-open probing (ADR-0028).
//!
//! Authority is memory; persistence only snapshots transitions. Business
//! outcomes never count as failures (INV-GW-03), but a business reply during a
//! probe proves the upstream is reachable, so the breaker closes.
//!
//! Half-open admits exactly one probe per key; everyone else is rejected until
//! the probe settles (avoids a thundering herd on cooldown expiry).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use re0auth_api::connector::FaultClass;
use re0auth_api::{BindingId, ConnectorId, Unix};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CircuitKey {
    Connector(ConnectorId),
    Binding(ConnectorId, BindingId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitPolicy {
    pub failure_threshold: u32,
    pub open_for_secs: i64,
    /// How long a non-probe caller waits when a probe is already in flight.
    pub probe_retry_secs: i64,
}

impl Default for CircuitPolicy {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_for_secs: 30 * 60,
            probe_retry_secs: 1,
        }
    }
}

/// What the gateway should do with this key right now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    /// Breaker closed, or half-open and this caller won the probe slot.
    Pass,
    /// Breaker open; `retry_after_secs` is a hint for `Retry-After`.
    Reject { retry_after_secs: i64 },
}

/// Result of one upstream call, as far as the breaker is concerned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Success,
    Business,
    Internal,
}

impl Outcome {
    #[must_use]
    pub fn from_fault_class(class: FaultClass) -> Self {
        match class {
            FaultClass::Business => Self::Business,
            _ => Self::Internal,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum State {
    Closed { failures: u32 },
    Open { until: Unix },
    HalfOpen { probe_in_flight: bool },
}

pub struct CircuitTracker {
    policy: CircuitPolicy,
    states: Arc<Mutex<HashMap<CircuitKey, State>>>,
}

impl CircuitTracker {
    #[must_use]
    pub fn new(policy: CircuitPolicy) -> Self {
        Self {
            policy,
            states: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Atomically decides admission and, when the cooldown has elapsed, takes
    /// the single probe slot for this caller.
    pub fn admit(&self, key: &CircuitKey, now: Unix) -> Admission {
        let mut states = self.lock();
        match states.get_mut(key) {
            None => Admission::Pass,
            Some(State::Closed { .. }) => Admission::Pass,
            Some(State::Open { until }) => {
                if now < *until {
                    return Admission::Reject {
                        retry_after_secs: (*until - now).max(1),
                    };
                }
                *states
                    .get_mut(key)
                    .expect("state exists after cooldown check") = State::HalfOpen {
                    probe_in_flight: true,
                };
                Admission::Pass
            }
            Some(State::HalfOpen { probe_in_flight }) => {
                if *probe_in_flight {
                    Admission::Reject {
                        retry_after_secs: self.policy.probe_retry_secs.max(1),
                    }
                } else {
                    *probe_in_flight = true;
                    Admission::Pass
                }
            }
        }
    }

    /// Applies one upstream result. Only internal failures move the breaker
    /// toward open; a business reply during a probe closes it.
    pub fn settle(&self, key: &CircuitKey, outcome: Outcome, now: Unix) {
        let mut states = self.lock();
        match outcome {
            Outcome::Success => {
                states.remove(key);
            }
            Outcome::Business => {
                // Connection worked; a 4xx is not evidence of upstream failure.
                if matches!(states.get(key), Some(State::HalfOpen { .. })) {
                    states.remove(key);
                }
            }
            Outcome::Internal => {
                let failures = match states.get(key) {
                    Some(State::Closed { failures }) => *failures,
                    Some(State::Open { .. }) => {
                        // Already open: a late internal failure restarts the clock.
                        states.insert(
                            *key,
                            State::Open {
                                until: now + self.policy.open_for_secs,
                            },
                        );
                        return;
                    }
                    Some(State::HalfOpen { .. }) => {
                        states.insert(
                            *key,
                            State::Open {
                                until: now + self.policy.open_for_secs,
                            },
                        );
                        return;
                    }
                    None => 0,
                };
                let failures = failures.saturating_add(1);
                if failures >= self.policy.failure_threshold {
                    states.insert(
                        *key,
                        State::Open {
                            until: now + self.policy.open_for_secs,
                        },
                    );
                } else {
                    states.insert(*key, State::Closed { failures });
                }
            }
        }
    }

    /// Gives back a probe slot that was claimed by `admit` but never used.
    ///
    /// `admit` claims the single half-open probe slot as a side effect. When a
    /// caller takes a slot for one key and then declines the request because a
    /// second key rejected, nothing would ever settle the first key: it would
    /// stay `HalfOpen { probe_in_flight: true }` and reject every later caller
    /// until restart. This returns the key to `Open` with the original deadline
    /// already elapsed, so the next caller may probe again immediately.
    pub fn release_probe(&self, key: &CircuitKey, now: Unix) {
        let mut states = self.lock();
        if let Some(State::HalfOpen { .. }) = states.get(key) {
            states.insert(*key, State::Open { until: now });
        }
    }

    /// Read-only view. `None` means "would be admitted".
    #[must_use]
    pub fn retry_after(&self, key: &CircuitKey, now: Unix) -> Option<i64> {
        match self.admit_view(key, now) {
            Admission::Pass => None,
            Admission::Reject { retry_after_secs } => Some(retry_after_secs),
        }
    }

    fn admit_view(&self, key: &CircuitKey, now: Unix) -> Admission {
        match self.lock().get(key) {
            None | Some(State::Closed { .. }) => Admission::Pass,
            Some(State::Open { until }) => {
                if now < *until {
                    Admission::Reject {
                        retry_after_secs: (*until - now).max(1),
                    }
                } else {
                    Admission::Pass
                }
            }
            Some(State::HalfOpen { probe_in_flight }) => {
                if *probe_in_flight {
                    Admission::Reject {
                        retry_after_secs: self.policy.probe_retry_secs.max(1),
                    }
                } else {
                    Admission::Pass
                }
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<CircuitKey, State>> {
        self.states
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn key() -> CircuitKey {
        CircuitKey::Connector(ConnectorId::new())
    }

    fn tracker(threshold: u32, open_for: i64) -> CircuitTracker {
        CircuitTracker::new(CircuitPolicy {
            failure_threshold: threshold,
            open_for_secs: open_for,
            probe_retry_secs: 1,
        })
    }

    fn open(tracker: &CircuitTracker, key: &CircuitKey, now: Unix) {
        for _ in 0..tracker.policy.failure_threshold {
            tracker.settle(key, Outcome::Internal, now);
        }
    }

    #[test]
    fn business_outcomes_do_not_open_the_breaker() {
        let tracker = tracker(2, 60);
        let key = key();
        for _ in 0..10 {
            tracker.settle(&key, Outcome::Business, 1_000);
        }
        assert_eq!(tracker.admit(&key, 1_000), Admission::Pass);

        tracker.settle(&key, Outcome::Internal, 1_000);
        assert_eq!(tracker.admit(&key, 1_000), Admission::Pass);
        tracker.settle(&key, Outcome::Internal, 1_001);
        assert!(matches!(
            tracker.admit(&key, 1_001),
            Admission::Reject { .. }
        ));
    }

    #[test]
    fn cooldown_expiry_allows_exactly_one_probe() {
        let tracker = tracker(1, 30);
        let key = key();
        open(&tracker, &key, 1_000);
        assert_eq!(
            tracker.admit(&key, 1_010),
            Admission::Reject {
                retry_after_secs: 20
            }
        );

        // Cooldown elapsed: first caller wins the probe, the rest are rejected.
        assert_eq!(tracker.admit(&key, 1_030), Admission::Pass);
        assert_eq!(
            tracker.admit(&key, 1_030),
            Admission::Reject {
                retry_after_secs: 1
            }
        );
        assert_eq!(
            tracker.admit(&key, 1_031),
            Admission::Reject {
                retry_after_secs: 1
            }
        );
    }

    #[test]
    fn a_released_probe_can_be_taken_again_immediately() {
        let tracker = tracker(1, 30);
        let key = key();
        open(&tracker, &key, 1_000);
        // The cooldown has elapsed, so the first caller wins the probe slot.
        assert_eq!(tracker.admit(&key, 1_030), Admission::Pass);
        assert!(matches!(
            tracker.admit(&key, 1_030),
            Admission::Reject { .. }
        ));
        // Handing the slot back must make it available again, not merely clear
        // the flag: the key returns to Open with an elapsed deadline.
        tracker.release_probe(&key, 1_030);
        assert_eq!(tracker.admit(&key, 1_030), Admission::Pass);
    }

    #[test]
    fn releasing_a_probe_does_not_close_a_healthy_breaker() {
        let tracker = tracker(1, 30);
        let key = key();
        // No half-open state at all: release must be a no-op, not a state edit.
        tracker.release_probe(&key, 1_030);
        assert_eq!(tracker.admit(&key, 1_030), Admission::Pass);
        assert_eq!(tracker.retry_after(&key, 1_030), None);
    }

    #[test]
    fn successful_probe_closes_the_breaker() {
        let tracker = tracker(1, 30);
        let key = key();
        open(&tracker, &key, 1_000);
        assert_eq!(tracker.admit(&key, 1_030), Admission::Pass);
        tracker.settle(&key, Outcome::Success, 1_031);
        assert_eq!(tracker.admit(&key, 1_032), Admission::Pass);
        assert_eq!(tracker.admit(&key, 1_032), Admission::Pass);
    }

    #[test]
    fn failed_probe_reopens_and_restarts_the_clock() {
        let tracker = tracker(1, 30);
        let key = key();
        open(&tracker, &key, 1_000);
        assert_eq!(tracker.admit(&key, 1_030), Admission::Pass);
        tracker.settle(&key, Outcome::Internal, 1_031);
        assert_eq!(
            tracker.admit(&key, 1_031),
            Admission::Reject {
                retry_after_secs: 30
            }
        );
        assert_eq!(
            tracker.admit(&key, 1_060),
            Admission::Reject {
                retry_after_secs: 1
            }
        );
        assert_eq!(tracker.admit(&key, 1_061), Admission::Pass);
    }

    #[test]
    fn business_reply_during_probe_closes_the_breaker() {
        let tracker = tracker(1, 30);
        let key = key();
        open(&tracker, &key, 1_000);
        assert_eq!(tracker.admit(&key, 1_030), Admission::Pass);
        tracker.settle(&key, Outcome::Business, 1_031);
        assert_eq!(
            tracker.admit(&key, 1_032),
            Admission::Pass,
            "a 4xx proves the upstream is reachable"
        );
    }

    #[test]
    fn success_resets_the_failure_count() {
        let tracker = tracker(2, 30);
        let key = key();
        tracker.settle(&key, Outcome::Internal, 1_000);
        tracker.settle(&key, Outcome::Success, 1_001);
        tracker.settle(&key, Outcome::Internal, 1_002);
        assert_eq!(
            tracker.admit(&key, 1_002),
            Admission::Pass,
            "one failure after a success is below threshold"
        );
        tracker.settle(&key, Outcome::Internal, 1_003);
        assert!(matches!(
            tracker.admit(&key, 1_003),
            Admission::Reject { .. }
        ));
    }

    #[test]
    fn independent_keys_do_not_share_state() {
        let tracker = tracker(1, 30);
        let first = key();
        let second = key();
        open(&tracker, &first, 1_000);
        assert!(matches!(
            tracker.admit(&first, 1_000),
            Admission::Reject { .. }
        ));
        assert_eq!(tracker.admit(&second, 1_000), Admission::Pass);
    }

    #[test]
    fn binding_keys_are_distinct_from_connector_keys() {
        let connector = ConnectorId::new();
        let binding = BindingId::new();
        let tracker = tracker(1, 30);
        open(&tracker, &CircuitKey::Connector(connector), 1_000);
        assert_eq!(
            tracker.admit(&CircuitKey::Binding(connector, binding), 1_000),
            Admission::Pass
        );
    }

    #[test]
    fn outcome_maps_fault_class() {
        assert_eq!(
            Outcome::from_fault_class(FaultClass::Business),
            Outcome::Business
        );
        assert_eq!(
            Outcome::from_fault_class(FaultClass::Internal),
            Outcome::Internal
        );
    }

    #[test]
    fn tracker_is_shareable_across_threads() {
        let tracker = Arc::new(tracker(1, 30));
        let key = key();
        let handle = {
            let tracker = Arc::clone(&tracker);
            std::thread::spawn(move || open(&tracker, &key, 1_000))
        };
        handle.join().expect("thread");
        assert!(matches!(
            tracker.admit(&key, 1_000),
            Admission::Reject { .. }
        ));
    }
}
