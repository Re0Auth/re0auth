//! Per-connector in-flight byte budget (INV-RES-01).
//!
//! A single response is already capped at 4 MiB. The gap this closes is the
//! aggregate: N concurrent fetches each inside the cap still sum to N times it.
//!
//! Reservations are taken *before* the request and released on drop, so a
//! cancelled fetch cannot leak capacity. The reserve is an all-or-nothing compare
//! and swap: a partial grant would let two callers each believe they hold the
//! same bytes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use re0auth_api::ConnectorId;
use re0auth_api::connector::{InflightBudget, InflightReservation};

/// The configured ceiling applied to each connector independently.
///
/// Per connector rather than global because the limit exists to stop one
/// misbehaving upstream from starving the others; a shared pool would let a
/// single busy connector do exactly that.
pub struct ByteBudget {
    per_connector: u64,
    used: Mutex<HashMap<ConnectorId, Arc<AtomicU64>>>,
}

impl ByteBudget {
    #[must_use]
    pub fn new(per_connector: u64) -> Self {
        Self {
            per_connector,
            used: Mutex::new(HashMap::new()),
        }
    }

    fn counter(&self, connector: &ConnectorId) -> Arc<AtomicU64> {
        let mut used = self.used.lock().expect("byte budget lock");
        Arc::clone(used.entry(*connector).or_default())
    }

    #[must_use]
    pub fn in_use(&self, connector: &ConnectorId) -> u64 {
        let used = self.used.lock().expect("byte budget lock");
        used.get(connector)
            .map_or(0, |counter| counter.load(Ordering::SeqCst))
    }
}

impl InflightBudget for ByteBudget {
    fn reserve(
        &self,
        connector: &ConnectorId,
        wanted: u64,
    ) -> Option<Box<dyn InflightReservation>> {
        // A request larger than the whole budget can never be admitted, and
        // admitting it would put the counter permanently over the ceiling.
        if wanted > self.per_connector {
            return None;
        }
        let counter = self.counter(connector);
        loop {
            let current = counter.load(Ordering::SeqCst);
            let next = current.checked_add(wanted)?;
            if next > self.per_connector {
                return None;
            }
            if counter
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(Box::new(Reservation {
                    counter,
                    bytes: wanted,
                }));
            }
        }
    }
}

/// Releases its bytes on drop, including on cancellation.
struct Reservation {
    counter: Arc<AtomicU64>,
    bytes: u64,
}

impl InflightReservation for Reservation {}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.counter.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connector() -> ConnectorId {
        ConnectorId::new()
    }

    #[test]
    fn reservations_are_released_on_drop() {
        let budget = ByteBudget::new(100);
        let id = connector();
        {
            let _held = budget.reserve(&id, 60).expect("first");
            assert_eq!(budget.in_use(&id), 60);
        }
        assert_eq!(budget.in_use(&id), 0, "drop must release the bytes");
        assert!(
            budget.reserve(&id, 100).is_some(),
            "the budget is usable again"
        );
    }

    #[test]
    fn the_aggregate_is_capped_not_just_one_request() {
        let budget = ByteBudget::new(100);
        let id = connector();
        let first = budget.reserve(&id, 60).expect("first");
        // 60 + 60 > 100 even though each request is individually under the cap.
        assert!(
            budget.reserve(&id, 60).is_none(),
            "aggregate must be bounded"
        );
        drop(first);
        assert!(budget.reserve(&id, 60).is_some());
    }

    #[test]
    fn a_request_larger_than_the_whole_budget_is_refused() {
        let budget = ByteBudget::new(100);
        assert!(budget.reserve(&connector(), 101).is_none());
        assert!(
            budget.reserve(&connector(), 100).is_some(),
            "exactly the cap fits"
        );
    }

    #[test]
    fn connectors_do_not_starve_each_other() {
        let budget = ByteBudget::new(100);
        let busy = connector();
        let quiet = connector();
        let _all = budget
            .reserve(&busy, 100)
            .expect("busy takes its whole budget");
        assert!(
            budget.reserve(&quiet, 100).is_some(),
            "a maxed-out connector must not consume another's budget"
        );
    }

    #[test]
    fn concurrent_reservations_never_exceed_the_cap() {
        use std::sync::atomic::AtomicUsize;

        let budget = Arc::new(ByteBudget::new(1_000));
        let id = connector();
        let holders = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..32 {
            let budget = Arc::clone(&budget);
            let holders = Arc::clone(&holders);
            handles.push(std::thread::spawn(move || {
                // Each thread asks for a quarter of the budget; at most four fit.
                if let Some(_held) = budget.reserve(&id, 250) {
                    holders.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }));
        }
        for handle in handles {
            handle.join().expect("thread");
        }
        assert!(
            holders.load(Ordering::SeqCst) <= 4,
            "more reservations were granted than the budget allows"
        );
        assert_eq!(budget.in_use(&id), 0, "every reservation must be released");
    }
}
