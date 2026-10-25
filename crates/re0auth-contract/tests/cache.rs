//! Cache contract and the two safety properties (INV-CACHE-01, INV-CACHE-02).
//!
//! The contract suite is the generic part every implementation runs. The two
//! tests after it are the specific red lines the user asked for, written so they
//! fail loudly if someone reorders the gateway or drops the sweep.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use re0auth_api::cache::{Cache, CachedResponse, binding_prefix, key};
use re0auth_api::{BindingId, Clock, Unix};
use re0auth_contract::memory_cache::{ClockedCache, MemoryCache};

fn response(body: &[u8]) -> CachedResponse {
    CachedResponse {
        content_type: "application/json".to_string(),
        body: body.to_vec(),
        stale: false,
    }
}

struct TestClock(Arc<AtomicI64>);

impl Clock for TestClock {
    fn now(&self) -> Unix {
        self.0.load(Ordering::SeqCst)
    }
}

fn setup() -> (Arc<TestClock>, ClockedCache) {
    let clock = Arc::new(TestClock(Arc::new(AtomicI64::new(1_000))));
    let cache = ClockedCache::new(MemoryCache::new(), clock.clone());
    (clock, cache)
}

#[tokio::test]
async fn memory_cache_passes_the_contract_suite() {
    let (clock, cache) = setup();
    let advance_clock = clock.clone();
    re0auth_contract::cache_contract_suite(&cache, move |seconds| {
        advance_clock.0.fetch_add(seconds, Ordering::SeqCst);
    })
    .await;
}

/// INV-CACHE-02: revoking a binding must drop every entry it owns.
///
/// Without this the stale path keeps serving a player's scores for up to the
/// 1800 s grace window after they explicitly unbound the account — the user
/// believes access is gone while data keeps flowing.
#[tokio::test]
async fn revoking_a_binding_removes_every_cached_entry_it_owns() {
    let (_clock, cache) = setup();
    let revoked = BindingId::new();
    let untouched = BindingId::new();

    for resource in ["scores", "profile", "stats"] {
        cache
            .put(
                &key(&revoked, "phigros", resource),
                &response(b"secret"),
                Duration::from_secs(300),
            )
            .await;
    }
    cache
        .put(
            &key(&untouched, "phigros", "scores"),
            &response(b"other"),
            Duration::from_secs(300),
        )
        .await;

    let removed = cache.invalidate(&binding_prefix(&revoked)).await;
    assert_eq!(removed, 3, "every resource of the revoked binding must go");

    for resource in ["scores", "profile", "stats"] {
        assert!(
            cache
                .get_any(&key(&revoked, "phigros", resource))
                .await
                .is_none(),
            "resource {resource} survived the revoke; the user's data would keep being served"
        );
    }
    assert!(
        cache
            .get_any(&key(&untouched, "phigros", "scores"))
            .await
            .is_some(),
        "a different binding must be untouched by someone else's revoke"
    );
}

/// The sweep must reach stale entries too, not just fresh ones.
///
/// A sweep that only looked at fresh entries would leave exactly the data the
/// outage path is allowed to serve — the worst possible remainder.
#[tokio::test]
async fn the_sweep_also_removes_stale_entries() {
    let (clock, cache) = setup();
    let binding = BindingId::new();
    let entry = key(&binding, "phigros", "scores");
    cache
        .put(&entry, &response(b"secret"), Duration::from_secs(10))
        .await;

    // Past the fresh TTL but well inside the grace window: still serveable by
    // the outage path, therefore still dangerous after a revoke.
    clock.0.fetch_add(20, Ordering::SeqCst);
    assert!(cache.get(&entry).await.is_none(), "should be stale by now");
    assert!(
        cache.get_any(&entry).await.is_some(),
        "the stale entry must still be readable here, or this test proves nothing"
    );

    assert_eq!(cache.invalidate(&binding_prefix(&binding)).await, 1);
    assert!(
        cache.get_any(&entry).await.is_none(),
        "a stale entry survived the sweep and could still be served"
    );
}
