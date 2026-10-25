//! Cache contract suite (INV-CACHE-01, INV-CACHE-02).
//!
//! Every cache implementation runs this. It covers the two properties the
//! gateway relies on: freshness is decided by the injected clock, and a binding
//! prefix sweep removes exactly that binding's entries.
//!
//! An adapter adds one test:
//!
//! ```ignore
//! #[tokio::test]
//! async fn memory_cache_passes_the_contract() {
//!     let clock = Arc::new(TestClock::new(1_000));
//!     let cache = ClockedCache::new(MemoryCache::new(), clock.clone());
//!     cache_contract_suite(&cache, |seconds| clock.advance(seconds)).await;
//! }
//! ```

use std::time::Duration;

use re0auth_api::BindingId;
use re0auth_api::cache::{Cache, CachedResponse, binding_prefix, key};

fn response(body: &[u8]) -> CachedResponse {
    CachedResponse {
        content_type: "application/json".to_string(),
        body: body.to_vec(),
        stale: false,
    }
}

/// Runs every cache assertion against `cache`.
///
/// `advance` moves the clock the cache reads by `n` seconds. It is a closure
/// rather than a `&dyn Clock` because the port can read time but not change it;
/// a suite that could not move the clock would let every TTL assertion pass
/// without testing anything.
pub async fn cache_contract_suite(cache: &dyn Cache, advance: impl Fn(i64)) {
    let binding = BindingId::new();
    let other = BindingId::new();
    let entry_key = key(&binding, "phigros", "scores");

    // --- a missing key is a miss, not an error -------------------------
    assert!(
        cache.get(&entry_key).await.is_none(),
        "an unwritten key must miss"
    );

    // --- a fresh entry round-trips -------------------------------------
    cache
        .put(&entry_key, &response(b"payload"), Duration::from_secs(60))
        .await;
    let fresh = cache.get(&entry_key).await.expect("a fresh entry must hit");
    assert_eq!(fresh.body, b"payload", "the body must be returned verbatim");
    assert_eq!(
        fresh.content_type, "application/json",
        "the media type must survive the round trip"
    );
    assert!(!fresh.stale, "a fresh entry must not be flagged stale");

    // --- freshness follows the injected clock --------------------------
    advance(61);
    assert!(
        cache.get(&entry_key).await.is_none(),
        "an entry must expire when the injected clock passes its TTL"
    );

    // --- the stale path can still see it -------------------------------
    let hit = cache
        .get_any(&entry_key)
        .await
        .expect("a stale entry must remain readable during the grace window");
    assert!(hit.stale, "the entry is past its TTL and must be flagged");
    assert_eq!(hit.body, b"payload");

    // --- past the grace window it is gone entirely ---------------------
    advance(1_801);
    assert!(
        cache.get_any(&entry_key).await.is_none(),
        "a stale entry must not outlive the grace window"
    );

    // --- a prefix sweep removes only that binding ----------------------
    cache
        .put(&entry_key, &response(b"a"), Duration::from_secs(60))
        .await;
    cache
        .put(
            &key(&binding, "phigros", "profile"),
            &response(b"b"),
            Duration::from_secs(60),
        )
        .await;
    cache
        .put(
            &key(&binding, "phihub", "scores"),
            &response(b"c"),
            Duration::from_secs(60),
        )
        .await;
    let survivor = key(&other, "phigros", "scores");
    cache
        .put(&survivor, &response(b"keep"), Duration::from_secs(60))
        .await;

    let removed = cache.invalidate(&binding_prefix(&binding)).await;
    assert_eq!(
        removed, 3,
        "the sweep must remove every resource of that binding"
    );
    assert!(
        cache.get(&entry_key).await.is_none(),
        "the revoked binding's entry must be gone"
    );
    assert_eq!(
        cache.get(&survivor).await.map(|hit| hit.body),
        Some(b"keep".to_vec()),
        "another binding's entries must survive the sweep"
    );

    // --- a second sweep is a no-op, not an error -----------------------
    assert_eq!(
        cache.invalidate(&binding_prefix(&binding)).await,
        0,
        "sweeping an already-empty prefix must report zero, not fail"
    );
}
