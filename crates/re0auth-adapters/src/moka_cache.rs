//! Response cache backed by `moka` (INV-CACHE-01/-02/-03).
//!
//! **`moka` is used as a concurrent map, not as a TTL cache.** Its expiry clock
//! is `std::time::Instant`, hard-wired at construction; its `Mocked` variant is
//! `#[cfg(test)]`-only and there is no public injection point. Using
//! `time_to_live` would therefore make every expiry test sleep, and would leave
//! the stale window — which the outage path depends on — unrepresentable.
//!
//! Instead each entry carries its own absolute deadlines, computed from the
//! injected [`Clock`](re0auth_api::Clock), exactly as the in-memory reference
//! implementation does. `moka` contributes concurrent eviction, size-bounded
//! capacity and cheap concurrent reads; everything time-related stays ours.
//!
//! Entries are never given a `moka` TTL, so a stale entry survives until
//! overwritten or swept. The stale deadline is enforced on read, which is where
//! it matters.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache as Moka;
use moka::sync::Cache as SyncMoka;
use re0auth_api::Clock;
use re0auth_api::cache::{Cache, CachedResponse, FailureCache};
use re0auth_api::connector::UpstreamError;

/// How long past its fresh TTL an entry may still be served during an outage.
///
/// `test-v1.3.md` §6.8 caps stale data at 1800 s.
pub const STALE_GRACE: Duration = Duration::from_secs(1_800);

/// What is actually stored: the response plus our own two deadlines.
#[derive(Clone)]
struct Entry {
    response: CachedResponse,
    fresh_until: i64,
    stale_until: i64,
}

/// `moka`-backed cache with the port's expiry semantics.
pub struct MokaCache {
    entries: Moka<String, Entry>,
    clock: Arc<dyn Clock>,
}

impl MokaCache {
    /// Builds a cache whose combined key and response-body weights are bounded
    /// by `max_weight`.
    ///
    /// A capacity is required rather than optional: an unbounded process-local
    /// cache is a memory leak with a friendly name, and the whole point of
    /// taking `moka` was to get eviction. JSON responses and binary assets use
    /// separate instances so their budgets cannot evict one another.
    #[must_use]
    pub fn new(max_weight: u64, clock: Arc<dyn Clock>) -> Self {
        let entries = Moka::builder()
            .max_capacity(max_weight)
            // Weight by body size so one 4 MiB response cannot silently occupy
            // the space of thousands of small ones.
            .weigher(|key: &String, entry: &Entry| {
                let body = u32::try_from(entry.response.body().len()).unwrap_or(u32::MAX);
                let key_len = u32::try_from(key.len()).unwrap_or(u32::MAX);
                body.saturating_add(key_len).saturating_add(1)
            })
            .build();
        Self { entries, clock }
    }

    /// Builds the positive binary-asset cache with its independent byte budget.
    /// Keys and the per-entry weight marker are included in the accounting.
    #[must_use]
    pub fn new_asset(asset_max_bytes: u64, clock: Arc<dyn Clock>) -> Self {
        Self::new(asset_max_bytes, clock)
    }

    fn fresh_until(now: i64, fresh_for: Duration) -> i64 {
        now.saturating_add(i64::try_from(fresh_for.as_secs()).unwrap_or(i64::MAX))
    }

    fn stale_until(fresh_until: i64) -> i64 {
        fresh_until.saturating_add(i64::try_from(STALE_GRACE.as_secs()).unwrap_or(i64::MAX))
    }
}

const MAX_FAILURE_ENTRIES: u64 = 10_000;

#[derive(Clone)]
struct FailureEntry {
    error: UpstreamError,
    expires_at: i64,
}

/// Synchronous negative cache for asset requests whose upstream recently failed.
///
/// As with [`MokaCache`], expiry uses the application clock rather than moka's
/// monotonic clock. Expired entries may remain in the map until eviction, but
/// they can never be returned by [`FailureCache::get`].
pub struct MokaFailureCache {
    entries: SyncMoka<String, FailureEntry>,
    clock: Arc<dyn Clock>,
}

impl MokaFailureCache {
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            entries: SyncMoka::builder()
                .max_capacity(MAX_FAILURE_ENTRIES)
                .build(),
            clock,
        }
    }
}

impl FailureCache for MokaFailureCache {
    fn get(&self, key: &str) -> Option<UpstreamError> {
        let entry = self.entries.get(key)?;
        (self.clock.now() < entry.expires_at).then_some(entry.error)
    }

    fn put(&self, key: String, error: UpstreamError, ttl: Duration) {
        let ttl_secs = i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);
        let expires_at = self.clock.now().saturating_add(ttl_secs);
        self.entries.insert(key, FailureEntry { error, expires_at });
    }
}

impl std::fmt::Debug for MokaFailureCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MokaFailureCache")
            .field("entries", &self.entries.entry_count())
            .finish()
    }
}

impl std::fmt::Debug for MokaCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MokaCache")
            .field("entries", &self.entries.entry_count())
            .finish()
    }
}

#[async_trait]
impl Cache for MokaCache {
    async fn get(&self, key: &str) -> Option<CachedResponse> {
        let now = self.clock.now();
        let entry = self.entries.get(key).await?;
        (now < entry.fresh_until).then(|| entry.response.as_fresh())
    }

    async fn get_any(&self, key: &str) -> Option<CachedResponse> {
        let now = self.clock.now();
        let entry = self.entries.get(key).await?;
        if now >= entry.stale_until {
            return None;
        }
        Some(if now >= entry.fresh_until {
            entry.response.as_stale()
        } else {
            entry.response.as_fresh()
        })
    }

    async fn put(&self, key: &str, value: &CachedResponse, fresh_for: Duration) {
        let now = self.clock.now();
        let fresh_until = Self::fresh_until(now, fresh_for);
        self.entries
            .insert(
                key.to_string(),
                Entry {
                    response: value.as_fresh(),
                    fresh_until,
                    stale_until: Self::stale_until(fresh_until),
                },
            )
            .await;
    }

    async fn invalidate(&self, prefix: &str) -> usize {
        // Collect first, then remove: `moka`'s iterator holds a lock while it
        // scans, and awaiting inside that scan would stall every other reader.
        let doomed: Vec<String> = self
            .entries
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, _)| key.as_ref().clone())
            .collect();
        for key in &doomed {
            self.entries.invalidate(key).await;
        }
        doomed.len()
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

    fn setup() -> (Arc<TestClock>, MokaCache) {
        let clock = Arc::new(TestClock(Arc::new(AtomicI64::new(1_000))));
        let cache = MokaCache::new(100, clock.clone());
        (clock, cache)
    }

    #[tokio::test]
    async fn the_contract_suite_passes() {
        let (clock, cache) = setup();
        let advance = clock.clone();
        re0auth_contract::cache_contract_suite(&cache, move |seconds| {
            advance.0.fetch_add(seconds, Ordering::SeqCst);
        })
        .await;
    }

    #[test]
    fn failure_hits_are_synchronous() {
        let clock = Arc::new(TestClock(Arc::new(AtomicI64::new(1_000))));
        let cache = MokaFailureCache::new(clock);

        cache.put(
            "shared:phisong:jacket".into(),
            UpstreamError::NotFound,
            Duration::from_secs(5),
        );

        assert_eq!(
            cache.get("shared:phisong:jacket"),
            Some(UpstreamError::NotFound)
        );
    }

    #[test]
    fn failure_entries_expire_after_five_seconds_on_the_injected_clock() {
        let clock = Arc::new(TestClock(Arc::new(AtomicI64::new(1_000))));
        let cache = MokaFailureCache::new(clock.clone());
        cache.put(
            "asset".into(),
            UpstreamError::Unavailable,
            Duration::from_secs(5),
        );

        clock.0.store(1_004, Ordering::SeqCst);
        assert_eq!(cache.get("asset"), Some(UpstreamError::Unavailable));
        clock.0.store(1_005, Ordering::SeqCst);
        assert_eq!(cache.get("asset"), None);
    }

    #[test]
    fn failure_cache_is_bounded_to_ten_thousand_entries() {
        let clock = Arc::new(TestClock(Arc::new(AtomicI64::new(1_000))));
        let cache = MokaFailureCache::new(clock);
        for index in 0..=MAX_FAILURE_ENTRIES {
            cache.put(
                format!("asset:{index}"),
                UpstreamError::Unavailable,
                Duration::from_secs(5),
            );
        }
        cache.entries.run_pending_tasks();

        assert!(cache.entries.entry_count() <= MAX_FAILURE_ENTRIES);
    }

    #[tokio::test]
    async fn positive_asset_capacity_is_enforced_by_weight() {
        let clock = Arc::new(TestClock(Arc::new(AtomicI64::new(1_000))));
        // Each three-byte response has weight five: one key byte, three body
        // bytes and the per-entry marker. Both together exceed the budget.
        let cache = MokaCache::new_asset(7, clock);
        let response = CachedResponse::new("image/png", vec![0; 3]);
        cache.put("a", &response, Duration::from_secs(60)).await;
        cache.put("b", &response, Duration::from_secs(60)).await;
        cache.entries.run_pending_tasks().await;

        let weight: usize = cache
            .entries
            .iter()
            .map(|(key, entry)| key.len() + entry.response.body().len() + 1)
            .sum();
        assert!(weight <= 7);
    }

    #[tokio::test]
    async fn a_prefix_sweep_leaves_other_bindings_alone() {
        // The reference implementation proves this too, but `moka`'s iterator
        // and invalidation are different code, so the property is re-asserted
        // against the adapter that actually ships.
        let (_clock, cache) = setup();
        let revoked = re0auth_api::BindingId::new();
        let other = re0auth_api::BindingId::new();
        let value = CachedResponse::new("application/json", b"x".to_vec());
        for resource in ["scores", "profile"] {
            cache
                .put(
                    &re0auth_api::cache::key(&revoked, "phigros", resource),
                    &value,
                    Duration::from_secs(60),
                )
                .await;
        }
        let survivor = re0auth_api::cache::key(&other, "phigros", "scores");
        cache.put(&survivor, &value, Duration::from_secs(60)).await;

        let removed = cache
            .invalidate(&re0auth_api::cache::binding_prefix(&revoked))
            .await;
        assert_eq!(removed, 2);
        assert!(cache.get(&survivor).await.is_some());
    }
}
