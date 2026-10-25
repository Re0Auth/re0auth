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
use re0auth_api::Clock;
use re0auth_api::cache::{Cache, CachedResponse};

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
    /// Builds a cache holding at most `max_entries` responses.
    ///
    /// A capacity is required rather than optional: an unbounded process-local
    /// cache is a memory leak with a friendly name, and the whole point of
    /// taking `moka` was to get eviction.
    #[must_use]
    pub fn new(max_entries: u64, clock: Arc<dyn Clock>) -> Self {
        let entries = Moka::builder()
            .max_capacity(max_entries)
            // Weight by body size so one 4 MiB response cannot silently occupy
            // the space of thousands of small ones.
            .weigher(|key: &String, entry: &Entry| {
                let body = u32::try_from(entry.response.body.len()).unwrap_or(u32::MAX);
                let key_len = u32::try_from(key.len()).unwrap_or(u32::MAX);
                body.saturating_add(key_len).saturating_add(1)
            })
            .build();
        Self { entries, clock }
    }

    fn fresh_until(now: i64, fresh_for: Duration) -> i64 {
        now.saturating_add(i64::try_from(fresh_for.as_secs()).unwrap_or(i64::MAX))
    }

    fn stale_until(fresh_until: i64) -> i64 {
        fresh_until.saturating_add(i64::try_from(STALE_GRACE.as_secs()).unwrap_or(i64::MAX))
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
        (now < entry.fresh_until).then_some(CachedResponse {
            content_type: entry.response.content_type,
            body: entry.response.body,
            stale: false,
        })
    }

    async fn get_any(&self, key: &str) -> Option<CachedResponse> {
        let now = self.clock.now();
        let entry = self.entries.get(key).await?;
        if now >= entry.stale_until {
            return None;
        }
        Some(CachedResponse {
            content_type: entry.response.content_type,
            body: entry.response.body,
            stale: now >= entry.fresh_until,
        })
    }

    async fn put(&self, key: &str, value: &CachedResponse, fresh_for: Duration) {
        let now = self.clock.now();
        let fresh_until = Self::fresh_until(now, fresh_for);
        self.entries
            .insert(
                key.to_string(),
                Entry {
                    response: CachedResponse {
                        content_type: value.content_type.clone(),
                        body: value.body.clone(),
                        stale: false,
                    },
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

    #[tokio::test]
    async fn a_prefix_sweep_leaves_other_bindings_alone() {
        // The reference implementation proves this too, but `moka`'s iterator
        // and invalidation are different code, so the property is re-asserted
        // against the adapter that actually ships.
        let (_clock, cache) = setup();
        let revoked = re0auth_api::BindingId::new();
        let other = re0auth_api::BindingId::new();
        let value = CachedResponse {
            content_type: "application/json".to_string(),
            body: b"x".to_vec(),
            stale: false,
        };
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
