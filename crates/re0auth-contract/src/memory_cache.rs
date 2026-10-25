//! In-memory cache with the port's expiry semantics (INV-CACHE-01/-02).
//!
//! Deliberately not backed by `moka`: the port owns freshness, so the test
//! double must own it too. A cache library with its own clock would make the
//! TTL tests sleep instead of advancing the injected clock.
//!
//! Stale entries are kept, not dropped on expiry, because the outage path is
//! allowed to serve them. They are dropped once past [`STALE_GRACE`] — keeping
//! them forever would turn the cache into an unbounded leak.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use re0auth_api::Clock;
use re0auth_api::cache::{Cache, CachedResponse};

/// How long past its fresh TTL an entry may still be served during an outage.
///
/// `test-v1.3.md` §6.8 caps stale data at 1800 s; this matches it so the double
/// and production agree on the window.
pub const STALE_GRACE: Duration = Duration::from_secs(1_800);

struct Entry {
    content_type: String,
    value: Vec<u8>,
    /// Absolute expiry in Unix seconds, from the injected clock.
    fresh_until: i64,
    stale_until: i64,
}

#[derive(Default)]
struct Inner {
    entries: Mutex<HashMap<String, Entry>>,
}

/// Shared so the same instance can observe writes made through a port object.
#[derive(Clone, Default)]
pub struct MemoryCache {
    inner: Arc<Inner>,
}

impl MemoryCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries held, including stale ones. Tests use this to prove a
    /// sweep actually removed something rather than merely returning zero.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .entries
            .lock()
            .expect("cache lock poisoned")
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn fresh_until(now: i64, fresh_for: Duration) -> i64 {
        now.saturating_add(i64::try_from(fresh_for.as_secs()).unwrap_or(i64::MAX))
    }

    fn stale_until(fresh_until: i64) -> i64 {
        fresh_until.saturating_add(i64::try_from(STALE_GRACE.as_secs()).unwrap_or(i64::MAX))
    }
}

impl std::fmt::Debug for MemoryCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryCache")
            .field("len", &self.len())
            .finish()
    }
}

/// Binds the clock so `get` can decide freshness. The port methods take no
/// `now` on purpose: every component asks the same clock, which is what keeps
/// tests reproducible.
pub struct ClockedCache {
    cache: MemoryCache,
    clock: Arc<dyn Clock>,
}

impl ClockedCache {
    #[must_use]
    pub fn new(cache: MemoryCache, clock: Arc<dyn Clock>) -> Self {
        Self { cache, clock }
    }

    #[must_use]
    pub fn handle(&self) -> MemoryCache {
        self.cache.clone()
    }

    /// Number of entries held, including stale ones.
    ///
    /// Tests use this to prove a sweep actually removed something rather than
    /// merely returning zero.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

#[async_trait]
impl Cache for ClockedCache {
    async fn get(&self, key: &str) -> Option<CachedResponse> {
        let now = self.clock.now();
        let entries = self
            .cache
            .inner
            .entries
            .lock()
            .expect("cache lock poisoned");
        entries
            .get(key)
            .filter(|entry| now < entry.fresh_until)
            .map(|entry| CachedResponse {
                content_type: entry.content_type.clone(),
                body: entry.value.clone(),
                stale: false,
            })
    }

    async fn get_any(&self, key: &str) -> Option<CachedResponse> {
        let now = self.clock.now();
        let entries = self
            .cache
            .inner
            .entries
            .lock()
            .expect("cache lock poisoned");
        let entry = entries.get(key)?;
        if now >= entry.stale_until {
            return None;
        }
        Some(CachedResponse {
            content_type: entry.content_type.clone(),
            body: entry.value.clone(),
            stale: now >= entry.fresh_until,
        })
    }

    async fn put(&self, key: &str, value: &CachedResponse, fresh_for: Duration) {
        let now = self.clock.now();
        let fresh_until = MemoryCache::fresh_until(now, fresh_for);
        self.cache
            .inner
            .entries
            .lock()
            .expect("cache lock poisoned")
            .insert(
                key.to_string(),
                Entry {
                    content_type: value.content_type.clone(),
                    value: value.body.clone(),
                    fresh_until,
                    stale_until: MemoryCache::stale_until(fresh_until),
                },
            );
    }

    async fn invalidate(&self, prefix: &str) -> usize {
        let mut entries = self
            .cache
            .inner
            .entries
            .lock()
            .expect("cache lock poisoned");
        let before = entries.len();
        entries.retain(|key, _| !key.starts_with(prefix));
        before - entries.len()
    }
}
