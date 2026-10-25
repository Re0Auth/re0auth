//! Response cache as a port (INV-CACHE-01, INV-CACHE-02).
//!
//! The gateway caches upstream responses so a player's data is not fetched
//! again on every call. Three rules shape this contract:
//!
//! 1. **Reads happen after authorization, never before.** The cache must not be
//!    consulted until the scope gate and the binding lookup have passed. A
//!    stale entry served to a caller who lost the scope would be a privilege
//!    escalation, so the ordering is an invariant rather than a coding habit.
//! 2. **A revoked binding invalidates its entries.** Leaving them behind would
//!    let the stale path keep serving a player's data after they explicitly
//!    unbound the account.
//! 3. **Keys are namespaced by binding.** [`key`] and [`binding_prefix`] are the
//!    only ways to build one. The prefix ends with `:` and the binding id is a
//!    fixed-width UUID, so one binding's prefix can never match another's.
//!
//! Freshness is decided by this layer, not by the storage engine. The port
//! takes a fresh TTL per write and reports staleness itself; a cache library
//! that owns its own clock would make TTL untestable and could not distinguish
//! "expired but still usable during an outage" from "gone".

use std::time::Duration;

use async_trait::async_trait;

use crate::BindingId;

/// A cached upstream response.
///
/// The media type travels with the body rather than being assumed: the gateway
/// forwards `content_type` verbatim, and hard-coding `application/json` would
/// mislabel a connector that returns something else.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedResponse {
    pub content_type: String,
    pub body: Vec<u8>,
    /// Past its fresh TTL but still within the stale window.
    ///
    /// Only the gateway's outage path may serve these; the normal path must
    /// treat them as a miss.
    pub stale: bool,
}

/// Key builders. Nothing else may construct a cache key.
///
/// `connector` and `resource` are validated as `[a-z0-9_-]` by the registry, and
/// the binding id is a UUID, so `:` cannot appear inside any component. That is
/// what makes [`binding_prefix`] safe to use as a blast radius.
#[must_use]
pub fn key(binding: &BindingId, connector: &str, resource: &str) -> String {
    format!("binding:{}:{connector}:{resource}", binding.0)
}

/// Every key belonging to one binding.
#[must_use]
pub fn binding_prefix(binding: &BindingId) -> String {
    format!("binding:{}:", binding.0)
}

/// Response cache.
///
/// Implementations must be safe to call concurrently and must not block the
/// caller for longer than a map operation.
#[async_trait]
pub trait Cache: Send + Sync {
    /// Returns the entry only if it is still fresh.
    ///
    /// A stale entry is a miss here on purpose: the ordinary path must never
    /// serve data past its TTL, even though the outage path may.
    async fn get(&self, key: &str) -> Option<CachedResponse>;

    /// Returns the entry whether fresh or stale, so the outage path can decide.
    async fn get_any(&self, key: &str) -> Option<CachedResponse>;

    /// Stores `value` under `key`, fresh for `fresh_for`.
    async fn put(&self, key: &str, value: &CachedResponse, fresh_for: Duration);

    /// Drops every entry whose key starts with `prefix`.
    ///
    /// Called with [`binding_prefix`] when a binding is revoked
    /// (INV-CACHE-02). Returns how many entries were removed, so callers can
    /// tell "nothing was cached" from "the sweep silently failed".
    async fn invalidate(&self, prefix: &str) -> usize;
}

/// A cache that stores nothing. Used where no cache is configured, so call
/// sites do not need an `Option` and the gateway keeps one code path.
pub struct NoCache;

#[async_trait]
impl Cache for NoCache {
    async fn get(&self, _key: &str) -> Option<CachedResponse> {
        None
    }

    async fn get_any(&self, _key: &str) -> Option<CachedResponse> {
        None
    }

    async fn put(&self, _key: &str, _value: &CachedResponse, _fresh_for: Duration) {}

    async fn invalidate(&self, _prefix: &str) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binding_prefix_never_matches_another_binding() {
        let first = BindingId::new();
        let second = BindingId::new();
        let first_key = key(&first, "phigros", "scores");
        assert!(first_key.starts_with(&binding_prefix(&first)));
        assert!(
            !first_key.starts_with(&binding_prefix(&second)),
            "one binding's prefix must not reach another's entries"
        );
    }

    #[test]
    fn the_prefix_covers_every_resource_of_one_binding() {
        let binding = BindingId::new();
        let prefix = binding_prefix(&binding);
        for resource in ["scores", "profile", "stats"] {
            assert!(key(&binding, "phigros", resource).starts_with(&prefix));
        }
        // A different connector for the same binding is still that binding's
        // data, so it must be swept by the same call.
        assert!(key(&binding, "phihub", "scores").starts_with(&prefix));
    }

    #[test]
    fn keys_are_distinct_per_resource_and_connector() {
        let binding = BindingId::new();
        assert_ne!(key(&binding, "a", "scores"), key(&binding, "a", "profile"));
        assert_ne!(key(&binding, "a", "scores"), key(&binding, "b", "scores"));
    }
}
