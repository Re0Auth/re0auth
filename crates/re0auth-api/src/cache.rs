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

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

use async_trait::async_trait;

use crate::BindingId;
use crate::connector::{UpstreamError, ValidatedParamValue};

/// A cached upstream response.
///
/// The media type travels with the body rather than being assumed: the gateway
/// forwards `content_type` verbatim, and hard-coding `application/json` would
/// mislabel a connector that returns something else.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedResponse {
    /// Shared so a cache hit clones two words instead of the whole body.
    /// The payload never changes after construction; `stale` sits outside so
    /// marking an entry does not force a copy.
    data: std::sync::Arc<CachedData>,
    /// Past its fresh TTL but still within the stale window.
    ///
    /// Only the gateway's outage path may serve these; the normal path must
    /// treat them as a miss.
    stale: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct CachedData {
    content_type: String,
    body: bytes::Bytes,
}

impl CachedResponse {
    #[must_use]
    pub fn new(content_type: impl Into<String>, body: impl Into<bytes::Bytes>) -> Self {
        Self {
            data: std::sync::Arc::new(CachedData {
                content_type: content_type.into(),
                body: body.into(),
            }),
            stale: false,
        }
    }

    #[must_use]
    pub fn content_type(&self) -> &str {
        &self.data.content_type
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.data.body
    }

    #[must_use]
    pub fn body_bytes(&self) -> bytes::Bytes {
        self.data.body.clone()
    }

    #[must_use]
    pub fn is_stale(&self) -> bool {
        self.stale
    }

    #[must_use]
    pub fn as_fresh(&self) -> Self {
        Self {
            data: std::sync::Arc::clone(&self.data),
            stale: false,
        }
    }

    #[must_use]
    pub fn as_stale(&self) -> Self {
        Self {
            data: std::sync::Arc::clone(&self.data),
            stale: true,
        }
    }
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

/// Extends [`key`] with the validated parameter map. The parameter order is
/// canonical because `BTreeMap` iterates sorted; each value carries its wire
/// type and its own length so no delimiter can make two different maps collide.
#[must_use]
pub fn key_with_params(
    binding: &BindingId,
    connector: &str,
    resource: &str,
    params: &BTreeMap<String, ValidatedParamValue>,
) -> String {
    append_params(key(binding, connector, resource), params)
}

#[must_use]
pub fn key_asset(
    binding: &BindingId,
    subject: &str,
    connector: &str,
    resource: &str,
    params: &BTreeMap<String, ValidatedParamValue>,
) -> String {
    let mut key = key_with_params(binding, connector, resource, params);
    let _ = write!(key, ":subject:{}:{subject}", subject.len());
    key
}

#[must_use]
pub fn key_shared(
    connector: &str,
    resource: &str,
    params: &BTreeMap<String, ValidatedParamValue>,
) -> String {
    append_params(format!("shared:{connector}:{resource}"), params)
}

fn append_params(mut key: String, params: &BTreeMap<String, ValidatedParamValue>) -> String {
    for (name, value) in params {
        let (kind, value) = match value {
            ValidatedParamValue::String(value) => ("s", value.clone()),
            ValidatedParamValue::Integer(value) => ("i", value.to_string()),
            ValidatedParamValue::Number { raw, .. } => ("n", raw.clone()),
            ValidatedParamValue::Boolean(value) => ("b", value.to_string()),
            // Members are already sorted and de-duplicated by validation, so a
            // length-prefixed join cannot be confused by a value holding the
            // separator.
            ValidatedParamValue::List(items) => (
                "l",
                items
                    .iter()
                    .map(|item| {
                        let value = item.as_query_string();
                        format!("{}:{value}", value.len())
                    })
                    .collect::<String>(),
            ),
        };
        let _ = write!(
            key,
            ":{}:{}:{}:{}:{}",
            name.len(),
            name,
            kind,
            value.len(),
            value
        );
    }
    key
}

/// Every key belonging to one binding.
#[must_use]
pub fn binding_prefix(binding: &BindingId) -> String {
    format!("binding:{}:", binding.0)
}

pub trait FailureCache: Send + Sync {
    fn get(&self, key: &str) -> Option<UpstreamError>;
    fn put(&self, key: String, error: UpstreamError, ttl: Duration);
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
    fn cloning_a_response_shares_the_payload() {
        let original = CachedResponse::new("application/json", vec![1, 2, 3]);
        let copy = original.clone();
        assert_eq!(copy.body(), original.body());
        assert!(
            std::ptr::eq(copy.body().as_ptr(), original.body().as_ptr()),
            "a cache hit must not copy the body"
        );
        assert_eq!(original.body_bytes().as_ptr(), original.body().as_ptr());
    }

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

    #[test]
    fn empty_parameters_keep_the_old_key_and_order_is_irrelevant() {
        let binding = BindingId::new();
        assert_eq!(
            key_with_params(&binding, "phigros", "scores", &BTreeMap::new()),
            key(&binding, "phigros", "scores")
        );
        let first = BTreeMap::from([
            (
                "a".to_string(),
                ValidatedParamValue::String("1".to_string()),
            ),
            ("b".to_string(), ValidatedParamValue::Boolean(false)),
        ]);
        let second = BTreeMap::from([
            ("b".to_string(), ValidatedParamValue::Boolean(false)),
            (
                "a".to_string(),
                ValidatedParamValue::String("1".to_string()),
            ),
        ]);
        assert_eq!(
            key_with_params(&binding, "phigros", "scores", &first),
            key_with_params(&binding, "phigros", "scores", &second)
        );
    }

    #[test]
    fn keys_separate_parameter_names_values_and_wire_types() {
        let binding = BindingId::new();
        let integer = BTreeMap::from([("limit".to_string(), ValidatedParamValue::Integer(10))]);
        let string = BTreeMap::from([(
            "limit".to_string(),
            ValidatedParamValue::String("10".to_string()),
        )]);
        let other_value = BTreeMap::from([("limit".to_string(), ValidatedParamValue::Integer(11))]);
        let other_name = BTreeMap::from([("rank".to_string(), ValidatedParamValue::Integer(10))]);
        let base = key_with_params(&binding, "phigros", "scores", &integer);
        assert_ne!(
            base,
            key_with_params(&binding, "phigros", "scores", &string)
        );
        assert_ne!(
            base,
            key_with_params(&binding, "phigros", "scores", &other_value)
        );
        assert_ne!(
            base,
            key_with_params(&binding, "phigros", "scores", &other_name)
        );
        assert_eq!(
            base,
            key_with_params(
                &binding,
                "phigros",
                "scores",
                &BTreeMap::from([("limit".to_string(), ValidatedParamValue::Integer(10))])
            )
        );
    }

    #[test]
    fn different_path_values_produce_different_private_keys() {
        let binding = BindingId::new();
        let key = |song: &str| {
            key_with_params(
                &binding,
                "phigros",
                "song",
                &BTreeMap::from([(
                    "song".to_string(),
                    ValidatedParamValue::String(song.to_string()),
                )]),
            )
        };
        assert_ne!(key("IN/OUT"), key("other"));
    }

    #[test]
    fn shared_keys_canonicalize_params_without_naming_a_binding() {
        let params = BTreeMap::from([(
            "song".to_string(),
            ValidatedParamValue::String("IN/OUT".to_string()),
        )]);
        let shared = key_shared("phigros", "jacket", &params);
        assert!(shared.starts_with("shared:phigros:jacket:"), "{shared}");
        assert!(!shared.starts_with("binding:"));
        assert_eq!(shared, key_shared("phigros", "jacket", &params));
        assert_ne!(
            shared,
            key_shared(
                "phigros",
                "jacket",
                &BTreeMap::from([(
                    "song".to_string(),
                    ValidatedParamValue::String("other".to_string()),
                )])
            )
        );
    }
}
