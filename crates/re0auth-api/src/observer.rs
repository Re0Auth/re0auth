//! Gateway request-path counters.
//!
//! Kept apart from the telemetry sink: these are exact numbers, not the lossy
//! audit ledger, and a full queue must not change them.

/// Optional, non-blocking gateway counters for hit/miss attribution.
pub trait GatewayObserver: Send + Sync {
    fn cache_hit(&self, connector: &str, resource: &str);
    fn cache_miss(&self, connector: &str, resource: &str);
}

/// The observer used when metrics are not wired.
pub struct NoGatewayObserver;

impl GatewayObserver for NoGatewayObserver {
    fn cache_hit(&self, _connector: &str, _resource: &str) {}
    fn cache_miss(&self, _connector: &str, _resource: &str) {}
}
