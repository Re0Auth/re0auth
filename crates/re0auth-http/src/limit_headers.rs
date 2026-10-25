//! Response headers that describe *this* service's limits.
//!
//! Split out of `lib.rs`, which is at its line budget, and grouped because they
//! share one distinction: headers about our own budget (`RateLimit-*`) are not
//! the same thing as headers about an upstream's (`Retry-After` on a breaker).

use axum::http::{HeaderMap, HeaderValue, header};

/// `Retry-After` alone, for the gateway's 503/429.
///
/// No `RateLimit-*` here: those describe *this* service's budget, and a breaker
/// tripping says nothing about it.
#[must_use]
pub fn retry_after_only(retry_after_secs: u64) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        headers.insert(header::RETRY_AFTER, value);
    }
    headers
}

/// `RateLimit-Limit` and `RateLimit-Policy` on a denial.
///
/// `RateLimit-Remaining` is deliberately absent. GCRA keeps its allowance in an
/// opaque atomic, so the only way to publish a remaining count would be a second
/// counter updated alongside it — two writers that drift, and a client told it
/// has budget when it does not. A missing header is honest; a wrong one is worse
/// than none.
#[must_use]
pub fn rate_limit(retry_after_secs: u64, limit: u64, window_secs: u64) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        headers.insert(header::RETRY_AFTER, value);
    }
    if let Ok(value) = HeaderValue::from_str(&limit.to_string()) {
        headers.insert("ratelimit-limit", value);
    }
    // The window is implied by Retry-After only at the moment of denial, so state
    // the policy explicitly rather than making clients infer it.
    if let Ok(value) = HeaderValue::from_str(&format!("{limit};w={window_secs}")) {
        headers.insert("ratelimit-policy", value);
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gateway_denial_does_not_claim_a_service_budget() {
        // A tripped breaker says nothing about our request allowance; publishing
        // RateLimit-* here would make a client throttle against the wrong thing.
        let headers = retry_after_only(30);
        assert_eq!(
            headers
                .get(header::RETRY_AFTER)
                .expect("retry")
                .to_str()
                .expect("ascii"),
            "30"
        );
        assert!(headers.get("ratelimit-limit").is_none());
    }

    #[test]
    fn a_rate_denial_states_the_ceiling_and_window_it_hit() {
        let headers = rate_limit(12, 30, 60);
        assert_eq!(
            headers
                .get(header::RETRY_AFTER)
                .expect("retry")
                .to_str()
                .expect("ascii"),
            "12"
        );
        assert_eq!(
            headers
                .get("ratelimit-limit")
                .expect("limit")
                .to_str()
                .expect("ascii"),
            "30"
        );
        assert_eq!(
            headers
                .get("ratelimit-policy")
                .expect("policy")
                .to_str()
                .expect("ascii"),
            "30;w=60"
        );
        assert!(headers.get("ratelimit-remaining").is_none());
    }
}
