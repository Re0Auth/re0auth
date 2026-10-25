//! Rate-limit charging shared by the anonymous and authenticated lanes.

use axum::http::StatusCode;
use re0auth_api::rate::Lane;

use crate::error::{ApiError, Shape};
use crate::{AppState, limit_headers};

/// INV-RATE-01: charges the unauthenticated lane to `key`.
///
/// Returns the refusal as an `ApiError` so handlers can `?` it. The 429 carries
/// `Retry-After`, which is the only thing that makes a rate limit actionable —
/// without it a well-behaved client can only retry blindly.
///
/// The error shape is a parameter because this helper is shared by lanes that
/// answer differently: `/oauth/token` is an RFC 6749 endpoint, the gateway is not.
pub(crate) fn charge_unauthenticated(
    state: &AppState,
    key: &str,
    shape: Shape,
) -> Result<(), ApiError> {
    charge(state, Lane::Unauthenticated, key, shape)
}

pub(crate) fn charge(
    state: &AppState,
    lane: Lane,
    key: &str,
    shape: Shape,
) -> Result<(), ApiError> {
    match state.rate.check(lane, key) {
        re0auth_api::rate::RateDecision::Allow => Ok(()),
        re0auth_api::rate::RateDecision::Deny {
            retry_after_secs,
            limit,
            window_secs,
        } => {
            let mut response = shape.response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many requests; retry later",
            );
            // Merge, not replace: the problem shape carries its content type here.
            for (name, value) in limit_headers::rate_limit(retry_after_secs, limit, window_secs) {
                if let Some(name) = name {
                    response.headers.insert(name, value);
                }
            }
            Err(response)
        }
    }
}
