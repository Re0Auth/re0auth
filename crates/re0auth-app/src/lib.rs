#![forbid(unsafe_code)]

//! Use-case orchestration. Knows ports, not adapters.

use re0auth_api::{Clock, Unix};

pub mod admin;
pub mod admin_service;
pub mod auth;
pub mod binding;
pub mod circuit;
pub mod gateway;
pub mod hints;
pub mod housekeeping;
pub mod oauth;
pub mod return_to;
pub mod rotation;

pub use auth::{AuthError, AuthService, CreatedSession, LoginOutcome};

pub fn now(clock: &dyn Clock) -> Unix {
    clock.now()
}

pub fn access_token_ttl(now: Unix) -> Unix {
    re0auth_domain::access_token_ttl(now)
}

pub fn build_info() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
