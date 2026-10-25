#![forbid(unsafe_code)]

//! Data-plane adapters: game upstreams.
//!
//! This crate fetches resources from connectors and holds their root credentials
//! in a vault of its own. It never names a user, a session or an identity
//! (ADR-0021) — `re0auth-idp` is its sibling, not its dependency. Both may use
//! `re0auth-runtime` for shared infrastructure.

pub mod connector;
pub mod connector_secret;
pub mod inflight;
pub mod oauth;

pub use inflight::ByteBudget;
