#![forbid(unsafe_code)]

//! Reference kit for Re0Auth upstream data sources.
//!
//! Provides the discovery document, canonical scope validation, resource and
//! account routes, optional cascade revocation, and a conformance report.
//! It has no dependency on Re0Auth's internal crates.

pub mod conformance;
pub mod discovery;
pub mod server;

pub use discovery::{
    ACCOUNT_SCOPE, Config, Discovery, DiscoveryError, OAuthEndpoints, PROTOCOL_VERSION, RawSpec,
    Resource, TokenClass, is_canonical_schema, is_canonical_scope, new_discovery,
};
pub use server::{
    AccountInfo, CascadeRevocationRequest, CascadeRevoker, Hooks, ResourceError, ResourceHandler,
    Server, ServerError,
};
