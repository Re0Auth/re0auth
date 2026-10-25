#![forbid(unsafe_code)]

//! Local adapters: persistence, signing and rate limiting.
//!
//! The split away from this crate (ADR-0021): identity providers live in
//! `re0auth-idp`, game upstreams in `re0auth-connectors`, and the outbound HTTP
//! stack in `re0auth-runtime`. Each is a separate crate so Cargo enforces the
//! separation that a module boundary cannot.

pub mod client_secret;
pub mod clock;
pub mod crypto;
pub mod moka_cache;
pub mod random;
pub mod rate_limit;
pub mod sealer;
pub mod sqlite_path;
pub mod storage;
