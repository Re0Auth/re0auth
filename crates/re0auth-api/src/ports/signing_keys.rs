//! Signing-key publication and revocation.
//!
//! Split out of `ports.rs` to keep that file inside its line budget; the path
//! `re0auth_api::ports::SigningKeyRepo` is preserved by the re-export.

use async_trait::async_trait;

use super::*;

/// Retiring a key does not delete it: tokens signed before the rotation remain
/// verifiable until they expire (OPERATIONS.md §5.2). Reusing a `kid` would make
/// old tokens resolve to a new key, which is the known failure mode this table
/// exists to prevent.
#[async_trait]
pub trait SigningKeyRepo: Send + Sync {
    /// Inserts a key, or updates it when `kid` already exists. Idempotent so a
    /// restart re-publishing the same key does not fail.
    async fn publish(&self, record: &SigningKeyRecord) -> RepoResult<()>;
    /// Every key that must appear in the JWKS document, newest first.
    ///
    /// Includes retired keys: dropping them would make unexpired tokens signed
    /// by the old key fail verification.
    async fn published(&self) -> RepoResult<Vec<SigningKeyRecord>>;
    /// The key new tokens should be signed with: the newest non-retired one.
    async fn active(&self) -> RepoResult<Option<SigningKeyRecord>>;
    /// Marks `kid` as retired. Idempotent.
    async fn retire(&self, kid: &str, at: Unix) -> RepoResult<()>;
    /// Deletes a published key so it is no longer trusted at all.
    ///
    /// Retirement keeps a key for verification; purging is the revocation path
    /// for a key that must stop being accepted (for example after a leak).
    async fn purge(&self, kid: &str) -> RepoResult<()>;
}
