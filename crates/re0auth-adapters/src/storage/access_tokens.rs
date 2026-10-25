//! Revoked access tokens.
//!
//! Access tokens are JWTs, so there is no row to flip on revocation. The `jti`
//! is recorded instead, and verification consults it. Rows are deleted once the
//! token would have expired regardless, which bounds the table automatically.

use async_trait::async_trait;
use re0auth_api::audit::SecurityFact;
use re0auth_api::ports::{AccessTokenRepo, RepoResult};
use re0auth_api::{ClientId, Unix, UserId};

use super::audit::record_fact;
use super::{SqliteStore, db_error};

#[async_trait]
impl AccessTokenRepo for SqliteStore {
    async fn revoke(
        &self,
        jti: &str,
        client_id: Option<ClientId>,
        revoked_by: Option<UserId>,
        expires_at: Unix,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()> {
        // Revocation and its fact land together (INV-AUDIT-01).
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        // Idempotent: a repeat revoke updates the timestamp rather than failing.
        // RFC 7009 requires the endpoint to be silent about unknown tokens, and
        // a conflict error here would leak whether the token was known.
        sqlx::query(
            "INSERT INTO access_revocations (jti, expires_at, revoked_at, revoked_by, client_id) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(jti) DO UPDATE SET revoked_at = excluded.revoked_at",
        )
        .bind(jti)
        .bind(expires_at)
        .bind(now)
        .bind(revoked_by.map(|id| id.0.to_string()))
        .bind(client_id.map(|id| id.0.to_string()))
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        record_fact(&mut tx, fact).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn is_revoked(&self, jti: &str, now: Unix) -> RepoResult<bool> {
        // The `expires_at` filter keeps an accidental reuse of an expired jti
        // from resurrecting a revocation that no longer matters.
        let row = sqlx::query("SELECT 1 FROM access_revocations WHERE jti = ? AND expires_at > ?")
            .bind(jti)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(row.is_some())
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let result = sqlx::query("DELETE FROM access_revocations WHERE expires_at <= ?")
            .bind(before)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected())
    }
}
