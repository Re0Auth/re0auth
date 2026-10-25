//! Published signing keys.
//!
//! Public material only. The private half is a `0600` PEM file that the signer
//! loads directly; nothing here can mint a token (INV-KEY-01).

use async_trait::async_trait;
use re0auth_api::Unix;
use re0auth_api::ports::{RepoError, RepoResult, SigningKeyRecord, SigningKeyRepo};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;

use super::{SqliteStore, db_error};

fn row_to_key(row: &SqliteRow) -> RepoResult<SigningKeyRecord> {
    Ok(SigningKeyRecord {
        kid: row.try_get("kid").map_err(db_error)?,
        alg: row.try_get("alg").map_err(db_error)?,
        public_jwk_json: row.try_get("public_jwk_json").map_err(db_error)?,
        created_at: row.try_get("created_at").map_err(db_error)?,
        activated_at: row.try_get("activated_at").map_err(db_error)?,
        retired_at: row.try_get("retired_at").map_err(db_error)?,
    })
}

#[async_trait]
impl SigningKeyRepo for SqliteStore {
    async fn publish(&self, record: &SigningKeyRecord) -> RepoResult<()> {
        // Upsert rather than insert: a restart re-publishes the same key, and
        // failing on the second start would make every restart an outage.
        //
        // `retired_at` is deliberately not overwritten. Re-publishing a key that
        // an operator retired must not silently un-retire it and start signing
        // with it again.
        sqlx::query(
            "INSERT INTO signing_keys \
             (kid, alg, public_jwk_json, created_at, activated_at, retired_at) \
             VALUES (?, ?, ?, ?, ?, NULL) \
             ON CONFLICT(kid) DO UPDATE SET \
               alg = excluded.alg, \
               public_jwk_json = excluded.public_jwk_json, \
               activated_at = excluded.activated_at",
        )
        .bind(&record.kid)
        .bind(&record.alg)
        .bind(&record.public_jwk_json)
        .bind(record.created_at)
        .bind(record.activated_at)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn published(&self) -> RepoResult<Vec<SigningKeyRecord>> {
        let rows = sqlx::query(
            "SELECT kid, alg, public_jwk_json, created_at, activated_at, retired_at \
             FROM signing_keys ORDER BY activated_at DESC, kid DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        rows.iter().map(row_to_key).collect()
    }

    async fn active(&self) -> RepoResult<Option<SigningKeyRecord>> {
        let row = sqlx::query(
            "SELECT kid, alg, public_jwk_json, created_at, activated_at, retired_at \
             FROM signing_keys WHERE retired_at IS NULL \
             ORDER BY activated_at DESC, kid DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        row.as_ref().map(row_to_key).transpose()
    }

    async fn retire(&self, kid: &str, at: Unix) -> RepoResult<()> {
        let result = sqlx::query(
            "UPDATE signing_keys SET retired_at = COALESCE(retired_at, ?) WHERE kid = ?",
        )
        .bind(at)
        .bind(kid)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        if result.rows_affected() == 0 {
            return Err(RepoError::NotFound);
        }
        Ok(())
    }
}
