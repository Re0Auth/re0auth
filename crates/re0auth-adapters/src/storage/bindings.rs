use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use re0auth_api::audit::SecurityFact;
use re0auth_api::ports::{
    ANONYMIZED_UPSTREAM_USER_ID, Binding, BindingQuery, BindingRepo, RepoError, RepoResult,
};
use re0auth_api::secret::SealedSecret;
use re0auth_api::{BindingId, Unix, UserId};

use super::audit::record_fact;
use super::{SqliteStore, db_error, parse_uuid, row_to_binding, status_to_str};
#[async_trait]
impl BindingRepo for SqliteStore {
    async fn upsert(&self, binding: &Binding, fact: &SecurityFact) -> RepoResult<()> {
        // The conflict target is (user_id, upstream_id): one binding per user per
        // connector, matching the unique index. Re-binding refreshes the row in
        // place so the binding id — and the sub-credential hanging off it —
        // survives.
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        sqlx::query(
            "INSERT INTO bindings \
             (id, user_id, upstream_id, upstream_user_id, status, created_at, updated_at, \
              last_refreshed_at, last_error_code) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(user_id, upstream_id) DO UPDATE SET \
             upstream_user_id = excluded.upstream_user_id, \
             status = excluded.status, \
             updated_at = excluded.updated_at, \
             last_refreshed_at = excluded.last_refreshed_at, \
             last_error_code = excluded.last_error_code, \
             revoked_at = NULL",
        )
        .bind(binding.id.0.to_string())
        .bind(binding.user_id.0.to_string())
        .bind(&binding.upstream_id)
        .bind(&binding.upstream_user_id)
        .bind(status_to_str(binding.status))
        .bind(binding.created_at)
        .bind(binding.updated_at)
        .bind(binding.last_refreshed_at)
        .bind(binding.last_error_code.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        record_fact(&mut tx, fact).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn upsert_with_credential(
        &self,
        binding: &Binding,
        sealed: &SealedSecret,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<Binding> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(db_error)?;

        let existing = sqlx::query(
            "SELECT id, created_at FROM bindings WHERE user_id = ? AND upstream_id = ?",
        )
        .bind(binding.user_id.0.to_string())
        .bind(&binding.upstream_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let stored = match existing {
            Some(row) => {
                let stored_id = BindingId(parse_uuid(
                    &row.try_get::<String, _>("id").map_err(db_error)?,
                )?);
                if stored_id != binding.id {
                    return Err(RepoError::Conflict("binding id"));
                }
                Binding {
                    created_at: row.try_get("created_at").map_err(db_error)?,
                    ..binding.clone()
                }
            }
            None => binding.clone(),
        };

        sqlx::query(
            "INSERT INTO bindings              (id, user_id, upstream_id, upstream_user_id, status, created_at, updated_at,               last_refreshed_at, last_error_code)              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)              ON CONFLICT(user_id, upstream_id) DO UPDATE SET              upstream_user_id = excluded.upstream_user_id,              status = excluded.status,              updated_at = excluded.updated_at,              last_refreshed_at = excluded.last_refreshed_at,              last_error_code = excluded.last_error_code,              revoked_at = NULL",
        )
        .bind(stored.id.0.to_string())
        .bind(stored.user_id.0.to_string())
        .bind(&stored.upstream_id)
        .bind(&stored.upstream_user_id)
        .bind(status_to_str(stored.status))
        .bind(stored.created_at)
        .bind(stored.updated_at)
        .bind(stored.last_refreshed_at)
        .bind(stored.last_error_code.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;

        sqlx::query(
            "INSERT INTO sub_credentials              (binding_id, key_version, dek_nonce, wrapped_dek, nonce, ciphertext, created_at, updated_at)              VALUES (?, ?, ?, ?, ?, ?, ?, ?)              ON CONFLICT(binding_id) DO UPDATE SET              key_version = excluded.key_version, dek_nonce = excluded.dek_nonce,              wrapped_dek = excluded.wrapped_dek, nonce = excluded.nonce,              ciphertext = excluded.ciphertext, updated_at = excluded.updated_at",
        )
        .bind(stored.id.0.to_string())
        .bind(i64::from(sealed.key_version()))
        .bind(sealed.dek_nonce())
        .bind(sealed.wrapped_dek())
        .bind(sealed.nonce())
        .bind(sealed.ciphertext())
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;

        let mut fact = fact.clone();
        fact.target = format!("binding:{}", stored.id.0);
        record_fact(&mut tx, &fact).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(stored)
    }

    async fn find(&self, user: &UserId, upstream: &str) -> RepoResult<Option<Binding>> {
        let row = sqlx::query(
            "SELECT id, user_id, upstream_id, upstream_user_id, status, created_at, \
             updated_at, last_refreshed_at, last_error_code \
             FROM bindings WHERE user_id = ? AND upstream_id = ?",
        )
        .bind(user.0.to_string())
        .bind(upstream)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        row.as_ref().map(row_to_binding).transpose()
    }

    async fn list_by_user(&self, user: &UserId) -> RepoResult<Vec<Binding>> {
        let rows = sqlx::query(
            "SELECT id, user_id, upstream_id, upstream_user_id, status, created_at, \
             updated_at, last_refreshed_at, last_error_code \
             FROM bindings WHERE user_id = ? ORDER BY upstream_id",
        )
        .bind(user.0.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        rows.iter().map(row_to_binding).collect()
    }

    async fn mark_needs_reauth(
        &self,
        id: &BindingId,
        reason: &str,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let result = sqlx::query(
            "UPDATE bindings SET status = 'needs_reauth', last_error_code = ?, updated_at = ? \
             WHERE id = ?",
        )
        .bind(reason)
        .bind(now)
        .bind(id.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        if result.rows_affected() == 0 {
            return Err(RepoError::NotFound);
        }
        record_fact(&mut tx, fact).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn revoke(&self, id: &BindingId, fact: &SecurityFact, now: Unix) -> RepoResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let result = sqlx::query(
            "UPDATE bindings SET status = 'revoked', updated_at = ?, revoked_at = ? WHERE id = ?",
        )
        .bind(now)
        .bind(now)
        .bind(id.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        if result.rows_affected() == 0 {
            return Err(RepoError::NotFound);
        }
        // The row is kept for audit and for the user's history, but the sealed
        // sub-credential must go: leaving it behind would let a revoked binding
        // keep fetching if the gateway ever looked up by binding id alone.
        sqlx::query("DELETE FROM sub_credentials WHERE binding_id = ?")
            .bind(id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        record_fact(&mut tx, fact).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn revoke_all(&self, user: &UserId, fact: &SecurityFact, now: Unix) -> RepoResult<u64> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let result = sqlx::query(
            "UPDATE bindings SET status = 'revoked', updated_at = ?, revoked_at = ? \
             WHERE user_id = ? AND status != 'revoked'",
        )
        .bind(now)
        .bind(now)
        .bind(user.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let revoked = result.rows_affected();
        if revoked == 0 {
            // Nothing moved, so there is no change for the fact to describe.
            return Ok(0);
        }
        // Every credential of this user's bindings goes, not only the rows this
        // statement touched: a binding revoked earlier must not keep a readable
        // credential just because the killswitch ran after it.
        sqlx::query(
            "DELETE FROM sub_credentials WHERE binding_id IN \
             (SELECT id FROM bindings WHERE user_id = ?)",
        )
        .bind(user.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        record_fact(&mut tx, fact).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(revoked)
    }

    async fn anonymize_revoked_before(&self, before: Unix) -> RepoResult<u64> {
        let result = sqlx::query(
            "UPDATE bindings SET upstream_user_id = ? \
             WHERE status = 'revoked' AND revoked_at IS NOT NULL AND revoked_at <= ? \
             AND upstream_user_id != ?",
        )
        .bind(ANONYMIZED_UPSTREAM_USER_ID)
        .bind(before)
        .bind(ANONYMIZED_UPSTREAM_USER_ID)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected())
    }

    async fn store_sub_credential(
        &self,
        binding: &BindingId,
        sealed: &SealedSecret,
        now: Unix,
    ) -> RepoResult<()> {
        sqlx::query(
            "INSERT INTO sub_credentials \
             (binding_id, key_version, dek_nonce, wrapped_dek, nonce, ciphertext, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(binding_id) DO UPDATE SET \
             key_version = excluded.key_version, dek_nonce = excluded.dek_nonce, \
             wrapped_dek = excluded.wrapped_dek, nonce = excluded.nonce, \
             ciphertext = excluded.ciphertext, updated_at = excluded.updated_at",
        )
        .bind(binding.0.to_string())
        .bind(i64::from(sealed.key_version()))
        .bind(sealed.dek_nonce())
        .bind(sealed.wrapped_dek())
        .bind(sealed.nonce())
        .bind(sealed.ciphertext())
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn load_sub_credential(&self, binding: &BindingId) -> RepoResult<Option<SealedSecret>> {
        let row = sqlx::query(
            "SELECT key_version, dek_nonce, wrapped_dek, nonce, ciphertext \
             FROM sub_credentials WHERE binding_id = ?",
        )
        .bind(binding.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let key_version: i64 = row.try_get("key_version").map_err(db_error)?;
        let key_version = u32::try_from(key_version)
            .map_err(|_| RepoError::Backend("invalid key_version".to_string()))?;
        Ok(Some(
            SealedSecret::new(
                key_version,
                row.try_get("dek_nonce").map_err(db_error)?,
                row.try_get("wrapped_dek").map_err(db_error)?,
                row.try_get("nonce").map_err(db_error)?,
                row.try_get("ciphertext").map_err(db_error)?,
            )
            .map_err(|error| RepoError::Backend(error.to_string()))?,
        ))
    }

    /// Replaces only the key envelope, and only when the row still holds the
    /// envelope that was read.
    ///
    /// Not assembled by the caller from a load-then-store: the window between
    /// those two is where a credential enrolled concurrently is silently rolled
    /// back, because the rotation writes back the payload it read while reporting
    /// success. The comparison on `wrapped_dek` is what makes it a swap: a
    /// concurrent enrol or a concurrent re-wrap both change it.
    async fn rewrap_sub_credential(
        &self,
        binding: &BindingId,
        expect: &SealedSecret,
        new: &SealedSecret,
        now: Unix,
    ) -> RepoResult<bool> {
        let result = sqlx::query(
            "UPDATE sub_credentials \
             SET key_version = ?, dek_nonce = ?, wrapped_dek = ?, updated_at = ? \
             WHERE binding_id = ? AND wrapped_dek = ?",
        )
        .bind(i64::from(new.key_version()))
        .bind(new.dek_nonce())
        .bind(new.wrapped_dek())
        .bind(now)
        .bind(binding.0.to_string())
        .bind(expect.wrapped_dek())
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn delete_sub_credential(&self, binding: &BindingId) -> RepoResult<()> {
        sqlx::query("DELETE FROM sub_credentials WHERE binding_id = ?")
            .bind(binding.0.to_string())
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    /// Pages by binding id, so a rotation that re-wraps rows mid-scan cannot
    /// skip any: the cursor is the last id seen and re-wrapping never moves it.
    async fn scan_sub_credentials(
        &self,
        after: Option<&BindingId>,
        limit: u32,
    ) -> RepoResult<Vec<(BindingId, SealedSecret)>> {
        let cursor = after.map(|id| id.0.to_string()).unwrap_or_default();
        let rows = sqlx::query(
            "SELECT binding_id, key_version, dek_nonce, wrapped_dek, nonce, ciphertext \
             FROM sub_credentials WHERE binding_id > ? ORDER BY binding_id ASC LIMIT ?",
        )
        .bind(cursor)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let raw: String = row.try_get("binding_id").map_err(db_error)?;
            let binding = BindingId(
                Uuid::parse_str(&raw)
                    .map_err(|_| RepoError::Backend("invalid binding_id".to_string()))?,
            );
            let key_version: i64 = row.try_get("key_version").map_err(db_error)?;
            let key_version = u32::try_from(key_version)
                .map_err(|_| RepoError::Backend("invalid key_version".to_string()))?;
            let sealed = SealedSecret::new(
                key_version,
                row.try_get("dek_nonce").map_err(db_error)?,
                row.try_get("wrapped_dek").map_err(db_error)?,
                row.try_get("nonce").map_err(db_error)?,
                row.try_get("ciphertext").map_err(db_error)?,
            )
            .map_err(|error| RepoError::Backend(error.to_string()))?;
            out.push((binding, sealed));
        }
        Ok(out)
    }

    async fn list_all(
        &self,
        before: Option<&BindingId>,
        query: &BindingQuery,
        limit: u32,
    ) -> RepoResult<Vec<Binding>> {
        let cursor = before.map(|id| id.0.to_string());
        let user = query.user.map(|id| id.0.to_string());
        let status = query.status.map(status_to_str);
        let rows = sqlx::query(
            "SELECT id, user_id, upstream_id, upstream_user_id, status, created_at, \
             updated_at, last_refreshed_at, last_error_code FROM bindings \
             WHERE (? IS NULL OR id < ?) \
               AND (? IS NULL OR user_id = ?) \
               AND (? IS NULL OR upstream_id = ?) \
               AND (? IS NULL OR status = ?) \
             ORDER BY id DESC LIMIT ?",
        )
        .bind(&cursor)
        .bind(&cursor)
        .bind(&user)
        .bind(&user)
        .bind(&query.upstream)
        .bind(&query.upstream)
        .bind(status)
        .bind(status)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        rows.iter().map(row_to_binding).collect()
    }
}
