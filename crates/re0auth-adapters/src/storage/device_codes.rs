//! Device-code persistence.
//!
//! Polling is the only writer here that is driven by an untrusted caller, so
//! both the interval discipline (RFC 8628 `slow_down`) and the one-shot
//! consumption of an approved code are enforced in SQL rather than in the
//! handler.

use async_trait::async_trait;
use re0auth_api::ports::{
    DeviceCode, DeviceCodeRepo, DeviceCodeState, DeviceCodeStatus, DevicePoll, RepoError,
    RepoResult,
};
use re0auth_api::{ClientId, Unix, UserId};
use sqlx::Row;

use super::{SqliteStore, db_error, device_status_to_str, row_to_device_code, scopes_json};

/// Names the unique constraint an insert violated.
///
/// `db_error` cannot tell which column collided: SQLite reports one unique
/// violation per statement, with no field. So the label is recovered by asking
/// the table whether a row already holds this user code. That is a read only on
/// the error path, and a wrong answer cannot admit a duplicate — it can only
/// mislabel which row was refused.
async fn classify_insert_conflict(
    store: &SqliteStore,
    error: sqlx::Error,
    user_code_hash: &[u8],
) -> RepoError {
    let classified = db_error(error);
    if !matches!(classified, RepoError::Conflict(_)) {
        return classified;
    }
    match store.find_by_user_code_hash(user_code_hash).await {
        Ok(Some(_)) => RepoError::UserCodeConflict,
        // Neither the caller nor the operator can act on "some unique column
        // collided"; leave it as the generic conflict it is.
        Ok(None) => classified,
        // A failed lookup must never be reported as a collision: that is the
        // masquerade — an infrastructure fault read as an exhausted code space —
        // that `UserCodeConflict` exists to rule out.
        Err(error) => error,
    }
}

#[async_trait]
impl DeviceCodeRepo for SqliteStore {
    async fn insert(&self, code: &DeviceCode) -> RepoResult<()> {
        let inserted = sqlx::query(
            "INSERT INTO device_codes \
             (id, device_code_hash, user_code_hash, client_id, scopes, status, user_id, \
              interval_secs, last_polled_at, poll_count, user_code_misses, created_at, \
              expires_at, consumed_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(code.id.0.to_string())
        .bind(&code.device_code_hash)
        .bind(&code.user_code_hash)
        .bind(code.client_id.0.to_string())
        .bind(scopes_json(&code.scopes)?)
        .bind(device_status_to_str(code.state.status()))
        .bind(code.state.approver().map(|user| user.0.to_string()))
        .bind(i64::from(code.interval_secs))
        .bind(code.last_polled_at)
        .bind(i64::from(code.poll_count))
        .bind(i64::from(code.user_code_misses))
        .bind(code.created_at)
        .bind(code.expires_at)
        .bind(code.consumed_at)
        .execute(&self.pool)
        .await;

        match inserted {
            Ok(_) => Ok(()),
            Err(error) => Err(classify_insert_conflict(self, error, &code.user_code_hash).await),
        }
    }

    async fn find_by_device_hash(&self, hash: &[u8]) -> RepoResult<Option<DeviceCode>> {
        let row = sqlx::query(
            "SELECT id, device_code_hash, user_code_hash, client_id, scopes, status, user_id, \
             interval_secs, last_polled_at, poll_count, user_code_misses, created_at, expires_at, \
             consumed_at FROM device_codes WHERE device_code_hash = ?",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        row.as_ref().map(row_to_device_code).transpose()
    }

    async fn find_by_user_code_hash(&self, hash: &[u8]) -> RepoResult<Option<DeviceCode>> {
        let row = sqlx::query(
            "SELECT id, device_code_hash, user_code_hash, client_id, scopes, status, user_id, \
             interval_secs, last_polled_at, poll_count, user_code_misses, created_at, expires_at, \
             consumed_at FROM device_codes WHERE user_code_hash = ?",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        row.as_ref().map(row_to_device_code).transpose()
    }

    async fn approve(&self, user_code_hash: &[u8], user_id: UserId, now: Unix) -> RepoResult<()> {
        // Only a pending, unexpired code can be approved. Matching that in the
        // UPDATE means two people racing to approve the same user code produce
        // one success and one Conflict, not a silent overwrite of `user_id`.
        let result = sqlx::query(
            "UPDATE device_codes SET status = 'approved', user_id = ? \
             WHERE user_code_hash = ? AND status = 'pending' AND expires_at > ?",
        )
        .bind(user_id.0.to_string())
        .bind(user_code_hash)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        if result.rows_affected() == 1 {
            return Ok(());
        }
        let row =
            sqlx::query("SELECT status, expires_at FROM device_codes WHERE user_code_hash = ?")
                .bind(user_code_hash)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_error)?;
        let Some(row) = row else {
            return Err(RepoError::NotFound);
        };
        let expires_at: i64 = row.try_get("expires_at").map_err(db_error)?;
        if expires_at <= now {
            return Err(RepoError::Expired);
        }
        Err(RepoError::Conflict("device code is not pending"))
    }

    async fn deny(&self, user_code_hash: &[u8], now: Unix) -> RepoResult<()> {
        let result = sqlx::query(
            "UPDATE device_codes SET status = 'denied' \
             WHERE user_code_hash = ? AND status = 'pending' AND expires_at > ?",
        )
        .bind(user_code_hash)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        if result.rows_affected() == 1 {
            return Ok(());
        }
        let row =
            sqlx::query("SELECT status, expires_at FROM device_codes WHERE user_code_hash = ?")
                .bind(user_code_hash)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_error)?;
        let Some(row) = row else {
            return Err(RepoError::NotFound);
        };
        let expires_at: i64 = row.try_get("expires_at").map_err(db_error)?;
        if expires_at <= now {
            return Err(RepoError::Expired);
        }
        Err(RepoError::Conflict("device code is not pending"))
    }

    async fn revoke_approved_for_client(
        &self,
        user: &UserId,
        client: &ClientId,
    ) -> RepoResult<u64> {
        let result = sqlx::query(
            "UPDATE device_codes SET status = 'denied' \
             WHERE user_id = ? AND client_id = ? AND status = 'approved'",
        )
        .bind(user.0.to_string())
        .bind(client.0.to_string())
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected())
    }

    async fn poll(&self, device_code_hash: &[u8], now: Unix) -> RepoResult<DevicePoll> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(db_error)?;
        let row = sqlx::query(
            "SELECT id, device_code_hash, user_code_hash, client_id, scopes, status, user_id, \
             interval_secs, last_polled_at, poll_count, user_code_misses, created_at, expires_at, \
             consumed_at FROM device_codes WHERE device_code_hash = ?",
        )
        .bind(device_code_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some(row) = row else {
            return Ok(DevicePoll::NotFound);
        };
        let code = row_to_device_code(&row)?;

        if code.state.status() == DeviceCodeStatus::Consumed {
            return Ok(DevicePoll::Consumed);
        }
        if code.state.status() == DeviceCodeStatus::Denied {
            return Ok(DevicePoll::Denied);
        }
        if code.state.status() == DeviceCodeStatus::Expired || code.expires_at <= now {
            // Treat an unexpired status row past its deadline as expired: the
            // status column is only a cache, the timestamp is authoritative.
            return Ok(DevicePoll::Expired);
        }

        // The approver is in the variant, so there is no "approved but no
        // approver" branch to defend against: `from_columns` already refused
        // such a row when it was read.
        if let DeviceCodeState::Approved { approver: user_id } = code.state {
            let result = sqlx::query(
                "UPDATE device_codes SET status = 'consumed', consumed_at = ?, \
                 last_polled_at = ? WHERE device_code_hash = ? AND status = 'approved'",
            )
            .bind(now)
            .bind(now)
            .bind(device_code_hash)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
            tx.commit().await.map_err(db_error)?;
            if result.rows_affected() == 1 {
                return Ok(DevicePoll::Approved {
                    client_id: code.client_id,
                    user_id,
                    scopes: code.scopes,
                });
            }
            return Ok(DevicePoll::Consumed);
        }

        if let Some(last) = code.last_polled_at
            && now < last + i64::from(code.interval_secs)
        {
            // Polling faster than the advertised interval: RFC 8628 says raise the
            // interval by 5 seconds and keep refusing. The new interval persists,
            // so hammering the endpoint gets monotonically slower.
            let interval = code.interval_secs + 5;
            sqlx::query(
                "UPDATE device_codes SET interval_secs = ?, last_polled_at = ? \
                 WHERE device_code_hash = ?",
            )
            .bind(i64::from(interval))
            .bind(now)
            .bind(device_code_hash)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
            tx.commit().await.map_err(db_error)?;
            return Ok(DevicePoll::SlowDown {
                interval_secs: interval,
            });
        }

        sqlx::query(
            "UPDATE device_codes SET last_polled_at = ?, poll_count = poll_count + 1 \
             WHERE device_code_hash = ?",
        )
        .bind(now)
        .bind(device_code_hash)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        Ok(DevicePoll::Pending)
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let result = sqlx::query(
            "DELETE FROM device_codes WHERE expires_at <= ? \
             OR (consumed_at IS NOT NULL AND consumed_at <= ?)",
        )
        .bind(before)
        .bind(before)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected())
    }
}
