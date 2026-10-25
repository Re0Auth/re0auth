use async_trait::async_trait;
use re0auth_api::Unix;
use re0auth_api::ports::{DeviceAttemptRepo, RepoResult};
use sqlx::Row;

use super::{SqliteStore, db_error};

const WINDOW: i64 = 900;

#[async_trait]
impl DeviceAttemptRepo for SqliteStore {
    async fn misses(&self, client_ip: &str, user_code_hash: &[u8], now: Unix) -> RepoResult<u32> {
        let row = sqlx::query(
            "SELECT misses, last_miss_at FROM device_attempts \
             WHERE ip = ? AND user_code_hash = ?",
        )
        .bind(client_ip)
        .bind(user_code_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;

        let Some(row) = row else {
            return Ok(0);
        };
        let misses: i64 = row.try_get("misses").map_err(db_error)?;
        let last_miss_at: i64 = row.try_get("last_miss_at").map_err(db_error)?;
        if last_miss_at <= now - WINDOW {
            Ok(0)
        } else {
            Ok(misses as u32)
        }
    }

    async fn record_miss(
        &self,
        client_ip: &str,
        user_code_hash: &[u8],
        now: Unix,
    ) -> RepoResult<u32> {
        let row = sqlx::query(
            "INSERT INTO device_attempts (ip, user_code_hash, misses, last_miss_at) \
             VALUES (?, ?, 1, ?) \
             ON CONFLICT(ip, user_code_hash) DO UPDATE SET \
               misses = CASE WHEN device_attempts.last_miss_at <= ? THEN 1 \
                             ELSE device_attempts.misses + 1 END, \
               last_miss_at = excluded.last_miss_at \
             RETURNING misses",
        )
        .bind(client_ip)
        .bind(user_code_hash)
        .bind(now)
        .bind(now - WINDOW)
        .fetch_one(&self.pool)
        .await
        .map_err(db_error)?;
        let misses: i64 = row.try_get("misses").map_err(db_error)?;
        Ok(misses as u32)
    }

    async fn clear(&self, client_ip: &str, user_code_hash: &[u8]) -> RepoResult<()> {
        sqlx::query("DELETE FROM device_attempts WHERE ip = ? AND user_code_hash = ?")
            .bind(client_ip)
            .bind(user_code_hash)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let result = sqlx::query("DELETE FROM device_attempts WHERE last_miss_at <= ?")
            .bind(before)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected())
    }
}
