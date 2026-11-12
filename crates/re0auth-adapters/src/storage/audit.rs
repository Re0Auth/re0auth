//! Audit log persistence.
//!
//! Two write paths share one encoding:
//!
//! - `record_fact` runs on a transaction owned by the caller, so a security
//!   fact lands or rolls back together with the state change it describes
//!   (INV-AUDIT-01).
//! - `AuditRepo::append` is the standalone path for events that have no
//!   surrounding transaction.

use async_trait::async_trait;
use re0auth_api::audit::{
    AuditAction, AuditOutcome, AuditRecord, AuditTier, SecurityFact, Severity,
};
use re0auth_api::ports::{AuditFilter, AuditRepo, RepoError, RepoResult};
use re0auth_api::{AuditId, ClientId, Unix, UserId};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;

use super::{SqliteStore, db_error, parse_uuid};

/// Writes one security fact on the given transaction.
pub(super) async fn record_fact(
    tx: &mut sqlx::SqliteConnection,
    fact: &SecurityFact,
) -> RepoResult<()> {
    sqlx::query(
        "INSERT INTO audit_logs \
         (id, occurred_at, actor_user_id, client_id, action, target, outcome, request_id, \
          severity, detail_json, tier) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', 'fact')",
    )
    .bind(fact.id.0.to_string())
    .bind(fact.occurred_at)
    .bind(fact.actor_user_id.map(|id| id.0.to_string()))
    .bind(fact.client_id.map(|id| id.0.to_string()))
    .bind(fact.action.as_str())
    .bind(&fact.target)
    .bind(fact.outcome.as_str())
    .bind(fact.request_id.as_deref())
    .bind(fact.severity.as_str())
    .execute(tx)
    .await
    .map_err(db_error)?;
    Ok(())
}

fn row_to_audit(row: &SqliteRow) -> RepoResult<AuditRecord> {
    let action = row.try_get::<String, _>("action").map_err(db_error)?;
    let outcome = row.try_get::<String, _>("outcome").map_err(db_error)?;
    let severity = row.try_get::<String, _>("severity").map_err(db_error)?;
    let tier = row.try_get::<String, _>("tier").map_err(db_error)?;
    Ok(AuditRecord {
        id: AuditId(parse_uuid(
            &row.try_get::<String, _>("id").map_err(db_error)?,
        )?),
        occurred_at: row.try_get("occurred_at").map_err(db_error)?,
        actor_user_id: row
            .try_get::<Option<String>, _>("actor_user_id")
            .map_err(db_error)?
            .map(|value| parse_uuid(&value).map(UserId))
            .transpose()?,
        client_id: row
            .try_get::<Option<String>, _>("client_id")
            .map_err(db_error)?
            .map(|value| parse_uuid(&value).map(ClientId))
            .transpose()?,
        action: AuditAction::parse(&action)
            .ok_or_else(|| RepoError::Backend(format!("unknown audit action {action}")))?,
        target: row.try_get("target").map_err(db_error)?,
        outcome: AuditOutcome::parse(&outcome)
            .ok_or_else(|| RepoError::Backend(format!("unknown audit outcome {outcome}")))?,
        severity: Severity::parse(&severity)
            .ok_or_else(|| RepoError::Backend(format!("unknown severity {severity}")))?,
        request_id: row.try_get("request_id").map_err(db_error)?,
        detail: row.try_get("detail_json").map_err(db_error)?,
        tier: AuditTier::parse(&tier)
            .ok_or_else(|| RepoError::Backend(format!("unknown audit tier {tier}")))?,
    })
}

async fn append_with_executor<'e, E>(record: &AuditRecord, executor: E) -> RepoResult<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query(
        "INSERT INTO audit_logs \
         (id, occurred_at, actor_user_id, client_id, action, target, outcome, request_id, \
          severity, detail_json, tier) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'telemetry')",
    )
    .bind(record.id.0.to_string())
    .bind(record.occurred_at)
    .bind(record.actor_user_id.map(|id| id.0.to_string()))
    .bind(record.client_id.map(|id| id.0.to_string()))
    .bind(record.action.as_str())
    .bind(&record.target)
    .bind(record.outcome.as_str())
    .bind(record.request_id.as_deref())
    .bind(record.severity.as_str())
    .bind(&record.detail)
    .execute(executor)
    .await
    .map_err(db_error)?;
    Ok(())
}

#[async_trait]
impl AuditRepo for SqliteStore {
    async fn recent(&self, limit: u32) -> RepoResult<Vec<AuditRecord>> {
        let rows = sqlx::query(
            "SELECT id, occurred_at, actor_user_id, client_id, action, target, outcome, \
             request_id, severity, detail_json, tier FROM audit_logs \
             ORDER BY occurred_at DESC, id DESC LIMIT ?",
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        rows.iter().map(row_to_audit).collect()
    }

    async fn count(&self) -> RepoResult<u64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM audit_logs")
            .fetch_one(&self.pool)
            .await
            .map_err(db_error)?;
        row.try_get::<i64, _>("n")
            .map(|value| value as u64)
            .map_err(db_error)
    }

    async fn by_actor(&self, user: &UserId, limit: u32) -> RepoResult<Vec<AuditRecord>> {
        let rows = sqlx::query(
            "SELECT id, occurred_at, actor_user_id, client_id, action, target, outcome, \
             request_id, severity, detail_json, tier FROM audit_logs \
             WHERE actor_user_id = ? ORDER BY occurred_at DESC, id DESC LIMIT ?",
        )
        .bind(user.0.to_string())
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        rows.iter().map(row_to_audit).collect()
    }

    async fn append(&self, record: &AuditRecord) -> RepoResult<()> {
        append_with_executor(record, &self.pool).await
    }

    async fn append_batch(&self, records: &[AuditRecord]) -> RepoResult<(u64, Vec<RepoError>)> {
        if records.is_empty() {
            return Ok((0, Vec::new()));
        }
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let mut appended = 0;
        let mut failures = Vec::new();
        for record in records {
            sqlx::query("SAVEPOINT telemetry_append")
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
            match append_with_executor(record, &mut *tx).await {
                Ok(()) => {
                    sqlx::query("RELEASE SAVEPOINT telemetry_append")
                        .execute(&mut *tx)
                        .await
                        .map_err(db_error)?;
                    appended += 1;
                }
                Err(error) => {
                    sqlx::query("ROLLBACK TO SAVEPOINT telemetry_append")
                        .execute(&mut *tx)
                        .await
                        .map_err(db_error)?;
                    sqlx::query("RELEASE SAVEPOINT telemetry_append")
                        .execute(&mut *tx)
                        .await
                        .map_err(db_error)?;
                    failures.push(error);
                }
            }
        }
        tx.commit().await.map_err(db_error)?;
        Ok((appended, failures))
    }

    async fn record_fact(&self, fact: &SecurityFact) -> RepoResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        record_fact(&mut tx, fact).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn purge_tier_before(&self, tier: AuditTier, before: Unix) -> RepoResult<u64> {
        const BATCH_SIZE: i64 = 500;
        let mut purged = 0;
        loop {
            let result = sqlx::query(
                "DELETE FROM audit_logs WHERE rowid IN (\
                 SELECT rowid FROM audit_logs WHERE tier = ? AND occurred_at <= ? LIMIT ?\
                 )",
            )
            .bind(tier.as_str())
            .bind(before)
            .bind(BATCH_SIZE)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
            let rows = result.rows_affected();
            purged += rows;
            if rows < BATCH_SIZE as u64 {
                return Ok(purged);
            }
        }
    }

    async fn query(
        &self,
        filter: &AuditFilter,
        before: Option<&AuditId>,
        limit: u32,
    ) -> RepoResult<Vec<AuditRecord>> {
        // Read-only by contract (HR-04): this method has no write path.
        //
        // Only the filters the caller supplied become predicates. The previous
        // `(? IS NULL OR col = ?)` shape made every plan a full scan because no
        // index can serve it. Fragments are static; values stay bound.
        let mut sql = String::from(
            "SELECT id, occurred_at, actor_user_id, client_id, action, target, outcome, \
             request_id, severity, detail_json, tier FROM audit_logs WHERE 1 = 1",
        );
        if before.is_some() {
            sql.push_str(" AND id < ?");
        }
        if filter.actor.is_some() {
            sql.push_str(" AND actor_user_id = ?");
        }
        if filter.client.is_some() {
            sql.push_str(" AND client_id = ?");
        }
        if filter.action.is_some() {
            sql.push_str(" AND action = ?");
        }
        if filter.tier.is_some() {
            sql.push_str(" AND tier = ?");
        }
        if filter.from.is_some() {
            sql.push_str(" AND occurred_at >= ?");
        }
        if filter.to.is_some() {
            sql.push_str(" AND occurred_at <= ?");
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");

        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
        if let Some(cursor) = before {
            query = query.bind(cursor.0.to_string());
        }
        if let Some(actor) = filter.actor {
            query = query.bind(actor.0.to_string());
        }
        if let Some(client) = filter.client {
            query = query.bind(client.0.to_string());
        }
        if let Some(action) = filter.action {
            query = query.bind(action.as_str());
        }
        if let Some(tier) = filter.tier {
            query = query.bind(tier.as_str());
        }
        if let Some(from) = filter.from {
            query = query.bind(from);
        }
        if let Some(to) = filter.to {
            query = query.bind(to);
        }
        let rows = query
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(db_error)?;
        rows.iter().map(row_to_audit).collect()
    }
}
