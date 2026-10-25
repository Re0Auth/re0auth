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
        // The tier is forced rather than taken from the record: this port is the
        // telemetry path (ADR-0025), and letting a caller write a security fact
        // through the lossy path would be exactly the mistake it exists to prevent.
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
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn purge_tier_before(&self, tier: AuditTier, before: Unix) -> RepoResult<u64> {
        let result = sqlx::query("DELETE FROM audit_logs WHERE tier = ? AND occurred_at <= ?")
            .bind(tier.as_str())
            .bind(before)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected())
    }

    async fn query(
        &self,
        filter: &AuditFilter,
        before: Option<&AuditId>,
        limit: u32,
    ) -> RepoResult<Vec<AuditRecord>> {
        // Read-only by contract (HR-04): this method has no write path.
        let cursor = before.map(|id| id.0.to_string());
        let actor = filter.actor.map(|id| id.0.to_string());
        let client = filter.client.map(|id| id.0.to_string());
        let action = filter.action.map(AuditAction::as_str);
        let tier = filter.tier.map(AuditTier::as_str);
        let rows = sqlx::query(
            "SELECT id, occurred_at, actor_user_id, client_id, action, target, outcome, \
             request_id, severity, detail_json, tier FROM audit_logs \
             WHERE (? IS NULL OR id < ?) \
               AND (? IS NULL OR actor_user_id = ?) \
               AND (? IS NULL OR client_id = ?) \
               AND (? IS NULL OR action = ?) \
               AND (? IS NULL OR tier = ?) \
               AND (? IS NULL OR occurred_at >= ?) \
               AND (? IS NULL OR occurred_at <= ?) \
             ORDER BY id DESC LIMIT ?",
        )
        .bind(&cursor)
        .bind(&cursor)
        .bind(&actor)
        .bind(&actor)
        .bind(&client)
        .bind(&client)
        .bind(action)
        .bind(action)
        .bind(tier)
        .bind(tier)
        .bind(filter.from)
        .bind(filter.from)
        .bind(filter.to)
        .bind(filter.to)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        rows.iter().map(row_to_audit).collect()
    }
}
