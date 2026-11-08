//! User and identity rows.
//!
//! Split out of `storage.rs` to stay inside the per-file line budget; the same
//! contract suite covers both halves.

use async_trait::async_trait;
use re0auth_api::audit::SecurityFact;
use re0auth_api::ports::{Identity, RepoError, RepoResult, User, UserRepo, UserRole, UserStatus};
use re0auth_api::{IdentityId, Unix, UserId};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;

use super::audit::record_fact;
use super::{SqliteStore, db_error, parse_uuid};

fn role_to_str(role: UserRole) -> &'static str {
    match role {
        UserRole::User => "user",
        UserRole::Admin => "admin",
    }
}

pub(super) fn role_from_str(value: &str) -> RepoResult<UserRole> {
    match value {
        "user" => Ok(UserRole::User),
        "admin" => Ok(UserRole::Admin),
        other => Err(RepoError::Backend(format!("unknown user role: {other}"))),
    }
}

fn user_status_to_str(status: UserStatus) -> &'static str {
    match status {
        UserStatus::Active => "active",
        UserStatus::Banned => "banned",
    }
}

fn user_status_from_str(value: &str) -> RepoResult<UserStatus> {
    UserStatus::parse(value)
        .ok_or_else(|| RepoError::Backend(format!("unknown user status: {value}")))
}

fn row_to_user(row: &SqliteRow) -> RepoResult<User> {
    Ok(User {
        id: UserId(parse_uuid(
            &row.try_get::<String, _>("id").map_err(db_error)?,
        )?),
        display_name: row.try_get("display_name").map_err(db_error)?,
        role: role_from_str(&row.try_get::<String, _>("role").map_err(db_error)?)?,
        status: user_status_from_str(&row.try_get::<String, _>("status").map_err(db_error)?)?,
        created_at: row.try_get("created_at").map_err(db_error)?,
        updated_at: row.try_get("updated_at").map_err(db_error)?,
    })
}

fn row_to_identity(row: &SqliteRow) -> RepoResult<Identity> {
    Ok(Identity {
        id: IdentityId(parse_uuid(
            &row.try_get::<String, _>("id").map_err(db_error)?,
        )?),
        user_id: UserId(parse_uuid(
            &row.try_get::<String, _>("user_id").map_err(db_error)?,
        )?),
        issuer: row.try_get("issuer").map_err(db_error)?,
        subject: row.try_get("subject").map_err(db_error)?,
        created_at: row.try_get("created_at").map_err(db_error)?,
    })
}

#[async_trait]
impl UserRepo for SqliteStore {
    async fn create(&self, user: &User) -> RepoResult<()> {
        sqlx::query(
            "INSERT INTO users (id, display_name, role, status, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(user.id.0.to_string())
        .bind(&user.display_name)
        .bind(role_to_str(user.role))
        .bind(user_status_to_str(user.status))
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn get(&self, id: &UserId) -> RepoResult<Option<User>> {
        let row = sqlx::query(
            "SELECT id, display_name, role, status, created_at, updated_at FROM users WHERE id = ?",
        )
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        row.as_ref().map(row_to_user).transpose()
    }

    async fn link_identity(&self, identity: &Identity) -> RepoResult<()> {
        sqlx::query(
            "INSERT INTO identities (id, user_id, issuer, subject, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(identity.id.0.to_string())
        .bind(identity.user_id.0.to_string())
        .bind(&identity.issuer)
        .bind(&identity.subject)
        .bind(identity.created_at)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn list_identities(&self, user: &UserId) -> RepoResult<Vec<Identity>> {
        let rows = sqlx::query(
            "SELECT id, user_id, issuer, subject, created_at FROM identities \
             WHERE user_id = ? ORDER BY created_at, id",
        )
        .bind(user.0.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        rows.iter().map(row_to_identity).collect()
    }

    async fn unlink_identity(
        &self,
        user: &UserId,
        issuer: &str,
        subject: &str,
    ) -> RepoResult<bool> {
        let result =
            sqlx::query("DELETE FROM identities WHERE user_id = ? AND issuer = ? AND subject = ?")
                .bind(user.0.to_string())
                .bind(issuer)
                .bind(subject)
                .execute(&self.pool)
                .await
                .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn find_by_identity(&self, issuer: &str, subject: &str) -> RepoResult<Option<User>> {
        let row = sqlx::query(
            "SELECT u.id, u.display_name, u.role, u.status, u.created_at, u.updated_at \
             FROM users u JOIN identities i ON i.user_id = u.id \
             WHERE i.issuer = ? AND i.subject = ?",
        )
        .bind(issuer)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        row.as_ref().map(row_to_user).transpose()
    }

    async fn delete(&self, id: &UserId) -> RepoResult<bool> {
        let result = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id.0.to_string())
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list(&self, before: Option<&UserId>, limit: u32) -> RepoResult<Vec<User>> {
        let cursor = before.map(|id| id.0.to_string());
        let rows = sqlx::query(
            "SELECT id, display_name, role, status, created_at, updated_at FROM users \
             WHERE (? IS NULL OR id < ?) ORDER BY id DESC LIMIT ?",
        )
        .bind(&cursor)
        .bind(&cursor)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        rows.iter().map(row_to_user).collect()
    }

    async fn set_role(
        &self,
        id: &UserId,
        role: UserRole,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let result = sqlx::query("UPDATE users SET role = ?, updated_at = ? WHERE id = ?")
            .bind(role_to_str(role))
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

    async fn set_status(
        &self,
        id: &UserId,
        status: UserStatus,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let result = sqlx::query("UPDATE users SET status = ?, updated_at = ? WHERE id = ?")
            .bind(user_status_to_str(status))
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

    async fn count_admins(&self) -> RepoResult<u64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM users WHERE role = ?")
            .bind(role_to_str(UserRole::Admin))
            .fetch_one(&self.pool)
            .await
            .map_err(db_error)?;
        let count: i64 = row.try_get("n").map_err(db_error)?;
        Ok(u64::try_from(count).unwrap_or(0))
    }
}
