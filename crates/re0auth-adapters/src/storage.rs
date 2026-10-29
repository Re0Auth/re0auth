//! SQLite storage adapter.
//!
//! Every method here is a single transaction or a single statement. The
//! contract suite in `re0auth-contract` is the acceptance test.

use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use re0auth_api::audit::SecurityFact;
use re0auth_api::ports::{
    ApprovalDecision, ApprovalTicket, ApprovalTicketRepo, AuthCode, AuthCodeRepo, AuthGrant,
    Binding, BindingStatus, Client, ClientRepo, ClientStatus, ConsumeAuthCode, DeviceCode,
    DeviceCodeState, DeviceCodeStatus, Identity, LoginTransaction, LoginTransactionRepo,
    PendingBinding, PendingBindingRepo, RefreshToken, RefreshTokenRepo, RepoError, RepoResult,
    RotateOutcome, RotateRefreshToken, Session, SessionRepo, User, UserRepo, UserRole,
};
use re0auth_api::secret::ClientSecretHash;
use re0auth_api::{
    BindingId, ClientId, DeviceCodeId, FamilyId, RefreshTokenId, SessionId, Unix, UserId,
};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

mod access_tokens;
mod audit;
mod bindings;
mod connectors;
mod consent;
mod device_attempts;
mod device_codes;
mod registry;
mod signing_keys;

use audit::record_fact;

#[derive(Clone, Debug)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        // One reading of the URL, shared with the vault-collision guard: the
        // `sqlite:` grammar is sqlx's, and `contains(":memory:")` also matched a
        // file whose name happened to contain that text.
        let database_file = crate::sqlite_path::database_file_path(url);
        let memory = database_file.is_none();
        let mut options = SqliteConnectOptions::from_str(url)
            .with_context(|| format!("invalid SQLite URL: {url}"))?
            .foreign_keys(true)
            // 写事务很短，超过 5 秒的等待交给 503 重试
            .busy_timeout(Duration::from_secs(5));

        if memory {
            // An in-memory database is private to one connection; a second one
            // would see an empty schema, so the pool is pinned to a single slot.
            options = options.create_if_missing(false);
        } else {
            if let Some(parent) = database_file.as_deref().and_then(std::path::Path::parent)
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create SQLite directory {}", parent.display()))?;
            }
            // WAL keeps the housekeeping sweep from blocking request-path reads.
            options = options
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal);
        }

        let pool = SqlitePoolOptions::new()
            .max_connections(if memory { 1 } else { 5 })
            .min_connections(if memory { 1 } else { 0 })
            // Idle connections are kept: single-binary deployments are low
            // traffic, and reconnecting costs more than holding the handle.
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(options)
            .await
            .context("connect SQLite")?;

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("run SQLite migrations")?;

        Ok(Self { pool })
    }

    /// Drains the connection pool and rejects further queries.
    ///
    /// Used on shutdown, and by tests that need to observe how the app behaves
    /// when the backend is gone.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

fn parse_uuid(value: &str) -> RepoResult<Uuid> {
    Uuid::parse_str(value).map_err(|error| RepoError::Backend(format!("invalid UUID: {error}")))
}

fn db_error(error: sqlx::Error) -> RepoError {
    if let sqlx::Error::Database(database) = &error
        && let Some(code) = database.code()
        && let Some(mapped) = sqlite_code_error(code.as_ref())
    {
        return mapped;
    }
    RepoError::Backend(error.to_string())
}

fn sqlite_code_error(code: &str) -> Option<RepoError> {
    match code {
        "1555" | "2067" => Some(RepoError::Conflict("unique constraint")),
        "787" => Some(RepoError::NotFound),
        "5" | "6" | "517" => Some(RepoError::Busy),
        _ => None,
    }
}

fn scopes_json(scopes: &[String]) -> RepoResult<String> {
    serde_json::to_string(scopes).map_err(|error| RepoError::Backend(error.to_string()))
}

fn scopes_from_json(value: &str) -> RepoResult<Vec<String>> {
    serde_json::from_str(value).map_err(|error| RepoError::Backend(error.to_string()))
}

fn role_to_str(role: UserRole) -> &'static str {
    match role {
        UserRole::User => "user",
        UserRole::Admin => "admin",
    }
}

fn role_from_str(value: &str) -> RepoResult<UserRole> {
    match value {
        "user" => Ok(UserRole::User),
        "admin" => Ok(UserRole::Admin),
        other => Err(RepoError::Backend(format!("unknown user role: {other}"))),
    }
}

fn status_to_str(status: BindingStatus) -> &'static str {
    match status {
        BindingStatus::Pending => "pending",
        BindingStatus::Active => "active",
        BindingStatus::NeedsReauth => "needs_reauth",
        BindingStatus::Revoked => "revoked",
        BindingStatus::Expired => "expired",
    }
}

fn device_status_to_str(status: DeviceCodeStatus) -> &'static str {
    match status {
        DeviceCodeStatus::Pending => "pending",
        DeviceCodeStatus::Approved => "approved",
        DeviceCodeStatus::Denied => "denied",
        DeviceCodeStatus::Consumed => "consumed",
        DeviceCodeStatus::Expired => "expired",
    }
}

fn device_status_from_str(value: &str) -> RepoResult<DeviceCodeStatus> {
    match value {
        "pending" => Ok(DeviceCodeStatus::Pending),
        "approved" => Ok(DeviceCodeStatus::Approved),
        "denied" => Ok(DeviceCodeStatus::Denied),
        "consumed" => Ok(DeviceCodeStatus::Consumed),
        "expired" => Ok(DeviceCodeStatus::Expired),
        other => Err(RepoError::Backend(format!(
            "unknown device code status: {other}"
        ))),
    }
}

fn client_status_to_str(status: ClientStatus) -> &'static str {
    match status {
        ClientStatus::Pending => "pending",
        ClientStatus::Approved => "approved",
        ClientStatus::Suspended => "suspended",
        ClientStatus::Revoked => "revoked",
    }
}

fn client_status_from_str(value: &str) -> RepoResult<ClientStatus> {
    match value {
        "pending" => Ok(ClientStatus::Pending),
        "approved" => Ok(ClientStatus::Approved),
        "suspended" => Ok(ClientStatus::Suspended),
        "revoked" => Ok(ClientStatus::Revoked),
        other => Err(RepoError::Backend(format!(
            "unknown client status: {other}"
        ))),
    }
}

fn status_from_str(value: &str) -> RepoResult<BindingStatus> {
    match value {
        "pending" => Ok(BindingStatus::Pending),
        "active" => Ok(BindingStatus::Active),
        "needs_reauth" => Ok(BindingStatus::NeedsReauth),
        "revoked" => Ok(BindingStatus::Revoked),
        "expired" => Ok(BindingStatus::Expired),
        other => Err(RepoError::Backend(format!(
            "unknown binding status: {other}"
        ))),
    }
}

fn row_to_user(row: &SqliteRow) -> RepoResult<User> {
    Ok(User {
        id: UserId(parse_uuid(
            &row.try_get::<String, _>("id").map_err(db_error)?,
        )?),
        display_name: row.try_get("display_name").map_err(db_error)?,
        role: role_from_str(&row.try_get::<String, _>("role").map_err(db_error)?)?,
        created_at: row.try_get("created_at").map_err(db_error)?,
        updated_at: row.try_get("updated_at").map_err(db_error)?,
    })
}

fn row_to_session(row: &SqliteRow) -> RepoResult<Session> {
    Ok(Session {
        id: SessionId(parse_uuid(
            &row.try_get::<String, _>("id").map_err(db_error)?,
        )?),
        id_hash: row.try_get("id_hash").map_err(db_error)?,
        user_id: UserId(parse_uuid(
            &row.try_get::<String, _>("user_id").map_err(db_error)?,
        )?),
        csrf_hash: row.try_get("csrf_hash").map_err(db_error)?,
        created_at: row.try_get("created_at").map_err(db_error)?,
        last_seen_at: row.try_get("last_seen_at").map_err(db_error)?,
        idle_expires_at: row.try_get("idle_expires_at").map_err(db_error)?,
        absolute_expires_at: row.try_get("absolute_expires_at").map_err(db_error)?,
        revoked_at: row.try_get("revoked_at").map_err(db_error)?,
    })
}

fn row_to_login_transaction(row: &SqliteRow) -> RepoResult<LoginTransaction> {
    Ok(LoginTransaction {
        state_hash: row.try_get("state_hash").map_err(db_error)?,
        nonce: row.try_get("nonce").map_err(db_error)?,
        pkce_verifier: row.try_get("pkce_verifier").map_err(db_error)?,
        return_to: row.try_get("return_to").map_err(db_error)?,
        provider: row.try_get("provider").map_err(db_error)?,
        created_at: row.try_get("created_at").map_err(db_error)?,
        expires_at: row.try_get("expires_at").map_err(db_error)?,
        consumed_at: row.try_get("consumed_at").map_err(db_error)?,
    })
}

fn row_to_pending_binding(row: &SqliteRow) -> RepoResult<PendingBinding> {
    Ok(PendingBinding {
        state_hash: row.try_get("state_hash").map_err(db_error)?,
        user_id: UserId(parse_uuid(
            &row.try_get::<String, _>("user_id").map_err(db_error)?,
        )?),
        upstream_id: row.try_get("upstream_id").map_err(db_error)?,
        pkce_verifier: row.try_get("pkce_verifier").map_err(db_error)?,
        return_to: row.try_get("return_to").map_err(db_error)?,
        created_at: row.try_get("created_at").map_err(db_error)?,
        expires_at: row.try_get("expires_at").map_err(db_error)?,
        consumed_at: row.try_get("consumed_at").map_err(db_error)?,
    })
}

fn row_to_approval_ticket(row: &SqliteRow) -> RepoResult<ApprovalTicket> {
    Ok(ApprovalTicket {
        jti: row.try_get("jti").map_err(db_error)?,
        user_id: UserId(parse_uuid(
            &row.try_get::<String, _>("user_id").map_err(db_error)?,
        )?),
        user_code: row.try_get("user_code").map_err(db_error)?,
        expires_at: row.try_get("expires_at").map_err(db_error)?,
        consumed_at: row.try_get("consumed_at").map_err(db_error)?,
    })
}

fn row_to_device_code(row: &SqliteRow) -> RepoResult<DeviceCode> {
    let approver = row
        .try_get::<Option<String>, _>("user_id")
        .map_err(db_error)?
        .map(|value| parse_uuid(&value).map(UserId))
        .transpose()?;
    let status = device_status_from_str(&row.try_get::<String, _>("status").map_err(db_error)?)?;
    Ok(DeviceCode {
        id: DeviceCodeId(parse_uuid(
            &row.try_get::<String, _>("id").map_err(db_error)?,
        )?),
        device_code_hash: row.try_get("device_code_hash").map_err(db_error)?,
        user_code_hash: row.try_get("user_code_hash").map_err(db_error)?,
        client_id: ClientId(parse_uuid(
            &row.try_get::<String, _>("client_id").map_err(db_error)?,
        )?),
        scopes: scopes_from_json(&row.try_get::<String, _>("scopes").map_err(db_error)?)?,
        state: DeviceCodeState::from_columns(status, approver)?,
        interval_secs: row.try_get("interval_secs").map_err(db_error)?,
        last_polled_at: row.try_get("last_polled_at").map_err(db_error)?,
        poll_count: row.try_get("poll_count").map_err(db_error)?,
        user_code_misses: row.try_get("user_code_misses").map_err(db_error)?,
        created_at: row.try_get("created_at").map_err(db_error)?,
        expires_at: row.try_get("expires_at").map_err(db_error)?,
        consumed_at: row.try_get("consumed_at").map_err(db_error)?,
    })
}

fn row_to_client(row: &SqliteRow) -> RepoResult<Client> {
    Ok(Client {
        id: ClientId(parse_uuid(
            &row.try_get::<String, _>("id").map_err(db_error)?,
        )?),
        name: row.try_get("name").map_err(db_error)?,
        redirect_uris: scopes_from_json(
            &row.try_get::<String, _>("redirect_uris")
                .map_err(db_error)?,
        )?,
        allowed_scopes: scopes_from_json(
            &row.try_get::<String, _>("allowed_scopes")
                .map_err(db_error)?,
        )?,
        raw_access: row.try_get::<i64, _>("raw_access").map_err(db_error)? != 0,
        status: client_status_from_str(&row.try_get::<String, _>("status").map_err(db_error)?)?,
        secret_hash: match row
            .try_get::<Option<Vec<u8>>, _>("secret_hash")
            .map_err(db_error)?
        {
            Some(digest) => Some(
                ClientSecretHash::new(
                    u32::try_from(
                        row.try_get::<Option<i64>, _>("secret_key_version")
                            .map_err(db_error)?
                            .unwrap_or(0),
                    )
                    .unwrap_or(0),
                    digest,
                )
                .map_err(|error| RepoError::Backend(error.to_string()))?,
            ),
            None => None,
        },
        created_at: row.try_get("created_at").map_err(db_error)?,
        updated_at: row.try_get("updated_at").map_err(db_error)?,
    })
}

fn row_to_refresh_token(row: &SqliteRow) -> RepoResult<RefreshToken> {
    let replaced_by = row
        .try_get::<Option<String>, _>("replaced_by")
        .map_err(db_error)?
        .map(|value| parse_uuid(&value).map(RefreshTokenId))
        .transpose()?;
    Ok(RefreshToken {
        id: RefreshTokenId(parse_uuid(
            &row.try_get::<String, _>("id").map_err(db_error)?,
        )?),
        token_hash: row.try_get("token_hash").map_err(db_error)?,
        family_id: FamilyId(parse_uuid(
            &row.try_get::<String, _>("family_id").map_err(db_error)?,
        )?),
        client_id: ClientId(parse_uuid(
            &row.try_get::<String, _>("client_id").map_err(db_error)?,
        )?),
        user_id: UserId(parse_uuid(
            &row.try_get::<String, _>("user_id").map_err(db_error)?,
        )?),
        scopes: scopes_from_json(&row.try_get::<String, _>("scopes").map_err(db_error)?)?,
        created_at: row.try_get("created_at").map_err(db_error)?,
        expires_at: row.try_get("expires_at").map_err(db_error)?,
        consumed_at: row.try_get("consumed_at").map_err(db_error)?,
        revoked_at: row.try_get("revoked_at").map_err(db_error)?,
        replaced_by,
    })
}

fn row_to_binding(row: &SqliteRow) -> RepoResult<Binding> {
    Ok(Binding {
        id: BindingId(parse_uuid(
            &row.try_get::<String, _>("id").map_err(db_error)?,
        )?),
        user_id: UserId(parse_uuid(
            &row.try_get::<String, _>("user_id").map_err(db_error)?,
        )?),
        upstream_id: row.try_get("upstream_id").map_err(db_error)?,
        upstream_user_id: row.try_get("upstream_user_id").map_err(db_error)?,
        status: status_from_str(&row.try_get::<String, _>("status").map_err(db_error)?)?,
        created_at: row.try_get("created_at").map_err(db_error)?,
        updated_at: row.try_get("updated_at").map_err(db_error)?,
        last_refreshed_at: row.try_get("last_refreshed_at").map_err(db_error)?,
        last_error_code: row.try_get("last_error_code").map_err(db_error)?,
    })
}

#[async_trait]
impl UserRepo for SqliteStore {
    async fn create(&self, user: &User) -> RepoResult<()> {
        sqlx::query(
            "INSERT INTO users (id, display_name, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(user.id.0.to_string())
        .bind(&user.display_name)
        .bind(role_to_str(user.role))
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn get(&self, id: &UserId) -> RepoResult<Option<User>> {
        let row = sqlx::query(
            "SELECT id, display_name, role, created_at, updated_at FROM users WHERE id = ?",
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

    async fn find_by_identity(&self, issuer: &str, subject: &str) -> RepoResult<Option<User>> {
        let row = sqlx::query(
            "SELECT u.id, u.display_name, u.role, u.created_at, u.updated_at \
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
            "SELECT id, display_name, role, created_at, updated_at FROM users \
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

#[async_trait]
impl SessionRepo for SqliteStore {
    async fn create(&self, session: &Session) -> RepoResult<()> {
        sqlx::query(
            "INSERT INTO sessions \
             (id, id_hash, user_id, csrf_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(session.id.0.to_string())
        .bind(session.id_hash.as_slice())
        .bind(session.user_id.0.to_string())
        .bind(session.csrf_hash.as_slice())
        .bind(session.created_at)
        .bind(session.last_seen_at)
        .bind(session.idle_expires_at)
        .bind(session.absolute_expires_at)
        .bind(session.revoked_at)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn find_active(&self, id_hash: &[u8], now: Unix) -> RepoResult<Option<Session>> {
        let row = sqlx::query(
            "SELECT id, id_hash, user_id, csrf_hash, created_at, last_seen_at, \
             idle_expires_at, absolute_expires_at, revoked_at \
             FROM sessions WHERE id_hash = ? AND revoked_at IS NULL \
             AND idle_expires_at > ? AND absolute_expires_at > ?",
        )
        .bind(id_hash)
        .bind(now)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        row.as_ref().map(row_to_session).transpose()
    }

    async fn touch(&self, id_hash: &[u8], now: Unix, idle_expires_at: Unix) -> RepoResult<()> {
        let result = sqlx::query(
            "UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? \
             WHERE id_hash = ? AND revoked_at IS NULL \
             AND idle_expires_at > ? AND absolute_expires_at > ?",
        )
        .bind(now)
        .bind(idle_expires_at)
        .bind(id_hash)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        if result.rows_affected() > 0 {
            return Ok(());
        }
        // The update matched nothing. Re-read to tell a revoked session from a
        // missing one, because only the former tells the caller to stop using
        // the cookie. An expired session reports NotFound on purpose: whether
        // the row still exists is not the caller's business.
        let row = sqlx::query("SELECT revoked_at FROM sessions WHERE id_hash = ?")
            .bind(id_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?;
        match row {
            None => Err(RepoError::NotFound),
            Some(row) => {
                let revoked_at: Option<i64> = row.try_get("revoked_at").map_err(db_error)?;
                if revoked_at.is_some() {
                    Err(RepoError::Revoked)
                } else {
                    Err(RepoError::NotFound)
                }
            }
        }
    }

    async fn revoke(&self, id_hash: &[u8], now: Unix) -> RepoResult<()> {
        // COALESCE keeps the first revocation time: a second logout of the same
        // session must not move the timestamp that audit and expiry depend on.
        let result = sqlx::query(
            "UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE id_hash = ?",
        )
        .bind(now)
        .bind(id_hash)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        if result.rows_affected() == 0 {
            return Err(RepoError::NotFound);
        }
        Ok(())
    }

    async fn revoke_all(&self, user: &UserId, now: Unix) -> RepoResult<u64> {
        let result = sqlx::query(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(user.0.to_string())
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected())
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        // `before` bounds revoked rows only. Rows whose own expiry has passed
        // are deleted regardless of retention: keeping them serves nobody, and
        // a caller must never be able to widen the window by passing an old
        // timestamp.
        let result = sqlx::query(
            "DELETE FROM sessions WHERE idle_expires_at <= ? OR absolute_expires_at <= ? \
             OR (revoked_at IS NOT NULL AND revoked_at <= ?)",
        )
        .bind(before)
        .bind(before)
        .bind(before)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected())
    }
}

#[async_trait]
impl AuthCodeRepo for SqliteStore {
    async fn insert(&self, code: &AuthCode, fact: &SecurityFact) -> RepoResult<()> {
        // INV-AUDIT-01: the code and its audit fact land together or not at all.
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        sqlx::query(
            "INSERT INTO auth_codes \
             (id, code_hash, client_id, user_id, redirect_uri, scopes, code_challenge, \
              code_challenge_method, nonce, created_at, expires_at, consumed_at, family_id) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(code.id.0.to_string())
        .bind(code.code_hash.as_slice())
        .bind(code.client_id.0.to_string())
        .bind(code.user_id.0.to_string())
        .bind(&code.redirect_uri)
        .bind(scopes_json(&code.scopes)?)
        .bind(code.code_challenge.as_deref())
        .bind(code.code_challenge_method.as_deref())
        .bind(code.nonce.as_deref())
        .bind(code.created_at)
        .bind(code.expires_at)
        .bind(code.consumed_at)
        .bind(code.family_id.map(|family| family.0.to_string()))
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        record_fact(&mut tx, fact).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn consume(&self, req: ConsumeAuthCode<'_>, now: Unix) -> RepoResult<AuthGrant> {
        // The UPDATE is the whole check: matching on the challenge with `IS ?`
        // rather than `=` makes a NULL challenge match a NULL column, so a code
        // issued without PKCE cannot be redeemed with one (and vice versa). The
        // row only disappears under RETURNING if every binding still holds,
        // which is what makes concurrent redemption have exactly one winner.
        let row = sqlx::query(
            "UPDATE auth_codes SET consumed_at = ?, family_id = ? \
             WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > ? \
             AND client_id = ? AND redirect_uri = ? \
             AND code_challenge IS ? AND code_challenge_method IS ? \
             RETURNING user_id, client_id, redirect_uri, scopes, nonce",
        )
        .bind(now)
        .bind(req.family_id.0.to_string())
        .bind(req.code_hash)
        .bind(now)
        .bind(req.client_id.0.to_string())
        .bind(req.redirect_uri)
        .bind(req.code_challenge)
        .bind(req.code_challenge_method)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;

        if let Some(row) = row {
            return Ok(AuthGrant {
                user_id: UserId(parse_uuid(
                    &row.try_get::<String, _>("user_id").map_err(db_error)?,
                )?),
                client_id: ClientId(parse_uuid(
                    &row.try_get::<String, _>("client_id").map_err(db_error)?,
                )?),
                redirect_uri: row.try_get("redirect_uri").map_err(db_error)?,
                scopes: scopes_from_json(&row.try_get::<String, _>("scopes").map_err(db_error)?)?,
                nonce: row.try_get("nonce").map_err(db_error)?,
            });
        }

        let existing =
            sqlx::query("SELECT consumed_at, expires_at FROM auth_codes WHERE code_hash = ?")
                .bind(req.code_hash)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_error)?;
        let Some(existing) = existing else {
            return Err(RepoError::NotFound);
        };
        let consumed_at: Option<i64> = existing.try_get("consumed_at").map_err(db_error)?;
        let expires_at: i64 = existing.try_get("expires_at").map_err(db_error)?;
        if consumed_at.is_some() {
            Err(RepoError::AlreadyConsumed)
        } else if expires_at <= now {
            Err(RepoError::Expired)
        } else {
            Err(RepoError::NotFound)
        }
    }

    async fn family_of(&self, code_hash: &[u8]) -> RepoResult<Option<FamilyId>> {
        let row = sqlx::query("SELECT family_id FROM auth_codes WHERE code_hash = ?")
            .bind(code_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let raw: Option<String> = row.try_get("family_id").map_err(db_error)?;
        raw.map(|value| parse_uuid(&value).map(FamilyId))
            .transpose()
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let result = sqlx::query(
            "DELETE FROM auth_codes WHERE expires_at <= ? \
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

#[async_trait]
impl RefreshTokenRepo for SqliteStore {
    async fn insert(&self, token: &RefreshToken) -> RepoResult<()> {
        sqlx::query(
            "INSERT INTO refresh_tokens \
             (id, token_hash, family_id, client_id, user_id, scopes, created_at, expires_at, \
              consumed_at, revoked_at, replaced_by) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(token.id.0.to_string())
        .bind(token.token_hash.as_slice())
        .bind(token.family_id.0.to_string())
        .bind(token.client_id.0.to_string())
        .bind(token.user_id.0.to_string())
        .bind(scopes_json(&token.scopes)?)
        .bind(token.created_at)
        .bind(token.expires_at)
        .bind(token.consumed_at)
        .bind(token.revoked_at)
        .bind(token.replaced_by.map(|id| id.0.to_string()))
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn find(&self, token_hash: &[u8]) -> RepoResult<Option<RefreshToken>> {
        let row = sqlx::query(
            "SELECT id, token_hash, family_id, client_id, user_id, scopes, created_at, \
             expires_at, consumed_at, revoked_at, replaced_by \
             FROM refresh_tokens WHERE token_hash = ?",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        row.as_ref().map(row_to_refresh_token).transpose()
    }

    async fn rotate(
        &self,
        req: RotateRefreshToken<'_>,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<RotateOutcome> {
        let RotateRefreshToken { old_hash, new } = req;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(db_error)?;

        let row = sqlx::query(
            "SELECT id, token_hash, family_id, client_id, user_id, scopes, created_at, \
             expires_at, consumed_at, revoked_at, replaced_by \
             FROM refresh_tokens WHERE token_hash = ?",
        )
        .bind(old_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some(row) = row else {
            return Ok(RotateOutcome::NotFound);
        };
        let old = row_to_refresh_token(&row)?;

        if old.revoked_at.is_some() {
            return Ok(RotateOutcome::Revoked);
        }
        if old.expires_at <= now {
            return Ok(RotateOutcome::Expired);
        }
        if old.consumed_at.is_some() {
            // Already rotated once: presenting it again means the token leaked.
            // Revoke the whole family rather than just this row, because the
            // attacker and the legitimate client now both hold valid descendants.
            let result = sqlx::query(
                "UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(old.family_id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
            record_fact(&mut tx, &fact.as_reuse()).await?;
            tx.commit().await.map_err(db_error)?;
            return Ok(RotateOutcome::ReuseDetected {
                family_revoked: result.rows_affected(),
            });
        }

        if old.user_id != new.user_id
            || old.client_id != new.client_id
            || old.family_id != new.family_id
        {
            return Err(RepoError::Conflict("refresh token identity"));
        }

        let updated = sqlx::query(
            "UPDATE refresh_tokens SET consumed_at = ?, replaced_by = ? \
             WHERE token_hash = ? AND consumed_at IS NULL",
        )
        .bind(now)
        .bind(new.id.0.to_string())
        .bind(old_hash)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        if updated.rows_affected() == 0 {
            // The row was unconsumed when read above but consumed before this
            // update: another request rotated it concurrently. That is the same
            // reuse signal as above, just observed one step later, so it must
            // revoke the family too rather than retry.
            let result = sqlx::query(
                "UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(old.family_id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
            record_fact(&mut tx, &fact.as_reuse()).await?;
            tx.commit().await.map_err(db_error)?;
            return Ok(RotateOutcome::ReuseDetected {
                family_revoked: result.rows_affected(),
            });
        }

        sqlx::query(
            "INSERT INTO refresh_tokens \
             (id, token_hash, family_id, client_id, user_id, scopes, created_at, expires_at, \
              consumed_at, revoked_at, replaced_by) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(new.id.0.to_string())
        .bind(new.token_hash.as_slice())
        .bind(new.family_id.0.to_string())
        .bind(new.client_id.0.to_string())
        .bind(new.user_id.0.to_string())
        .bind(scopes_json(&new.scopes)?)
        .bind(new.created_at)
        .bind(new.expires_at)
        .bind(new.consumed_at)
        .bind(new.revoked_at)
        .bind(new.replaced_by.map(|id| id.0.to_string()))
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;

        record_fact(&mut tx, fact).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(RotateOutcome::Rotated(new))
    }

    async fn revoke_family(
        &self,
        family: &FamilyId,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<u64> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let result = sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(family.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let revoked = result.rows_affected();
        // 同事务标记家族，令其访问令牌失效
        sqlx::query(
            "INSERT INTO revoked_families (family_id, revoked_at) VALUES (?, ?) \
             ON CONFLICT(family_id) DO NOTHING",
        )
        .bind(family.0.to_string())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        if revoked > 0 {
            record_fact(&mut tx, fact).await?;
        }
        tx.commit().await.map_err(db_error)?;
        Ok(revoked)
    }

    async fn revoke_all_for_client(
        &self,
        user: &UserId,
        client: &ClientId,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<u64> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let result = sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = ? \
             WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(user.0.to_string())
        .bind(client.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let revoked = result.rows_affected();
        if revoked > 0 {
            record_fact(&mut tx, fact).await?;
        }
        tx.commit().await.map_err(db_error)?;
        Ok(revoked)
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let result = sqlx::query(
            "DELETE FROM refresh_tokens WHERE expires_at <= ? \
             OR (revoked_at IS NOT NULL AND revoked_at <= ?) \
             OR (consumed_at IS NOT NULL AND consumed_at <= ?)",
        )
        .bind(before)
        .bind(before)
        .bind(before)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected())
    }
}

#[async_trait]
impl LoginTransactionRepo for SqliteStore {
    async fn insert(&self, transaction: &LoginTransaction) -> RepoResult<()> {
        sqlx::query(
            "INSERT INTO login_transactions \
             (state_hash, nonce, pkce_verifier, return_to, provider, created_at, expires_at, \
              consumed_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(transaction.state_hash.as_slice())
        .bind(&transaction.nonce)
        .bind(&transaction.pkce_verifier)
        .bind(&transaction.return_to)
        .bind(&transaction.provider)
        .bind(transaction.created_at)
        .bind(transaction.expires_at)
        .bind(transaction.consumed_at)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn consume(&self, state_hash: &[u8], now: Unix) -> RepoResult<LoginTransaction> {
        let row = sqlx::query(
            "UPDATE login_transactions SET consumed_at = ? \
             WHERE state_hash = ? AND consumed_at IS NULL AND expires_at > ? \
             RETURNING state_hash, nonce, pkce_verifier, return_to, provider, created_at, \
              expires_at, consumed_at",
        )
        .bind(now)
        .bind(state_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        if let Some(row) = row {
            return row_to_login_transaction(&row);
        }

        let existing = sqlx::query(
            "SELECT consumed_at, expires_at FROM login_transactions WHERE state_hash = ?",
        )
        .bind(state_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        let Some(existing) = existing else {
            return Err(RepoError::NotFound);
        };
        let consumed_at: Option<i64> = existing.try_get("consumed_at").map_err(db_error)?;
        let expires_at: i64 = existing.try_get("expires_at").map_err(db_error)?;
        if consumed_at.is_some() {
            Err(RepoError::AlreadyConsumed)
        } else if expires_at <= now {
            Err(RepoError::Expired)
        } else {
            Err(RepoError::NotFound)
        }
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let result = sqlx::query(
            "DELETE FROM login_transactions WHERE expires_at <= ? \
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

#[async_trait]
impl PendingBindingRepo for SqliteStore {
    async fn insert(&self, pending: &PendingBinding) -> RepoResult<()> {
        sqlx::query(
            "INSERT INTO pending_bindings \
             (state_hash, user_id, upstream_id, pkce_verifier, return_to, created_at, \
              expires_at, consumed_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(pending.state_hash.as_slice())
        .bind(pending.user_id.0.to_string())
        .bind(&pending.upstream_id)
        .bind(&pending.pkce_verifier)
        .bind(&pending.return_to)
        .bind(pending.created_at)
        .bind(pending.expires_at)
        .bind(pending.consumed_at)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn consume(&self, state_hash: &[u8], now: Unix) -> RepoResult<PendingBinding> {
        let row = sqlx::query(
            "UPDATE pending_bindings SET consumed_at = ? \
             WHERE state_hash = ? AND consumed_at IS NULL AND expires_at > ? \
             RETURNING state_hash, user_id, upstream_id, pkce_verifier, return_to, created_at, \
              expires_at, consumed_at",
        )
        .bind(now)
        .bind(state_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        if let Some(row) = row {
            return row_to_pending_binding(&row);
        }

        // Tell "already used" apart from "never existed": the former is a replay
        // attempt and worth a different answer than a callback for a flow that
        // was never started on this instance.
        let existing = sqlx::query(
            "SELECT consumed_at, expires_at FROM pending_bindings WHERE state_hash = ?",
        )
        .bind(state_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        let Some(existing) = existing else {
            return Err(RepoError::NotFound);
        };
        let consumed_at: Option<i64> = existing.try_get("consumed_at").map_err(db_error)?;
        let expires_at: i64 = existing.try_get("expires_at").map_err(db_error)?;
        if consumed_at.is_some() {
            Err(RepoError::AlreadyConsumed)
        } else if expires_at <= now {
            Err(RepoError::Expired)
        } else {
            Err(RepoError::NotFound)
        }
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let result = sqlx::query(
            "DELETE FROM pending_bindings WHERE expires_at <= ? \
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

#[async_trait]
impl ApprovalTicketRepo for SqliteStore {
    async fn insert(&self, ticket: &ApprovalTicket) -> RepoResult<()> {
        sqlx::query(
            "INSERT INTO approval_tickets (jti, user_id, user_code, expires_at, consumed_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&ticket.jti)
        .bind(ticket.user_id.0.to_string())
        .bind(&ticket.user_code)
        .bind(ticket.expires_at)
        .bind(ticket.consumed_at)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn find(&self, jti: &str) -> RepoResult<Option<ApprovalTicket>> {
        let row = sqlx::query(
            "SELECT jti, user_id, user_code, expires_at, consumed_at \
             FROM approval_tickets WHERE jti = ?",
        )
        .bind(jti)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        row.as_ref().map(row_to_approval_ticket).transpose()
    }

    async fn consume_and_decide(
        &self,
        jti: &str,
        user_id: UserId,
        user_code_hash: &[u8],
        decision: ApprovalDecision,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<ClientId> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let ticket = sqlx::query(
            "UPDATE approval_tickets SET consumed_at = ? \
             WHERE jti = ? AND user_id = ? AND consumed_at IS NULL AND expires_at > ? \
             RETURNING jti",
        )
        .bind(now)
        .bind(jti)
        .bind(user_id.0.to_string())
        .bind(now)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        if ticket.is_none() {
            tx.rollback().await.map_err(db_error)?;
            let existing = sqlx::query(
                "SELECT consumed_at, expires_at FROM approval_tickets WHERE jti = ? AND user_id = ?",
            )
            .bind(jti)
            .bind(user_id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?;
            let Some(existing) = existing else {
                return Err(RepoError::NotFound);
            };
            let consumed_at: Option<i64> = existing.try_get("consumed_at").map_err(db_error)?;
            let expires_at: i64 = existing.try_get("expires_at").map_err(db_error)?;
            return if consumed_at.is_some() {
                Err(RepoError::AlreadyConsumed)
            } else if expires_at <= now {
                Err(RepoError::Expired)
            } else {
                Err(RepoError::NotFound)
            };
        }

        let status = match decision {
            ApprovalDecision::Approve => "approved",
            ApprovalDecision::Deny => "denied",
        };
        // RETURNING client_id: the device code is the only holder of that id, and
        // reading it in the same statement avoids a second query racing a purge.
        let result = sqlx::query(
            "UPDATE device_codes SET status = ?, user_id = ? \
             WHERE user_code_hash = ? AND status = 'pending' AND expires_at > ? \
             RETURNING client_id",
        )
        .bind(status)
        .bind(user_id.0.to_string())
        .bind(user_code_hash)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some(row) = result else {
            tx.rollback().await.map_err(db_error)?;
            let existing =
                sqlx::query("SELECT status, expires_at FROM device_codes WHERE user_code_hash = ?")
                    .bind(user_code_hash)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(db_error)?;
            let Some(existing) = existing else {
                return Err(RepoError::NotFound);
            };
            let expires_at: i64 = existing.try_get("expires_at").map_err(db_error)?;
            if expires_at <= now {
                return Err(RepoError::Expired);
            }
            return Err(RepoError::Conflict("device code is not pending"));
        };
        let client_id =
            parse_uuid(&row.try_get::<String, _>("client_id").map_err(db_error)?).map(ClientId)?;

        // INV-AUDIT-01 + INV-DEVICE-03: the fact lands with the decision, and
        // its client is taken from the device code — the caller cannot know it,
        // and trusting a caller-supplied value would let one client attribute a
        // decision to another.
        let mut fact = fact.clone();
        fact.client_id = Some(client_id);
        record_fact(&mut tx, &fact).await?;

        tx.commit().await.map_err(db_error)?;
        Ok(client_id)
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let result = sqlx::query(
            "DELETE FROM approval_tickets WHERE expires_at <= ? \
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

#[async_trait]
impl ClientRepo for SqliteStore {
    async fn insert(&self, client: &Client, fact: &SecurityFact) -> RepoResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        sqlx::query(
            "INSERT INTO clients \
             (id, name, redirect_uris, allowed_scopes, raw_access, status, \
              secret_hash, secret_key_version, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(client.id.0.to_string())
        .bind(&client.name)
        .bind(scopes_json(&client.redirect_uris)?)
        .bind(scopes_json(&client.allowed_scopes)?)
        .bind(i64::from(client.raw_access))
        .bind(client_status_to_str(client.status))
        .bind(
            client
                .secret_hash
                .as_ref()
                .map(|hash| hash.digest().to_vec()),
        )
        .bind(
            client
                .secret_hash
                .as_ref()
                .map(|hash| i64::from(hash.key_version())),
        )
        .bind(client.created_at)
        .bind(client.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        record_fact(&mut tx, fact).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn get(&self, id: &ClientId) -> RepoResult<Option<Client>> {
        let row = sqlx::query(
            "SELECT id, name, redirect_uris, allowed_scopes, raw_access, status, \
             secret_hash, secret_key_version, created_at, updated_at \
             FROM clients WHERE id = ?",
        )
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        row.as_ref().map(row_to_client).transpose()
    }

    async fn set_status(&self, id: &ClientId, status: ClientStatus, now: Unix) -> RepoResult<()> {
        let result = sqlx::query("UPDATE clients SET status = ?, updated_at = ? WHERE id = ?")
            .bind(client_status_to_str(status))
            .bind(now)
            .bind(id.0.to_string())
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        if result.rows_affected() == 0 {
            return Err(RepoError::NotFound);
        }
        Ok(())
    }

    async fn list(&self, before: Option<&ClientId>, limit: u32) -> RepoResult<Vec<Client>> {
        let cursor = before.map(|id| id.0.to_string());
        let rows = sqlx::query(
            "SELECT id, name, redirect_uris, allowed_scopes, raw_access, status, \
             secret_hash, secret_key_version, created_at, updated_at FROM clients \
             WHERE (? IS NULL OR id < ?) ORDER BY id DESC LIMIT ?",
        )
        .bind(&cursor)
        .bind(&cursor)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        rows.iter().map(row_to_client).collect()
    }

    async fn update(&self, client: &Client, fact: &SecurityFact, now: Unix) -> RepoResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let result = sqlx::query(
            "UPDATE clients SET name = ?, redirect_uris = ?, allowed_scopes = ?, \
             raw_access = ?, status = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&client.name)
        .bind(scopes_json(&client.redirect_uris)?)
        .bind(scopes_json(&client.allowed_scopes)?)
        .bind(i64::from(client.raw_access))
        .bind(client_status_to_str(client.status))
        .bind(now)
        .bind(client.id.0.to_string())
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

    async fn set_secret_hash(
        &self,
        id: &ClientId,
        secret_hash: Option<&ClientSecretHash>,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let result = sqlx::query(
            "UPDATE clients SET secret_hash = ?, secret_key_version = ?, updated_at = ? WHERE id = ?",
        )
        .bind(secret_hash.map(|hash| hash.digest().to_vec()))
        .bind(secret_hash.map(|hash| i64::from(hash.key_version())))
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_and_statuses_round_trip() {
        assert_eq!(role_from_str("user").expect("role"), UserRole::User);
        assert!(role_from_str("root").is_err());
        assert_eq!(
            status_from_str("needs_reauth").expect("status"),
            BindingStatus::NeedsReauth
        );
        assert!(status_from_str("unknown").is_err());
    }

    #[test]
    fn sqlite_busy_codes_map_to_retryable_error() {
        for code in ["5", "6", "517"] {
            assert_eq!(sqlite_code_error(code), Some(RepoError::Busy));
        }
        assert_eq!(
            sqlite_code_error("1555"),
            Some(RepoError::Conflict("unique constraint"))
        );
        assert_eq!(sqlite_code_error("787"), Some(RepoError::NotFound));
        assert_eq!(sqlite_code_error("999"), None);
    }
}
