use async_trait::async_trait;
use sqlx::{Row, sqlite::SqliteRow};

use re0auth_api::audit::SecurityFact;
use re0auth_api::ports::{
    Consent, ConsentRepo, PendingAuthorization, PendingAuthorizationRepo, RepoError, RepoResult,
};
use re0auth_api::{ClientId, ConsentId, PendingAuthorizationId, SessionId, Unix, UserId};

use super::audit::record_fact;
use super::{SqliteStore, db_error, parse_uuid, scopes_from_json, scopes_json};

fn row_to_consent(row: &SqliteRow) -> RepoResult<Consent> {
    Ok(Consent {
        id: ConsentId(parse_uuid(
            &row.try_get::<String, _>("id").map_err(db_error)?,
        )?),
        user_id: UserId(parse_uuid(
            &row.try_get::<String, _>("user_id").map_err(db_error)?,
        )?),
        client_id: ClientId(parse_uuid(
            &row.try_get::<String, _>("client_id").map_err(db_error)?,
        )?),
        scopes: scopes_from_json(&row.try_get::<String, _>("scopes").map_err(db_error)?)?,
        created_at: row.try_get("created_at").map_err(db_error)?,
        updated_at: row.try_get("updated_at").map_err(db_error)?,
        revoked_at: row.try_get("revoked_at").map_err(db_error)?,
    })
}

fn row_to_pending_authorization(row: &SqliteRow) -> RepoResult<PendingAuthorization> {
    Ok(PendingAuthorization {
        id: PendingAuthorizationId(parse_uuid(
            &row.try_get::<String, _>("id").map_err(db_error)?,
        )?),
        session_id: SessionId(parse_uuid(
            &row.try_get::<String, _>("session_id").map_err(db_error)?,
        )?),
        user_id: UserId(parse_uuid(
            &row.try_get::<String, _>("user_id").map_err(db_error)?,
        )?),
        client_id: ClientId(parse_uuid(
            &row.try_get::<String, _>("client_id").map_err(db_error)?,
        )?),
        redirect_uri: row.try_get("redirect_uri").map_err(db_error)?,
        scopes: scopes_from_json(&row.try_get::<String, _>("scopes").map_err(db_error)?)?,
        state: row.try_get("state").map_err(db_error)?,
        code_challenge: row.try_get("code_challenge").map_err(db_error)?,
        code_challenge_method: row.try_get("code_challenge_method").map_err(db_error)?,
        nonce: row.try_get("nonce").map_err(db_error)?,
        created_at: row.try_get("created_at").map_err(db_error)?,
        expires_at: row.try_get("expires_at").map_err(db_error)?,
        consumed_at: row.try_get("consumed_at").map_err(db_error)?,
    })
}

#[async_trait]
impl ConsentRepo for SqliteStore {
    async fn find(&self, user: &UserId, client: &ClientId) -> RepoResult<Option<Consent>> {
        sqlx::query(
            "SELECT id, user_id, client_id, scopes, created_at, updated_at, revoked_at \
             FROM consents WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL",
        )
        .bind(user.0.to_string())
        .bind(client.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?
        .map(|row| row_to_consent(&row))
        .transpose()
    }

    async fn list_by_user(&self, user: &UserId) -> RepoResult<Vec<Consent>> {
        sqlx::query(
            "SELECT id, user_id, client_id, scopes, created_at, updated_at, revoked_at \
             FROM consents WHERE user_id = ? AND revoked_at IS NULL ORDER BY updated_at DESC",
        )
        .bind(user.0.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?
        .iter()
        .map(row_to_consent)
        .collect()
    }

    async fn grant(&self, consent: &Consent, fact: &SecurityFact) -> RepoResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        sqlx::query(
            "INSERT INTO consents \
             (id, user_id, client_id, scopes, created_at, updated_at, revoked_at) \
             VALUES (?, ?, ?, ?, ?, ?, NULL) \
             ON CONFLICT(user_id, client_id) DO UPDATE SET \
             scopes = excluded.scopes, updated_at = excluded.updated_at, revoked_at = NULL",
        )
        .bind(consent.id.0.to_string())
        .bind(consent.user_id.0.to_string())
        .bind(consent.client_id.0.to_string())
        .bind(scopes_json(&consent.scopes)?)
        .bind(consent.created_at)
        .bind(consent.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        record_fact(&mut tx, fact).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn revoke(
        &self,
        user: &UserId,
        client: &ClientId,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let result = sqlx::query(
            "UPDATE consents SET revoked_at = ?, updated_at = ? \
             WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(now)
        .bind(user.0.to_string())
        .bind(client.0.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        if result.rows_affected() == 0 {
            // Nothing was revoked. Rolling back leaves no stray audit row.
            return Err(RepoError::NotFound);
        }
        record_fact(&mut tx, fact).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }
}

#[async_trait]
impl PendingAuthorizationRepo for SqliteStore {
    async fn insert(&self, request: &PendingAuthorization) -> RepoResult<()> {
        sqlx::query(
            "INSERT INTO pending_authorizations \
             (id, session_id, user_id, client_id, redirect_uri, scopes, state, \
              code_challenge, code_challenge_method, nonce, created_at, expires_at, consumed_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(request.id.0.to_string())
        .bind(request.session_id.0.to_string())
        .bind(request.user_id.0.to_string())
        .bind(request.client_id.0.to_string())
        .bind(&request.redirect_uri)
        .bind(scopes_json(&request.scopes)?)
        .bind(request.state.as_deref())
        .bind(&request.code_challenge)
        .bind(&request.code_challenge_method)
        .bind(request.nonce.as_deref())
        .bind(request.created_at)
        .bind(request.expires_at)
        .bind(request.consumed_at)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn get(&self, id: &PendingAuthorizationId) -> RepoResult<Option<PendingAuthorization>> {
        sqlx::query(
            "SELECT id, session_id, user_id, client_id, redirect_uri, scopes, state, \
             code_challenge, code_challenge_method, nonce, created_at, expires_at, consumed_at \
             FROM pending_authorizations WHERE id = ?",
        )
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?
        .map(|row| row_to_pending_authorization(&row))
        .transpose()
    }

    async fn consume(
        &self,
        id: &PendingAuthorizationId,
        session_id: &SessionId,
        now: Unix,
    ) -> RepoResult<PendingAuthorization> {
        let consumed = sqlx::query(
            "UPDATE pending_authorizations SET consumed_at = ? \
             WHERE id = ? AND session_id = ? AND consumed_at IS NULL AND expires_at > ? \
             RETURNING id, session_id, user_id, client_id, redirect_uri, scopes, state, \
             code_challenge, code_challenge_method, nonce, created_at, expires_at, consumed_at",
        )
        .bind(now)
        .bind(id.0.to_string())
        .bind(session_id.0.to_string())
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        if let Some(row) = consumed {
            return row_to_pending_authorization(&row);
        }

        let row = sqlx::query(
            "SELECT consumed_at, expires_at, session_id \
             FROM pending_authorizations WHERE id = ?",
        )
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        let Some(row) = row else {
            return Err(RepoError::NotFound);
        };
        let stored_session: String = row.try_get("session_id").map_err(db_error)?;
        if stored_session != session_id.0.to_string() {
            return Err(RepoError::NotFound);
        }
        let consumed_at: Option<Unix> = row.try_get("consumed_at").map_err(db_error)?;
        if consumed_at.is_some() {
            return Err(RepoError::AlreadyConsumed);
        }
        let expires_at: Unix = row.try_get("expires_at").map_err(db_error)?;
        if expires_at <= now {
            return Err(RepoError::Expired);
        }
        Err(RepoError::NotFound)
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let result = sqlx::query(
            "DELETE FROM pending_authorizations \
             WHERE expires_at <= ? OR (consumed_at IS NOT NULL AND consumed_at <= ?)",
        )
        .bind(before)
        .bind(before)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected())
    }
}
