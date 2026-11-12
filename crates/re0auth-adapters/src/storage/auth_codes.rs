//! Authorization-code persistence.
//!
//! `inspect` is read-only so the token exchange can run its fallible steps
//! (consent re-check, signing) before committing anything; the consumption and
//! the refresh-token insert then land in one transaction (INV-AUTH-01).

use async_trait::async_trait;
use re0auth_api::audit::SecurityFact;
use re0auth_api::ports::{
    AuthCode, AuthCodeRepo, AuthGrant, ConsumeAuthCode, RefreshToken, RepoError, RepoResult,
};
use re0auth_api::{ClientId, FamilyId, Unix};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;

use super::audit::record_fact;
use super::{SqliteStore, db_error, insert_refresh_row, parse_uuid, scopes_json};

/// Reads the grant columns of an `auth_codes` row.
///
/// Shared so `inspect` and the atomic consumption cannot drift in what they
/// return to the caller.
fn grant_from_row(row: &SqliteRow) -> RepoResult<AuthGrant> {
    Ok(AuthGrant {
        user_id: re0auth_api::UserId(parse_uuid(
            &row.try_get::<String, _>("user_id").map_err(db_error)?,
        )?),
        client_id: ClientId(parse_uuid(
            &row.try_get::<String, _>("client_id").map_err(db_error)?,
        )?),
        redirect_uri: row.try_get("redirect_uri").map_err(db_error)?,
        scopes: super::scopes_from_json(&row.try_get::<String, _>("scopes").map_err(db_error)?)?,
        nonce: row.try_get("nonce").map_err(db_error)?,
        auth_time: row.try_get("auth_time").map_err(db_error)?,
    })
}

#[async_trait]
impl AuthCodeRepo for SqliteStore {
    async fn insert(&self, code: &AuthCode, fact: &SecurityFact) -> RepoResult<()> {
        // INV-AUDIT-01: the code and its audit fact land together or not at all.
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        sqlx::query(
            "INSERT INTO auth_codes \
             (id, code_hash, client_id, user_id, redirect_uri, scopes, code_challenge, \
              code_challenge_method, nonce, auth_time, created_at, expires_at, consumed_at, family_id) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .bind(code.auth_time)
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

    async fn inspect(&self, req: &ConsumeAuthCode<'_>, now: Unix) -> RepoResult<AuthGrant> {
        let row = sqlx::query(
            "SELECT user_id, client_id, redirect_uri, scopes, nonce, auth_time, \
             code_challenge, code_challenge_method, consumed_at, expires_at \
             FROM auth_codes WHERE code_hash = ?",
        )
        .bind(req.code_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        let Some(row) = row else {
            return Err(RepoError::NotFound);
        };
        // Precedence matches a single-statement consume: a consumed row reports
        // `AlreadyConsumed` even if it is also expired, and a live row that does
        // not match the request is indistinguishable from a missing one.
        let consumed_at: Option<i64> = row.try_get("consumed_at").map_err(db_error)?;
        if consumed_at.is_some() {
            return Err(RepoError::AlreadyConsumed);
        }
        let expires_at: i64 = row.try_get("expires_at").map_err(db_error)?;
        if expires_at <= now {
            return Err(RepoError::Expired);
        }
        let stored_challenge: Option<String> = row.try_get("code_challenge").map_err(db_error)?;
        let stored_method: Option<String> =
            row.try_get("code_challenge_method").map_err(db_error)?;
        let grant = grant_from_row(&row)?;
        if grant.client_id != req.client_id
            || grant.redirect_uri != req.redirect_uri
            || stored_challenge.as_deref() != req.code_challenge
            || stored_method.as_deref() != req.code_challenge_method
        {
            return Err(RepoError::NotFound);
        }
        Ok(grant)
    }

    async fn consume_and_insert_refresh(
        &self,
        req: ConsumeAuthCode<'_>,
        refresh: &RefreshToken,
        now: Unix,
    ) -> RepoResult<AuthGrant> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(db_error)?;
        // The UPDATE is the whole check: matching on the challenge with `IS ?`
        // rather than `=` makes a NULL challenge match a NULL column, so a code
        // issued without PKCE cannot be redeemed with one (and vice versa). The
        // row only comes back under RETURNING if every binding still holds,
        // which is what makes concurrent redemption have exactly one winner.
        let row = sqlx::query(
            "UPDATE auth_codes SET consumed_at = ?, family_id = ? \
             WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > ? \
             AND client_id = ? AND redirect_uri = ? \
             AND code_challenge IS ? AND code_challenge_method IS ? \
             RETURNING user_id, client_id, redirect_uri, scopes, nonce, auth_time, \
             code_challenge, code_challenge_method, consumed_at, expires_at",
        )
        .bind(now)
        .bind(req.family_id.0.to_string())
        .bind(req.code_hash)
        .bind(now)
        .bind(req.client_id.0.to_string())
        .bind(req.redirect_uri)
        .bind(req.code_challenge)
        .bind(req.code_challenge_method)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;

        let Some(row) = row else {
            let existing =
                sqlx::query("SELECT consumed_at, expires_at FROM auth_codes WHERE code_hash = ?")
                    .bind(req.code_hash)
                    .fetch_optional(&mut *tx)
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
        };
        let grant = grant_from_row(&row)?;
        // Same transaction as the consumption: a failed insert rolls the code
        // back to unconsumed, so the client can retry instead of getting a 500
        // for a code it can never redeem.
        insert_refresh_row(&mut *tx, refresh).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(grant)
    }

    async fn family_and_client_of(
        &self,
        code_hash: &[u8],
    ) -> RepoResult<Option<(FamilyId, ClientId)>> {
        let row = sqlx::query("SELECT family_id, client_id FROM auth_codes WHERE code_hash = ?")
            .bind(code_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let raw: Option<String> = row.try_get("family_id").map_err(db_error)?;
        let Some(family) = raw else {
            return Ok(None);
        };
        let client = ClientId(parse_uuid(
            &row.try_get::<String, _>("client_id").map_err(db_error)?,
        )?);
        Ok(Some((FamilyId(parse_uuid(&family)?), client)))
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
