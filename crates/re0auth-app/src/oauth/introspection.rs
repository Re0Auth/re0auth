//! RFC 7662 token introspection.
use super::*;

impl OAuthService {
    /// RFC 7662: a protected resource asks whether a token is still valid.
    ///
    /// The caller is a client, so only tokens issued to that same client can be
    /// active. Every failure path collapses to `active: false`; the caller must
    /// not be able to distinguish expired, revoked, and forged tokens.
    pub async fn introspect(
        &self,
        token: &str,
        client_id: ClientId,
        client_secret: Option<&str>,
    ) -> Result<IntrospectionResponse, OAuthError> {
        // RFC 7662 §2.1: the endpoint is protected by client authentication.
        self.authenticate_client(client_id, client_secret).await?;
        let now = self.clock.now();

        if let Ok(claims) = self.signer.verify_access(token) {
            if claims.client_id != client_id.0.to_string() {
                return Ok(IntrospectionResponse::inactive());
            }
            if self.reject_if_revoked(&claims).await.is_err() {
                return Ok(IntrospectionResponse::inactive());
            }
            let Ok(user_id) = Uuid::parse_str(&claims.sub).map(UserId) else {
                return Ok(IntrospectionResponse::inactive());
            };
            let scopes = scope::parse_scope(&claims.scope);
            if self.require_active_user(user_id).await.is_err()
                || self
                    .require_token_consent(user_id, client_id, &scopes, claims.consent_version)
                    .await
                    .is_err()
            {
                return Ok(IntrospectionResponse::inactive());
            }
            return Ok(IntrospectionResponse {
                active: true,
                scope: Some(claims.scope),
                client_id: Some(claims.client_id),
                token_type: Some("Bearer".to_string()),
                exp: Some(claims.exp),
                iat: Some(claims.iat),
                sub: Some(claims.sub),
                aud: Some(claims.aud),
                iss: Some(claims.iss),
                jti: Some(claims.jti),
            });
        }

        let Some(stored) = self
            .storage
            .refresh_tokens()
            .find(&hash_secret(token))
            .await
            .map_err(map_repo)?
        else {
            return Ok(IntrospectionResponse::inactive());
        };
        if stored.client_id != client_id
            || stored.revoked_at.is_some()
            || stored.expires_at <= now
            || stored.consumed_at.is_some()
            || now.saturating_sub(stored.family_created_at)
                >= re0auth_domain::refresh_token_absolute_ttl(now)
        {
            return Ok(IntrospectionResponse::inactive());
        }
        // A consumed refresh token is a rotated one; it is no longer active.
        if self
            .require_grant_consent(stored.user_id, client_id, &stored.scopes)
            .await
            .is_err()
        {
            return Ok(IntrospectionResponse::inactive());
        }
        Ok(IntrospectionResponse {
            active: true,
            scope: Some(stored.scopes.join(" ")),
            client_id: Some(stored.client_id.0.to_string()),
            token_type: Some("refresh_token".to_string()),
            exp: Some(stored.expires_at),
            iat: Some(stored.created_at),
            sub: Some(stored.user_id.0.to_string()),
            aud: None,
            iss: Some(self.issuer.clone()),
            jti: None,
        })
    }
}
