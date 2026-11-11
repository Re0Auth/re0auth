//! Minimum OAuth/OIDC use cases: authorize, code exchange, refresh, userinfo.
use re0auth_api::audit::{AuditAction, SecurityFact};

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use re0auth_api::oauth::{
    ACCESS_TOKEN_USE, AccessTokenClaims, ConsentVersion, IdTokenClaims, TokenSigner,
};
use re0auth_api::ports::{
    AuthCode, BindingHints, Client, ClientStatus, Consent, ConsumeAuthCode, DeviceCode,
    DeviceCodeState, DevicePoll, NoBindingHints, PendingAuthorization, RefreshToken, RepoError,
    RotateOutcome, RotateRefreshToken, Storage, UserStatus,
};
use re0auth_api::secret::ClientSecretHasher;
use re0auth_api::{
    AuthCodeId, ClientId, Clock, ConsentId, DeviceCodeId, FamilyId, PendingAuthorizationId, Random,
    RefreshTokenId, SessionId, Unix, UserId,
};
use re0auth_domain::{device, pending_authorization_ttl, pkce, scope};

/// How many user codes to draw before giving up.
///
/// A collision needs an existing row holding the same eight characters, so one
/// redraw is already a large margin; the cap exists so a broken source of
/// randomness fails the request instead of looping.
const USER_CODE_ATTEMPTS: u8 = 5;

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("invalid_request: {0}")]
    InvalidRequest(&'static str),
    #[error("invalid_client")]
    InvalidClient,
    #[error("invalid_grant: {0}")]
    InvalidGrant(&'static str),
    #[error("invalid_scope")]
    InvalidScope,
    #[error("invalid_token")]
    InvalidToken,
    #[error("unauthorized_client")]
    UnauthorizedClient,
    #[error("login_required")]
    LoginRequired,
    #[error("authorization_pending")]
    AuthorizationPending,
    #[error("slow_down")]
    SlowDown { interval_secs: u32 },
    #[error("expired_token")]
    ExpiredToken,
    #[error("access_denied")]
    AccessDenied,
    #[error("consent request not found")]
    ConsentNotFound,
    #[error("consent request expired")]
    ConsentExpired,
    #[error("consent request already used")]
    ConsentUsed,
    #[error("temporarily_unavailable")]
    TemporarilyUnavailable,
    #[error("internal")]
    Internal,
}

mod introspection;
mod types;
pub use types::*;

#[derive(Clone)]
pub struct OAuthService {
    storage: Arc<dyn Storage>,
    signer: Arc<dyn TokenSigner>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn Random>,
    client_secrets: Arc<dyn ClientSecretHasher>,
    issuer: String,
    resource: String,
    hints: Arc<dyn BindingHints>,
}

impl OAuthService {
    #[must_use]
    pub fn new(
        storage: Arc<dyn Storage>,
        signer: Arc<dyn TokenSigner>,
        clock: Arc<dyn Clock>,
        random: Arc<dyn Random>,
        client_secrets: Arc<dyn ClientSecretHasher>,
        issuer: impl Into<String>,
    ) -> Self {
        let issuer = issuer.into().trim_end_matches('/').to_string();
        let resource = format!("{issuer}/api/v1");
        Self {
            storage,
            signer,
            clock,
            random,
            client_secrets,
            issuer,
            resource,
            hints: Arc::new(NoBindingHints),
        }
    }

    /// Attaches the consent screen's "you have not connected this yet" source.
    ///
    /// A builder rather than a constructor argument because the default is
    /// correct for every deployment without connectors, and that is most of them.
    #[must_use]
    pub fn with_binding_hints(mut self, hints: Arc<dyn BindingHints>) -> Self {
        self.hints = hints;
        self
    }

    /// Verifies the presented secret against the registered one (ADR-0030).
    ///
    /// A public client (`secret_hash == None`) must present **no** secret. If it
    /// does, the request is rejected: accepting it would let anyone attach an
    /// arbitrary secret to a public client and hide a misconfiguration.
    ///
    /// Must run before any single-use credential is consumed — otherwise a
    /// wrong secret burns the authorization code it was aimed at.
    /// Authenticates a client and returns the record.
    ///
    /// Returning the client lets `device_authorization` reuse the lookup instead
    /// of fetching it twice; the other callers discard it with `?;`.
    async fn authenticate_client(
        &self,
        client_id: ClientId,
        presented: Option<&str>,
    ) -> Result<Client, OAuthError> {
        let client = self
            .storage
            .clients()
            .get(&client_id)
            .await
            .map_err(map_repo)?
            .ok_or(OAuthError::InvalidClient)?;
        if client.status != ClientStatus::Approved {
            return Err(OAuthError::UnauthorizedClient);
        }
        let authenticated = match (&client.secret_hash, presented) {
            (Some(stored), Some(secret)) => self.client_secrets.matches(secret, stored),
            (Some(_), None) => false,
            (None, None) => true,
            (None, Some(_)) => false,
        };
        if authenticated {
            Ok(client)
        } else {
            Err(OAuthError::InvalidClient)
        }
    }

    #[must_use]
    pub fn jwks(&self) -> String {
        self.signer.jwks()
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Probes the storage backend. Used by `/readyz`, which must distinguish
    /// "process alive" from "can actually serve requests".
    pub async fn check_storage(&self) -> Result<(), OAuthError> {
        self.storage.ping().await.map_err(map_repo)
    }

    pub async fn session_user(&self, session_hash: &[u8]) -> Result<Option<UserId>, OAuthError> {
        let now = self.clock.now();
        Ok(self
            .storage
            .sessions()
            .find_active(session_hash, now)
            .await
            .map_err(map_repo)?
            .map(|session| session.user_id))
    }

    /// `correlation_id` is the HTTP `X-Request-Id` recorded in the audit row.
    pub async fn authorize(
        &self,
        session_id: SessionId,
        user_id: UserId,
        request: AuthorizeRequest,
        correlation_id: Option<&str>,
    ) -> Result<AuthorizeOutcome, OAuthError> {
        let client = self
            .validate_client_redirect(request.client_id, &request.redirect_uri)
            .await?;
        self.authorize_with_client(session_id, user_id, request, client, false, correlation_id)
            .await
    }
    pub async fn authorize_with_client(
        &self,
        session_id: SessionId,
        user_id: UserId,
        request: AuthorizeRequest,
        client: Client,
        force_consent: bool,
        correlation_id: Option<&str>,
    ) -> Result<AuthorizeOutcome, OAuthError> {
        self.validate_authorize_request(&client, &request)?;
        let consent = self
            .storage
            .consents()
            .find(&user_id, &request.client_id)
            .await
            .map_err(map_repo)?;
        if !force_consent
            && let Some(consent) = consent
            && scope::is_subset(&request.scopes, &consent.scopes)
        {
            let code = self.issue_code(user_id, &request, correlation_id).await?;
            return Ok(AuthorizeOutcome::Redirect(
                self.redirect_with_code(&request, &code)?,
            ));
        }
        let now = self.clock.now();
        let pending = PendingAuthorization {
            id: PendingAuthorizationId::new(),
            session_id,
            user_id,
            client_id: request.client_id,
            redirect_uri: request.redirect_uri,
            scopes: request.scopes,
            state: request.state,
            code_challenge: request.code_challenge,
            code_challenge_method: "S256".to_string(),
            nonce: request.nonce,
            auth_time: request.auth_time,
            created_at: now,
            expires_at: now + pending_authorization_ttl(now),
            consumed_at: None,
        };
        let request_id = pending.id.0.to_string();
        self.storage
            .pending_authorizations()
            .insert(&pending)
            .await
            .map_err(map_repo)?;
        Ok(AuthorizeOutcome::Consent { request_id })
    }

    pub async fn pending(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        request_id: &str,
    ) -> Result<PendingConsentView, OAuthError> {
        let id = parse_request_id(request_id)?;
        let now = self.clock.now();
        let request = self
            .storage
            .pending_authorizations()
            .get(&id)
            .await
            .map_err(map_repo)?
            .ok_or(OAuthError::ConsentNotFound)?;
        if request.session_id != *session_id || request.user_id != *user_id {
            return Err(OAuthError::ConsentNotFound);
        }
        if request.consumed_at.is_some() {
            return Err(OAuthError::ConsentUsed);
        }
        if request.expires_at <= now {
            return Err(OAuthError::ConsentExpired);
        }
        let client = self
            .storage
            .clients()
            .get(&request.client_id)
            .await
            .map_err(map_repo)?
            .ok_or(OAuthError::UnauthorizedClient)?;
        if client.status != ClientStatus::Approved {
            return Err(OAuthError::UnauthorizedClient);
        }
        // Advisory only, so a failure to compute it degrades to "no hint" rather
        // than failing the authorization. Refusing to show consent because a
        // non-essential query failed would trade a missing suggestion for an
        // unusable login; the data plane re-checks the binding either way.
        let missing_bindings = self
            .hints
            .missing(&request.user_id, &request.scopes)
            .await
            .unwrap_or_default();
        Ok(PendingConsentView {
            request_id: request.id.0.to_string(),
            client_id: request.client_id.0.to_string(),
            client_name: client.name,
            redirect_uri: request.redirect_uri,
            scopes: request.scopes,
            expires_at: request.expires_at,
            missing_bindings,
        })
    }

    pub async fn consent(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        request_id: &str,
        decision: ConsentDecision,
        correlation_id: Option<&str>,
    ) -> Result<ConsentOutcome, OAuthError> {
        let id = parse_request_id(request_id)?;
        let now = self.clock.now();
        let request = match self
            .storage
            .pending_authorizations()
            .consume(&id, session_id, now)
            .await
        {
            Ok(request) => request,
            Err(RepoError::NotFound) => return Err(OAuthError::ConsentNotFound),
            Err(RepoError::Expired) => return Err(OAuthError::ConsentExpired),
            Err(RepoError::AlreadyConsumed) => return Err(OAuthError::ConsentUsed),
            Err(error) => return Err(map_repo(error)),
        };
        if request.user_id != *user_id {
            return Err(OAuthError::ConsentNotFound);
        }

        if decision == ConsentDecision::Deny {
            return Ok(ConsentOutcome {
                redirect_to: self.redirect_with_error(&request, "access_denied")?,
            });
        }

        let client = self
            .storage
            .clients()
            .get(&request.client_id)
            .await
            .map_err(map_repo)?
            .ok_or(OAuthError::UnauthorizedClient)?;
        if client.status != ClientStatus::Approved {
            return Err(OAuthError::UnauthorizedClient);
        }
        if !scope::is_subset(&request.scopes, &client.allowed_scopes) {
            return Err(OAuthError::InvalidScope);
        }

        // The consent page is the one place allowed to re-grant after a revoke.
        self.grant_consent(
            *user_id,
            request.client_id,
            &request.scopes,
            now,
            correlation_id,
            None,
        )
        .await?;
        let code = self
            .issue_code(
                *user_id,
                &AuthorizeRequest {
                    client_id: request.client_id,
                    redirect_uri: request.redirect_uri.clone(),
                    scopes: request.scopes.clone(),
                    state: request.state.clone(),
                    code_challenge: request.code_challenge.clone(),
                    nonce: request.nonce.clone(),
                    auth_time: request.auth_time,
                },
                correlation_id,
            )
            .await?;
        Ok(ConsentOutcome {
            redirect_to: self.redirect_with_code(
                &AuthorizeRequest {
                    client_id: request.client_id,
                    redirect_uri: request.redirect_uri,
                    scopes: request.scopes,
                    state: request.state,
                    code_challenge: request.code_challenge,
                    nonce: request.nonce,
                    auth_time: request.auth_time,
                },
                &code,
            )?,
        })
    }

    /// Validates only what is needed before redirecting an error: the client is
    /// approved and `redirect_uri` is registered (RFC 6749 §4.1.2.1). The rest
    /// of the request is validated by `authorize`.
    pub async fn validate_client_redirect(
        &self,
        client_id: ClientId,
        redirect_uri: &str,
    ) -> Result<Client, OAuthError> {
        re0auth_api::redirect_uri::validate(redirect_uri)
            .map_err(|_| OAuthError::InvalidRequest("redirect_uri"))?;
        let client = self
            .storage
            .clients()
            .get(&client_id)
            .await
            .map_err(map_repo)?
            .ok_or(OAuthError::UnauthorizedClient)?;
        if client.status != ClientStatus::Approved {
            return Err(OAuthError::UnauthorizedClient);
        }
        if !client
            .redirect_uris
            .iter()
            .any(|candidate| candidate == redirect_uri)
        {
            return Err(OAuthError::InvalidRequest("redirect_uri"));
        }
        Ok(client)
    }

    fn validate_authorize_request(
        &self,
        client: &Client,
        request: &AuthorizeRequest,
    ) -> Result<(), OAuthError> {
        if request.scopes.is_empty() || request.code_challenge.is_empty() {
            return Err(OAuthError::InvalidRequest("scope/code_challenge"));
        }
        // 登记规则同源，旧脏数据在这里也会被拒
        re0auth_api::redirect_uri::validate(&request.redirect_uri)
            .map_err(|_| OAuthError::InvalidRequest("redirect_uri"))?;
        if client.status != ClientStatus::Approved {
            return Err(OAuthError::UnauthorizedClient);
        }
        if !client
            .redirect_uris
            .iter()
            .any(|candidate| candidate == &request.redirect_uri)
        {
            return Err(OAuthError::InvalidRequest("redirect_uri"));
        }
        if !scope::is_subset(&request.scopes, &client.allowed_scopes) {
            return Err(OAuthError::InvalidScope);
        }
        Ok(())
    }

    async fn issue_code(
        &self,
        user_id: UserId,
        request: &AuthorizeRequest,
        request_id: Option<&str>,
    ) -> Result<String, OAuthError> {
        let now = self.clock.now();
        let (raw, hash) = new_secret(self.random.as_ref());
        let code = AuthCode {
            id: AuthCodeId::new(),
            code_hash: hash,
            client_id: request.client_id,
            user_id,
            redirect_uri: request.redirect_uri.clone(),
            scopes: request.scopes.clone(),
            code_challenge: Some(request.code_challenge.clone()),
            code_challenge_method: Some("S256".to_string()),
            nonce: request.nonce.clone(),
            auth_time: request.auth_time,
            created_at: now,
            expires_at: now + re0auth_domain::auth_code_ttl(now),
            consumed_at: None,
            family_id: None,
        };
        let fact = SecurityFact::new(
            AuditAction::AuthCodeIssued,
            now,
            format!("auth_code:{}", code.id.0),
        )
        .actor(user_id)
        .client(request.client_id)
        .with_request_id(request_id);
        self.storage
            .auth_codes()
            .insert(&code, &fact)
            .await
            .map_err(map_repo)?;
        Ok(raw)
    }

    async fn grant_consent(
        &self,
        user_id: UserId,
        client_id: ClientId,
        requested: &[String],
        now: Unix,
        correlation_id: Option<&str>,
        // `None` = interactive grant (may revive). `Some(t)` = device flow,
        // where a revocation at or after `t` still wins.
        revive_after: Option<Unix>,
    ) -> Result<Consent, OAuthError> {
        // INV-CONSENT-01: the consent record stores only the union of scopes.
        let existing = self
            .storage
            .consents()
            .find(&user_id, &client_id)
            .await
            .map_err(map_repo)?;
        // 覆盖已授权 scopes 时不重复写入，避免误 bump version
        if let Some(consent) = &existing
            && scope::is_subset(requested, &consent.scopes)
        {
            return Ok(consent.clone());
        }
        let (id, created_at, mut scopes) = match existing {
            Some(consent) => (consent.id, consent.created_at, consent.scopes),
            None => (ConsentId::new(), now, Vec::new()),
        };
        for requested_scope in requested {
            if !scopes.contains(requested_scope) {
                scopes.push(requested_scope.clone());
            }
        }
        scopes.sort();
        scopes.dedup();
        let fact = SecurityFact::new(
            AuditAction::ConsentGranted,
            now,
            format!("consent:{client_id:?}"),
        )
        .actor(user_id)
        .client(client_id)
        .with_request_id(correlation_id);
        let pending = Consent {
            id,
            user_id,
            client_id,
            scopes,
            created_at,
            updated_at: now,
            revoked_at: None,
            version: ConsentVersion(0),
        };
        // The consent page always revives. The device flow revives only when the
        // revocation predates the device code being exchanged; a revoke after
        // the flow began wins (INV-AUTHZ-02).
        let stored = match revive_after {
            None => self
                .storage
                .consents()
                .grant(&pending, &fact)
                .await
                .map(Some),
            Some(threshold) => {
                self.storage
                    .consents()
                    .grant_if_live(&pending, &fact, threshold)
                    .await
            }
        }
        .map_err(map_repo)?
        .ok_or(OAuthError::InvalidGrant("consent revoked"))?;
        Ok(stored)
    }

    fn redirect_with_code(
        &self,
        request: &AuthorizeRequest,
        code: &str,
    ) -> Result<String, OAuthError> {
        let mut url = Url::parse(&request.redirect_uri)
            .map_err(|_| OAuthError::InvalidRequest("redirect_uri"))?;
        url.query_pairs_mut().append_pair("code", code);
        if let Some(state) = &request.state {
            url.query_pairs_mut().append_pair("state", state);
        }
        Ok(url.to_string())
    }

    fn redirect_with_error(
        &self,
        request: &PendingAuthorization,
        error: &str,
    ) -> Result<String, OAuthError> {
        let mut url = Url::parse(&request.redirect_uri)
            .map_err(|_| OAuthError::InvalidRequest("redirect_uri"))?;
        url.query_pairs_mut().append_pair("error", error);
        if let Some(state) = &request.state {
            url.query_pairs_mut().append_pair("state", state);
        }
        Ok(url.to_string())
    }

    pub async fn device_authorization(
        &self,
        client_id: ClientId,
        secret: Option<&str>,
        scopes: Vec<String>,
    ) -> Result<DeviceAuthorizationResponse, OAuthError> {
        // RFC 8628 §3.1 reads scope as optional. Omitting it means the
        // client's registered default set, not an empty grant.
        let client = self.authenticate_client(client_id, secret).await?;
        let scopes = if scopes.is_empty() {
            client.allowed_scopes.clone()
        } else {
            scopes
        };
        if scopes.is_empty() || !scope::is_subset(&scopes, &client.allowed_scopes) {
            return Err(OAuthError::InvalidScope);
        }
        let now = self.clock.now();
        let ttl = device::device_code_ttl(now);
        let interval = device::device_poll_interval();
        // Drawn once, not per attempt: the device code is 8 random bytes, so a
        // collision there is a defect rather than an unlucky draw, and redrawing
        // it would hide exactly the bug worth seeing.
        let (device_code, device_code_hash) = new_secret(self.random.as_ref());
        let verification_uri = format!("{}/device", self.issuer);

        // The user code is eight characters a human types, drawn from ~2^40, so a
        // collision is possible rather than theoretical — and `user_code_hash` is
        // UNIQUE, so a collision is a refused insert. RFC 8628 §6.1 leaves the
        // code space ours to choose, so the answer is another draw.
        for _ in 0..USER_CODE_ATTEMPTS {
            let user_code = device::generate_user_code(self.random.as_ref());
            let user_code_hash = hash_secret(&device::normalize_user_code(&user_code));
            let code = DeviceCode {
                id: DeviceCodeId::new(),
                device_code_hash: device_code_hash.clone(),
                user_code_hash,
                client_id,
                scopes: scopes.clone(),
                state: DeviceCodeState::Pending,
                interval_secs: interval,
                last_polled_at: None,
                poll_count: 0,
                user_code_misses: 0,
                created_at: now,
                expires_at: now + ttl,
                consumed_at: None,
                family_id: None,
            };
            match self.storage.device_codes().insert(&code).await {
                Ok(()) => {
                    let verification_uri_complete =
                        format!("{verification_uri}?user_code={user_code}");
                    return Ok(DeviceAuthorizationResponse {
                        device_code,
                        user_code,
                        verification_uri,
                        verification_uri_complete,
                        expires_in: ttl,
                        interval,
                    });
                }
                Err(RepoError::UserCodeConflict) => continue,
                // Only the user code is retried. Anything else is either the
                // client's fault or ours, and redrawing would report it as
                // neither.
                Err(error) => return Err(map_repo(error)),
            }
        }
        // The code space is ours and it did not yield in a handful of draws. That
        // is our problem, not the client's, so it must not surface as
        // `invalid_request`.
        Err(OAuthError::Internal)
    }

    pub async fn exchange_device_code(
        &self,
        client_id: ClientId,
        client_secret: Option<&str>,
        device_code: &str,
        correlation_id: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        self.authenticate_client(client_id, client_secret).await?;
        let now = self.clock.now();
        let hash = hash_secret(device_code);
        // The family is only persisted if this poll consumes an approved code;
        // the token response then uses this same id.
        let family = FamilyId::new();

        let outcome = self
            .storage
            .device_codes()
            .poll(&hash, now, client_id, &family)
            .await
            .map_err(map_repo)?;
        match outcome {
            DevicePoll::Pending => Err(OAuthError::AuthorizationPending),
            DevicePoll::SlowDown { interval_secs } => Err(OAuthError::SlowDown { interval_secs }),
            DevicePoll::ClientMismatch => Err(OAuthError::InvalidGrant("client mismatch")),
            DevicePoll::Approved {
                user_id,
                scopes,
                created_at,
                ..
            } => {
                // B15: a banned account must not turn an approved device code
                // into a grant, even if it was approved before the ban.
                self.require_active_user(user_id).await?;
                // D2=A: the token exchange is the point where the device
                // authorization becomes a consent record. A token can never
                // exist without one.
                let consent = self
                    .grant_consent(
                        user_id,
                        client_id,
                        &scopes,
                        now,
                        correlation_id,
                        Some(created_at),
                    )
                    .await?;
                let (refresh_raw, refresh_hash) = new_secret(self.random.as_ref());
                let refresh = RefreshToken {
                    id: RefreshTokenId::new(),
                    token_hash: refresh_hash,
                    family_id: family,
                    client_id,
                    user_id,
                    scopes: scopes.clone(),
                    created_at: now,
                    family_created_at: now,
                    auth_time: now,
                    expires_at: now + re0auth_domain::refresh_token_ttl(now),
                    consumed_at: None,
                    revoked_at: None,
                    replaced_by: None,
                };
                // Sign first: a signer failure must not leave a refresh token
                // nobody can ever learn.
                let signed = self
                    .sign_tokens(
                        user_id,
                        client_id,
                        &scopes,
                        now,
                        None,
                        Some(now),
                        consent.version,
                        &family,
                    )
                    .await?;
                self.storage
                    .refresh_tokens()
                    .insert(&refresh)
                    .await
                    .map_err(map_repo)?;
                Ok(signed.into_response(Some(refresh_raw)))
            }
            DevicePoll::Denied => Err(OAuthError::AccessDenied),
            DevicePoll::Expired => Err(OAuthError::ExpiredToken),
            DevicePoll::Consumed { family } => {
                self.revoke_replayed_device_code(family, client_id, now)
                    .await?;
                Err(OAuthError::InvalidGrant("device code already consumed"))
            }
            DevicePoll::NotFound => Err(OAuthError::InvalidGrant("unknown device code")),
        }
    }

    pub async fn exchange_code(
        &self,
        client_id: ClientId,
        client_secret: Option<&str>,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, OAuthError> {
        // Before `consume`: a wrong secret must not burn the code.
        self.authenticate_client(client_id, client_secret).await?;
        // 先校验 verifier 语法
        if !pkce::is_valid_verifier(code_verifier) {
            return Err(OAuthError::InvalidRequest("code_verifier"));
        }
        let challenge = pkce::challenge_s256(code_verifier);
        let code_hash = hash_secret(code);
        let now = self.clock.now();
        let family_id = FamilyId::new();
        let attempt = self
            .storage
            .auth_codes()
            .consume(
                ConsumeAuthCode {
                    code_hash: &code_hash,
                    client_id,
                    redirect_uri,
                    code_challenge: Some(&challenge),
                    code_challenge_method: Some("S256"),
                    family_id,
                },
                now,
            )
            .await;
        let grant = match attempt {
            Ok(grant) => grant,
            // 重放则回收该码签发的令牌
            Err(RepoError::AlreadyConsumed) => {
                self.revoke_replayed_code(&code_hash, client_id, now)
                    .await?;
                return Err(OAuthError::InvalidGrant("already consumed"));
            }
            Err(error) => return Err(map_repo(error)),
        };

        let consent = self
            .require_grant_consent(grant.user_id, client_id, &grant.scopes)
            .await?;

        let (refresh_raw, refresh_hash) = new_secret(self.random.as_ref());
        let refresh = RefreshToken {
            id: RefreshTokenId::new(),
            token_hash: refresh_hash,
            family_id,
            client_id,
            user_id: grant.user_id,
            scopes: grant.scopes.clone(),
            created_at: now,
            family_created_at: now,
            auth_time: now,
            expires_at: now + re0auth_domain::refresh_token_ttl(now),
            consumed_at: None,
            revoked_at: None,
            replaced_by: None,
        };
        // Sign first: a signer failure must not leave an unreachable refresh
        // row behind. The auth code is already consumed either way.
        let signed = self
            .sign_tokens(
                grant.user_id,
                client_id,
                &grant.scopes,
                now,
                grant.nonce,
                Some(grant.auth_time),
                consent.version,
                &family_id,
            )
            .await?;
        self.storage
            .refresh_tokens()
            .insert(&refresh)
            .await
            .map_err(map_repo)?;

        Ok(signed.into_response(Some(refresh_raw)))
    }

    /// 重放已消费的设备码时，撤销它签发过的家族。
    async fn revoke_replayed_device_code(
        &self,
        family: Option<FamilyId>,
        client_id: ClientId,
        now: Unix,
    ) -> Result<(), OAuthError> {
        let Some(family) = family else {
            // Codes consumed before the family column existed have nothing to
            // revoke; their tokens expire normally.
            return Ok(());
        };
        let fact = SecurityFact::new(
            AuditAction::DeviceCodeReuseDetected,
            now,
            format!("family:{}", family.0),
        )
        .client(client_id);
        self.storage
            .refresh_tokens()
            .revoke_family(&family, &fact, now)
            .await
            .map_err(map_repo)?;
        Ok(())
    }

    /// 重放已兑换的码时，撤销它签发过的家族
    async fn revoke_replayed_code(
        &self,
        code_hash: &[u8],
        client_id: ClientId,
        now: Unix,
    ) -> Result<(), OAuthError> {
        let Some((family_id, owner)) = self
            .storage
            .auth_codes()
            .family_and_client_of(code_hash)
            .await
            .map_err(map_repo)?
        else {
            return Ok(());
        };
        // A client that did not receive this code must not be able to revoke
        // the family it issued; the response is the same either way.
        if owner != client_id {
            return Ok(());
        }
        let fact = SecurityFact::new(
            AuditAction::AuthCodeReuseDetected,
            now,
            format!("family:{}", family_id.0),
        )
        .client(owner);
        self.storage
            .refresh_tokens()
            .revoke_family(&family_id, &fact, now)
            .await
            .map_err(map_repo)?;
        Ok(())
    }

    pub async fn refresh(
        &self,
        client_id: ClientId,
        client_secret: Option<&str>,
        raw_refresh: &str,
        requested_scope: Option<&[String]>,
        correlation_id: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        // Before the rotation claim: a wrong secret must not rotate the token.
        self.authenticate_client(client_id, client_secret).await?;
        let now = self.clock.now();
        let old_hash = hash_secret(raw_refresh);
        let old = self
            .storage
            .refresh_tokens()
            .find(&old_hash)
            .await
            .map_err(map_repo)?
            .ok_or(OAuthError::InvalidGrant("unknown refresh token"))?;
        if old.client_id != client_id {
            return Err(OAuthError::InvalidGrant("client mismatch"));
        }
        if old.revoked_at.is_some() || old.expires_at <= now {
            return Err(OAuthError::InvalidGrant("expired or revoked"));
        }
        if now.saturating_sub(old.family_created_at)
            >= re0auth_domain::refresh_token_absolute_ttl(now)
        {
            return Err(OAuthError::InvalidGrant(
                "refresh token family exceeded its absolute lifetime",
            ));
        }
        // RFC 6749 §6: a requested scope must be a subset of the original
        // grant; omitting it keeps the original scopes.
        let scopes = match requested_scope {
            // An explicit empty scope is not "all scopes"; it is a malformed
            // request (RFC 6749 §3.3).
            Some([]) => {
                return Err(OAuthError::InvalidScope);
            }
            Some(requested) => {
                if !scope::is_subset(requested, &old.scopes) {
                    return Err(OAuthError::InvalidScope);
                }
                requested.to_vec()
            }
            None => old.scopes.clone(),
        };
        let consent = self
            .require_grant_consent(old.user_id, client_id, &scopes)
            .await?;

        let (new_raw, new_hash) = new_secret(self.random.as_ref());
        // Sign before the rotation claim: a signer failure must leave the old
        // token usable and no unreachable replacement behind.
        let signed = self
            .sign_tokens(
                old.user_id,
                old.client_id,
                &scopes,
                now,
                None,
                Some(old.auth_time),
                consent.version,
                &old.family_id,
            )
            .await?;
        let new = RefreshToken {
            id: RefreshTokenId::new(),
            token_hash: new_hash,
            family_id: old.family_id,
            client_id: old.client_id,
            user_id: old.user_id,
            scopes: scopes.clone(),
            created_at: now,
            family_created_at: old.family_created_at,
            auth_time: old.auth_time,
            expires_at: now + re0auth_domain::refresh_token_ttl(now),
            consumed_at: None,
            revoked_at: None,
            replaced_by: None,
        };
        let outcome = self
            .storage
            .refresh_tokens()
            .rotate(
                RotateRefreshToken {
                    old_hash: &old_hash,
                    new,
                },
                // The storage layer re-labels this as a reuse fact if it turns
                // out the token was already consumed.
                &SecurityFact::new(
                    AuditAction::RefreshTokenRotated,
                    now,
                    format!("family:{}", old.family_id.0),
                )
                .actor(old.user_id)
                .client(old.client_id)
                .with_request_id(correlation_id),
                now,
            )
            .await
            .map_err(map_repo)?;

        match outcome {
            RotateOutcome::Rotated(_) => Ok(signed.into_response(Some(new_raw))),
            RotateOutcome::ReuseDetected { .. } => {
                Err(OAuthError::InvalidGrant("refresh token reuse"))
            }
            RotateOutcome::Expired => Err(OAuthError::InvalidGrant("expired")),
            RotateOutcome::Revoked => Err(OAuthError::InvalidGrant("revoked")),
            RotateOutcome::NotFound => Err(OAuthError::InvalidGrant("not found")),
        }
    }

    /// Verifies an access token for the data plane and returns the caller's
    /// identity, granted scopes and the client it was issued to. Unlike
    /// `userinfo` it does not require the `openid` scope: a gateway token only
    /// needs the connector's own scope.
    ///
    /// `client_id` is returned because the data plane budgets by client
    /// (INV-RATE-01): one bot must not be able to spend the instance's whole
    /// capacity, and the budget must follow the token rather than the address.
    pub async fn verify_gateway_token(
        &self,
        access_token: &str,
    ) -> Result<(UserId, String, String), OAuthError> {
        let claims = self
            .signer
            .verify_access(access_token)
            .map_err(|_| OAuthError::InvalidToken)?;
        if claims.token_use != ACCESS_TOKEN_USE {
            return Err(OAuthError::InvalidToken);
        }
        self.reject_if_revoked(&claims).await?;
        let user_id = Uuid::parse_str(&claims.sub)
            .map(UserId)
            .map_err(|_| OAuthError::InvalidToken)?;
        if self
            .storage
            .users()
            .get(&user_id)
            .await
            .map_err(map_repo)?
            .is_none()
        {
            return Err(OAuthError::InvalidToken);
        }
        let client_id = Uuid::parse_str(&claims.client_id)
            .map(ClientId)
            .map_err(|_| OAuthError::InvalidToken)?;
        self.require_approved_client(client_id).await?;
        let scopes = scope::parse_scope(&claims.scope);
        self.require_token_consent(user_id, client_id, &scopes, claims.consent_version)
            .await?;
        Ok((user_id, claims.scope, claims.client_id))
    }

    pub async fn userinfo(&self, access_token: &str) -> Result<UserInfo, OAuthError> {
        let claims = self
            .signer
            .verify_access(access_token)
            .map_err(|_| OAuthError::InvalidToken)?;
        if claims.token_use != ACCESS_TOKEN_USE
            || !claims
                .scope
                .split_ascii_whitespace()
                .any(|scope| scope == "openid")
        {
            return Err(OAuthError::InvalidToken);
        }
        self.reject_if_revoked(&claims).await?;
        let user_id = Uuid::parse_str(&claims.sub)
            .map(UserId)
            .map_err(|_| OAuthError::InvalidToken)?;
        let user = self
            .storage
            .users()
            .get(&user_id)
            .await
            .map_err(map_repo)?
            .ok_or(OAuthError::InvalidToken)?;
        if user.status == UserStatus::Banned {
            return Err(OAuthError::InvalidToken);
        }
        let client_id = Uuid::parse_str(&claims.client_id)
            .map(ClientId)
            .map_err(|_| OAuthError::InvalidToken)?;
        // A suspended client loses its tokens immediately, not at their TTL.
        self.require_approved_client(client_id).await?;
        let scopes = scope::parse_scope(&claims.scope);
        self.require_token_consent(user_id, client_id, &scopes, claims.consent_version)
            .await?;
        // OIDC Core §5.4: `name` belongs to the `profile` scope; an `openid`
        // only grant must not disclose it.
        let include_profile = scopes.iter().any(|scope| scope == "profile");
        Ok(UserInfo {
            sub: claims.sub,
            name: include_profile.then_some(user.display_name),
        })
    }

    /// A revoked token must fail identically to a forged one: telling the caller
    /// *why* it was rejected would confirm the token was once valid.
    async fn reject_if_revoked(&self, claims: &AccessTokenClaims) -> Result<(), OAuthError> {
        let now = self.clock.now();
        let family = Uuid::parse_str(&claims.family_id)
            .map(FamilyId)
            .map_err(|_| OAuthError::InvalidToken)?;
        if self
            .storage
            .access_tokens()
            .is_denied(&claims.jti, &family, now)
            .await
            .map_err(map_repo)?
        {
            return Err(OAuthError::InvalidToken);
        }
        Ok(())
    }

    /// Revokes the token in `token`, per RFC 7009.
    ///
    /// The token may be an access JWT or an opaque refresh token. The endpoint
    /// must answer 200 even for unknown or malformed tokens: a different status
    /// would let a caller probe whether a token exists. The returned outcome
    /// records which branch actually ran without changing the response.
    pub async fn revoke_token(
        &self,
        token: &str,
        client_id: ClientId,
        client_secret: Option<&str>,
        correlation_id: Option<&str>,
    ) -> Result<RevocationOutcome, OAuthError> {
        self.authenticate_client(client_id, client_secret).await?;
        let now = self.clock.now();

        if let Ok(claims) = self.signer.verify_access(token) {
            if claims.token_use != ACCESS_TOKEN_USE {
                return Ok(RevocationOutcome::Unknown);
            }
            // RFC 7009 §2.1: a client may only revoke tokens issued to it. The
            // response stays 200 either way so this cannot become an oracle.
            if claims.client_id != client_id.0.to_string() {
                return Ok(RevocationOutcome::NotOwned);
            }
            let revoked_by = Uuid::parse_str(&claims.sub).ok().map(UserId);
            let mut fact = SecurityFact::new(
                AuditAction::AccessTokenRevoked,
                now,
                format!("jti:{}", claims.jti),
            )
            .client(client_id)
            .with_request_id(correlation_id);
            if let Some(user) = revoked_by {
                fact = fact.actor(user);
            }
            self.storage
                .access_tokens()
                .revoke(
                    &claims.jti,
                    Some(client_id),
                    revoked_by,
                    claims.exp,
                    &fact,
                    now,
                )
                .await
                .map_err(map_repo)?;
            return Ok(RevocationOutcome::Revoked);
        }

        // Not an access JWT: it may be the opaque refresh token. Look it up by
        // hash and revoke the whole family, because the caller asked to end the
        // grant that token represents.
        let hash = hash_secret(token);
        let Some(stored) = self
            .storage
            .refresh_tokens()
            .find(&hash)
            .await
            .map_err(map_repo)?
        else {
            return Ok(RevocationOutcome::Unknown);
        };
        if stored.client_id != client_id {
            return Ok(RevocationOutcome::NotOwned);
        }
        let fact = SecurityFact::new(
            AuditAction::RefreshTokenRevoked,
            now,
            format!("family:{}", stored.family_id.0),
        )
        .actor(stored.user_id)
        .client(stored.client_id)
        .with_request_id(correlation_id);
        // 同事务写入 revoked_families，连带失效该家族访问令牌
        self.storage
            .refresh_tokens()
            .revoke_family(&stored.family_id, &fact, now)
            .await
            .map_err(map_repo)?;
        Ok(RevocationOutcome::Revoked)
    }

    /// A banned account must not obtain or keep an OAuth grant (B15).
    ///
    /// The session and gateway paths already read the status; this closes the
    /// issuance paths (code exchange, refresh, device flow), which only looked
    /// at consent before.
    async fn require_active_user(&self, user_id: UserId) -> Result<(), OAuthError> {
        let user = self
            .storage
            .users()
            .get(&user_id)
            .await
            .map_err(map_repo)?
            .ok_or(OAuthError::InvalidGrant("user not found"))?;
        if user.status == UserStatus::Banned {
            return Err(OAuthError::InvalidGrant("account banned"));
        }
        Ok(())
    }

    /// A suspended or revoked client must lose its tokens at once.
    ///
    /// `authenticate_client` covers issuance; a token that already exists
    /// bypasses it, so the bearer boundary re-checks the live status instead of
    /// trusting the JWT until it expires.
    async fn require_approved_client(&self, client_id: ClientId) -> Result<(), OAuthError> {
        let client = self
            .storage
            .clients()
            .get(&client_id)
            .await
            .map_err(map_repo)?
            .ok_or(OAuthError::InvalidToken)?;
        if client.status != ClientStatus::Approved {
            return Err(OAuthError::InvalidToken);
        }
        Ok(())
    }

    /// Consent check for token issuance (code exchange, refresh, device flow).
    ///
    /// A missing or revoked consent is `invalid_grant`: the grant itself is no
    /// longer valid. This is deliberately separate from the token check below,
    /// whose failure is `invalid_token` at the bearer boundary.
    async fn require_grant_consent(
        &self,
        user_id: UserId,
        client_id: ClientId,
        scopes: &[String],
    ) -> Result<Consent, OAuthError> {
        self.require_active_user(user_id).await?;
        let consent = self
            .storage
            .consents()
            .find(&user_id, &client_id)
            .await
            .map_err(map_repo)?
            .ok_or(OAuthError::InvalidGrant("consent revoked"))?;
        if !scope::is_subset(scopes, &consent.scopes) {
            return Err(OAuthError::InvalidGrant("consent scope"));
        }
        Ok(consent)
    }

    /// Consent check for an already-signed access token.
    ///
    /// The version comparison is what makes revocation immediate: the consent
    /// row increments its version on revoke/re-grant, so every token issued
    /// under an older version fails even though its JWT still verifies.
    async fn require_token_consent(
        &self,
        user_id: UserId,
        client_id: ClientId,
        scopes: &[String],
        version: ConsentVersion,
    ) -> Result<(), OAuthError> {
        let consent = self
            .storage
            .consents()
            .find(&user_id, &client_id)
            .await
            .map_err(map_repo)?
            .ok_or(OAuthError::InvalidToken)?;
        if consent.version != version || !scope::is_subset(scopes, &consent.scopes) {
            return Err(OAuthError::InvalidToken);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn sign_tokens(
        &self,
        user_id: UserId,
        client_id: ClientId,
        scopes: &[String],
        now: i64,
        nonce: Option<String>,
        auth_time: Option<Unix>,
        consent_version: ConsentVersion,
        family: &FamilyId,
    ) -> Result<SignedTokens, OAuthError> {
        let scope_value = scopes.join(" ");
        let access_claims = AccessTokenClaims {
            iss: self.issuer.clone(),
            sub: user_id.0.to_string(),
            aud: self.resource.clone(),
            client_id: client_id.0.to_string(),
            scope: scope_value.clone(),
            exp: now + re0auth_domain::access_token_ttl(now),
            iat: now,
            jti: URL_SAFE_NO_PAD.encode(self.random.bytes(16)),
            token_use: ACCESS_TOKEN_USE.to_string(),
            family_id: family.0.to_string(),
            consent_version,
        };
        let id_claims = scopes
            .iter()
            .any(|scope| scope == "openid")
            .then(|| IdTokenClaims {
                iss: self.issuer.clone(),
                sub: user_id.0.to_string(),
                aud: client_id.0.to_string(),
                exp: now + re0auth_domain::access_token_ttl(now),
                iat: now,
                nonce,
                auth_time,
            });

        // Two independent RSA signatures, ~0.76 ms each. Running them on the
        // blocking pool concurrently halves the endpoint's wall time without
        // changing what is signed.
        let access_task = spawn_signature({
            let signer = self.signer.clone();
            move || signer.sign_access(&access_claims)
        });
        let id_task = id_claims.map(|claims| {
            spawn_signature({
                let signer = self.signer.clone();
                move || signer.sign_id(&claims)
            })
        });

        let access_token = await_signature(access_task).await?;
        let id_token = match id_task {
            Some(task) => Some(await_signature(task).await?),
            None => None,
        };

        Ok(SignedTokens {
            access_token,
            id_token,
            expires_in: re0auth_domain::access_token_ttl(now),
            scope: scope_value,
        })
    }
}

/// A signed token pair that is not yet attached to a refresh token.
///
/// Signing is fallible, so it must finish before any single-use credential is
/// consumed; only then does the caller commit the refresh row and wrap this in
/// a `TokenResponse`.
struct SignedTokens {
    access_token: String,
    id_token: Option<String>,
    expires_in: i64,
    scope: String,
}

impl SignedTokens {
    fn into_response(self, refresh_token: Option<String>) -> TokenResponse {
        TokenResponse {
            access_token: self.access_token,
            token_type: "Bearer",
            expires_in: self.expires_in,
            refresh_token,
            id_token: self.id_token,
            scope: self.scope,
        }
    }
}

type SignatureTask = tokio::task::JoinHandle<re0auth_api::Re0Result<String>>;

fn spawn_signature<F>(sign: F) -> SignatureTask
where
    F: FnOnce() -> re0auth_api::Re0Result<String> + Send + 'static,
{
    tokio::task::spawn_blocking(sign)
}

async fn await_signature(task: SignatureTask) -> Result<String, OAuthError> {
    task.await
        .map_err(|_| OAuthError::Internal)?
        .map_err(|_| OAuthError::Internal)
}

#[must_use]
pub fn hash_secret(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}

#[must_use]
pub fn parse_scope(raw: &str) -> Vec<String> {
    scope::parse_scope(raw)
}

/// RFC 7636 §4.2 challenge syntax, re-exported so the HTTP layer stays
/// dependent on `re0auth-app` rather than the domain crate.
#[must_use]
pub fn is_valid_challenge(challenge: &str) -> bool {
    pkce::is_valid_challenge(challenge)
}

fn parse_request_id(value: &str) -> Result<PendingAuthorizationId, OAuthError> {
    Uuid::parse_str(value)
        .map(PendingAuthorizationId)
        .map_err(|_| OAuthError::ConsentNotFound)
}

fn new_secret(random: &dyn Random) -> (String, Vec<u8>) {
    let raw = URL_SAFE_NO_PAD.encode(random.bytes(32));
    let hash = hash_secret(&raw);
    (raw, hash)
}

fn map_repo(error: RepoError) -> OAuthError {
    match error {
        RepoError::NotFound => OAuthError::InvalidGrant("not found"),
        RepoError::Expired => OAuthError::InvalidGrant("expired"),
        RepoError::AlreadyConsumed => OAuthError::InvalidGrant("already consumed"),
        RepoError::Revoked => OAuthError::InvalidGrant("revoked"),
        RepoError::Conflict(_) => OAuthError::InvalidRequest("conflict"),
        // Unreachable from `device_authorization`, which redraws instead; a
        // caller that did not retry is looking at our failure to draw a code, not
        // at anything the client did.
        RepoError::UserCodeConflict => OAuthError::Internal,
        RepoError::Busy => OAuthError::TemporarilyUnavailable,
        RepoError::Backend(_) => OAuthError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use re0auth_api::ports::MissingBinding;

    /// The schema twin must stay field-for-field equal to the port type it
    /// stands in for; nothing else can catch the two drifting apart.
    #[test]
    fn missing_bindings_shape_matches_the_port() {
        let port = MissingBinding {
            upstream_id: "phihub".to_string(),
            scopes: vec!["save_info".to_string()],
        };
        let shape = super::MissingBindingShape {
            upstream_id: port.upstream_id.clone(),
            scopes: port.scopes.clone(),
        };
        assert_eq!(
            serde_json::to_value(&port).expect("the port serialises"),
            serde_json::to_value(&shape).expect("the shape serialises"),
        );
    }

    use super::*;

    #[test]
    fn busy_maps_to_temporarily_unavailable() {
        assert!(matches!(
            map_repo(RepoError::Busy),
            OAuthError::TemporarilyUnavailable
        ));
    }
}
