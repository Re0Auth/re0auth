//! Login, session/CSRF, and device-approval use cases.
use re0auth_api::audit::{AuditAction, SecurityFact};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uuid::Uuid;

use re0auth_api::idp::{IdpClient, IdpError};
use re0auth_api::oauth::{APPROVAL_TICKET_USE, ApprovalTicketClaims, TokenSigner};
use re0auth_api::ports::{
    ApprovalDecision, ApprovalTicket, Binding, BindingStatus, Identity, LoginPurpose,
    LoginTransaction, RepoError, Session, Storage, User, UserRole, UserStatus,
};
use re0auth_api::{BindingId, ClientId, Clock, IdentityId, Random, SessionId, UserId};
use re0auth_domain::{
    approval_ticket_ttl, device, login_state_ttl, pkce, session_absolute_ttl, session_idle_ttl,
};
use serde::Serialize;

use crate::oauth::hash_secret;
use crate::return_to;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("login required")]
    LoginRequired,
    /// The account exists but is not admitted (B15).
    #[error("account is banned")]
    AccountBanned,
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("invalid csrf token")]
    Csrf,
    #[error("login state not found")]
    StateInvalid,
    #[error("login state expired")]
    StateExpired,
    #[error("login state already used")]
    StateConsumed,
    #[error("identity provider is not configured")]
    IdpUnavailable,
    /// The requested provider name is not in the configuration.
    #[error("unknown identity provider")]
    UnknownIdentityProvider,
    /// Several providers exist and the caller did not pick one.
    #[error("identity provider must be chosen")]
    IdentityProviderRequired,
    #[error("identity provider: {0}")]
    Idp(#[from] IdpError),
    #[error("storage: {0}")]
    Repo(#[from] RepoError),
    #[error("invalid approval ticket")]
    InvalidTicket,
    #[error("approval ticket expired")]
    TicketExpired,
    #[error("approval ticket already used")]
    TicketConsumed,
    #[error("device code is not available")]
    DeviceUnavailable,
    #[error("not found")]
    NotFound,
    /// The account has one identity left; removing it would lock the account out
    /// for good. Deleting the account is the operation that intent needs.
    #[error("an account must keep at least one identity")]
    LastIdentity,
    /// The identity is already attached to a different account. There is no merge.
    #[error("this identity is already bound to another account")]
    IdentityAlreadyBound,
    /// A login arrived while signed in with an identity this server has never
    /// seen. Creating an account there is how one person gets two orphans, so the
    /// only way forward is the account page.
    #[error("you are signed in; attach the login method from the account page")]
    LoginRequiresAttach,
    /// A login arrived while signed in and would switch accounts. Switching is a
    /// deliberate act, so it has to start from a signed-out state.
    #[error("sign out before signing in with another account")]
    LoginRequiresLogout,
    #[error("too many attempts")]
    RateLimited,
    #[error("internal error")]
    Internal,
}

pub type AuthResult<T> = Result<T, AuthError>;

#[derive(Clone)]
pub struct LoginStart {
    pub url: String,
    /// The `state` handed to the identity provider.
    ///
    /// INV-LOGIN-05: the HTTP layer binds it to the browser that started the
    /// login. It is a short-lived secret, so `Debug` redacts it.
    pub state: String,
}

impl std::fmt::Debug for LoginStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginStart")
            .field("url", &self.url)
            .field("state", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct CreatedSession {
    pub cookie: String,
    pub csrf_token: String,
    pub session: Session,
}

#[derive(Clone, Debug)]
pub struct SessionContext {
    pub session: Session,
    pub user: User,
}

#[derive(Clone, Debug)]
pub struct DeviceInfo {
    pub client_id: ClientId,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, utoipa::ToSchema)]
pub struct AuthorizationView {
    pub client_id: String,
    pub client_name: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// One upstream binding, as shown in the account portal.
///
/// Deliberately excludes the sealed sub-credential: the portal needs to know
/// that a binding exists and whether it is usable, never what it can decrypt to.
#[derive(Clone, Debug, Serialize, utoipa::ToSchema)]
pub struct BindingView {
    pub id: String,
    pub connector: String,
    pub status: &'static str,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_refreshed_at: Option<i64>,
    /// The upstream's own error code, e.g. `upstream_401`. Present only when the
    /// binding needs the user to re-authorize.
    pub last_error_code: Option<String>,
}

/// The outcome of the binding killswitch.
///
/// A summary rather than a bare count so that adding an upstream revocation
/// step later does not change the wire contract — but it carries no `failed`
/// list today, because the local store commits in one transaction and cannot
/// produce a partial success.
#[derive(Clone, Debug, Serialize, utoipa::ToSchema)]
pub struct BindingRevocationSummary {
    pub revoked: u64,
    /// Bindings the cascade left alone because the upstream would not confirm.
    ///
    /// A cascade keeps the credential when the upstream cannot be reached
    /// (F-6): the credential is the only way to retry, and deleting it would
    /// hide a token that is still alive upstream. The list makes that visible
    /// instead of reporting a clean sweep.
    pub failed: Vec<FailedRevocation>,
}

/// One binding a cascade could not revoke upstream.
#[derive(Clone, Debug, Serialize, utoipa::ToSchema)]
pub struct FailedRevocation {
    pub id: String,
    pub upstream: String,
    pub reason: &'static str,
}

fn binding_status_str(status: BindingStatus) -> &'static str {
    match status {
        BindingStatus::Pending => "pending",
        BindingStatus::Active => "active",
        BindingStatus::NeedsReauth => "needs_reauth",
        BindingStatus::Revoked => "revoked",
    }
}

#[derive(Clone, Debug)]
pub enum LoginOutcome {
    Session {
        created: CreatedSession,
        return_to: String,
    },
    DeviceApproval {
        ticket: String,
        user_code: String,
        client_id: ClientId,
        scopes: Vec<String>,
    },
    /// The identity was attached to the account that started the flow. No session
    /// is created: the caller already has one.
    IdentityAttached,
}

#[derive(Clone)]
pub struct AuthService {
    storage: Arc<dyn Storage>,
    /// INV-IDP-01: providers keyed by their stable name. Empty means login is
    /// unavailable, which is the same state as "not configured" before.
    idps: Vec<NamedIdp>,
    signer: Arc<dyn TokenSigner>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn Random>,
    issuer: String,
    secure_cookies: bool,
    device_attempts: Arc<Mutex<HashMap<String, Vec<i64>>>>,
    /// INV-CACHE-02: swept when a binding is revoked, so the stale path cannot
    /// keep serving a player's data after they unbound.
    cache: Arc<dyn re0auth_api::cache::Cache>,
    /// 推断凭证失效的秒数阈值，0 表示不推断
    binding_probe_after_secs: i64,
}

/// One configured identity provider and the name that selects it.
#[derive(Clone)]
pub struct NamedIdp {
    pub name: String,
    /// Human-readable label for the login selector. Defaults to `name`.
    pub display_name: String,
    pub client: Arc<dyn IdpClient>,
}

impl std::fmt::Debug for NamedIdp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamedIdp")
            .field("name", &self.name)
            .field("display_name", &self.display_name)
            .finish()
    }
}

/// A provider as exposed to the login UI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct ProviderView {
    pub name: String,
    pub display_name: String,
}

impl AuthService {
    #[must_use]
    pub fn new(
        storage: Arc<dyn Storage>,
        idps: Vec<NamedIdp>,
        signer: Arc<dyn TokenSigner>,
        clock: Arc<dyn Clock>,
        random: Arc<dyn Random>,
        issuer: impl Into<String>,
    ) -> Self {
        let issuer = issuer.into().trim_end_matches('/').to_string();
        let secure_cookies = issuer.starts_with("https://");
        Self {
            storage,
            idps,
            signer,
            clock,
            random,
            issuer,
            secure_cookies,
            device_attempts: Arc::new(Mutex::new(HashMap::new())),
            cache: Arc::new(re0auth_api::cache::NoCache),
            binding_probe_after_secs: 0,
        }
    }

    /// 启用超时未刷新即视为失效的推断
    #[must_use]
    pub fn with_binding_probe(mut self, after_days: u64) -> Self {
        self.binding_probe_after_secs = i64::try_from(after_days)
            .unwrap_or(i64::MAX)
            .saturating_mul(86_400);
        self
    }

    /// Enables cache invalidation on binding revoke (INV-CACHE-02).
    ///
    /// Separate from [`Self::new`] so wiring that has no cache keeps compiling,
    /// and so "no invalidation" is an explicit default rather than an oversight.
    #[must_use]
    pub fn with_cache(mut self, cache: Arc<dyn re0auth_api::cache::Cache>) -> Self {
        self.cache = cache;
        self
    }

    /// The default provider, or `None` when none is configured.
    ///
    /// Used only to render a selector and to keep the single-provider path free
    /// of a required query parameter. Never used to pick a provider at callback
    /// time — that comes from the login transaction (INV-IDP-01).
    fn sole_or_none(&self) -> Option<&NamedIdp> {
        self.idps.first()
    }

    /// Resolves the provider a login should start against.
    ///
    /// An omitted name means "the only configured provider"; with several, the
    /// caller must choose. Guessing would silently log users into the wrong IdP.
    fn provider_for_start(&self, requested: Option<&str>) -> AuthResult<&NamedIdp> {
        match (
            requested.map(str::trim).filter(|name| !name.is_empty()),
            self.idps.len(),
        ) {
            (Some(name), _) => self
                .idps
                .iter()
                .find(|idp| idp.name == name)
                .ok_or(AuthError::UnknownIdentityProvider),
            (None, 1) => self.sole_or_none().ok_or(AuthError::IdpUnavailable),
            (None, 0) => Err(AuthError::IdpUnavailable),
            (None, _) => Err(AuthError::IdentityProviderRequired),
        }
    }

    /// Providers in configuration order, for rendering a login selector.
    #[must_use]
    pub fn providers(&self) -> Vec<ProviderView> {
        self.idps
            .iter()
            .map(|idp| ProviderView {
                name: idp.name.clone(),
                display_name: idp.display_name.clone(),
            })
            .collect()
    }

    #[must_use]
    pub fn secure_cookies(&self) -> bool {
        self.secure_cookies
    }

    #[must_use]
    pub fn device_attempt_allowed(&self, client_ip: &str) -> bool {
        let now = self.clock.now();
        let cutoff = now - device::device_attempt_window();
        let mut attempts = self
            .device_attempts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entries = attempts.entry(client_ip.to_string()).or_default();
        entries.retain(|at| *at > cutoff);
        entries.len() < device::device_attempt_limit()
    }

    pub fn record_device_failure(&self, client_ip: &str) {
        let now = self.clock.now();
        let mut attempts = self
            .device_attempts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entries = attempts.entry(client_ip.to_string()).or_default();
        if entries.len() < device::device_attempt_limit() {
            entries.push(now);
        }
    }

    pub fn clear_device_attempts(&self, client_ip: &str) {
        self.device_attempts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(client_ip);
    }

    pub async fn device_code_attempt_locked(
        &self,
        client_ip: &str,
        user_code: &str,
    ) -> AuthResult<bool> {
        let hash = hash_secret(&device::normalize_user_code(user_code));
        let misses = self
            .storage
            .device_attempts()
            .misses(client_ip, &hash, self.clock.now())
            .await?;
        Ok(misses >= device::device_attempt_limit() as u32)
    }

    pub async fn record_device_code_miss(
        &self,
        client_ip: &str,
        user_code: &str,
    ) -> AuthResult<()> {
        let hash = hash_secret(&device::normalize_user_code(user_code));
        self.storage
            .device_attempts()
            .record_miss(client_ip, &hash, self.clock.now())
            .await?;
        Ok(())
    }

    pub async fn clear_device_code_attempts(
        &self,
        client_ip: &str,
        user_code: &str,
    ) -> AuthResult<()> {
        let hash = hash_secret(&device::normalize_user_code(user_code));
        self.storage
            .device_attempts()
            .clear(client_ip, &hash)
            .await?;
        Ok(())
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub async fn start_login(
        &self,
        return_to: &str,
        provider: Option<&str>,
    ) -> AuthResult<LoginStart> {
        self.start(return_to, provider, LoginPurpose::Login, None)
            .await
    }

    /// Starts an attach flow: the identity that comes back joins `user`.
    ///
    /// The intent travels in the transaction because an IdP has one configured
    /// redirect URI: both flows land on `/auth/callback`, and only the stored
    /// purpose can tell them apart (ADR-0050).
    pub async fn start_attach(
        &self,
        user: UserId,
        return_to: &str,
        provider: Option<&str>,
    ) -> AuthResult<LoginStart> {
        self.start(return_to, provider, LoginPurpose::Attach, Some(user))
            .await
    }

    async fn start(
        &self,
        return_to: &str,
        provider: Option<&str>,
        purpose: LoginPurpose,
        initiator: Option<UserId>,
    ) -> AuthResult<LoginStart> {
        if !return_to::is_safe(return_to) {
            return Err(AuthError::InvalidRequest("invalid return_to"));
        }
        let idp = self.provider_for_start(provider)?;
        let now = self.clock.now();
        let state = URL_SAFE_NO_PAD.encode(self.random.bytes(32));
        let nonce = URL_SAFE_NO_PAD.encode(self.random.bytes(16));
        let verifier = URL_SAFE_NO_PAD.encode(self.random.bytes(32));
        let challenge = pkce::challenge_s256(&verifier);
        let transaction = LoginTransaction {
            state_hash: hash_secret(&state),
            nonce: nonce.clone(),
            pkce_verifier: verifier,
            return_to: return_to.to_string(),
            // INV-IDP-01: bound here, read back at the callback.
            provider: idp.name.clone(),
            purpose,
            initiator,
            created_at: now,
            expires_at: now + login_state_ttl(now),
            consumed_at: None,
        };
        self.storage
            .login_transactions()
            .insert(&transaction)
            .await?;
        Ok(LoginStart {
            url: idp.client.authorization_url(&state, &nonce, &challenge),
            state,
        })
    }

    pub async fn complete_login(
        &self,
        code: &str,
        state: &str,
        current: Option<UserId>,
    ) -> AuthResult<LoginOutcome> {
        // Checked before the state lookup on purpose: an instance with no provider
        // configured cannot complete any login, so saying so is more honest than
        // reporting the state as invalid and sending the user to retry.
        if self.idps.is_empty() {
            return Err(AuthError::IdpUnavailable);
        }
        let now = self.clock.now();
        let transaction = match self
            .storage
            .login_transactions()
            .consume(&hash_secret(state), now)
            .await
        {
            Ok(transaction) => transaction,
            Err(RepoError::NotFound) => return Err(AuthError::StateInvalid),
            Err(RepoError::Expired) => return Err(AuthError::StateExpired),
            Err(RepoError::AlreadyConsumed) => return Err(AuthError::StateConsumed),
            Err(error) => return Err(AuthError::Repo(error)),
        };

        // INV-IDP-01: the provider comes from the transaction, never from the
        // callback's query string. A caller must not be able to present one IdP's
        // code to another IdP's token endpoint.
        let idp = self
            .idps
            .iter()
            .find(|idp| idp.name == transaction.provider)
            .ok_or(AuthError::UnknownIdentityProvider)?;

        let identity = idp
            .client
            .exchange_code(code, &transaction.pkce_verifier, &transaction.nonce)
            .await?;

        // Resolved before the device branch on purpose: an attach flow never
        // approves a device, whatever its `return_to` says.
        if transaction.purpose == LoginPurpose::Attach {
            return self
                .attach_identity(&identity, &transaction, current, now)
                .await;
        }

        let user_id = self.upsert_identity(&identity, now, current).await?;

        if let Some(user_code) = device_user_code(&transaction.return_to)? {
            let normalized = device::normalize_user_code(&user_code);
            let device_code = self
                .storage
                .device_codes()
                .find_by_user_code_hash(&hash_secret(&normalized))
                .await?
                .ok_or(AuthError::DeviceUnavailable)?;
            if !device_code.state.is_pending() || device_code.expires_at <= now {
                return Err(AuthError::DeviceUnavailable);
            }

            let formatted = device::format_user_code(&normalized);
            let jti = URL_SAFE_NO_PAD.encode(self.random.bytes(16));
            let expires_at = now + approval_ticket_ttl(now);
            let ticket = self
                .signer
                .sign_approval_ticket(&ApprovalTicketClaims {
                    iss: self.issuer.clone(),
                    sub: user_id.0.to_string(),
                    aud: self.issuer.clone(),
                    user_code: formatted.clone(),
                    exp: expires_at,
                    iat: now,
                    jti: jti.clone(),
                    token_use: APPROVAL_TICKET_USE.to_string(),
                })
                .map_err(|_| AuthError::Internal)?;
            self.storage
                .approval_tickets()
                .insert(&ApprovalTicket {
                    jti,
                    user_id,
                    user_code: formatted.clone(),
                    expires_at,
                    consumed_at: None,
                })
                .await?;
            return Ok(LoginOutcome::DeviceApproval {
                ticket,
                user_code: formatted,
                client_id: device_code.client_id,
                scopes: device_code.scopes,
            });
        }

        let created = self.create_session(user_id).await?;
        Ok(LoginOutcome::Session {
            created,
            return_to: transaction.return_to,
        })
    }

    pub async fn create_session(&self, user_id: UserId) -> AuthResult<CreatedSession> {
        Ok(create_session_record(
            self.storage.as_ref(),
            self.clock.as_ref(),
            self.random.as_ref(),
            user_id,
        )
        .await?)
    }

    pub async fn session_context(&self, cookie: &str) -> AuthResult<SessionContext> {
        // 封禁后再访问会话入口一律拒绝；会话本身通常已被撤销，这里是第二道闸。
        let now = self.clock.now();
        let id_hash = hash_secret(cookie);
        let session = self
            .storage
            .sessions()
            .find_active(&id_hash, now)
            .await?
            .ok_or(AuthError::LoginRequired)?;
        self.storage
            .sessions()
            .touch(&id_hash, now, now + session_idle_ttl(now))
            .await
            .map_err(|error| match error {
                RepoError::NotFound | RepoError::Revoked => AuthError::LoginRequired,
                other => AuthError::Repo(other),
            })?;
        let user = self
            .storage
            .users()
            .get(&session.user_id)
            .await?
            .ok_or(AuthError::LoginRequired)?;
        if user.status == UserStatus::Banned {
            return Err(AuthError::AccountBanned);
        }
        Ok(SessionContext { session, user })
    }

    #[must_use]
    pub fn validate_csrf(&self, session: &Session, token: &str) -> bool {
        csrf_matches(token, &session.csrf_hash)
    }

    pub async fn logout(&self, cookie: &str) -> AuthResult<()> {
        let now = self.clock.now();
        match self
            .storage
            .sessions()
            .revoke(&hash_secret(cookie), now)
            .await
        {
            Ok(()) | Err(RepoError::NotFound) => Ok(()),
            Err(error) => Err(AuthError::Repo(error)),
        }
    }

    pub async fn logout_all(&self, user_id: UserId) -> AuthResult<u64> {
        Ok(self
            .storage
            .sessions()
            .revoke_all(&user_id, self.clock.now())
            .await?)
    }

    /// The login methods attached to an account, oldest first.
    ///
    /// The subject never leaves the app layer: the portal only needs an id to act
    /// on and something to show, and the subject is the IdP-side identifier.
    pub async fn list_identities(&self, user_id: UserId) -> AuthResult<Vec<Identity>> {
        Ok(self.storage.users().list_identities(&user_id).await?)
    }

    /// Detaches one login method from an account.
    ///
    /// The last one cannot go: an account with zero identities can never be
    /// entered again, so allowing it would be an irreversible self-lockout
    /// dressed up as cleanup. Deleting the account is the operation for that.
    pub async fn detach_identity(&self, user_id: UserId, identity: IdentityId) -> AuthResult<()> {
        let identities = self.storage.users().list_identities(&user_id).await?;
        if !identities.iter().any(|candidate| candidate.id == identity) {
            return Err(AuthError::NotFound);
        }
        if identities.len() < 2 {
            return Err(AuthError::LastIdentity);
        }
        if !self
            .storage
            .users()
            .unlink_identity(&user_id, &identity)
            .await?
        {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    /// Deletes the account and everything hanging off it.
    ///
    /// The fact commits with the deletion (`UserRepo::delete_with_fact`); the
    /// foreign key nulls its actor, so the trail keeps the target and loses the
    /// link to a person who no longer exists.
    ///
    /// Revoking upstream credentials is **not** done here: that needs the binding
    /// surface, and a live credential left behind because the local row vanished
    /// is the exact failure F-6 exists to prevent. The caller cascades first and
    /// aborts when an upstream refuses.
    pub async fn delete_account(
        &self,
        user_id: UserId,
        correlation_id: Option<&str>,
    ) -> AuthResult<()> {
        let fact = SecurityFact::new(
            AuditAction::AccountDeleted,
            self.clock.now(),
            format!("user:{}", user_id.0),
        )
        .actor(user_id)
        .with_request_id(correlation_id);
        if !self
            .storage
            .users()
            .delete_with_fact(&user_id, &fact)
            .await?
        {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    pub async fn list_authorizations(&self, user_id: UserId) -> AuthResult<Vec<AuthorizationView>> {
        let consents = self.storage.consents().list_by_user(&user_id).await?;
        let mut views = Vec::with_capacity(consents.len());
        for consent in consents {
            let Some(client) = self.storage.clients().get(&consent.client_id).await? else {
                continue;
            };
            views.push(AuthorizationView {
                client_id: consent.client_id.0.to_string(),
                client_name: client.name,
                scopes: consent.scopes,
                created_at: consent.created_at,
                updated_at: consent.updated_at,
            });
        }
        Ok(views)
    }

    pub async fn revoke_authorization(
        &self,
        user_id: UserId,
        client_id: ClientId,
        correlation_id: Option<&str>,
    ) -> AuthResult<()> {
        let now = self.clock.now();
        // 先收令牌再撤销 consent；清理失败时授权仍有效，可重试
        self.storage
            .device_codes()
            .revoke_approved_for_client(&user_id, &client_id)
            .await
            .map_err(AuthError::Repo)?;
        let fact = SecurityFact::new(
            AuditAction::RefreshTokenRevoked,
            now,
            format!("user:{}:client:{}", user_id.0, client_id.0),
        )
        .actor(user_id)
        .client(client_id)
        .with_request_id(correlation_id);
        self.storage
            .refresh_tokens()
            .revoke_all_for_client(&user_id, &client_id, &fact, now)
            .await
            .map_err(AuthError::Repo)?;
        match self
            .storage
            .consents()
            .revoke(
                &user_id,
                &client_id,
                &SecurityFact::new(
                    AuditAction::ConsentRevoked,
                    now,
                    format!("consent:{client_id:?}"),
                )
                .actor(user_id)
                .client(client_id)
                .with_request_id(correlation_id),
                now,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(RepoError::NotFound) => Err(AuthError::NotFound),
            Err(error) => Err(AuthError::Repo(error)),
        }
    }

    /// Lists the caller's upstream bindings.
    ///
    /// Revoked rows are filtered out: the row survives so the audit trail still
    /// resolves, but showing it in the portal would make a user who just pressed
    /// "unlink" believe the action did not work.
    pub async fn list_bindings(&self, user_id: UserId) -> AuthResult<Vec<BindingView>> {
        let bindings = self.storage.bindings().list_by_user(&user_id).await?;
        let now = self.clock.now();
        let mut views = Vec::with_capacity(bindings.len());
        for mut binding in bindings {
            if binding.status == BindingStatus::Revoked {
                continue;
            }
            self.downgrade_if_stale(&mut binding, now).await;
            views.push(BindingView {
                id: binding.id.0.to_string(),
                connector: binding.upstream_id,
                status: binding_status_str(binding.status),
                created_at: binding.created_at,
                updated_at: binding.updated_at,
                last_refreshed_at: binding.last_refreshed_at,
                last_error_code: binding.last_error_code,
            });
        }
        Ok(views)
    }

    /// 超过阈值未刷新则推断凭证失效
    async fn downgrade_if_stale(&self, binding: &mut Binding, now: i64) {
        if self.binding_probe_after_secs <= 0 || binding.status != BindingStatus::Active {
            return;
        }
        let since = binding.last_refreshed_at.unwrap_or(binding.created_at);
        if now.saturating_sub(since) <= self.binding_probe_after_secs {
            return;
        }
        let fact = SecurityFact::new(
            AuditAction::BindingNeedsReauth,
            now,
            format!("binding:{}", binding.id.0),
        )
        .actor(binding.user_id);
        let marked = self
            .storage
            .bindings()
            .mark_needs_reauth(&binding.id, "stale_credential", &fact, now)
            .await;
        // 标记失败不阻断列表，下次访问再试
        if marked.is_ok() {
            binding.status = BindingStatus::NeedsReauth;
            binding.last_error_code = Some("stale_credential".to_string());
        }
    }

    /// Revokes a binding and deletes its stored sub-credential atomically.
    ///
    /// Ownership is enforced by the query, not by a read-then-write check: a
    /// caller passing someone else's binding id must get `NotFound` rather than
    /// a race window.
    pub async fn revoke_binding(
        &self,
        user_id: UserId,
        binding_id: BindingId,
        correlation_id: Option<&str>,
    ) -> AuthResult<()> {
        let now = self.clock.now();
        let owned = self
            .storage
            .bindings()
            .list_by_user(&user_id)
            .await?
            .into_iter()
            .any(|binding| binding.id == binding_id);
        if !owned {
            return Err(AuthError::NotFound);
        }
        let fact = SecurityFact::new(
            AuditAction::BindingRevoked,
            now,
            format!("binding:{}", binding_id.0),
        )
        .actor(user_id)
        .with_request_id(correlation_id);
        match self
            .storage
            .bindings()
            .revoke(&binding_id, &fact, now)
            .await
        {
            Ok(()) => {
                // INV-CACHE-02: the revoke is already durable, so the sweep
                // cannot be skipped by a later error. Doing it before the write
                // would open a window where a concurrent fetch repopulates the
                // cache for a binding that is about to disappear.
                self.cache
                    .invalidate(&re0auth_api::cache::binding_prefix(&binding_id))
                    .await;
                Ok(())
            }
            Err(RepoError::NotFound) => Err(AuthError::NotFound),
            Err(error) => Err(AuthError::Repo(error)),
        }
    }

    /// Revokes every binding the caller owns, in one transaction.
    ///
    /// The killswitch answers "my account is compromised, cut everything". It is
    /// deliberately all-or-nothing: a half-revoked account is the state hardest
    /// to reason about. `revoked` counts what moved, so a retry after an
    /// uncertain response reports zero rather than failing.
    pub async fn revoke_all_bindings(
        &self,
        user_id: UserId,
        correlation_id: Option<&str>,
    ) -> AuthResult<BindingRevocationSummary> {
        let now = self.clock.now();
        // Read the ids first: INV-CACHE-02 needs the prefix of every binding
        // that is about to disappear, and a bulk update does not report them.
        let active: Vec<BindingId> = self
            .storage
            .bindings()
            .list_by_user(&user_id)
            .await?
            .into_iter()
            .filter(|binding| binding.status != BindingStatus::Revoked)
            .map(|binding| binding.id)
            .collect();
        let fact = SecurityFact::new(
            AuditAction::BindingRevoked,
            now,
            format!("user:{}", user_id.0),
        )
        .actor(user_id)
        .with_request_id(correlation_id);
        let revoked = self
            .storage
            .bindings()
            .revoke_all(&user_id, &fact, now)
            .await?;
        // After the commit, for the same reason as the single revoke: a later
        // error must not skip the sweep, and sweeping first would let a
        // concurrent fetch repopulate a binding that is about to vanish.
        for id in &active {
            self.cache
                .invalidate(&re0auth_api::cache::binding_prefix(id))
                .await;
        }
        Ok(BindingRevocationSummary {
            revoked,
            failed: Vec::new(),
        })
    }

    #[must_use]
    pub fn device_verification_uri(&self, user_code: &str) -> String {
        let formatted = device::format_user_code(&device::normalize_user_code(user_code));
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer.append_pair("user_code", &formatted);
        format!("{}/device?{}", self.issuer, serializer.finish())
    }

    pub async fn device_info(&self, user_code: &str) -> AuthResult<DeviceInfo> {
        let normalized = device::normalize_user_code(user_code);
        if normalized.len() != 8 {
            return Err(AuthError::DeviceUnavailable);
        }
        let now = self.clock.now();
        let code = self
            .storage
            .device_codes()
            .find_by_user_code_hash(&hash_secret(&normalized))
            .await?
            .ok_or(AuthError::DeviceUnavailable)?;
        if !code.state.is_pending() || code.expires_at <= now {
            return Err(AuthError::DeviceUnavailable);
        }
        Ok(DeviceInfo {
            client_id: code.client_id,
            scopes: code.scopes,
        })
    }

    pub async fn decide_device(
        &self,
        ticket: &str,
        decision: ApprovalDecision,
        correlation_id: Option<&str>,
    ) -> AuthResult<ClientId> {
        let claims = self
            .signer
            .verify_approval_ticket(ticket)
            .map_err(|_| AuthError::InvalidTicket)?;
        let user_id = Uuid::parse_str(&claims.sub)
            .map(UserId)
            .map_err(|_| AuthError::InvalidTicket)?;
        let user_code = device::normalize_user_code(&claims.user_code);
        let now = self.clock.now();
        // INV-AUDIT-01: the device approval is the authorization decision ADR-0025
        // names, and the only point where the flow can be attributed to a client.
        // `client_id` is filled in by the store, which reads it off the device
        // code in the same transaction — the ticket does not carry it.
        let action = match decision {
            ApprovalDecision::Approve => AuditAction::DeviceApproved,
            ApprovalDecision::Deny => AuditAction::DeviceDenied,
        };
        // `target` carries the hashed user code, never the code itself: a device
        // approval row outlives the flow, and the plain code is a credential.
        let target = format!(
            "user_code_hash:{}",
            URL_SAFE_NO_PAD.encode(hash_secret(&user_code))
        );
        let fact = SecurityFact::new(action, now, target)
            .actor(user_id)
            .with_request_id(correlation_id);
        match self
            .storage
            .approval_tickets()
            .consume_and_decide(
                &claims.jti,
                user_id,
                &hash_secret(&user_code),
                decision,
                &fact,
                now,
            )
            .await
        {
            Ok(client_id) => Ok(client_id),
            Err(RepoError::AlreadyConsumed) => Err(AuthError::TicketConsumed),
            Err(RepoError::Expired) => Err(AuthError::TicketExpired),
            Err(RepoError::NotFound | RepoError::Conflict(_)) => Err(AuthError::DeviceUnavailable),
            Err(error) => Err(AuthError::Repo(error)),
        }
    }

    /// Resolves the account behind a freshly exchanged identity.
    ///
    /// `current` is the account whose session is already present, if any. When it
    /// is set, two refusals apply (ADR-0050):
    ///
    /// - an identity this server has never seen is **not** turned into a new
    ///   account: that is exactly how one person ends up with two orphans, so the
    ///   only way forward is the account page (`login_requires_attach`);
    /// - an identity owned by somebody else is refused instead of switching the
    ///   session behind the user's back (`login_requires_logout`).
    async fn upsert_identity(
        &self,
        identity: &re0auth_api::idp::IdpIdentity,
        now: i64,
        current: Option<UserId>,
    ) -> AuthResult<UserId> {
        if let Some(user) = self
            .storage
            .users()
            .find_by_identity(&identity.issuer, &identity.subject)
            .await?
        {
            if current.is_some_and(|current| current != user.id) {
                return Err(AuthError::LoginRequiresLogout);
            }
            // 封禁在登录入口就要拦住，不能等到会话建立之后。
            if user.status == UserStatus::Banned {
                return Err(AuthError::AccountBanned);
            }
            return Ok(user.id);
        }

        if current.is_some() {
            return Err(AuthError::LoginRequiresAttach);
        }

        let user = User {
            id: UserId::new(),
            display_name: display_name(identity),
            role: UserRole::User,
            status: re0auth_api::ports::UserStatus::Active,
            created_at: now,
            updated_at: now,
        };
        self.storage.users().create(&user).await?;
        let linked = Identity {
            id: IdentityId::new(),
            user_id: user.id,
            issuer: identity.issuer.clone(),
            subject: identity.subject.clone(),
            created_at: now,
        };
        match self.storage.users().link_identity(&linked).await {
            Ok(()) => Ok(user.id),
            Err(RepoError::Conflict(_)) => {
                let existing = self
                    .storage
                    .users()
                    .find_by_identity(&identity.issuer, &identity.subject)
                    .await?
                    .ok_or(AuthError::Internal)?;
                let _ = self.storage.users().delete(&user.id).await;
                Ok(existing.id)
            }
            Err(error) => Err(AuthError::Repo(error)),
        }
    }

    /// Attaches a freshly exchanged identity to the account that started the flow.
    ///
    /// The callback only gets here with a live session: `complete_login` passes the
    /// caller's account as `current`, and it must equal the initiator stored on the
    /// transaction. Re-attaching an identity the account already owns is a no-op
    /// rather than an error: the user asked for the end state, not an operation.
    async fn attach_identity(
        &self,
        identity: &re0auth_api::idp::IdpIdentity,
        transaction: &LoginTransaction,
        current: Option<UserId>,
        now: i64,
    ) -> AuthResult<LoginOutcome> {
        let initiator = transaction.initiator.ok_or(AuthError::StateInvalid)?;
        if current != Some(initiator) {
            return Err(AuthError::LoginRequiresLogout);
        }
        match self
            .storage
            .users()
            .find_by_identity(&identity.issuer, &identity.subject)
            .await?
        {
            Some(user) if user.id == initiator => {}
            Some(_) => return Err(AuthError::IdentityAlreadyBound),
            None => {
                let linked = Identity {
                    id: IdentityId::new(),
                    user_id: initiator,
                    issuer: identity.issuer.clone(),
                    subject: identity.subject.clone(),
                    created_at: now,
                };
                self.storage
                    .users()
                    .link_identity(&linked)
                    .await
                    .map_err(|error| match error {
                        RepoError::Conflict(_) => AuthError::IdentityAlreadyBound,
                        other => AuthError::Repo(other),
                    })?;
            }
        }
        Ok(LoginOutcome::IdentityAttached)
    }
}

pub async fn create_session_record(
    storage: &dyn Storage,
    clock: &dyn Clock,
    random: &dyn Random,
    user_id: UserId,
) -> Result<CreatedSession, RepoError> {
    let now = clock.now();
    let raw = URL_SAFE_NO_PAD.encode(random.bytes(32));
    let csrf_token = URL_SAFE_NO_PAD.encode(random.bytes(32));
    let session = Session {
        id: SessionId::new(),
        id_hash: hash_secret(&raw),
        user_id,
        csrf_hash: hash_secret(&csrf_token),
        created_at: now,
        last_seen_at: now,
        idle_expires_at: now + session_idle_ttl(now),
        absolute_expires_at: now + session_absolute_ttl(now),
        revoked_at: None,
    };
    storage.sessions().create(&session).await?;
    Ok(CreatedSession {
        cookie: raw,
        csrf_token,
        session,
    })
}

fn device_user_code(return_to: &str) -> AuthResult<Option<String>> {
    let url = return_to::parse(return_to).ok_or(AuthError::InvalidRequest("invalid return_to"))?;
    if url.path() != "/device" {
        return Ok(None);
    }
    url.query_pairs()
        .find(|(key, _)| key == "user_code")
        .map(|(_, value)| value.into_owned())
        .map(Some)
        .ok_or(AuthError::InvalidRequest("user_code is required"))
}

/// Compares a presented CSRF token against the stored digest.
///
/// Both sides are SHA-256 digests, so they are the same length and the compare
/// leaks nothing about position. `==` on slices short-circuits at the first
/// differing byte; the client-secret verifier already avoids that, and the CSRF
/// token is the same kind of secret. Not exploitable over a network in practice
/// — recovering a 256-bit digest from timing noise is not realistic — but the
/// rule has to hold everywhere or it is not a rule.
fn csrf_matches(token: &str, stored: &[u8]) -> bool {
    if token.is_empty() {
        return false;
    }
    let digest = hash_secret(token);
    bool::from(subtle::ConstantTimeEq::ct_eq(digest.as_slice(), stored))
}

fn display_name(identity: &re0auth_api::idp::IdpIdentity) -> String {
    if identity.display_name.trim().is_empty() {
        identity.subject.clone()
    } else {
        identity.display_name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_accepts_only_the_matching_token() {
        let stored = hash_secret("csrf-token");
        assert!(csrf_matches("csrf-token", &stored));
        assert!(!csrf_matches("csrf-toke", &stored));
        assert!(!csrf_matches("csrf-tokens", &stored));
        assert!(!csrf_matches("", &stored), "an empty token is never valid");
        assert!(
            !csrf_matches("csrf-token", &[]),
            "an empty digest matches nothing"
        );
    }

    #[test]
    fn csrf_rejects_a_digest_of_the_wrong_length() {
        // The constant-time comparison must report "not equal" rather than
        // panicking when the stored digest is not 32 bytes. A short-circuiting
        // `==` would also be false here, which is why this asserts the path that
        // the constant-time primitive touches.
        let mut stored = hash_secret("csrf-token");
        stored.truncate(8);
        assert!(!csrf_matches("csrf-token", &stored));
        stored.extend_from_slice(&[0u8; 4]);
        assert!(!csrf_matches("csrf-token", &stored));
    }
}
