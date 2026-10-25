//! In-memory storage used by unit tests.
//!
//! This is a test double, not a second production backend. It has no
//! transactions: `push_fact` runs after the state change and cannot be rolled
//! back with it. INV-AUDIT-01's atomicity is therefore asserted only against
//! SQLite (see `re0auth-adapters/tests/audit_invariants.rs`); do not read this
//! file as evidence that the invariant holds for this store.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use re0auth_api::audit::{AuditRecord, AuditTier, SecurityFact};
use re0auth_api::connector::ResourceSpec;
use re0auth_api::ports::{
    ANONYMIZED_UPSTREAM_USER_ID, AccessTokenRepo, ApprovalDecision, ApprovalTicket,
    ApprovalTicketRepo, AuditRepo, AuthCode, AuthCodeRepo, AuthGrant, Binding, BindingQuery,
    BindingRepo, BindingStatus, Client, ClientRepo, ConnectorRecord, ConnectorRepo, Consent,
    ConsentRepo, ConsumeAuthCode, DeviceAttemptRepo, DeviceCode, DeviceCodeRepo, DeviceCodeState,
    DeviceCodeStatus, DevicePoll, Identity, LoginTransaction, LoginTransactionRepo,
    PendingAuthorization, PendingAuthorizationRepo, PendingBinding, PendingBindingRepo,
    RefreshToken, RefreshTokenRepo, RepoError, RepoResult, RotateOutcome, RotateRefreshToken,
    Session, SessionRepo, SigningKeyRecord, SigningKeyRepo, Storage, User, UserRepo, UserRole,
};
use re0auth_api::secret::SealedSecret;
use re0auth_api::{
    BindingId, ClientId, ConnectorId, FamilyId, PendingAuthorizationId, SessionId, Unix, UserId,
};

mod audit;
mod clients;

#[derive(Default)]
struct Inner {
    users: HashMap<UserId, User>,
    identities: HashMap<(String, String), Identity>,
    sessions: HashMap<Vec<u8>, Session>,
    auth_codes: HashMap<Vec<u8>, AuthCode>,
    refresh_tokens: HashMap<Vec<u8>, RefreshToken>,
    device_codes: HashMap<Vec<u8>, DeviceCode>,
    device_attempts: HashMap<(String, Vec<u8>), (u32, i64)>,
    sub_credentials: HashMap<BindingId, SealedSecret>,
    login_transactions: HashMap<Vec<u8>, LoginTransaction>,
    pending_bindings: HashMap<Vec<u8>, PendingBinding>,
    approval_tickets: HashMap<String, ApprovalTicket>,
    consents: HashMap<(UserId, ClientId), Consent>,
    pending_authorizations: HashMap<PendingAuthorizationId, PendingAuthorization>,
    bindings: HashMap<BindingId, Binding>,
    /// When each binding was revoked, so the anonymization window does not have
    /// to ride on `Binding::updated_at` (which any later write moves).
    binding_revocations: HashMap<BindingId, Unix>,
    clients: HashMap<ClientId, Client>,
    audits: Vec<AuditRecord>,
    access_revocations: HashMap<String, Unix>,
    connectors: HashMap<ConnectorId, (ConnectorRecord, Vec<ResourceSpec>)>,
    connector_secrets: HashMap<(ConnectorId, String), SealedSecret>,
    signing_keys: HashMap<String, SigningKeyRecord>,
}

/// In-memory reference implementation of the storage ports.
///
/// **Not atomic.** Facts recorded alongside a change are appended on the same
/// call, but a `HashMap` has no rollback: if a later step fails, the fact stays.
/// The contract suite therefore skips the transaction-rollback case for this
/// implementation. It exists for fast unit tests, not for correctness claims.
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("memory store mutex poisoned")
    }

    /// Appends a fact. Sequenced, not transactional: see the type docs.
    fn push_fact(inner: &mut Inner, fact: &SecurityFact) {
        inner.audits.push(AuditRecord {
            id: fact.id,
            occurred_at: fact.occurred_at,
            actor_user_id: fact.actor_user_id,
            client_id: fact.client_id,
            action: fact.action,
            target: fact.target.clone(),
            outcome: fact.outcome,
            severity: fact.severity,
            request_id: fact.request_id.clone(),
            detail: "{}".to_string(),
            tier: AuditTier::Fact,
        });
    }
}

#[async_trait]
impl UserRepo for MemoryStore {
    async fn list(&self, before: Option<&UserId>, limit: u32) -> RepoResult<Vec<User>> {
        let inner = self.lock();
        let mut users: Vec<User> = inner
            .users
            .values()
            .filter(|user| before.is_none_or(|cursor| user.id.0 < cursor.0))
            .cloned()
            .collect();
        users.sort_by_key(|user| std::cmp::Reverse(user.id.0));
        users.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(users)
    }

    async fn set_role(
        &self,
        id: &UserId,
        role: UserRole,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()> {
        let mut inner = self.lock();
        let Some(user) = inner.users.get_mut(id) else {
            return Err(RepoError::NotFound);
        };
        user.role = role;
        user.updated_at = now;
        Self::push_fact(&mut inner, fact);
        Ok(())
    }

    async fn count_admins(&self) -> RepoResult<u64> {
        let inner = self.lock();
        Ok(inner
            .users
            .values()
            .filter(|user| user.role == UserRole::Admin)
            .count() as u64)
    }
    async fn create(&self, user: &User) -> RepoResult<()> {
        let mut inner = self.lock();
        if inner.users.contains_key(&user.id) {
            return Err(RepoError::Conflict("user id"));
        }
        inner.users.insert(user.id, user.clone());
        Ok(())
    }

    async fn get(&self, id: &UserId) -> RepoResult<Option<User>> {
        Ok(self.lock().users.get(id).cloned())
    }

    async fn link_identity(&self, identity: &Identity) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.users.contains_key(&identity.user_id) {
            return Err(RepoError::NotFound);
        }
        let key = (identity.issuer.clone(), identity.subject.clone());
        if inner.identities.contains_key(&key) {
            return Err(RepoError::Conflict("identity"));
        }
        inner.identities.insert(key, identity.clone());
        Ok(())
    }

    async fn find_by_identity(&self, issuer: &str, subject: &str) -> RepoResult<Option<User>> {
        let inner = self.lock();
        let Some(identity) = inner
            .identities
            .get(&(issuer.to_string(), subject.to_string()))
        else {
            return Ok(None);
        };
        Ok(inner.users.get(&identity.user_id).cloned())
    }

    async fn delete(&self, id: &UserId) -> RepoResult<bool> {
        let mut inner = self.lock();
        if inner.users.remove(id).is_none() {
            return Ok(false);
        }
        inner
            .identities
            .retain(|_, identity| identity.user_id != *id);
        inner.sessions.retain(|_, session| session.user_id != *id);
        inner.auth_codes.retain(|_, code| code.user_id != *id);
        inner.refresh_tokens.retain(|_, token| token.user_id != *id);
        inner
            .device_codes
            .retain(|_, code| code.state.approver() != Some(*id));
        inner
            .approval_tickets
            .retain(|_, ticket| ticket.user_id != *id);
        inner.consents.retain(|_, consent| consent.user_id != *id);
        inner
            .pending_authorizations
            .retain(|_, request| request.user_id != *id);
        let removed: Vec<BindingId> = inner
            .bindings
            .iter()
            .filter(|(_, binding)| binding.user_id == *id)
            .map(|(id, _)| *id)
            .collect();
        inner.bindings.retain(|_, binding| binding.user_id != *id);
        for binding in removed {
            inner.sub_credentials.remove(&binding);
        }
        Ok(true)
    }
}

#[async_trait]
impl SessionRepo for MemoryStore {
    async fn create(&self, session: &Session) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.users.contains_key(&session.user_id) {
            return Err(RepoError::NotFound);
        }
        if inner.sessions.contains_key(&session.id_hash) {
            return Err(RepoError::Conflict("session hash"));
        }
        inner
            .sessions
            .insert(session.id_hash.clone(), session.clone());
        Ok(())
    }

    async fn find_active(&self, id_hash: &[u8], now: Unix) -> RepoResult<Option<Session>> {
        let inner = self.lock();
        let Some(session) = inner.sessions.get(id_hash) else {
            return Ok(None);
        };
        let active = session.revoked_at.is_none()
            && now < session.idle_expires_at
            && now < session.absolute_expires_at;
        Ok(active.then(|| session.clone()))
    }

    async fn touch(&self, id_hash: &[u8], now: Unix, idle_expires_at: Unix) -> RepoResult<()> {
        let mut inner = self.lock();
        let Some(session) = inner.sessions.get_mut(id_hash) else {
            return Err(RepoError::NotFound);
        };
        if session.revoked_at.is_some() {
            return Err(RepoError::Revoked);
        }
        if now >= session.idle_expires_at || now >= session.absolute_expires_at {
            return Err(RepoError::NotFound);
        }
        session.last_seen_at = now;
        session.idle_expires_at = idle_expires_at;
        Ok(())
    }

    async fn revoke(&self, id_hash: &[u8], now: Unix) -> RepoResult<()> {
        let mut inner = self.lock();
        let Some(session) = inner.sessions.get_mut(id_hash) else {
            return Err(RepoError::NotFound);
        };
        session.revoked_at = Some(now);
        Ok(())
    }

    async fn revoke_all(&self, user: &UserId, now: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let mut revoked = 0;
        for session in inner.sessions.values_mut() {
            if session.user_id == *user && session.revoked_at.is_none() {
                session.revoked_at = Some(now);
                revoked += 1;
            }
        }
        Ok(revoked)
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let previous = inner.sessions.len();
        inner.sessions.retain(|_, session| {
            !(session.idle_expires_at <= before
                || session.absolute_expires_at <= before
                || session.revoked_at.is_some_and(|at| at <= before))
        });
        Ok((previous - inner.sessions.len()) as u64)
    }
}

#[async_trait]
impl AuthCodeRepo for MemoryStore {
    async fn insert(&self, code: &AuthCode, fact: &SecurityFact) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.users.contains_key(&code.user_id) {
            return Err(RepoError::NotFound);
        }
        if inner.auth_codes.contains_key(&code.code_hash) {
            return Err(RepoError::Conflict("auth code hash"));
        }
        inner
            .auth_codes
            .insert(code.code_hash.clone(), code.clone());
        Self::push_fact(&mut inner, fact);
        Ok(())
    }

    async fn consume(&self, req: ConsumeAuthCode<'_>, now: Unix) -> RepoResult<AuthGrant> {
        let mut inner = self.lock();
        let Some(code) = inner.auth_codes.get_mut(req.code_hash) else {
            return Err(RepoError::NotFound);
        };
        if code.consumed_at.is_some() {
            return Err(RepoError::AlreadyConsumed);
        }
        if code.expires_at <= now {
            return Err(RepoError::Expired);
        }
        if code.client_id != req.client_id
            || code.redirect_uri != req.redirect_uri
            || code.code_challenge.as_deref() != req.code_challenge
            || code.code_challenge_method.as_deref() != req.code_challenge_method
        {
            return Err(RepoError::NotFound);
        }
        code.consumed_at = Some(now);
        Ok(AuthGrant {
            user_id: code.user_id,
            client_id: code.client_id,
            redirect_uri: code.redirect_uri.clone(),
            scopes: code.scopes.clone(),
            nonce: code.nonce.clone(),
        })
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let previous = inner.auth_codes.len();
        inner.auth_codes.retain(|_, code| {
            !(code.expires_at <= before || code.consumed_at.is_some_and(|at| at <= before))
        });
        Ok((previous - inner.auth_codes.len()) as u64)
    }
}

#[async_trait]
impl RefreshTokenRepo for MemoryStore {
    async fn insert(&self, token: &RefreshToken) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.users.contains_key(&token.user_id) {
            return Err(RepoError::NotFound);
        }
        if inner.refresh_tokens.contains_key(&token.token_hash) {
            return Err(RepoError::Conflict("refresh token hash"));
        }
        inner
            .refresh_tokens
            .insert(token.token_hash.clone(), token.clone());
        Ok(())
    }

    async fn find(&self, token_hash: &[u8]) -> RepoResult<Option<RefreshToken>> {
        Ok(self.lock().refresh_tokens.get(token_hash).cloned())
    }

    async fn rotate(
        &self,
        req: RotateRefreshToken<'_>,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<RotateOutcome> {
        let mut inner = self.lock();
        let Some(mut old) = inner.refresh_tokens.get(req.old_hash).cloned() else {
            return Ok(RotateOutcome::NotFound);
        };
        if old.revoked_at.is_some() {
            return Ok(RotateOutcome::Revoked);
        }
        if old.expires_at <= now {
            return Ok(RotateOutcome::Expired);
        }
        if old.consumed_at.is_some() {
            let mut family_revoked = 0;
            for token in inner.refresh_tokens.values_mut() {
                if token.family_id == old.family_id && token.revoked_at.is_none() {
                    token.revoked_at = Some(now);
                    family_revoked += 1;
                }
            }
            Self::push_fact(&mut inner, &fact.as_reuse());
            return Ok(RotateOutcome::ReuseDetected { family_revoked });
        }
        if old.user_id != req.new.user_id
            || old.client_id != req.new.client_id
            || old.family_id != req.new.family_id
        {
            return Err(RepoError::Conflict("refresh token identity"));
        }
        if inner.refresh_tokens.contains_key(&req.new.token_hash) {
            return Err(RepoError::Conflict("refresh token hash"));
        }
        old.consumed_at = Some(now);
        old.replaced_by = Some(req.new.id);
        inner.refresh_tokens.insert(old.token_hash.clone(), old);
        let new = req.new;
        inner
            .refresh_tokens
            .insert(new.token_hash.clone(), new.clone());
        Self::push_fact(&mut inner, fact);
        Ok(RotateOutcome::Rotated(new))
    }

    async fn revoke_family(
        &self,
        family: &FamilyId,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<u64> {
        let mut inner = self.lock();
        let mut revoked = 0;
        for token in inner.refresh_tokens.values_mut() {
            if token.family_id == *family && token.revoked_at.is_none() {
                token.revoked_at = Some(now);
                revoked += 1;
            }
        }
        if revoked > 0 {
            Self::push_fact(&mut inner, fact);
        }
        Ok(revoked)
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let previous = inner.refresh_tokens.len();
        inner.refresh_tokens.retain(|_, token| {
            !(token.expires_at <= before
                || token.revoked_at.is_some_and(|at| at <= before)
                || token.consumed_at.is_some_and(|at| at <= before))
        });
        Ok((previous - inner.refresh_tokens.len()) as u64)
    }
}

#[async_trait]
#[async_trait]
impl DeviceCodeRepo for MemoryStore {
    async fn insert(&self, code: &DeviceCode) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.clients.contains_key(&code.client_id) {
            return Err(RepoError::NotFound);
        }
        if let Some(user) = code.state.approver()
            && !inner.users.contains_key(&user)
        {
            return Err(RepoError::NotFound);
        }
        // The user code is the one the caller redraws, so it gets its own signal;
        // the device code is 8 random bytes and a collision there is a defect, not
        // a retry.
        if inner
            .device_codes
            .values()
            .any(|existing| existing.user_code_hash == code.user_code_hash)
        {
            return Err(RepoError::UserCodeConflict);
        }
        if inner.device_codes.contains_key(&code.device_code_hash) {
            return Err(RepoError::Conflict("device code hash"));
        }
        inner
            .device_codes
            .insert(code.device_code_hash.clone(), code.clone());
        Ok(())
    }

    async fn find_by_device_hash(&self, hash: &[u8]) -> RepoResult<Option<DeviceCode>> {
        Ok(self.lock().device_codes.get(hash).cloned())
    }

    async fn find_by_user_code_hash(&self, hash: &[u8]) -> RepoResult<Option<DeviceCode>> {
        Ok(self
            .lock()
            .device_codes
            .values()
            .find(|code| code.user_code_hash == hash)
            .cloned())
    }

    async fn approve(&self, user_code_hash: &[u8], user_id: UserId, now: Unix) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.users.contains_key(&user_id) {
            return Err(RepoError::NotFound);
        }
        let Some(code) = inner
            .device_codes
            .values_mut()
            .find(|code| code.user_code_hash == user_code_hash)
        else {
            return Err(RepoError::NotFound);
        };
        if code.expires_at <= now {
            code.state = DeviceCodeState::Expired;
            return Err(RepoError::Expired);
        }
        if !code.state.is_pending() {
            return Err(RepoError::Conflict("device code is not pending"));
        }
        code.state = DeviceCodeState::Approved { approver: user_id };
        Ok(())
    }

    async fn deny(&self, user_code_hash: &[u8], now: Unix) -> RepoResult<()> {
        let mut inner = self.lock();
        let Some(code) = inner
            .device_codes
            .values_mut()
            .find(|code| code.user_code_hash == user_code_hash)
        else {
            return Err(RepoError::NotFound);
        };
        if code.expires_at <= now {
            code.state = DeviceCodeState::Expired;
            return Err(RepoError::Expired);
        }
        if !code.state.is_pending() {
            return Err(RepoError::Conflict("device code is not pending"));
        }
        // This path has no authenticated actor, so it records no approver.
        code.state = DeviceCodeState::Denied { approver: None };
        Ok(())
    }

    async fn poll(&self, device_code_hash: &[u8], now: Unix) -> RepoResult<DevicePoll> {
        let mut inner = self.lock();
        let Some(code) = inner.device_codes.get_mut(device_code_hash) else {
            return Ok(DevicePoll::NotFound);
        };

        if code.state.status() == DeviceCodeStatus::Consumed {
            return Ok(DevicePoll::Consumed);
        }
        if code.state.status() == DeviceCodeStatus::Denied {
            return Ok(DevicePoll::Denied);
        }
        if code.state.status() == DeviceCodeStatus::Expired || code.expires_at <= now {
            code.state = DeviceCodeState::Expired;
            return Ok(DevicePoll::Expired);
        }

        // No defensive `else` here any more: an approved code always carries
        // its approver, so the polling path cannot invent an expired code from
        // a half-written row.
        if let DeviceCodeState::Approved { approver: user_id } = code.state {
            code.state = DeviceCodeState::Consumed { approver: user_id };
            code.consumed_at = Some(now);
            code.last_polled_at = Some(now);
            return Ok(DevicePoll::Approved {
                client_id: code.client_id,
                user_id,
                scopes: code.scopes.clone(),
            });
        }

        if let Some(last) = code.last_polled_at
            && now < last + i64::from(code.interval_secs)
        {
            code.interval_secs += 5;
            code.last_polled_at = Some(now);
            return Ok(DevicePoll::SlowDown {
                interval_secs: code.interval_secs,
            });
        }

        code.last_polled_at = Some(now);
        code.poll_count += 1;
        Ok(DevicePoll::Pending)
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let before_len = inner.device_codes.len();
        inner.device_codes.retain(|_, code| {
            !(code.expires_at <= before || code.consumed_at.is_some_and(|at| at <= before))
        });
        Ok((before_len - inner.device_codes.len()) as u64)
    }
}

#[async_trait]
impl DeviceAttemptRepo for MemoryStore {
    async fn misses(&self, client_ip: &str, user_code_hash: &[u8], now: Unix) -> RepoResult<u32> {
        let inner = self.lock();
        let Some((misses, last_miss_at)) = inner
            .device_attempts
            .get(&(client_ip.to_string(), user_code_hash.to_vec()))
        else {
            return Ok(0);
        };
        if *last_miss_at <= now - 900 {
            Ok(0)
        } else {
            Ok(*misses)
        }
    }

    async fn record_miss(
        &self,
        client_ip: &str,
        user_code_hash: &[u8],
        now: Unix,
    ) -> RepoResult<u32> {
        let mut inner = self.lock();
        let key = (client_ip.to_string(), user_code_hash.to_vec());
        let entry = inner.device_attempts.entry(key).or_insert((0, now));
        if entry.1 <= now - 900 {
            *entry = (1, now);
        } else {
            entry.0 += 1;
            entry.1 = now;
        }
        Ok(entry.0)
    }

    async fn clear(&self, client_ip: &str, user_code_hash: &[u8]) -> RepoResult<()> {
        self.lock()
            .device_attempts
            .remove(&(client_ip.to_string(), user_code_hash.to_vec()));
        Ok(())
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let before_len = inner.device_attempts.len();
        inner
            .device_attempts
            .retain(|_, (_, last_miss_at)| *last_miss_at > before);
        Ok((before_len - inner.device_attempts.len()) as u64)
    }
}

#[async_trait]
impl BindingRepo for MemoryStore {
    async fn list_all(
        &self,
        before: Option<&BindingId>,
        query: &BindingQuery,
        limit: u32,
    ) -> RepoResult<Vec<Binding>> {
        let inner = self.lock();
        let mut bindings: Vec<Binding> = inner
            .bindings
            .values()
            .filter(|binding| {
                before.is_none_or(|cursor| binding.id.0 < cursor.0)
                    && query.user.is_none_or(|user| binding.user_id == user)
                    && query
                        .upstream
                        .as_ref()
                        .is_none_or(|upstream| binding.upstream_id == *upstream)
                    && query.status.is_none_or(|status| binding.status == status)
            })
            .cloned()
            .collect();
        bindings.sort_by_key(|binding| std::cmp::Reverse(binding.id.0));
        bindings.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(bindings)
    }
    async fn upsert(&self, binding: &Binding, fact: &SecurityFact) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.users.contains_key(&binding.user_id) {
            return Err(RepoError::NotFound);
        }
        let existing_id = inner
            .bindings
            .iter()
            .find(|(_, stored)| {
                stored.user_id == binding.user_id && stored.upstream_id == binding.upstream_id
            })
            .map(|(id, _)| *id);
        if let Some(existing_id) = existing_id {
            let stored = inner
                .bindings
                .get_mut(&existing_id)
                .expect("binding found by pair");
            let created_at = stored.created_at;
            *stored = Binding {
                id: existing_id,
                created_at,
                ..binding.clone()
            };
            // Re-binding replaces the account, so the old revoke clock is stale.
            inner.binding_revocations.remove(&existing_id);
            Self::push_fact(&mut inner, fact);
            return Ok(());
        }
        if inner.bindings.contains_key(&binding.id) {
            return Err(RepoError::Conflict("binding id"));
        }
        inner.bindings.insert(binding.id, binding.clone());
        Self::push_fact(&mut inner, fact);
        Ok(())
    }

    async fn find(&self, user: &UserId, upstream: &str) -> RepoResult<Option<Binding>> {
        let inner = self.lock();
        Ok(inner
            .bindings
            .values()
            .find(|binding| binding.user_id == *user && binding.upstream_id == upstream)
            .cloned())
    }

    async fn list_by_user(&self, user: &UserId) -> RepoResult<Vec<Binding>> {
        let inner = self.lock();
        let mut bindings: Vec<_> = inner
            .bindings
            .values()
            .filter(|binding| binding.user_id == *user)
            .cloned()
            .collect();
        bindings.sort_by(|left, right| left.upstream_id.cmp(&right.upstream_id));
        Ok(bindings)
    }

    async fn mark_needs_reauth(
        &self,
        id: &BindingId,
        reason: &str,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()> {
        let mut inner = self.lock();
        let Some(binding) = inner.bindings.get_mut(id) else {
            return Err(RepoError::NotFound);
        };
        binding.status = BindingStatus::NeedsReauth;
        binding.last_error_code = Some(reason.to_string());
        binding.updated_at = now;
        Self::push_fact(&mut inner, fact);
        Ok(())
    }

    async fn revoke(&self, id: &BindingId, fact: &SecurityFact, now: Unix) -> RepoResult<()> {
        let mut inner = self.lock();
        let Some(binding) = inner.bindings.get_mut(id) else {
            return Err(RepoError::NotFound);
        };
        binding.status = BindingStatus::Revoked;
        binding.updated_at = now;
        inner.sub_credentials.remove(id);
        inner.binding_revocations.insert(*id, now);
        Self::push_fact(&mut inner, fact);
        Ok(())
    }

    async fn revoke_all(&self, user: &UserId, fact: &SecurityFact, now: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let ids: Vec<BindingId> = inner
            .bindings
            .iter()
            .filter(|(_, binding)| {
                binding.user_id == *user && binding.status != BindingStatus::Revoked
            })
            .map(|(id, _)| *id)
            .collect();
        if ids.is_empty() {
            return Ok(0);
        }
        for id in &ids {
            let binding = inner.bindings.get_mut(id).expect("selected binding");
            binding.status = BindingStatus::Revoked;
            binding.updated_at = now;
            inner.sub_credentials.remove(id);
            inner.binding_revocations.insert(*id, now);
        }
        Self::push_fact(&mut inner, fact);
        Ok(ids.len() as u64)
    }

    async fn anonymize_revoked_before(&self, before: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let targets: Vec<BindingId> = inner
            .bindings
            .iter()
            .filter(|(id, binding)| {
                binding.status == BindingStatus::Revoked
                    && binding.upstream_user_id != ANONYMIZED_UPSTREAM_USER_ID
                    && inner
                        .binding_revocations
                        .get(id)
                        .is_some_and(|at| *at <= before)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &targets {
            let binding = inner.bindings.get_mut(id).expect("selected binding");
            binding.upstream_user_id = ANONYMIZED_UPSTREAM_USER_ID.to_string();
        }
        Ok(targets.len() as u64)
    }

    async fn store_sub_credential(
        &self,
        binding: &BindingId,
        sealed: &SealedSecret,
        _now: Unix,
    ) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.bindings.contains_key(binding) {
            return Err(RepoError::NotFound);
        }
        inner.sub_credentials.insert(*binding, sealed.clone());
        Ok(())
    }

    async fn load_sub_credential(&self, binding: &BindingId) -> RepoResult<Option<SealedSecret>> {
        Ok(self.lock().sub_credentials.get(binding).cloned())
    }

    async fn delete_sub_credential(&self, binding: &BindingId) -> RepoResult<()> {
        self.lock().sub_credentials.remove(binding);
        Ok(())
    }

    async fn rewrap_sub_credential(
        &self,
        binding: &BindingId,
        expect: &SealedSecret,
        new: &SealedSecret,
        _now: Unix,
    ) -> RepoResult<bool> {
        let mut inner = self.lock();
        match inner.sub_credentials.get(binding) {
            Some(current) if current == expect => {
                inner.sub_credentials.insert(*binding, new.clone());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn scan_sub_credentials(
        &self,
        after: Option<&BindingId>,
        limit: u32,
    ) -> RepoResult<Vec<(BindingId, SealedSecret)>> {
        let inner = self.lock();
        let mut ids: Vec<&BindingId> = inner.sub_credentials.keys().collect();
        ids.sort_by_key(|id| id.0);
        Ok(ids
            .into_iter()
            .filter(|id| after.is_none_or(|cursor| id.0 > cursor.0))
            .take(limit as usize)
            .map(|id| (*id, inner.sub_credentials[id].clone()))
            .collect())
    }
}

#[async_trait]
impl LoginTransactionRepo for MemoryStore {
    async fn insert(&self, transaction: &LoginTransaction) -> RepoResult<()> {
        let mut inner = self.lock();
        if inner
            .login_transactions
            .contains_key(&transaction.state_hash)
        {
            return Err(RepoError::Conflict("login state"));
        }
        inner
            .login_transactions
            .insert(transaction.state_hash.clone(), transaction.clone());
        Ok(())
    }

    async fn consume(&self, state_hash: &[u8], now: Unix) -> RepoResult<LoginTransaction> {
        let mut inner = self.lock();
        let Some(transaction) = inner.login_transactions.get_mut(state_hash) else {
            return Err(RepoError::NotFound);
        };
        if transaction.consumed_at.is_some() {
            return Err(RepoError::AlreadyConsumed);
        }
        if transaction.expires_at <= now {
            return Err(RepoError::Expired);
        }
        transaction.consumed_at = Some(now);
        Ok(transaction.clone())
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let before_len = inner.login_transactions.len();
        inner.login_transactions.retain(|_, transaction| {
            !(transaction.expires_at <= before
                || transaction.consumed_at.is_some_and(|at| at <= before))
        });
        Ok((before_len - inner.login_transactions.len()) as u64)
    }
}

#[async_trait]
impl PendingBindingRepo for MemoryStore {
    async fn insert(&self, pending: &PendingBinding) -> RepoResult<()> {
        let mut inner = self.lock();
        if inner.pending_bindings.contains_key(&pending.state_hash) {
            return Err(RepoError::Conflict("binding state"));
        }
        inner
            .pending_bindings
            .insert(pending.state_hash.clone(), pending.clone());
        Ok(())
    }

    async fn consume(&self, state_hash: &[u8], now: Unix) -> RepoResult<PendingBinding> {
        let mut inner = self.lock();
        let Some(pending) = inner.pending_bindings.get(state_hash).cloned() else {
            return Err(RepoError::NotFound);
        };
        if pending.consumed_at.is_some() {
            return Err(RepoError::AlreadyConsumed);
        }
        if pending.expires_at <= now {
            return Err(RepoError::Expired);
        }
        let mut consumed = pending;
        consumed.consumed_at = Some(now);
        inner
            .pending_bindings
            .insert(state_hash.to_vec(), consumed.clone());
        Ok(consumed)
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let before_len = inner.pending_bindings.len();
        inner.pending_bindings.retain(|_, pending| {
            !(pending.expires_at <= before || pending.consumed_at.is_some_and(|at| at <= before))
        });
        Ok((before_len - inner.pending_bindings.len()) as u64)
    }
}

#[async_trait]
impl ApprovalTicketRepo for MemoryStore {
    async fn insert(&self, ticket: &ApprovalTicket) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.users.contains_key(&ticket.user_id) {
            return Err(RepoError::NotFound);
        }
        if inner.approval_tickets.contains_key(&ticket.jti) {
            return Err(RepoError::Conflict("approval ticket"));
        }
        inner
            .approval_tickets
            .insert(ticket.jti.clone(), ticket.clone());
        Ok(())
    }

    async fn find(&self, jti: &str) -> RepoResult<Option<ApprovalTicket>> {
        Ok(self.lock().approval_tickets.get(jti).cloned())
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
        let mut inner = self.lock();
        let Some(ticket) = inner.approval_tickets.get(jti).cloned() else {
            return Err(RepoError::NotFound);
        };
        if ticket.user_id != user_id {
            return Err(RepoError::NotFound);
        }
        if ticket.consumed_at.is_some() {
            return Err(RepoError::AlreadyConsumed);
        }
        if ticket.expires_at <= now {
            return Err(RepoError::Expired);
        }

        let Some(code_key) = inner
            .device_codes
            .iter()
            .find(|(_, code)| code.user_code_hash == user_code_hash)
            .map(|(key, _)| key.clone())
        else {
            return Err(RepoError::NotFound);
        };
        {
            let code = inner
                .device_codes
                .get(&code_key)
                .expect("device code key just found");
            if code.expires_at <= now {
                return Err(RepoError::Expired);
            }
            if !code.state.is_pending() {
                return Err(RepoError::Conflict("device code is not pending"));
            }
        }

        let Some(ticket) = inner.approval_tickets.get_mut(jti) else {
            return Err(RepoError::NotFound);
        };
        ticket.consumed_at = Some(now);
        let code = inner
            .device_codes
            .get_mut(&code_key)
            .expect("device code key just found");
        code.state = match decision {
            ApprovalDecision::Approve => DeviceCodeState::Approved { approver: user_id },
            ApprovalDecision::Deny => DeviceCodeState::Denied {
                approver: Some(user_id),
            },
        };
        let client_id = code.client_id;

        // Same contract as SQLite: the fact lands with the change. This store
        // has no rollback, so "together" here means "before returning Ok" — it
        // still must not report success without the audit row.
        let mut fact = fact.clone();
        fact.client_id = Some(client_id);
        Self::push_fact(&mut inner, &fact);
        Ok(client_id)
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let before_len = inner.approval_tickets.len();
        inner.approval_tickets.retain(|_, ticket| {
            !(ticket.expires_at <= before || ticket.consumed_at.is_some_and(|at| at <= before))
        });
        Ok((before_len - inner.approval_tickets.len()) as u64)
    }
}

#[async_trait]
impl ConsentRepo for MemoryStore {
    async fn find(&self, user: &UserId, client: &ClientId) -> RepoResult<Option<Consent>> {
        Ok(self
            .lock()
            .consents
            .get(&(*user, *client))
            .filter(|consent| consent.revoked_at.is_none())
            .cloned())
    }

    async fn list_by_user(&self, user: &UserId) -> RepoResult<Vec<Consent>> {
        let mut consents = self
            .lock()
            .consents
            .values()
            .filter(|consent| consent.user_id == *user && consent.revoked_at.is_none())
            .cloned()
            .collect::<Vec<_>>();
        consents.sort_by_key(|a| std::cmp::Reverse(a.updated_at));
        Ok(consents)
    }

    async fn grant(&self, consent: &Consent, fact: &SecurityFact) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.users.contains_key(&consent.user_id)
            || !inner.clients.contains_key(&consent.client_id)
        {
            return Err(RepoError::NotFound);
        }
        inner
            .consents
            .insert((consent.user_id, consent.client_id), consent.clone());
        Self::push_fact(&mut inner, fact);
        Ok(())
    }

    async fn revoke(
        &self,
        user: &UserId,
        client: &ClientId,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()> {
        let mut inner = self.lock();
        let Some(consent) = inner.consents.get_mut(&(*user, *client)) else {
            return Err(RepoError::NotFound);
        };
        if consent.revoked_at.is_some() {
            return Err(RepoError::NotFound);
        }
        consent.revoked_at = Some(now);
        consent.updated_at = now;
        Self::push_fact(&mut inner, fact);
        Ok(())
    }
}

#[async_trait]
impl PendingAuthorizationRepo for MemoryStore {
    async fn insert(&self, request: &PendingAuthorization) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.users.contains_key(&request.user_id)
            || !inner.clients.contains_key(&request.client_id)
        {
            return Err(RepoError::NotFound);
        }
        if !inner
            .sessions
            .values()
            .any(|session| session.id == request.session_id && session.user_id == request.user_id)
        {
            return Err(RepoError::NotFound);
        }
        if inner.pending_authorizations.contains_key(&request.id) {
            return Err(RepoError::Conflict("pending authorization"));
        }
        inner
            .pending_authorizations
            .insert(request.id, request.clone());
        Ok(())
    }

    async fn get(&self, id: &PendingAuthorizationId) -> RepoResult<Option<PendingAuthorization>> {
        Ok(self.lock().pending_authorizations.get(id).cloned())
    }

    async fn consume(
        &self,
        id: &PendingAuthorizationId,
        session_id: &SessionId,
        now: Unix,
    ) -> RepoResult<PendingAuthorization> {
        let mut inner = self.lock();
        let Some(request) = inner.pending_authorizations.get_mut(id) else {
            return Err(RepoError::NotFound);
        };
        if request.session_id != *session_id {
            return Err(RepoError::NotFound);
        }
        if request.consumed_at.is_some() {
            return Err(RepoError::AlreadyConsumed);
        }
        if request.expires_at <= now {
            return Err(RepoError::Expired);
        }
        request.consumed_at = Some(now);
        Ok(request.clone())
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let before_len = inner.pending_authorizations.len();
        inner.pending_authorizations.retain(|_, request| {
            request.expires_at > before && request.consumed_at.is_none_or(|at| at > before)
        });
        Ok((before_len - inner.pending_authorizations.len()) as u64)
    }
}

#[async_trait]
impl Storage for MemoryStore {
    fn access_tokens(&self) -> &dyn AccessTokenRepo {
        self
    }

    fn users(&self) -> &dyn UserRepo {
        self
    }

    fn sessions(&self) -> &dyn SessionRepo {
        self
    }

    fn auth_codes(&self) -> &dyn AuthCodeRepo {
        self
    }

    fn refresh_tokens(&self) -> &dyn RefreshTokenRepo {
        self
    }

    fn connectors(&self) -> &dyn ConnectorRepo {
        self
    }

    fn bindings(&self) -> &dyn BindingRepo {
        self
    }

    fn clients(&self) -> &dyn ClientRepo {
        self
    }

    fn device_codes(&self) -> &dyn DeviceCodeRepo {
        self
    }

    fn device_attempts(&self) -> &dyn DeviceAttemptRepo {
        self
    }

    fn login_transactions(&self) -> &dyn LoginTransactionRepo {
        self
    }

    fn pending_bindings(&self) -> &dyn PendingBindingRepo {
        self
    }

    fn approval_tickets(&self) -> &dyn ApprovalTicketRepo {
        self
    }

    fn consents(&self) -> &dyn ConsentRepo {
        self
    }

    fn pending_authorizations(&self) -> &dyn PendingAuthorizationRepo {
        self
    }

    fn audits(&self) -> &dyn AuditRepo {
        self
    }

    fn signing_keys(&self) -> &dyn SigningKeyRepo {
        self
    }

    async fn ping(&self) -> RepoResult<()> {
        // Taking the lock proves the store is usable; there is no backend to reach.
        drop(self.lock());
        Ok(())
    }
}

#[async_trait]
#[async_trait]
impl AccessTokenRepo for MemoryStore {
    async fn revoke(
        &self,
        jti: &str,
        _client_id: Option<ClientId>,
        _revoked_by: Option<UserId>,
        expires_at: Unix,
        fact: &SecurityFact,
        _now: Unix,
    ) -> RepoResult<()> {
        let mut inner = self.lock();
        inner.access_revocations.insert(jti.to_string(), expires_at);
        Self::push_fact(&mut inner, fact);
        Ok(())
    }

    async fn is_revoked(&self, jti: &str, now: Unix) -> RepoResult<bool> {
        Ok(self
            .lock()
            .access_revocations
            .get(jti)
            .is_some_and(|expires_at| *expires_at > now))
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let stale: Vec<String> = inner
            .access_revocations
            .iter()
            .filter(|(_, expires_at)| **expires_at <= before)
            .map(|(jti, _)| jti.clone())
            .collect();
        let removed = stale.len() as u64;
        for jti in stale {
            inner.access_revocations.remove(&jti);
        }
        Ok(removed)
    }
}

// scratch: appended to memory.rs by the connector work
#[async_trait]
impl ConnectorRepo for MemoryStore {
    async fn upsert(
        &self,
        connector: &ConnectorRecord,
        resources: &[ResourceSpec],
        now: Unix,
    ) -> RepoResult<()> {
        let mut inner = self.lock();
        // A different connector already holding this name would violate the
        // UNIQUE(name) constraint in SQLite; mirror that here.
        if inner
            .connectors
            .iter()
            .any(|(id, (other, _))| *id != connector.id && other.name == connector.name)
        {
            return Err(RepoError::Conflict("connector name"));
        }
        let mut stored = connector.clone();
        stored.updated_at = now;
        inner
            .connectors
            .insert(connector.id, (stored, resources.to_vec()));
        Ok(())
    }

    async fn get(&self, id: &ConnectorId) -> RepoResult<Option<ConnectorRecord>> {
        Ok(self
            .lock()
            .connectors
            .get(id)
            .map(|(connector, _)| connector.clone()))
    }

    async fn find_by_name(&self, name: &str) -> RepoResult<Option<ConnectorRecord>> {
        Ok(self
            .lock()
            .connectors
            .values()
            .find(|(connector, _)| connector.name == name)
            .map(|(connector, _)| connector.clone()))
    }

    async fn list(&self) -> RepoResult<Vec<ConnectorRecord>> {
        let mut connectors: Vec<ConnectorRecord> = self
            .lock()
            .connectors
            .values()
            .map(|(connector, _)| connector.clone())
            .collect();
        connectors.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(connectors)
    }

    async fn resources(&self, id: &ConnectorId) -> RepoResult<Vec<ResourceSpec>> {
        Ok(self
            .lock()
            .connectors
            .get(id)
            .map(|(_, resources)| resources.clone())
            .unwrap_or_default())
    }

    async fn delete(&self, id: &ConnectorId) -> RepoResult<bool> {
        let mut inner = self.lock();
        inner
            .connector_secrets
            .retain(|(connector, _), _| connector != id);
        Ok(inner.connectors.remove(id).is_some())
    }

    async fn store_secret(
        &self,
        connector: &ConnectorId,
        kind: &str,
        sealed: &SealedSecret,
        _now: Unix,
    ) -> RepoResult<()> {
        self.lock()
            .connector_secrets
            .insert((*connector, kind.to_string()), sealed.clone());
        Ok(())
    }

    async fn load_secret(
        &self,
        connector: &ConnectorId,
        kind: &str,
    ) -> RepoResult<Option<SealedSecret>> {
        Ok(self
            .lock()
            .connector_secrets
            .get(&(*connector, kind.to_string()))
            .cloned())
    }

    async fn delete_secret(&self, connector: &ConnectorId, kind: &str) -> RepoResult<()> {
        self.lock()
            .connector_secrets
            .remove(&(*connector, kind.to_string()));
        Ok(())
    }
}

#[async_trait::async_trait]
impl SigningKeyRepo for MemoryStore {
    async fn publish(&self, record: &SigningKeyRecord) -> RepoResult<()> {
        let mut inner = self.lock();
        // Match the SQL upsert: re-publishing must not clear a retirement.
        match inner.signing_keys.get_mut(&record.kid) {
            Some(existing) => {
                existing.alg = record.alg.clone();
                existing.public_jwk_json = record.public_jwk_json.clone();
                existing.activated_at = record.activated_at;
            }
            None => {
                inner
                    .signing_keys
                    .insert(record.kid.clone(), record.clone());
            }
        }
        Ok(())
    }

    async fn published(&self) -> RepoResult<Vec<SigningKeyRecord>> {
        let inner = self.lock();
        let mut keys: Vec<SigningKeyRecord> = inner.signing_keys.values().cloned().collect();
        keys.sort_by(|a, b| {
            b.activated_at
                .cmp(&a.activated_at)
                .then_with(|| b.kid.cmp(&a.kid))
        });
        Ok(keys)
    }

    async fn active(&self) -> RepoResult<Option<SigningKeyRecord>> {
        let inner = self.lock();
        let mut keys: Vec<&SigningKeyRecord> = inner
            .signing_keys
            .values()
            .filter(|key| key.retired_at.is_none())
            .collect();
        keys.sort_by(|a, b| {
            b.activated_at
                .cmp(&a.activated_at)
                .then_with(|| b.kid.cmp(&a.kid))
        });
        Ok(keys.first().map(|key| (*key).clone()))
    }

    async fn retire(&self, kid: &str, at: Unix) -> RepoResult<()> {
        let mut inner = self.lock();
        match inner.signing_keys.get_mut(kid) {
            Some(key) => {
                key.retired_at.get_or_insert(at);
                Ok(())
            }
            None => Err(RepoError::NotFound),
        }
    }
}
