//! Binding a user to an upstream account (INV-BIND-01..03).
//!
//! Binding is a second authorization: the user is sent to the upstream's own
//! consent screen, and what comes back is a code that only Re0Auth can redeem.
//! That is the whole reason a user never has to hand us a token.
//!
//! Three properties are load-bearing and each has a way to get it wrong:
//!
//! - the flow is tied to the session that started it, so a leaked state cannot
//!   bind either direction: an attacker cannot attach their account to a victim,
//!   and a victim's completed flow cannot be claimed by the attacker
//!   (INV-BIND-04);
//! - `return_to` is never echoed from the query string, or the callback becomes
//!   an open redirect; what may be stored there is decided by [`crate::return_to`];
//! - re-binding replaces the credential and says so in the audit trail, because
//!   "the user switched accounts" and "the user lost access" are different facts.

use std::sync::Arc;

use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::connector::{
    ConnectorAuth, ConnectorEndpoint, ConnectorRegistry, ExchangedCredential, UpstreamError,
};
use re0auth_api::ports::{Binding, BindingStatus, PendingBinding, Storage};
use re0auth_api::secret::SecretSealer;
use re0auth_api::{BindingId, Clock, Random, Unix, UserId};
use re0auth_domain::gateway;
use re0auth_domain::pkce;

use crate::gateway::connector_id_for_name;
use crate::return_to;

/// How long a binding flow stays redeemable.
///
/// Long enough for a user to log in at the upstream on a phone, short enough that
/// a state left in a browser history is not useful tomorrow.
pub const PENDING_BINDING_TTL_SECS: Unix = 600;

/// A binding flow that has been started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedBinding {
    /// URL to redirect the browser to.
    pub authorization_url: String,
    /// The state value; also handed to the upstream so the callback can be
    /// matched. Returned so tests and the HTTP layer can assert on it.
    pub state: String,
}

/// A binding flow that completed.
#[derive(Debug, Clone)]
pub struct CompletedBinding {
    pub binding: Binding,
    /// True when an existing binding was replaced rather than created.
    pub rebound: bool,
    pub return_to: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error("unknown connector")]
    UnknownConnector,
    #[error("the binding flow is no longer valid")]
    FlowNotValid,
    #[error("the connector refused the authorization code: {0}")]
    UpstreamRejected(String),
    #[error("upstream is unavailable: {0}")]
    UpstreamUnavailable(String),
    #[error("insufficient scope for this connector")]
    InsufficientScope,
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<UpstreamError> for BindingError {
    fn from(error: UpstreamError) -> Self {
        match error {
            UpstreamError::CredentialExpired | UpstreamError::Rejected => {
                Self::UpstreamRejected(error.to_string())
            }
            UpstreamError::InsufficientScope => Self::InsufficientScope,
            // `UpstreamError` is `#[non_exhaustive]`: a variant added later must
            // degrade into "the upstream is unhappy", never into a business
            // rejection, because a business rejection tells the user to stop
            // trying and that would be a lie for a new failure mode.
            other => Self::UpstreamUnavailable(other.to_string()),
        }
    }
}

/// Starts and completes binding flows.
pub struct BindingService {
    storage: Arc<dyn Storage>,
    connectors: Arc<dyn ConnectorRegistry>,
    auth: Arc<dyn ConnectorAuth>,
    sealer: Arc<dyn SecretSealer>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn Random>,
    redirect_uri: String,
    /// Upstreams whose connector declares OAuth, so a flow can be redeemed.
    ///
    /// A `ConnectorRegistry` cannot enumerate, so the list is fixed at wiring
    /// time, from the same configuration the authorization URLs come from.
    bindable: Vec<String>,
}

impl BindingService {
    #[must_use]
    pub fn new(
        storage: Arc<dyn Storage>,
        connectors: Arc<dyn ConnectorRegistry>,
        auth: Arc<dyn ConnectorAuth>,
        sealer: Arc<dyn SecretSealer>,
        clock: Arc<dyn Clock>,
        random: Arc<dyn Random>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            storage,
            connectors,
            auth,
            sealer,
            clock,
            random,
            redirect_uri: redirect_uri.into(),
            bindable: Vec::new(),
        }
    }

    /// Declares which upstreams the portal may offer to connect.
    ///
    /// Only the composition root can produce this list, because a
    /// `ConnectorRegistry` resolves by id and cannot enumerate.
    #[must_use]
    pub fn with_bindable_upstreams(mut self, bindable: Vec<String>) -> Self {
        self.bindable = bindable;
        self
    }

    /// The upstreams a user can bind, as configured and sorted.
    #[must_use]
    pub fn bindable_upstreams(&self) -> &[String] {
        &self.bindable
    }

    /// Creates the flow and returns where to send the browser.
    ///
    /// The connector must exist before a flow is created: otherwise the user gets
    /// sent to an authorization page for something we cannot redeem.
    pub async fn start(
        &self,
        user: UserId,
        upstream_id: &str,
        return_to: &str,
    ) -> Result<StartedBinding, BindingError> {
        let endpoint = self.lookup(upstream_id).await?;

        let now = self.clock.now();
        let state = hex::encode(self.random.bytes(32));
        let verifier = hex::encode(self.random.bytes(32));
        let challenge = pkce::challenge_s256(&verifier);

        let url =
            self.auth
                .authorization_url(&endpoint, &state, &self.redirect_uri, Some(&challenge))?;

        self.storage
            .pending_bindings()
            .insert(&PendingBinding {
                state_hash: pkce::sha256(state.as_bytes()).to_vec(),
                user_id: user,
                upstream_id: upstream_id.to_string(),
                pkce_verifier: verifier,
                return_to: return_to::or_fallback(return_to),
                created_at: now,
                expires_at: now + PENDING_BINDING_TTL_SECS,
                consumed_at: None,
            })
            .await
            .map_err(|error| BindingError::Internal(error.to_string()))?;

        Ok(StartedBinding {
            authorization_url: url,
            state,
        })
    }

    /// Redeems the callback and stores the resulting credential.
    ///
    /// The user comes from the consumed flow, never from the callback: the
    /// callback is authenticated by the state alone, and a state is a bearer
    /// value. Binding to whoever presents it would let a leaked state attach an
    /// attacker's upstream account to the victim's list.
    pub async fn complete(
        &self,
        user: UserId,
        state: &str,
        code: &str,
    ) -> Result<CompletedBinding, BindingError> {
        let now = self.clock.now();
        let state_hash = pkce::sha256(state.as_bytes());
        let pending = self
            .storage
            .pending_bindings()
            .consume(&state_hash, now)
            .await
            .map_err(|_| BindingError::FlowNotValid)?;

        // INV-BIND-04: the callback must arrive in the session that started the
        // flow. Without this, an attacker can hand the upstream URL to a victim
        // and have the victim's account bound to the attacker's user. The flow is
        // consumed before the check on purpose: a mismatched callback burns it, so
        // an attacker cannot retry against the victim's browser.
        if pending.user_id != user {
            return Err(BindingError::FlowNotValid);
        }

        let endpoint = self.lookup(&pending.upstream_id).await?;

        let verifier = if pending.pkce_verifier.is_empty() {
            None
        } else {
            Some(pending.pkce_verifier.as_str())
        };
        // The flow is consumed before this call, so a rejected code costs the
        // user a new flow. That is intentional: the alternative is a state that
        // stays valid across attempts, which is the replay we are avoiding.
        let exchanged = self
            .auth
            .exchange_code(&endpoint, code, &self.redirect_uri, verifier)
            .await?;

        // The subject comes from the upstream and is stored, then substituted
        // into a path template on every later read. Validating it here is the
        // boundary check (`AGENTS.md` §3): the gateway would reject it on use,
        // but by then a binding exists that can never serve anything.
        gateway::validate_subject(&exchanged.subject)
            .map_err(|_| BindingError::Internal("upstream returned an invalid subject".into()))?;

        self.commit(pending, exchanged, now).await
    }

    async fn commit(
        &self,
        pending: PendingBinding,
        exchanged: ExchangedCredential,
        now: Unix,
    ) -> Result<CompletedBinding, BindingError> {
        let existing = self
            .storage
            .bindings()
            .find(&pending.user_id, &pending.upstream_id)
            .await
            .map_err(|error| BindingError::Internal(error.to_string()))?;

        let rebound = existing
            .as_ref()
            .is_some_and(|binding| binding.status != BindingStatus::Revoked);
        let id = existing.as_ref().map_or_else(BindingId::new, |b| b.id);

        let binding = Binding {
            id,
            user_id: pending.user_id,
            upstream_id: pending.upstream_id.clone(),
            // The upstream account is the one the credential identifies. The code
            // exchange is the only thing that establishes it; nothing from the
            // callback is trusted for this. It arrives with the credential rather
            // than being derived here: there is nothing local to derive it from,
            // and the gateway addresses every read by this value.
            upstream_user_id: exchanged.subject,
            status: BindingStatus::Active,
            created_at: existing.as_ref().map_or(now, |b| b.created_at),
            updated_at: now,
            last_refreshed_at: Some(now),
            last_error_code: None,
        };
        let fact = SecurityFact::new(
            if rebound {
                AuditAction::BindingRebound
            } else {
                AuditAction::BindingCreated
            },
            now,
            "binding",
        )
        .actor(pending.user_id);

        // The binding row first: the credential has a foreign key to it, so a
        // store that enforces referential integrity (SQLite does) rejects the
        // credential before the binding exists. Sealing happens before either
        // write, so a sealer failure leaves nothing behind.
        let sealed = self
            .sealer
            .seal(&id, &exchanged.credential)
            .map_err(|error| BindingError::Internal(error.to_string()))?;
        self.storage
            .bindings()
            .upsert(&binding, &fact)
            .await
            .map_err(|error| BindingError::Internal(error.to_string()))?;
        self.storage
            .bindings()
            .store_sub_credential(&id, &sealed, now)
            .await
            .map_err(|error| BindingError::Internal(error.to_string()))?;

        Ok(CompletedBinding {
            binding,
            rebound,
            return_to: pending.return_to,
        })
    }

    async fn lookup(&self, upstream_id: &str) -> Result<ConnectorEndpoint, BindingError> {
        self.connectors
            .resolve(&connector_id_for_name(upstream_id))
            .await
            .map_err(|_| BindingError::UnknownConnector)
    }
}

/// Whether a stored binding's credential can be used as-is.
///
/// Exists so the gateway does not have to know about `BindingStatus`, and so
/// "needs reauth" is one reading rather than a scattered comparison.
#[must_use]
pub fn is_usable(status: BindingStatus) -> bool {
    matches!(status, BindingStatus::Active)
}
