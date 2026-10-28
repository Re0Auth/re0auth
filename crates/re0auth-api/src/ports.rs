//! Storage ports.
//!
//! The traits in this module describe the transactional storage contract. They
//! are intentionally independent of SQLite; adapters implement them, and
//! `re0auth-contract` runs the same suite against every implementation.

use async_trait::async_trait;

use crate::audit::{AccessTelemetry, AuditAction, AuditRecord, AuditTier, SecurityFact};
use crate::connector::ResourceSpec;
use crate::oauth::ConsentVersion;
use crate::secret::{ClientSecretHash, SealedSecret};
use crate::{
    AuditId, AuthCodeId, BindingId, ClientId, ConnectorId, ConsentId, DeviceCodeId, FamilyId,
    IdentityId, PendingAuthorizationId, RefreshTokenId, SessionId, Unix, UserId,
};

/// INV-NOLOG-01: what a secret-bearing field prints instead of its value.
///
/// A `&'static str` rather than a helper function so the same literal is used
/// by every manual `Debug` impl; a test asserts that no such struct ever renders
/// its bytes.
const REDACTED: &str = "<redacted>";

/// Storage failure. Business-facing callers map these to protocol errors.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RepoError {
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(&'static str),
    /// The canonical user code already names another device authorization.
    ///
    /// Separate from [`RepoError::Conflict`] because the caller has to react
    /// differently: a user code is drawn at random, so a collision is redrawn
    /// (RFC 8628 §6.1 leaves the code space ours to choose), while every other
    /// conflict is fatal. Collapsing the two is what let an infrastructure fault
    /// masquerade as an exhausted code space.
    #[error("user code already in use")]
    UserCodeConflict,
    #[error("expired")]
    Expired,
    #[error("already consumed")]
    AlreadyConsumed,
    #[error("revoked")]
    Revoked,
    /// SQLite reported BUSY/LOCKED; the operation may succeed on retry.
    #[error("busy")]
    Busy,
    #[error("backend error: {0}")]
    Backend(String),
}

pub type RepoResult<T> = Result<T, RepoError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserRole {
    User,
    Admin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientStatus {
    Pending,
    Approved,
    Suspended,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Client {
    pub id: ClientId,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub raw_access: bool,
    pub status: ClientStatus,
    /// `None` means a public client (device flow, PKCE). A public client that
    /// presents a secret is rejected rather than silently accepted.
    pub secret_hash: Option<ClientSecretHash>,
    pub created_at: Unix,
    pub updated_at: Unix,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User {
    pub id: UserId,
    pub display_name: String,
    pub role: UserRole,
    pub created_at: Unix,
    pub updated_at: Unix,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub id: IdentityId,
    pub user_id: UserId,
    pub issuer: String,
    pub subject: String,
    pub created_at: Unix,
}

/// INV-NOLOG-01: `id_hash` and `csrf_hash` are password-equivalents.
#[derive(Clone, Eq, PartialEq)]
pub struct Session {
    pub id: SessionId,
    pub id_hash: Vec<u8>,
    pub user_id: UserId,
    pub csrf_hash: Vec<u8>,
    pub created_at: Unix,
    pub last_seen_at: Unix,
    pub idle_expires_at: Unix,
    pub absolute_expires_at: Unix,
    pub revoked_at: Option<Unix>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("id_hash", &REDACTED)
            .field("user_id", &self.user_id)
            .field("csrf_hash", &REDACTED)
            .field("created_at", &self.created_at)
            .field("last_seen_at", &self.last_seen_at)
            .field("idle_expires_at", &self.idle_expires_at)
            .field("absolute_expires_at", &self.absolute_expires_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

/// INV-NOLOG-01: `code_hash` and `nonce` are password-equivalents.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthCode {
    pub id: AuthCodeId,
    pub code_hash: Vec<u8>,
    pub client_id: ClientId,
    pub user_id: UserId,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub created_at: Unix,
    pub expires_at: Unix,
    pub consumed_at: Option<Unix>,
}

impl std::fmt::Debug for AuthCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthCode")
            .field("id", &self.id)
            .field("code_hash", &REDACTED)
            .field("client_id", &self.client_id)
            .field("user_id", &self.user_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .field("code_challenge", &self.code_challenge)
            .field("code_challenge_method", &self.code_challenge_method)
            .field("nonce", &redact_option(&self.nonce))
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .finish()
    }
}

/// Renders `None` as `None` and any `Some` as the redaction marker. Keeps the
/// "is it set?" bit without ever printing the value.
fn redact_option<T>(value: &Option<T>) -> Option<&'static str> {
    value.as_ref().map(|_| REDACTED)
}

#[cfg(test)]
mod redaction_tests {
    //! INV-NOLOG-01, executable. Every struct that carries a hash, a nonce or a
    //! one-time code must render `Debug` without those bytes. The marker is
    //! asserted **and** the raw value is asserted absent: a formatter that
    //! printed both would pass a marker-only check.

    use super::*;

    /// A value that is easy to recognise if it leaks into a `Debug` string.
    const LEAK: &[u8] = b"leak-canary-do-not-print";

    fn canary_bytes() -> Vec<u8> {
        LEAK.to_vec()
    }

    fn canary_string() -> String {
        String::from_utf8(LEAK.to_vec()).expect("ascii")
    }

    fn assert_redacted(rendered: &str, marker: &str) {
        assert!(
            rendered.contains("<redacted>"),
            "expected a redaction marker in {rendered}"
        );
        assert!(
            !rendered.contains(marker),
            "the secret value leaked into Debug output: {rendered}"
        );
        assert!(
            !rendered.contains("leak-canary"),
            "a canary byte sequence leaked into Debug output: {rendered}"
        );
        // `Vec<u8>` renders as `[108, 101, ...]`, so a string-only check would
        // miss the most likely leak. The first three canary bytes are enough.
        let byte_list = format!("{:?}", &LEAK[..3]);
        assert!(
            !rendered.contains(&byte_list),
            "a raw byte array leaked into Debug output: {rendered}"
        );
    }

    #[test]
    fn session_hides_its_hashes() {
        let session = Session {
            id: SessionId::new(),
            id_hash: canary_bytes(),
            user_id: UserId::new(),
            csrf_hash: canary_bytes(),
            created_at: 1,
            last_seen_at: 2,
            idle_expires_at: 3,
            absolute_expires_at: 4,
            revoked_at: None,
        };
        let rendered = format!("{session:?}");
        assert_redacted(&rendered, &canary_string());
        assert!(rendered.contains(&session.user_id.0.to_string()));
    }

    #[test]
    fn auth_code_hides_its_hash_and_nonce() {
        let code = AuthCode {
            id: AuthCodeId::new(),
            code_hash: canary_bytes(),
            client_id: ClientId::new(),
            user_id: UserId::new(),
            redirect_uri: "https://client.example/cb".to_string(),
            scopes: vec!["openid".to_string()],
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: Some(canary_string()),
            created_at: 1,
            expires_at: 2,
            consumed_at: None,
        };
        let rendered = format!("{code:?}");
        assert_redacted(&rendered, &canary_string());
        // The presence bit survives, which is what an operator needs.
        assert!(rendered.contains("Some(\"<redacted>\")"), "{rendered}");
    }

    #[test]
    fn a_device_row_without_an_approver_is_rejected() {
        let approver = UserId::new();
        // The two statuses that require an approver refuse to be rebuilt
        // without one. This used to be a state the adapters had to defend
        // against at every poll; now it cannot be constructed at all.
        for status in [DeviceCodeStatus::Approved, DeviceCodeStatus::Consumed] {
            assert!(
                DeviceCodeState::from_columns(status, None).is_err(),
                "{status:?} without an approver must not be representable"
            );
            assert!(DeviceCodeState::from_columns(status, Some(approver)).is_ok());
        }
        // Pending, expired and denied are legitimate without an approver.
        for status in [
            DeviceCodeStatus::Pending,
            DeviceCodeStatus::Expired,
            DeviceCodeStatus::Denied,
        ] {
            assert!(
                DeviceCodeState::from_columns(status, None).is_ok(),
                "{status:?} must be reconstructible without an approver"
            );
        }
    }

    #[test]
    fn device_code_hides_both_hashes() {
        let code = DeviceCode {
            id: DeviceCodeId::new(),
            device_code_hash: canary_bytes(),
            user_code_hash: canary_bytes(),
            client_id: ClientId::new(),
            scopes: vec!["openid".to_string()],
            state: DeviceCodeState::Pending,
            interval_secs: 5,
            last_polled_at: None,
            poll_count: 0,
            user_code_misses: 0,
            created_at: 1,
            expires_at: 2,
            consumed_at: None,
        };
        assert_redacted(&format!("{code:?}"), &canary_string());
    }

    #[test]
    fn login_transaction_hides_nonce_and_verifier() {
        let transaction = LoginTransaction {
            state_hash: canary_bytes(),
            nonce: canary_string(),
            pkce_verifier: canary_string(),
            return_to: "/app".to_string(),
            provider: "test-idp".to_string(),
            created_at: 1,
            expires_at: 2,
            consumed_at: None,
        };
        assert_redacted(&format!("{transaction:?}"), &canary_string());
    }

    #[test]
    fn refresh_token_hides_its_hash() {
        let token = RefreshToken {
            id: RefreshTokenId::new(),
            token_hash: canary_bytes(),
            family_id: FamilyId::new(),
            client_id: ClientId::new(),
            user_id: UserId::new(),
            scopes: vec!["openid".to_string()],
            created_at: 1,
            expires_at: 2,
            consumed_at: None,
            revoked_at: None,
            replaced_by: None,
        };
        assert_redacted(&format!("{token:?}"), &canary_string());

        let rotation = RotateRefreshToken {
            old_hash: LEAK,
            new: token,
        };
        assert_redacted(&format!("{rotation:?}"), &canary_string());
    }

    #[test]
    fn pending_authorization_hides_state_and_nonce() {
        let pending = PendingAuthorization {
            id: PendingAuthorizationId::new(),
            session_id: SessionId::new(),
            user_id: UserId::new(),
            client_id: ClientId::new(),
            redirect_uri: "https://client.example/cb".to_string(),
            scopes: vec!["openid".to_string()],
            state: Some(canary_string()),
            code_challenge: "challenge".to_string(),
            code_challenge_method: "S256".to_string(),
            nonce: Some(canary_string()),
            created_at: 1,
            expires_at: 2,
            consumed_at: None,
        };
        assert_redacted(&format!("{pending:?}"), &canary_string());
    }

    #[test]
    fn approval_ticket_hides_jti_and_user_code() {
        let ticket = ApprovalTicket {
            jti: canary_string(),
            user_id: UserId::new(),
            user_code: canary_string(),
            expires_at: 2,
            consumed_at: None,
        };
        assert_redacted(&format!("{ticket:?}"), &canary_string());
    }

    #[test]
    fn consume_auth_code_hides_its_hash() {
        let request = ConsumeAuthCode {
            code_hash: LEAK,
            client_id: ClientId::new(),
            redirect_uri: "https://client.example/cb",
            code_challenge: Some("challenge"),
            code_challenge_method: Some("S256"),
        };
        assert_redacted(&format!("{request:?}"), &canary_string());
    }
}

/// INV-NOLOG-01: `code_hash` is a password-equivalent.
#[derive(Clone, Eq, PartialEq)]
pub struct ConsumeAuthCode<'a> {
    pub code_hash: &'a [u8],
    pub client_id: ClientId,
    pub redirect_uri: &'a str,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
}

impl std::fmt::Debug for ConsumeAuthCode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsumeAuthCode")
            .field("code_hash", &REDACTED)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("code_challenge", &self.code_challenge)
            .field("code_challenge_method", &self.code_challenge_method)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthGrant {
    pub user_id: UserId,
    pub client_id: ClientId,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceCodeStatus {
    Pending,
    Approved,
    Denied,
    Consumed,
    Expired,
}

/// The device code's lifecycle, with the approver carried in the variants that
/// require one.
///
/// The previous shape was `status: DeviceCodeStatus` plus `user_id:
/// Option<UserId>`, which allowed `Approved` with no approver. Every adapter
/// had to defend against that with an `else` branch that could never run
/// through its own writes. Encoding it in the variant makes the impossible
/// state unrepresentable instead of merely untested.
///
/// `Denied` keeps an optional approver because the repository exposes two deny
/// paths: `consume_and_decide` knows who denied, `deny` does not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceCodeState {
    Pending,
    Approved { approver: UserId },
    Denied { approver: Option<UserId> },
    Consumed { approver: UserId },
    Expired,
}

impl DeviceCodeState {
    /// The persisted status column. Kept separate from the state so storage
    /// keeps a stable wire format while the domain type stays precise.
    #[must_use]
    pub fn status(&self) -> DeviceCodeStatus {
        match self {
            Self::Pending => DeviceCodeStatus::Pending,
            Self::Approved { .. } => DeviceCodeStatus::Approved,
            Self::Denied { .. } => DeviceCodeStatus::Denied,
            Self::Consumed { .. } => DeviceCodeStatus::Consumed,
            Self::Expired => DeviceCodeStatus::Expired,
        }
    }

    /// Rebuilds the state from the two stored columns.
    ///
    /// A row that says `approved` or `consumed` without a `user_id` is corrupt:
    /// no write path can produce it. Reporting it as a backend error keeps a
    /// damaged row visible instead of fabricating a state the rest of the code
    /// would then have to keep defending against.
    pub fn from_columns(status: DeviceCodeStatus, approver: Option<UserId>) -> RepoResult<Self> {
        match status {
            DeviceCodeStatus::Pending => Ok(Self::Pending),
            DeviceCodeStatus::Expired => Ok(Self::Expired),
            DeviceCodeStatus::Approved => approver
                .map(|approver| Self::Approved { approver })
                .ok_or_else(|| RepoError::Backend("approved device code has no approver".into())),
            DeviceCodeStatus::Consumed => approver
                .map(|approver| Self::Consumed { approver })
                .ok_or_else(|| RepoError::Backend("consumed device code has no approver".into())),
            DeviceCodeStatus::Denied => Ok(Self::Denied { approver }),
        }
    }

    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// The user who approved, denied or consumed this code, when one is known.
    /// The plain `deny` path records no actor, so this is not always present.
    #[must_use]
    pub fn approver(&self) -> Option<UserId> {
        match self {
            Self::Pending | Self::Expired => None,
            Self::Approved { approver } | Self::Consumed { approver } => Some(*approver),
            Self::Denied { approver } => *approver,
        }
    }
}

/// INV-NOLOG-01: both hashes are password-equivalents.
#[derive(Clone, Eq, PartialEq)]
pub struct DeviceCode {
    pub id: DeviceCodeId,
    pub device_code_hash: Vec<u8>,
    pub user_code_hash: Vec<u8>,
    pub client_id: ClientId,
    pub scopes: Vec<String>,
    pub state: DeviceCodeState,
    pub interval_secs: u32,
    pub last_polled_at: Option<Unix>,
    pub poll_count: u32,
    pub user_code_misses: u32,
    pub created_at: Unix,
    pub expires_at: Unix,
    pub consumed_at: Option<Unix>,
}

impl std::fmt::Debug for DeviceCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCode")
            .field("id", &self.id)
            .field("device_code_hash", &REDACTED)
            .field("user_code_hash", &REDACTED)
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .field("state", &self.state)
            .field("interval_secs", &self.interval_secs)
            .field("last_polled_at", &self.last_polled_at)
            .field("poll_count", &self.poll_count)
            .field("user_code_misses", &self.user_code_misses)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DevicePoll {
    Pending,
    SlowDown {
        interval_secs: u32,
    },
    Approved {
        client_id: ClientId,
        user_id: UserId,
        scopes: Vec<String>,
    },
    Denied,
    Expired,
    Consumed,
    NotFound,
}

/// INV-NOLOG-01: `nonce` and `pkce_verifier` are secrets.
#[derive(Clone, Eq, PartialEq)]
pub struct LoginTransaction {
    pub state_hash: Vec<u8>,
    pub nonce: String,
    pub pkce_verifier: String,
    pub return_to: String,
    /// INV-IDP-01: the provider this login started against.
    ///
    /// The callback must not choose a provider from the query string: the code
    /// was issued by one specific IdP, and honouring a caller-supplied provider
    /// would let a request present a code to the wrong one. Bound at start,
    /// read back at callback.
    pub provider: String,
    pub created_at: Unix,
    pub expires_at: Unix,
    pub consumed_at: Option<Unix>,
}

impl std::fmt::Debug for LoginTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginTransaction")
            .field("state_hash", &REDACTED)
            .field("nonce", &REDACTED)
            .field("pkce_verifier", &REDACTED)
            .field("return_to", &self.return_to)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .finish()
    }
}

/// INV-NOLOG-01: `jti` identifies a one-time approval ticket.
#[derive(Clone, Eq, PartialEq)]
pub struct ApprovalTicket {
    pub jti: String,
    pub user_id: UserId,
    pub user_code: String,
    pub expires_at: Unix,
    pub consumed_at: Option<Unix>,
}

impl std::fmt::Debug for ApprovalTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalTicket")
            .field("jti", &REDACTED)
            .field("user_id", &self.user_id)
            .field("user_code", &REDACTED)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Consent {
    pub id: ConsentId,
    pub user_id: UserId,
    pub client_id: ClientId,
    pub scopes: Vec<String>,
    pub created_at: Unix,
    pub updated_at: Unix,
    pub revoked_at: Option<Unix>,
    pub version: ConsentVersion,
}

/// INV-NOLOG-01: `nonce` and `state` are secrets.
#[derive(Clone, Eq, PartialEq)]
pub struct PendingAuthorization {
    pub id: PendingAuthorizationId,
    pub session_id: SessionId,
    pub user_id: UserId,
    pub client_id: ClientId,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
    pub created_at: Unix,
    pub expires_at: Unix,
    pub consumed_at: Option<Unix>,
}

impl std::fmt::Debug for PendingAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingAuthorization")
            .field("id", &self.id)
            .field("session_id", &self.session_id)
            .field("user_id", &self.user_id)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .field("state", &redact_option(&self.state))
            .field("code_challenge", &self.code_challenge)
            .field("code_challenge_method", &self.code_challenge_method)
            .field("nonce", &redact_option(&self.nonce))
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .finish()
    }
}

/// INV-NOLOG-01: `token_hash` is a password-equivalent.
#[derive(Clone, Eq, PartialEq)]
pub struct RefreshToken {
    pub id: RefreshTokenId,
    pub token_hash: Vec<u8>,
    pub family_id: FamilyId,
    pub client_id: ClientId,
    pub user_id: UserId,
    pub scopes: Vec<String>,
    pub created_at: Unix,
    pub expires_at: Unix,
    pub consumed_at: Option<Unix>,
    pub revoked_at: Option<Unix>,
    pub replaced_by: Option<RefreshTokenId>,
}

impl std::fmt::Debug for RefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshToken")
            .field("id", &self.id)
            .field("token_hash", &REDACTED)
            .field("family_id", &self.family_id)
            .field("client_id", &self.client_id)
            .field("user_id", &self.user_id)
            .field("scopes", &self.scopes)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .field("revoked_at", &self.revoked_at)
            .field("replaced_by", &self.replaced_by)
            .finish()
    }
}

/// INV-NOLOG-01: the inner token hash is a password-equivalent.
#[derive(Clone, Eq, PartialEq)]
pub struct RotateRefreshToken<'a> {
    pub old_hash: &'a [u8],
    pub new: RefreshToken,
}

impl std::fmt::Debug for RotateRefreshToken<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotateRefreshToken")
            .field("old_hash", &REDACTED)
            .field("new", &self.new)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RotateOutcome {
    Rotated(RefreshToken),
    ReuseDetected { family_revoked: u64 },
    Expired,
    Revoked,
    NotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingStatus {
    Pending,
    Active,
    NeedsReauth,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Binding {
    pub id: BindingId,
    pub user_id: UserId,
    pub upstream_id: String,
    pub upstream_user_id: String,
    pub status: BindingStatus,
    pub created_at: Unix,
    pub updated_at: Unix,
    pub last_refreshed_at: Option<Unix>,
    pub last_error_code: Option<String>,
}

/// Business primary keys use UUID v7; credential tables are looked up by a
/// unique hash column and never store the plaintext (INV-PK-01).
#[async_trait]
pub trait UserRepo: Send + Sync {
    async fn create(&self, user: &User) -> RepoResult<()>;
    async fn get(&self, id: &UserId) -> RepoResult<Option<User>>;
    async fn link_identity(&self, identity: &Identity) -> RepoResult<()>;
    async fn find_by_identity(&self, issuer: &str, subject: &str) -> RepoResult<Option<User>>;
    /// Deletes the user and all dependent rows; audit rows survive with a null
    /// actor (INV-FK-01).
    async fn delete(&self, id: &UserId) -> RepoResult<bool>;
    /// Users, newest first, strictly older than `before` when it is given.
    ///
    /// Cursor-based rather than offset-based so a concurrent insert cannot make
    /// a page skip or repeat a row (UUID v7 ids are time-ordered).
    async fn list(&self, before: Option<&UserId>, limit: u32) -> RepoResult<Vec<User>>;
    /// Changes a user's role. Reports `NotFound` for an unknown id. The audit
    /// fact lands in the same transaction (INV-AUDIT-01).
    async fn set_role(
        &self,
        id: &UserId,
        role: UserRole,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()>;
    /// How many admins exist, for the "cannot demote the last admin" guard.
    async fn count_admins(&self) -> RepoResult<u64>;
}

#[async_trait]
pub trait SessionRepo: Send + Sync {
    async fn create(&self, session: &Session) -> RepoResult<()>;
    async fn find_active(&self, id_hash: &[u8], now: Unix) -> RepoResult<Option<Session>>;
    async fn touch(&self, id_hash: &[u8], now: Unix, idle_expires_at: Unix) -> RepoResult<()>;
    async fn revoke(&self, id_hash: &[u8], now: Unix) -> RepoResult<()>;
    async fn revoke_all(&self, user: &UserId, now: Unix) -> RepoResult<u64>;
    async fn purge_expired(&self, before: Unix) -> RepoResult<u64>;
}

/// Authorization codes are single-use: concurrent consumption has exactly one
/// winner (INV-AUTH-01).
#[async_trait]
pub trait AuthCodeRepo: Send + Sync {
    /// Writes the code and its audit fact in one transaction (INV-AUDIT-01).
    /// The fact is required rather than optional: an `Option` here would make
    /// "forgot to audit" a silent success.
    async fn insert(&self, code: &AuthCode, fact: &SecurityFact) -> RepoResult<()>;
    /// Atomically validates the code and marks it consumed (INV-AUTH-01).
    async fn consume(&self, req: ConsumeAuthCode<'_>, now: Unix) -> RepoResult<AuthGrant>;
    async fn purge_expired(&self, before: Unix) -> RepoResult<u64>;
}

/// Reuse of a rotated refresh token revokes the whole family (INV-REFRESH-01).
#[async_trait]
pub trait RefreshTokenRepo: Send + Sync {
    async fn insert(&self, token: &RefreshToken) -> RepoResult<()>;
    async fn find(&self, token_hash: &[u8]) -> RepoResult<Option<RefreshToken>>;
    /// Atomically consumes the old token and inserts the replacement. A detected
    /// reuse reports it so the caller can revoke the family (INV-REFRESH-01).
    ///
    /// `fact` is written in the same transaction as the rotation, including the
    /// reuse-detection path: the family revocation and its audit record either
    /// both land or neither does (INV-AUDIT-01).
    async fn rotate(
        &self,
        req: RotateRefreshToken<'_>,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<RotateOutcome>;
    async fn revoke_family(
        &self,
        family: &FamilyId,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<u64>;

    /// Revokes every live refresh family for one `(user, client)` pair.
    ///
    /// Used when the user withdraws the whole authorization, not just one
    /// token. Records `fact` only when at least one row moved.
    async fn revoke_all_for_client(
        &self,
        user: &UserId,
        client: &ClientId,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<u64>;
    async fn purge_expired(&self, before: Unix) -> RepoResult<u64>;
}

#[async_trait]
pub trait LoginTransactionRepo: Send + Sync {
    async fn insert(&self, transaction: &LoginTransaction) -> RepoResult<()>;
    /// Atomically consumes the state and returns its transaction.
    async fn consume(&self, state_hash: &[u8], now: Unix) -> RepoResult<LoginTransaction>;
    async fn purge_expired(&self, before: Unix) -> RepoResult<u64>;
}

/// An in-progress binding flow.
///
/// Modelled on [`LoginTransaction`]: a one-shot state that ties an upstream
/// callback to the user who started it. Stored rather than kept in memory
/// because a restart mid-flow must not leave the user with a callback that no
/// longer resolves — and because a second in-memory store would need its own
/// sweep.
#[derive(Clone, Eq, PartialEq)]
pub struct PendingBinding {
    /// SHA-256 of the state handed to the upstream.
    pub state_hash: Vec<u8>,
    /// INV-BIND-02 / INV-BIND-04: the user who started the flow.
    ///
    /// The callback must bind to this user, never to whoever presents the state,
    /// and it must arrive in that user's session. The first rule stops a leaked
    /// state from attaching the attacker's account to the victim; the second
    /// stops a forwarded authorization URL from attaching the victim's account
    /// to the attacker.
    pub user_id: UserId,
    /// Configured connector name, which is also `bindings.upstream_id`.
    pub upstream_id: String,
    /// PKCE verifier for connectors that support it; empty otherwise.
    pub pkce_verifier: String,
    /// Where to send the browser afterwards. Validated against a local-path
    /// allowlist before use, never echoed from the query string.
    pub return_to: String,
    pub created_at: Unix,
    pub expires_at: Unix,
    pub consumed_at: Option<Unix>,
}

impl std::fmt::Debug for PendingBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingBinding")
            .field("state_hash", &REDACTED)
            .field("user_id", &self.user_id)
            .field("upstream_id", &self.upstream_id)
            .field("pkce_verifier", &REDACTED)
            .field("return_to", &self.return_to)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .finish()
    }
}

/// In-progress binding flows.
#[async_trait]
pub trait PendingBindingRepo: Send + Sync {
    async fn insert(&self, pending: &PendingBinding) -> RepoResult<()>;
    /// Atomically consumes the state and returns the flow.
    ///
    /// Consumption is the guard against replay: a callback that arrives twice
    /// must not create two bindings, and must not be usable to overwrite the
    /// first one.
    async fn consume(&self, state_hash: &[u8], now: Unix) -> RepoResult<PendingBinding>;
    async fn purge_expired(&self, before: Unix) -> RepoResult<u64>;
}

/// An approval ticket is single-use, and consuming it flips the device code in
/// the same transaction (INV-TICKET-01).
#[async_trait]
pub trait ApprovalTicketRepo: Send + Sync {
    async fn insert(&self, ticket: &ApprovalTicket) -> RepoResult<()>;
    async fn find(&self, jti: &str) -> RepoResult<Option<ApprovalTicket>>;
    /// Consumes the ticket and approves/denies the matching device code atomically
    /// (INV-TICKET-01), recording `fact` in the same transaction (INV-AUDIT-01).
    ///
    /// Returns the client the device code belonged to, so the caller can report
    /// who was authorized without a second lookup. The fact is built by the
    /// caller but can only be attributed to a client here, because the client id
    /// lives on the device code, not on the ticket.
    ///
    /// A failed decision records nothing: there is no state change to attach the
    /// fact to, and INV-AUDIT-01 is about facts that describe a change.
    async fn consume_and_decide(
        &self,
        jti: &str,
        user_id: UserId,
        user_code_hash: &[u8],
        decision: ApprovalDecision,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<ClientId>;
    async fn purge_expired(&self, before: Unix) -> RepoResult<u64>;
}

#[async_trait]
pub trait ConsentRepo: Send + Sync {
    async fn find(&self, user: &UserId, client: &ClientId) -> RepoResult<Option<Consent>>;
    async fn list_by_user(&self, user: &UserId) -> RepoResult<Vec<Consent>>;
    /// Inserts or replaces the consent record for `(user, client)` and records
    /// the grant in the same transaction (INV-AUDIT-01). The returned row is the
    /// stored one; its `version` is what newly issued access tokens must carry.
    async fn grant(&self, consent: &Consent, fact: &SecurityFact) -> RepoResult<Consent>;
    async fn revoke(
        &self,
        user: &UserId,
        client: &ClientId,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()>;
}

/// A pending authorization is bound to one session and consumable once
/// (INV-CONSENT-01).
#[async_trait]
pub trait PendingAuthorizationRepo: Send + Sync {
    async fn insert(&self, request: &PendingAuthorization) -> RepoResult<()>;
    async fn get(&self, id: &PendingAuthorizationId) -> RepoResult<Option<PendingAuthorization>>;
    /// Atomically consumes a request bound to the given session (INV-CONSENT-01).
    async fn consume(
        &self,
        id: &PendingAuthorizationId,
        session_id: &SessionId,
        now: Unix,
    ) -> RepoResult<PendingAuthorization>;
    async fn purge_expired(&self, before: Unix) -> RepoResult<u64>;
}

/// A device code is consumable once, and a poll inside the interval yields
/// `slow_down` without minting a token (INV-DEV-01).
#[async_trait]
pub trait DeviceCodeRepo: Send + Sync {
    async fn insert(&self, code: &DeviceCode) -> RepoResult<()>;
    async fn find_by_device_hash(&self, hash: &[u8]) -> RepoResult<Option<DeviceCode>>;
    async fn find_by_user_code_hash(&self, hash: &[u8]) -> RepoResult<Option<DeviceCode>>;
    async fn approve(&self, user_code_hash: &[u8], user_id: UserId, now: Unix) -> RepoResult<()>;
    async fn deny(&self, user_code_hash: &[u8], now: Unix) -> RepoResult<()>;
    /// Denies every approved device code for one `(user, client)` pair.
    ///
    /// Called when the user withdraws the authorization. Consumed codes have
    /// already minted tokens and are handled by the consent gate, so only the
    /// still-exchangeable approvals are touched.
    async fn revoke_approved_for_client(&self, user: &UserId, client: &ClientId)
    -> RepoResult<u64>;
    /// Atomically applies the polling rate limit and consumes approved codes
    /// (INV-DEV-01).
    async fn poll(&self, device_code_hash: &[u8], now: Unix) -> RepoResult<DevicePoll>;
    async fn purge_expired(&self, before: Unix) -> RepoResult<u64>;
}

/// Failed user-code attempts are counted per `(ip, user_code_hash)` and cleared
/// on success (INV-DEVICE-02).
#[async_trait]
pub trait DeviceAttemptRepo: Send + Sync {
    async fn misses(&self, client_ip: &str, user_code_hash: &[u8], now: Unix) -> RepoResult<u32>;
    async fn record_miss(
        &self,
        client_ip: &str,
        user_code_hash: &[u8],
        now: Unix,
    ) -> RepoResult<u32>;
    async fn clear(&self, client_ip: &str, user_code_hash: &[u8]) -> RepoResult<()>;
    async fn purge_expired(&self, before: Unix) -> RepoResult<u64>;
}

#[async_trait]
pub trait ClientRepo: Send + Sync {
    async fn insert(&self, client: &Client, fact: &SecurityFact) -> RepoResult<()>;
    async fn get(&self, id: &ClientId) -> RepoResult<Option<Client>>;
    async fn set_status(&self, id: &ClientId, status: ClientStatus, now: Unix) -> RepoResult<()>;
    /// Clients, newest first, strictly older than `before` when it is given.
    async fn list(&self, before: Option<&ClientId>, limit: u32) -> RepoResult<Vec<Client>>;
    /// Replaces the mutable fields (`name`, `redirect_uris`, `allowed_scopes`,
    /// `raw_access`, `status`). `id`, `created_at` and the secret are untouched.
    async fn update(&self, client: &Client, fact: &SecurityFact, now: Unix) -> RepoResult<()>;
    /// Replaces the secret hash (rotation). `None` makes the client public.
    async fn set_secret_hash(
        &self,
        id: &ClientId,
        secret_hash: Option<&ClientSecretHash>,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()>;
}

/// A connector as persisted. Secrets live in `connector_secrets`, never here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorRecord {
    pub id: ConnectorId,
    /// Stable identifier used in URLs and in `bindings.upstream_id`.
    pub name: String,
    pub base_url: String,
    pub allow_private_net: bool,
    pub allow_link_local_metadata: bool,
    pub created_at: Unix,
    pub updated_at: Unix,
}

/// Persistence mirror of the configured connectors.
///
/// Configuration remains authoritative (`AGENTS.md`: changing a connector means
/// editing config and restarting). This port exists so that connector-level
/// secrets and resources have rows to hang off, and so the registry can be read
/// back after a restart without re-parsing TOML.
#[async_trait]
pub trait ConnectorRepo: Send + Sync {
    /// Inserts or updates by `id`. Resources are replaced wholesale, because the
    /// config file is the source of truth and a partial update would leave
    /// templates that no longer exist upstream.
    async fn upsert(
        &self,
        connector: &ConnectorRecord,
        resources: &[ResourceSpec],
        now: Unix,
    ) -> RepoResult<()>;
    async fn get(&self, id: &ConnectorId) -> RepoResult<Option<ConnectorRecord>>;
    async fn find_by_name(&self, name: &str) -> RepoResult<Option<ConnectorRecord>>;
    async fn list(&self) -> RepoResult<Vec<ConnectorRecord>>;
    async fn resources(&self, id: &ConnectorId) -> RepoResult<Vec<ResourceSpec>>;
    /// Removes a connector, its resources and its secrets (FK cascade).
    async fn delete(&self, id: &ConnectorId) -> RepoResult<bool>;

    /// Stores connector-level secret ciphertext. The key never enters this port.
    async fn store_secret(
        &self,
        connector: &ConnectorId,
        kind: &str,
        sealed: &SealedSecret,
        now: Unix,
    ) -> RepoResult<()>;
    async fn load_secret(
        &self,
        connector: &ConnectorId,
        kind: &str,
    ) -> RepoResult<Option<SealedSecret>>;
    async fn delete_secret(&self, connector: &ConnectorId, kind: &str) -> RepoResult<()>;
}

/// An upstream that the requested scopes need but the user has not connected.
///
/// A hint for the consent screen, never a gate: the data plane re-checks the
/// binding on every read, so a stale hint cannot grant access — it can only fail
/// to warn.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct MissingBinding {
    /// The connector's configured name, spelled as `bindings.upstream_id` spells
    /// it, so the portal can send the user into the flow that fixes it.
    pub upstream_id: String,
    /// The requested scopes that need it.
    pub scopes: Vec<String>,
}

/// Answers which upstreams a scope set needs, and which of them the user lacks.
///
/// A port rather than a registry call because of `INV-LOGIN-03`: login must keep
/// working with no upstream configured, and that holds only while the login path
/// cannot name a connector. The question therefore travels as strings, and what
/// knows about connectors stays on the data plane.
#[async_trait]
pub trait BindingHints: Send + Sync {
    async fn missing(&self, user: &UserId, scopes: &[String]) -> RepoResult<Vec<MissingBinding>>;
}

/// The hint source when no connector is configured.
///
/// A no-op rather than `Option`, for the reason `INV-RATE-01` records: an optional
/// collaborator turns every call site into an `if let`, and one will forget.
pub struct NoBindingHints;

#[async_trait]
impl BindingHints for NoBindingHints {
    async fn missing(&self, _user: &UserId, _scopes: &[String]) -> RepoResult<Vec<MissingBinding>> {
        Ok(Vec::new())
    }
}

/// The placeholder written over a revoked binding's upstream account identity
/// once its anonymization window has passed.
///
/// A fixed string rather than `NULL` because the column is `NOT NULL`, and one
/// shared value so the SQL and in-memory implementations cannot disagree about
/// what "already anonymized" looks like.
pub const ANONYMIZED_UPSTREAM_USER_ID: &str = "anonymized";

/// Filters for the admin binding list. `None` means "no filter on this axis".
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BindingQuery {
    pub user: Option<UserId>,
    pub upstream: Option<String>,
    pub status: Option<BindingStatus>,
}

/// At most one active binding exists per `(user_id, upstream_id)` (INV-BIND-01).
#[async_trait]
pub trait BindingRepo: Send + Sync {
    /// Upserts on `(user_id, upstream_id)`; the pair is unique (INV-BIND-01).
    /// The audit fact lands in the same transaction (INV-AUDIT-01).
    async fn upsert(&self, binding: &Binding, fact: &SecurityFact) -> RepoResult<()>;
    /// Atomically upserts the binding and its sealed credential.
    ///
    /// `sealed` must have been sealed for `binding.id`. If the pair already
    /// exists under another id, returns `Conflict("binding id")` instead of
    /// attaching the credential to the wrong row. The returned binding carries
    /// the stored id/created_at, and the fact target is rewritten to
    /// `binding:{id}`.
    async fn upsert_with_credential(
        &self,
        binding: &Binding,
        sealed: &SealedSecret,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<Binding>;
    async fn find(&self, user: &UserId, upstream: &str) -> RepoResult<Option<Binding>>;
    async fn list_by_user(&self, user: &UserId) -> RepoResult<Vec<Binding>>;
    async fn mark_needs_reauth(
        &self,
        id: &BindingId,
        reason: &str,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()>;
    async fn revoke(&self, id: &BindingId, fact: &SecurityFact, now: Unix) -> RepoResult<()>;

    /// Revokes every non-revoked binding owned by `user` in one transaction,
    /// deleting their sub-credentials, and returns how many rows moved.
    ///
    /// The killswitch is all-or-nothing: a caller must never end up with half
    /// the bindings revoked, because that is the state hardest to reason about
    /// when an account is compromised. Idempotent — a second call reports zero
    /// rather than failing, so a retry after an uncertain response is safe.
    /// `fact` is recorded only when something changed.
    async fn revoke_all(&self, user: &UserId, fact: &SecurityFact, now: Unix) -> RepoResult<u64>;

    /// Stores only ciphertext; the key never enters this port.
    async fn store_sub_credential(
        &self,
        binding: &BindingId,
        sealed: &SealedSecret,
        now: Unix,
    ) -> RepoResult<()>;
    async fn load_sub_credential(&self, binding: &BindingId) -> RepoResult<Option<SealedSecret>>;
    async fn delete_sub_credential(&self, binding: &BindingId) -> RepoResult<()>;

    /// Replaces only the key envelope of a stored credential.
    ///
    /// Applies only when the stored value still equals `expect`, and reports
    /// whether it did. Not assembled from a load-then-store in the caller: the
    /// window between those two is where a credential enrolled concurrently gets
    /// silently rolled back, because a rotation would write back the payload it
    /// read while reporting success. Comparing on the wrapped DEK makes the
    /// update a swap — a concurrent enrol or a concurrent re-wrap both change it.
    async fn rewrap_sub_credential(
        &self,
        binding: &BindingId,
        expect: &SealedSecret,
        new: &SealedSecret,
        now: Unix,
    ) -> RepoResult<bool>;

    /// Every stored credential, oldest binding id first, after `after`.
    ///
    /// Exists for the key rotation, which has to visit records it did not create
    /// and has no reason to know about. Paged by binding id rather than offset so
    /// a rotation that re-wraps rows mid-scan cannot skip anything: the cursor is
    /// the last id seen, and re-wrapping never changes an id.
    async fn scan_sub_credentials(
        &self,
        after: Option<&BindingId>,
        limit: u32,
    ) -> RepoResult<Vec<(BindingId, SealedSecret)>>;

    /// Bindings across all users, newest first, for the admin view.
    async fn list_all(
        &self,
        before: Option<&BindingId>,
        query: &BindingQuery,
        limit: u32,
    ) -> RepoResult<Vec<Binding>>;

    /// Physically removes the upstream account identity from bindings revoked at
    /// or before `before`, without deleting the row.
    ///
    /// The row is the audit evidence that a binding existed and was withdrawn;
    /// the `upstream_user_id` is the part that identifies a person on the source
    /// platform, so it is replaced with [`ANONYMIZED_UPSTREAM_USER_ID`]. Only
    /// revoked bindings are touched, and a second run reports zero (idempotent).
    async fn anonymize_revoked_before(&self, before: Unix) -> RepoResult<u64>;
}

/// Stored audit records.
///
/// Security facts never go through this port: they are written by the repository
/// method that performs the change, inside the same transaction. This port
/// exists for reading them back and for the asynchronous telemetry tier
/// (ADR-0025), which may be dropped and is therefore never used for facts.
/// Filters for the admin audit query. `None` means "no filter on this axis".
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuditFilter {
    pub actor: Option<UserId>,
    pub client: Option<ClientId>,
    pub action: Option<AuditAction>,
    pub tier: Option<AuditTier>,
    pub from: Option<Unix>,
    pub to: Option<Unix>,
}

#[async_trait]
pub trait AuditRepo: Send + Sync {
    /// Reads records newest-first, bounded by `limit`.
    async fn recent(&self, limit: u32) -> RepoResult<Vec<AuditRecord>>;
    /// Reads records for one actor, newest-first.
    async fn by_actor(&self, user: &UserId, limit: u32) -> RepoResult<Vec<AuditRecord>>;
    /// Admin query: filters plus a descending cursor.
    ///
    /// Read-only by contract (HR-04): looking at the audit trail must never
    /// change it.
    async fn query(
        &self,
        filter: &AuditFilter,
        before: Option<&AuditId>,
        limit: u32,
    ) -> RepoResult<Vec<AuditRecord>>;
    /// Appends a telemetry-tier record. Best effort by contract; callers count
    /// drops rather than retrying forever.
    async fn append(&self, record: &AuditRecord) -> RepoResult<()>;
    /// Deletes records of one tier older than `before`.
    ///
    /// Tier-separated on purpose (Q-032): a fact purge must never take telemetry
    /// with it, nor the other way round. Returns how many rows were removed;
    /// zero is a normal result for a retention sweep that found nothing.
    async fn purge_tier_before(&self, tier: AuditTier, before: Unix) -> RepoResult<u64>;
}

/// A lossy sink for access telemetry (ADR-0025).
///
/// Synchronous and non-blocking on purpose: the gateway calls this on the
/// request hot path, and making it `async` would pull an async runtime into the
/// application layer. `false` means the record was **dropped**, never that the
/// caller should retry.
pub trait TelemetrySink: Send + Sync {
    fn record(&self, event: AccessTelemetry) -> bool;
}

/// The sink used when telemetry is not wired.
///
/// Accepts and discards, returning `true`: reporting `false` would claim a drop
/// that never happened, and a deployment without a sink simply has no access
/// ledger at all.
pub struct NoTelemetry;

impl TelemetrySink for NoTelemetry {
    fn record(&self, _event: AccessTelemetry) -> bool {
        true
    }
}

/// Revoked access tokens (RFC 7009).
///
/// Access tokens are self-contained: nothing is persisted when one is issued, so
/// revocation records only the `jti` of tokens that must stop working. Every
/// verification path consults this port, which is what makes revocation take
/// effect immediately rather than at expiry.
#[async_trait]
pub trait AccessTokenRepo: Send + Sync {
    /// Records `jti` as revoked and writes `fact` in the same transaction
    /// (INV-AUDIT-01: token revocation is a security fact, not telemetry).
    ///
    /// Idempotent: revoking twice is not an error, because the caller cannot
    /// distinguish "already revoked" from "never existed" without leaking
    /// whether a token was valid.
    async fn revoke(
        &self,
        jti: &str,
        client_id: Option<ClientId>,
        revoked_by: Option<UserId>,
        expires_at: Unix,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()>;
    /// True when `jti` has been revoked and has not yet expired.
    async fn is_revoked(&self, jti: &str, now: Unix) -> RepoResult<bool>;
    /// 家族是否已撤销
    async fn is_family_revoked(&self, family: &FamilyId) -> RepoResult<bool>;
    /// Deletes rows whose tokens have expired anyway; they can no longer be
    /// presented, so keeping them only grows the table.
    async fn purge_expired(&self, before: Unix) -> RepoResult<u64>;
}

/// A published signing key. Public material only: the private half lives in a
/// `0600` PEM file and never reaches the database (INV-KEY-01).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningKeyRecord {
    /// Derived from the public key, never hard-coded and never reused.
    pub kid: String,
    pub alg: String,
    /// The public JWK as JSON, ready to be spliced into a JWKS document.
    pub public_jwk_json: String,
    pub created_at: Unix,
    pub activated_at: Unix,
    /// `None` while the key may still be used for verification.
    pub retired_at: Option<Unix>,
}

/// Our own signing keys, not to be confused with an IdP's JWKS.
///
/// Retiring a key does not delete it: tokens signed before the rotation remain
/// verifiable until they expire (OPERATIONS.md §5.2). Reusing a `kid` would make
/// old tokens resolve to a new key, which is the known failure mode this table
/// exists to prevent.
#[async_trait]
pub trait SigningKeyRepo: Send + Sync {
    /// Inserts a key, or updates it when `kid` already exists. Idempotent so a
    /// restart re-publishing the same key does not fail.
    async fn publish(&self, record: &SigningKeyRecord) -> RepoResult<()>;
    /// Every key that must appear in the JWKS document, newest first.
    ///
    /// Includes retired keys: dropping them would make unexpired tokens signed
    /// by the old key fail verification.
    async fn published(&self) -> RepoResult<Vec<SigningKeyRecord>>;
    /// The key new tokens should be signed with: the newest non-retired one.
    async fn active(&self) -> RepoResult<Option<SigningKeyRecord>>;
    /// Marks `kid` as retired. Idempotent.
    async fn retire(&self, kid: &str, at: Unix) -> RepoResult<()>;
}

/// Aggregate port used by the contract suite.
#[async_trait]
pub trait Storage: Send + Sync {
    fn users(&self) -> &dyn UserRepo;
    fn sessions(&self) -> &dyn SessionRepo;
    fn auth_codes(&self) -> &dyn AuthCodeRepo;
    fn refresh_tokens(&self) -> &dyn RefreshTokenRepo;
    fn access_tokens(&self) -> &dyn AccessTokenRepo;
    fn bindings(&self) -> &dyn BindingRepo;
    fn connectors(&self) -> &dyn ConnectorRepo;
    fn clients(&self) -> &dyn ClientRepo;
    fn device_codes(&self) -> &dyn DeviceCodeRepo;
    fn device_attempts(&self) -> &dyn DeviceAttemptRepo;
    fn login_transactions(&self) -> &dyn LoginTransactionRepo;
    fn pending_bindings(&self) -> &dyn PendingBindingRepo;
    fn approval_tickets(&self) -> &dyn ApprovalTicketRepo;
    fn consents(&self) -> &dyn ConsentRepo;
    fn pending_authorizations(&self) -> &dyn PendingAuthorizationRepo;
    fn audits(&self) -> &dyn AuditRepo;
    fn signing_keys(&self) -> &dyn SigningKeyRepo;
    /// Round-trips one trivial query so `/readyz` can report whether the
    /// backend is actually reachable, not merely whether the process is up.
    async fn ping(&self) -> RepoResult<()>;
}
