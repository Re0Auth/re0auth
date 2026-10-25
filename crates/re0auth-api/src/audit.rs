//! Audit events.
//!
//! Two tiers, per ADR-0025:
//!
//! - **Security facts** (authorization decisions, token issuance and revocation,
//!   binding changes) are written in the *same transaction* as the state change
//!   they describe. They cannot be lost. See [`SecurityFact`].
//! - **Access telemetry** (who fetched what) is written asynchronously and may be
//!   dropped under load. Dropping is counted (INV-AUDIT-01).
//!
//! The types here are deliberately free of `serde_json`: the contract layer
//! carries structured values, and the storage adapter decides how to encode
//! `detail` into the `detail_json` column. That keeps `re0auth-api` free of a
//! JSON dependency and keeps the encoding in one place.

use serde::{Deserialize, Serialize};

use crate::{AuditId, ClientId, Unix, UserId};

/// What happened. Adding a variant is a compatible change (the enum is
/// `#[non_exhaustive]`), but the database string must be added to [`as_str`] at
/// the same time: that match is intentionally exhaustive.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditAction {
    /// An authorization code was issued to a client.
    AuthCodeIssued,
    /// A refresh token was rotated into its successor.
    RefreshTokenRotated,
    /// A refresh token was replayed; the whole family was revoked.
    RefreshTokenReuseDetected,
    /// A refresh token family was revoked.
    RefreshTokenRevoked,
    /// A user granted a client access to a set of scopes.
    ConsentGranted,
    /// A user withdrew a client's access.
    ConsentRevoked,
    /// An upstream binding was created or updated.
    BindingCreated,
    /// An upstream binding was revoked.
    BindingRevoked,
    /// An existing binding was re-bound to a different upstream account.
    ///
    /// Distinct from `BindingRevoked` followed by `BindingCreated`: the user's
    /// intent was to replace the account, not to withdraw and re-grant. Keeping
    /// the two readings apart is what makes "why did this user lose access at
    /// 03:00" answerable.
    BindingRebound,
    /// A binding attempt started but did not complete.
    BindingFailed,
    /// A binding was marked as needing re-authorization.
    BindingNeedsReauth,
    /// An access token was revoked before its natural expiry.
    AccessTokenRevoked,
    /// A user approved a device-code authorization. This is an authorization
    /// decision (ADR-0025) and the only point where a device flow can be
    /// attributed to a client.
    DeviceApproved,
    /// A user denied a device-code authorization.
    DeviceDenied,
    /// A user's upstream data was read through the gateway.
    ///
    /// The only telemetry-tier action: it is written asynchronously and may be
    /// dropped (ADR-0025), which is why it must be distinguishable from the
    /// security facts that share the same table.
    DataAccessed,
    /// An admin registered a client.
    ClientCreated,
    /// An admin edited a client's configuration.
    ClientUpdated,
    /// An admin rotated a client secret.
    ClientSecretRotated,
    /// An admin changed a user's role.
    UserRoleChanged,
}

impl AuditAction {
    /// Stable database representation.
    ///
    /// Exhaustive on purpose: adding a variant without updating this match is a
    /// compile error, which is the whole point of not relying on a derived
    /// string. A silent rename here would rewrite the meaning of history.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthCodeIssued => "auth_code_issued",
            Self::RefreshTokenRotated => "refresh_token_rotated",
            Self::RefreshTokenReuseDetected => "refresh_token_reuse_detected",
            Self::RefreshTokenRevoked => "refresh_token_revoked",
            Self::ConsentGranted => "consent_granted",
            Self::ConsentRevoked => "consent_revoked",
            Self::BindingCreated => "binding_created",
            Self::BindingRevoked => "binding_revoked",
            Self::BindingRebound => "binding_rebound",
            Self::BindingFailed => "binding_failed",
            Self::BindingNeedsReauth => "binding_needs_reauth",
            Self::AccessTokenRevoked => "access_token_revoked",
            Self::DeviceApproved => "device_approved",
            Self::DeviceDenied => "device_denied",
            Self::DataAccessed => "data_accessed",
            Self::ClientCreated => "client_created",
            Self::ClientUpdated => "client_updated",
            Self::ClientSecretRotated => "client_secret_rotated",
            Self::UserRoleChanged => "user_role_changed",
        }
    }

    /// Parses a stored value. Unknown strings are returned as `None` rather than
    /// guessed: a value written by a newer version must not be misread as one of
    /// today's actions.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "auth_code_issued" => Self::AuthCodeIssued,
            "refresh_token_rotated" => Self::RefreshTokenRotated,
            "refresh_token_reuse_detected" => Self::RefreshTokenReuseDetected,
            "refresh_token_revoked" => Self::RefreshTokenRevoked,
            "consent_granted" => Self::ConsentGranted,
            "consent_revoked" => Self::ConsentRevoked,
            "binding_created" => Self::BindingCreated,
            "binding_revoked" => Self::BindingRevoked,
            "binding_rebound" => Self::BindingRebound,
            "binding_failed" => Self::BindingFailed,
            "binding_needs_reauth" => Self::BindingNeedsReauth,
            "access_token_revoked" => Self::AccessTokenRevoked,
            "device_approved" => Self::DeviceApproved,
            "device_denied" => Self::DeviceDenied,
            "data_accessed" => Self::DataAccessed,
            "client_created" => Self::ClientCreated,
            "client_updated" => Self::ClientUpdated,
            "client_secret_rotated" => Self::ClientSecretRotated,
            "user_role_changed" => Self::UserRoleChanged,
            _ => return None,
        })
    }
}

/// Whether the action succeeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
}

impl AuditOutcome {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "success" => Self::Success,
            "failure" => Self::Failure,
            "denied" => Self::Denied,
            _ => return None,
        })
    }
}

/// How urgently a human should look at this record.
///
/// The split exists so that alerting does not need to enumerate actions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Severity {
    /// Routine authorization activity.
    Info,
    /// Something a reviewer would want to see without being paged.
    Notice,
    /// A probable attack or a broken security control.
    Alert,
}

impl Severity {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Alert => "alert",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "info" => Self::Info,
            "notice" => Self::Notice,
            "alert" => Self::Alert,
            _ => return None,
        })
    }
}

/// Which retention tier a record belongs to (ADR-0025).
///
/// The tier is a property of the *write path*, not of urgency: a security fact
/// is written in the transaction that changes state, while access telemetry is
/// best-effort and may be dropped. Retention differs by tier (Q-032), so they
/// must not be conflated with [`Severity`] — many security facts are `Info`
/// urgency and would be deleted early if urgency chose the retention rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditTier {
    /// A security fact, written with its state change.
    Fact,
    /// Access telemetry, best-effort and lossy.
    Telemetry,
}

impl AuditTier {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fact => "fact",
            Self::Telemetry => "telemetry",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "fact" => Self::Fact,
            "telemetry" => Self::Telemetry,
            _ => return None,
        })
    }
}

/// A security fact: written in the same transaction as the change it describes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityFact {
    pub id: AuditId,
    /// When it happened, from the injected clock.
    pub occurred_at: Unix,
    /// Absent when the actor was deleted (INV-FK-01 keeps the row).
    pub actor_user_id: Option<UserId>,
    pub client_id: Option<ClientId>,
    pub action: AuditAction,
    /// What was affected, e.g. `binding:01J...`. Never a secret.
    pub target: String,
    pub outcome: AuditOutcome,
    pub severity: Severity,
    /// Correlation id for the originating request, when known.
    pub request_id: Option<String>,
}

impl SecurityFact {
    /// Builds a routine record. Callers override `severity` when the outcome is
    /// more interesting than the action alone.
    #[must_use]
    pub fn new(action: AuditAction, occurred_at: Unix, target: impl Into<String>) -> Self {
        Self {
            id: AuditId::new(),
            occurred_at,
            actor_user_id: None,
            client_id: None,
            action,
            target: target.into(),
            outcome: AuditOutcome::Success,
            severity: Severity::Info,
            request_id: None,
        }
    }

    #[must_use]
    pub fn actor(mut self, user: UserId) -> Self {
        self.actor_user_id = Some(user);
        self
    }

    #[must_use]
    pub fn client(mut self, client: ClientId) -> Self {
        self.client_id = Some(client);
        self
    }

    #[must_use]
    pub fn outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = outcome;
        self
    }

    #[must_use]
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    #[must_use]
    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Attaches a correlation id only when there is one.
    ///
    /// Most call paths have no request id (internal jobs, tests), so this keeps
    /// the call site free of a `match` that would otherwise be repeated at every
    /// fact construction site.
    #[must_use]
    pub fn with_request_id(mut self, request_id: Option<&str>) -> Self {
        if let Some(id) = request_id {
            self.request_id = Some(id.to_string());
        }
        self
    }

    /// Re-labels a planned rotation as a detected replay.
    ///
    /// The storage layer learns that a rotation was a replay only after it has
    /// already looked the token up, so the caller cannot know up front. Recording
    /// the deceptive "rotated" label instead would make the audit trail lie about
    /// the event that actually occurred.
    #[must_use]
    pub fn as_reuse(&self) -> Self {
        let mut fact = self.clone();
        fact.action = AuditAction::RefreshTokenReuseDetected;
        fact.outcome = AuditOutcome::Denied;
        fact.severity = Severity::Alert;
        // The replayed token is a different subject from the successor.
        fact.id = AuditId::new();
        fact
    }
}

/// Where a gateway read was served from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AccessSource {
    Upstream,
    Cache,
}

impl AccessSource {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::Cache => "cache",
        }
    }
}

/// One access-telemetry event (ADR-0025's lossy tier).
///
/// Deliberately typed rather than an [`AuditRecord`]: the application layer has
/// no JSON dependency, so it must not have to build `detail_json` itself. The
/// runtime converts this into an `AuditRecord` on the way to storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessTelemetry {
    pub id: AuditId,
    pub occurred_at: Unix,
    pub actor_user_id: Option<UserId>,
    pub client_id: Option<ClientId>,
    pub connector: String,
    pub resource: String,
    pub source: AccessSource,
    pub latency_ms: u64,
    pub request_id: Option<String>,
}

/// A stored audit row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRecord {
    pub id: AuditId,
    pub occurred_at: Unix,
    pub actor_user_id: Option<UserId>,
    pub client_id: Option<ClientId>,
    pub action: AuditAction,
    pub target: String,
    pub outcome: AuditOutcome,
    pub severity: Severity,
    pub request_id: Option<String>,
    /// Storage-defined JSON. Never contains secrets (INV-JSON-01).
    pub detail: String,
    /// Retention tier: facts are kept longer than telemetry (Q-032).
    pub tier: AuditTier,
}

impl From<SecurityFact> for AuditRecord {
    fn from(fact: SecurityFact) -> Self {
        Self {
            id: fact.id,
            occurred_at: fact.occurred_at,
            actor_user_id: fact.actor_user_id,
            client_id: fact.client_id,
            action: fact.action,
            target: fact.target,
            outcome: fact.outcome,
            severity: fact.severity,
            request_id: fact.request_id,
            detail: "{}".to_string(),
            tier: AuditTier::Fact,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_action_round_trips_through_its_database_string() {
        // A mismatch here would silently rewrite history on the next read.
        for action in [
            AuditAction::AuthCodeIssued,
            AuditAction::RefreshTokenRotated,
            AuditAction::RefreshTokenReuseDetected,
            AuditAction::RefreshTokenRevoked,
            AuditAction::ConsentGranted,
            AuditAction::ConsentRevoked,
            AuditAction::BindingCreated,
            AuditAction::BindingRevoked,
            AuditAction::BindingNeedsReauth,
            AuditAction::DataAccessed,
            AuditAction::ClientCreated,
            AuditAction::ClientUpdated,
            AuditAction::ClientSecretRotated,
            AuditAction::UserRoleChanged,
        ] {
            assert_eq!(
                AuditAction::parse(action.as_str()),
                Some(action),
                "{action:?} does not survive a round trip"
            );
        }
    }

    #[test]
    fn outcome_and_severity_round_trip() {
        for outcome in [
            AuditOutcome::Success,
            AuditOutcome::Failure,
            AuditOutcome::Denied,
        ] {
            assert_eq!(AuditOutcome::parse(outcome.as_str()), Some(outcome));
        }
        for severity in [Severity::Info, Severity::Notice, Severity::Alert] {
            assert_eq!(Severity::parse(severity.as_str()), Some(severity));
        }
    }

    #[test]
    fn unknown_values_are_not_guessed() {
        // A row written by a newer version must never be misread as an old action.
        assert_eq!(AuditAction::parse("future_action"), None);
        assert_eq!(AuditAction::parse(""), None);
        assert_eq!(AuditOutcome::parse("maybe"), None);
        assert_eq!(Severity::parse("critical"), None);
    }

    #[test]
    fn database_strings_are_snake_case_and_unique() {
        let actions = [
            AuditAction::AuthCodeIssued,
            AuditAction::RefreshTokenRotated,
            AuditAction::RefreshTokenReuseDetected,
            AuditAction::RefreshTokenRevoked,
            AuditAction::ConsentGranted,
            AuditAction::ConsentRevoked,
            AuditAction::BindingCreated,
            AuditAction::BindingRevoked,
            AuditAction::BindingNeedsReauth,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for action in actions {
            let value = action.as_str();
            assert!(
                value
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{value} is not snake_case"
            );
            assert!(seen.insert(value), "duplicate action string {value}");
        }
    }
}
