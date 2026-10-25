//! Administrative use cases behind `/api/admin/*` (B1).
//!
//! Distinct from [`crate::admin`], which serves the CLI. This layer adds what an
//! HTTP surface needs and the CLI never did: the last-admin guard, refusal to
//! self-demote, secret rotation that returns the plaintext exactly once, and
//! cache invalidation on an admin binding revoke (INV-CACHE-02). It does no I/O
//! of its own and starts no background work.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;

use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::cache::{Cache, NoCache};
use re0auth_api::ports::{
    AuditFilter, Binding, BindingQuery, Client, ClientStatus, ConnectorRecord, RepoError, Storage,
    User, UserRole,
};
use re0auth_api::secret::ClientSecretHasher;
use re0auth_api::{BindingId, ClientId, Clock, ConnectorId, Random, Unix, UserId};

use crate::admin::{self, CLIENT_SECRET_BYTES, NewClient};

const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 200;

/// What an admin request can fail with.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("not found")]
    NotFound,
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    /// A rule the caller must resolve first (last admin, lost update).
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("storage error")]
    Repo(#[from] RepoError),
}

/// A cursor page. `next_cursor` is the last id of a full page, or `None`.
#[derive(Clone, Debug, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdminClientView {
    pub id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub raw_access: bool,
    pub status: &'static str,
    /// Whether a secret is set. The secret itself is never readable here.
    pub has_secret: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

/// The client and its freshly minted secret. The secret appears once.
#[derive(Clone, Debug, Serialize)]
pub struct CreatedClientView {
    pub id: String,
    pub secret: Option<String>,
}

/// A rotated secret. Returned exactly once, never stored in the clear.
#[derive(Clone, Debug, Serialize)]
pub struct RotatedSecretView {
    pub id: String,
    pub secret: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdminUserView {
    pub id: String,
    pub display_name: String,
    pub role: &'static str,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdminResourceView {
    pub name: String,
    pub path: String,
    pub scope: String,
    pub method: &'static str,
    pub idempotent: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdminConnectorView {
    pub id: String,
    pub name: String,
    pub base_url: String,
    pub allow_private_net: bool,
    pub allow_link_local_metadata: bool,
    pub resources: Vec<AdminResourceView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdminBindingView {
    pub id: String,
    pub user_id: String,
    pub connector: String,
    pub upstream_user_id: String,
    pub status: &'static str,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_refreshed_at: Option<i64>,
    pub last_error_code: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdminAuditView {
    pub id: String,
    pub occurred_at: i64,
    pub actor_user_id: Option<String>,
    pub client_id: Option<String>,
    pub action: &'static str,
    pub target: String,
    pub outcome: &'static str,
    pub severity: &'static str,
    pub request_id: Option<String>,
    pub tier: &'static str,
    pub detail: String,
}

/// What `POST /clients` accepts.
pub struct NewClientInput {
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub raw_access: bool,
    pub confidential: bool,
    pub status: ClientStatus,
}

/// A partial edit. Every field is optional; `expected_updated_at` is the
/// optimistic-lock precondition.
#[derive(Clone, Debug, Default)]
pub struct ClientPatch {
    pub name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub allowed_scopes: Option<Vec<String>>,
    pub raw_access: Option<bool>,
    pub status: Option<ClientStatus>,
    pub expected_updated_at: Option<i64>,
}

pub struct AdminService {
    storage: Arc<dyn Storage>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn Random>,
    hasher: Arc<dyn ClientSecretHasher>,
    /// For INV-CACHE-02. Absent means no gateway cache is wired.
    cache: Arc<dyn Cache>,
}

impl AdminService {
    #[must_use]
    pub fn new(
        storage: Arc<dyn Storage>,
        clock: Arc<dyn Clock>,
        random: Arc<dyn Random>,
        hasher: Arc<dyn ClientSecretHasher>,
    ) -> Self {
        Self {
            storage,
            clock,
            random,
            hasher,
            cache: Arc::new(NoCache),
        }
    }

    #[must_use]
    pub fn with_cache(mut self, cache: Arc<dyn Cache>) -> Self {
        self.cache = cache;
        self
    }

    // ---- Clients ---------------------------------------------------------

    pub async fn list_clients(
        &self,
        before: Option<ClientId>,
        limit: Option<u32>,
    ) -> Result<Page<AdminClientView>, AdminError> {
        let limit = clamp(limit);
        let clients = self.storage.clients().list(before.as_ref(), limit).await?;
        Ok(page(
            clients.into_iter().map(client_view).collect(),
            limit,
            |view| view.id.clone(),
        ))
    }

    pub async fn get_client(&self, id: &ClientId) -> Result<AdminClientView, AdminError> {
        let client = self
            .storage
            .clients()
            .get(id)
            .await?
            .ok_or(AdminError::NotFound)?;
        Ok(client_view(client))
    }

    pub async fn create_client(
        &self,
        actor: UserId,
        correlation_id: Option<&str>,
        input: NewClientInput,
    ) -> Result<CreatedClientView, AdminError> {
        if input.name.trim().is_empty() {
            return Err(AdminError::InvalidRequest("name is required"));
        }
        let created = admin::create_client(
            self.storage.as_ref(),
            self.clock.as_ref(),
            self.random.as_ref(),
            self.hasher.as_ref(),
            Some(actor),
            correlation_id,
            NewClient {
                name: &input.name,
                redirect_uris: input.redirect_uris,
                allowed_scopes: input.allowed_scopes,
                raw_access: input.raw_access,
                status: input.status,
                confidential: input.confidential,
            },
        )
        .await?;
        Ok(CreatedClientView {
            id: created.id.0.to_string(),
            secret: created.secret,
        })
    }

    pub async fn update_client(
        &self,
        actor: UserId,
        id: &ClientId,
        patch: ClientPatch,
        correlation_id: Option<&str>,
    ) -> Result<AdminClientView, AdminError> {
        let now = self.clock.now();
        let mut client = self
            .storage
            .clients()
            .get(id)
            .await?
            .ok_or(AdminError::NotFound)?;
        if let Some(expected) = patch.expected_updated_at
            && client.updated_at != expected
        {
            return Err(AdminError::Conflict("client was modified"));
        }
        if let Some(name) = patch.name {
            if name.trim().is_empty() {
                return Err(AdminError::InvalidRequest("name is required"));
            }
            client.name = name;
        }
        if let Some(uris) = patch.redirect_uris {
            client.redirect_uris = uris;
        }
        if let Some(scopes) = patch.allowed_scopes {
            client.allowed_scopes = scopes;
        }
        if let Some(raw) = patch.raw_access {
            client.raw_access = raw;
        }
        if let Some(status) = patch.status {
            client.status = status;
        }
        let fact = SecurityFact::new(
            AuditAction::ClientUpdated,
            now,
            format!("client:{}", client.id.0),
        )
        .actor(actor)
        .with_request_id(correlation_id);
        self.storage.clients().update(&client, &fact, now).await?;
        Ok(client_view(client))
    }

    /// Installs a new secret and returns the plaintext once.
    pub async fn rotate_client_secret(
        &self,
        actor: UserId,
        id: &ClientId,
        correlation_id: Option<&str>,
    ) -> Result<RotatedSecretView, AdminError> {
        let now = self.clock.now();
        if self.storage.clients().get(id).await?.is_none() {
            return Err(AdminError::NotFound);
        }
        let secret = URL_SAFE_NO_PAD.encode(self.random.bytes(CLIENT_SECRET_BYTES));
        let hash = self
            .hasher
            .hash(&secret)
            .map_err(|error| AdminError::Repo(RepoError::Backend(error.to_string())))?;
        let fact = SecurityFact::new(
            AuditAction::ClientSecretRotated,
            now,
            format!("client:{}", id.0),
        )
        .actor(actor)
        .with_request_id(correlation_id);
        self.storage
            .clients()
            .set_secret_hash(id, Some(&hash), &fact, now)
            .await?;
        Ok(RotatedSecretView {
            id: id.0.to_string(),
            secret,
        })
    }

    // ---- Users -----------------------------------------------------------

    pub async fn list_users(
        &self,
        before: Option<UserId>,
        limit: Option<u32>,
    ) -> Result<Page<AdminUserView>, AdminError> {
        let limit = clamp(limit);
        let users = self.storage.users().list(before.as_ref(), limit).await?;
        Ok(page(
            users.into_iter().map(user_view).collect(),
            limit,
            |view| view.id.clone(),
        ))
    }

    /// Changes a role, refusing moves that would lock the instance out.
    pub async fn set_user_role(
        &self,
        actor: UserId,
        target: UserId,
        role: UserRole,
        correlation_id: Option<&str>,
    ) -> Result<AdminUserView, AdminError> {
        let now = self.clock.now();
        let user = self
            .storage
            .users()
            .get(&target)
            .await?
            .ok_or(AdminError::NotFound)?;
        if user.role == UserRole::Admin && role != UserRole::Admin {
            if target == actor {
                return Err(AdminError::Conflict("you cannot demote yourself"));
            }
            if self.storage.users().count_admins().await? <= 1 {
                return Err(AdminError::Conflict("the last admin cannot be demoted"));
            }
        }
        let fact = SecurityFact::new(
            AuditAction::UserRoleChanged,
            now,
            format!("user:{}", target.0),
        )
        .actor(actor)
        .with_request_id(correlation_id);
        self.storage
            .users()
            .set_role(&target, role, &fact, now)
            .await?;
        Ok(AdminUserView {
            id: user.id.0.to_string(),
            display_name: user.display_name,
            role: role_str(role),
            created_at: user.created_at,
            updated_at: now,
        })
    }

    // ---- Tokens ----------------------------------------------------------

    /// Revokes one access token by its `jti`, for incident response.
    ///
    /// Takes the `jti` rather than the token string: an operator responding to a
    /// leak has the audit log or a database row, not the bearer token itself.
    /// Signature verification is therefore not part of this path — the caller is
    /// already an admin, and revoking a `jti` that was never issued is a no-op
    /// rather than a risk.
    ///
    /// A token that has already expired is refused instead of recorded: nothing
    /// can present it any more, and the row would be swept as garbage while the
    /// operator believes something was revoked.
    pub async fn revoke_access_token(
        &self,
        actor: UserId,
        jti: &str,
        client_id: Option<ClientId>,
        expires_at: Unix,
        correlation_id: Option<&str>,
    ) -> Result<(), AdminError> {
        if jti.trim().is_empty() {
            return Err(AdminError::InvalidRequest("jti is required"));
        }
        let now = self.clock.now();
        if expires_at <= now {
            return Err(AdminError::InvalidRequest(
                "the token has already expired; nothing can present it",
            ));
        }
        let mut fact =
            SecurityFact::new(AuditAction::AccessTokenRevoked, now, format!("jti:{jti}"))
                .actor(actor)
                .with_request_id(correlation_id);
        if let Some(client) = client_id {
            fact = fact.client(client);
        }
        self.storage
            .access_tokens()
            .revoke(jti, client_id, None, expires_at, &fact, now)
            .await?;
        Ok(())
    }

    // ---- Connectors (read-only) -----------------------------------------

    pub async fn list_connectors(&self) -> Result<Vec<AdminConnectorView>, AdminError> {
        let records = self.storage.connectors().list().await?;
        let mut views = Vec::with_capacity(records.len());
        for record in records {
            views.push(self.connector_view(record).await?);
        }
        Ok(views)
    }

    pub async fn get_connector(&self, id: &ConnectorId) -> Result<AdminConnectorView, AdminError> {
        let record = self
            .storage
            .connectors()
            .get(id)
            .await?
            .ok_or(AdminError::NotFound)?;
        self.connector_view(record).await
    }

    async fn connector_view(
        &self,
        record: ConnectorRecord,
    ) -> Result<AdminConnectorView, AdminError> {
        let resources = self.storage.connectors().resources(&record.id).await?;
        Ok(AdminConnectorView {
            id: record.id.0.to_string(),
            name: record.name,
            base_url: record.base_url,
            allow_private_net: record.allow_private_net,
            allow_link_local_metadata: record.allow_link_local_metadata,
            resources: resources
                .into_iter()
                .map(|spec| AdminResourceView {
                    name: spec.name,
                    path: spec.path_template,
                    scope: spec.required_scope,
                    method: spec.method.as_str(),
                    idempotent: spec.idempotent,
                })
                .collect(),
        })
    }

    // ---- Bindings --------------------------------------------------------

    pub async fn list_bindings(
        &self,
        before: Option<BindingId>,
        query: BindingQuery,
        limit: Option<u32>,
    ) -> Result<Page<AdminBindingView>, AdminError> {
        let limit = clamp(limit);
        let bindings = self
            .storage
            .bindings()
            .list_all(before.as_ref(), &query, limit)
            .await?;
        Ok(page(
            bindings.into_iter().map(binding_view).collect(),
            limit,
            |view| view.id.clone(),
        ))
    }

    /// The admin killswitch: revokes any binding, not only the caller's own.
    pub async fn revoke_binding(
        &self,
        actor: UserId,
        id: BindingId,
        correlation_id: Option<&str>,
    ) -> Result<(), AdminError> {
        let now = self.clock.now();
        let fact = SecurityFact::new(
            AuditAction::BindingRevoked,
            now,
            format!("binding:{}", id.0),
        )
        .actor(actor)
        .with_request_id(correlation_id);
        match self.storage.bindings().revoke(&id, &fact, now).await {
            Ok(()) => {
                // After the commit, for the same reason as the user path: a later
                // error must not skip the sweep (INV-CACHE-02).
                self.cache
                    .invalidate(&re0auth_api::cache::binding_prefix(&id))
                    .await;
                Ok(())
            }
            Err(RepoError::NotFound) => Err(AdminError::NotFound),
            Err(error) => Err(AdminError::Repo(error)),
        }
    }

    // ---- Audit -----------------------------------------------------------

    pub async fn list_audit(
        &self,
        filter: AuditFilter,
        before: Option<re0auth_api::AuditId>,
        limit: Option<u32>,
    ) -> Result<Page<AdminAuditView>, AdminError> {
        let limit = clamp(limit);
        let records = self
            .storage
            .audits()
            .query(&filter, before.as_ref(), limit)
            .await?;
        Ok(page(
            records.into_iter().map(audit_view).collect(),
            limit,
            |view| view.id.clone(),
        ))
    }
}

fn clamp(limit: Option<u32>) -> u32 {
    limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

fn page<T>(items: Vec<T>, limit: u32, cursor_of: impl Fn(&T) -> String) -> Page<T> {
    // A short page is the last page. A full page may or may not be, so the
    // cursor is offered and the next request finds out.
    let next_cursor = if items.len() as u32 == limit {
        items.last().map(cursor_of)
    } else {
        None
    };
    Page { items, next_cursor }
}

fn role_str(role: UserRole) -> &'static str {
    match role {
        UserRole::Admin => "admin",
        UserRole::User => "user",
    }
}

fn client_status_str(status: ClientStatus) -> &'static str {
    match status {
        ClientStatus::Pending => "pending",
        ClientStatus::Approved => "approved",
        ClientStatus::Suspended => "suspended",
        ClientStatus::Revoked => "revoked",
    }
}

fn binding_status_str(status: re0auth_api::ports::BindingStatus) -> &'static str {
    use re0auth_api::ports::BindingStatus;
    match status {
        BindingStatus::Pending => "pending",
        BindingStatus::Active => "active",
        BindingStatus::NeedsReauth => "needs_reauth",
        BindingStatus::Revoked => "revoked",
        BindingStatus::Expired => "expired",
    }
}

fn client_view(client: Client) -> AdminClientView {
    AdminClientView {
        id: client.id.0.to_string(),
        name: client.name,
        redirect_uris: client.redirect_uris,
        allowed_scopes: client.allowed_scopes,
        raw_access: client.raw_access,
        status: client_status_str(client.status),
        has_secret: client.secret_hash.is_some(),
        created_at: client.created_at,
        updated_at: client.updated_at,
    }
}

fn user_view(user: User) -> AdminUserView {
    AdminUserView {
        id: user.id.0.to_string(),
        display_name: user.display_name,
        role: role_str(user.role),
        created_at: user.created_at,
        updated_at: user.updated_at,
    }
}

fn binding_view(binding: Binding) -> AdminBindingView {
    AdminBindingView {
        id: binding.id.0.to_string(),
        user_id: binding.user_id.0.to_string(),
        connector: binding.upstream_id,
        upstream_user_id: binding.upstream_user_id,
        status: binding_status_str(binding.status),
        created_at: binding.created_at,
        updated_at: binding.updated_at,
        last_refreshed_at: binding.last_refreshed_at,
        last_error_code: binding.last_error_code,
    }
}

fn audit_view(record: re0auth_api::audit::AuditRecord) -> AdminAuditView {
    AdminAuditView {
        id: record.id.0.to_string(),
        occurred_at: record.occurred_at,
        actor_user_id: record.actor_user_id.map(|id| id.0.to_string()),
        client_id: record.client_id.map(|id| id.0.to_string()),
        action: record.action.as_str(),
        target: record.target,
        outcome: record.outcome.as_str(),
        severity: record.severity.as_str(),
        request_id: record.request_id,
        tier: record.tier.as_str(),
        detail: record.detail,
    }
}
