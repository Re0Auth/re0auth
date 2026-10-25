//! Administrative use cases used by the server CLI.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::ports::{Client, ClientStatus, RepoError, Storage, User, UserRole};
use re0auth_api::secret::ClientSecretHasher;
use re0auth_api::{ClientId, Clock, Random, UserId};
use re0auth_domain::device;

use crate::auth::{CreatedSession, create_session_record};
use crate::oauth::hash_secret;

/// 32 bytes of entropy, per ADR-0030.
pub const CLIENT_SECRET_BYTES: usize = 32;

pub async fn create_user(
    storage: &dyn Storage,
    clock: &dyn Clock,
    display_name: &str,
    role: UserRole,
) -> Result<UserId, RepoError> {
    let now = clock.now();
    let user = User {
        id: UserId::new(),
        display_name: display_name.to_string(),
        role,
        created_at: now,
        updated_at: now,
    };
    storage.users().create(&user).await?;
    Ok(user.id)
}

/// Result of `create_client`: the raw secret is returned exactly once and never
/// stored, so the caller must show it to the operator now or it is lost.
pub struct CreatedClient {
    pub id: ClientId,
    pub secret: Option<String>,
}

/// Everything needed to register a client. Ten positional arguments made call
/// sites unreadable and easy to transpose, so the fields are named.
pub struct NewClient<'a> {
    pub name: &'a str,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub raw_access: bool,
    pub status: ClientStatus,
    /// A confidential client gets a generated secret; a public one does not.
    pub confidential: bool,
}

pub async fn create_client(
    storage: &dyn Storage,
    clock: &dyn Clock,
    random: &dyn Random,
    hasher: &dyn ClientSecretHasher,
    actor: Option<UserId>,
    request_id: Option<&str>,
    new: NewClient<'_>,
) -> Result<CreatedClient, RepoError> {
    let now = clock.now();
    let secret = new
        .confidential
        .then(|| URL_SAFE_NO_PAD.encode(random.bytes(CLIENT_SECRET_BYTES)));
    let secret_hash = match &secret {
        Some(raw) => Some(
            hasher
                .hash(raw)
                .map_err(|error| RepoError::Backend(error.to_string()))?,
        ),
        None => None,
    };
    let client = Client {
        id: ClientId::new(),
        name: new.name.to_string(),
        redirect_uris: new.redirect_uris,
        allowed_scopes: new.allowed_scopes,
        raw_access: new.raw_access,
        status: new.status,
        secret_hash,
        created_at: now,
        updated_at: now,
    };
    let mut fact = SecurityFact::new(
        AuditAction::ClientCreated,
        now,
        format!("client:{}", client.id.0),
    );
    if let Some(actor) = actor {
        fact = fact.actor(actor);
    }
    fact = fact.with_request_id(request_id);
    storage.clients().insert(&client, &fact).await?;
    Ok(CreatedClient {
        id: client.id,
        secret,
    })
}

pub async fn approve_device(
    storage: &dyn Storage,
    clock: &dyn Clock,
    user_code: &str,
    user_id: UserId,
) -> Result<(), RepoError> {
    let hash = hash_secret(&device::normalize_user_code(user_code));
    storage
        .device_codes()
        .approve(&hash, user_id, clock.now())
        .await
}

pub async fn deny_device(
    storage: &dyn Storage,
    clock: &dyn Clock,
    user_code: &str,
) -> Result<(), RepoError> {
    let hash = hash_secret(&device::normalize_user_code(user_code));
    storage.device_codes().deny(&hash, clock.now()).await
}

/// Creates a session and returns the raw cookie and CSRF values exactly once.
pub async fn create_session(
    storage: &dyn Storage,
    clock: &dyn Clock,
    random: &dyn Random,
    user: UserId,
) -> Result<CreatedSession, RepoError> {
    create_session_record(storage, clock, random, user).await
}
