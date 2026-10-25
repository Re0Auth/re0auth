//! AdminService invariants that the HTTP surface relies on (B1).

use std::sync::Arc;

use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::ports::{
    AuditFilter, Binding, BindingStatus, ClientStatus, Storage, User, UserRole,
};
use re0auth_api::secret::{ClientSecretHash, ClientSecretHasher};
use re0auth_api::{BindingId, Clock, Random, Re0Result, UserId};
use re0auth_app::admin_service::{AdminError, AdminService, NewClientInput};
use re0auth_contract::MemoryStore;

struct FixedClock(i64);

impl Clock for FixedClock {
    fn now(&self) -> i64 {
        self.0
    }
}

struct FixedRandom;

impl Random for FixedRandom {
    fn bytes(&self, len: usize) -> Vec<u8> {
        vec![7u8; len]
    }
}

struct FakeHasher;

impl ClientSecretHasher for FakeHasher {
    fn hash(&self, secret: &str) -> Re0Result<ClientSecretHash> {
        ClientSecretHash::new(1, secret.as_bytes().to_vec())
    }

    fn matches(&self, secret: &str, hash: &ClientSecretHash) -> bool {
        secret.as_bytes() == hash.digest()
    }
}

async fn service() -> (Arc<MemoryStore>, AdminService, UserId) {
    let store = Arc::new(MemoryStore::new());
    let admin = UserId::new();
    store
        .users()
        .create(&User {
            id: admin,
            display_name: "root".to_string(),
            role: UserRole::Admin,
            created_at: 1,
            updated_at: 1,
        })
        .await
        .expect("admin user");
    let service = AdminService::new(
        store.clone(),
        Arc::new(FixedClock(1_000)),
        Arc::new(FixedRandom),
        Arc::new(FakeHasher),
    );
    (store, service, admin)
}

#[tokio::test]
async fn the_only_admin_cannot_be_demoted_and_nobody_can_demote_themselves() {
    let (_store, service, admin) = service().await;

    let self_demote = service
        .set_user_role(admin, admin, UserRole::User, None)
        .await;
    assert!(
        matches!(self_demote, Err(AdminError::Conflict(_))),
        "an admin must not demote themselves: {self_demote:?}"
    );

    // A different caller demoting the only admin would lock the instance out.
    let other = UserId::new();
    let last_admin = service
        .set_user_role(other, admin, UserRole::User, None)
        .await;
    assert!(
        matches!(last_admin, Err(AdminError::Conflict(_))),
        "the last admin must survive: {last_admin:?}"
    );
}

#[tokio::test]
async fn rotating_a_secret_returns_it_once_and_keeps_it_hashed_at_rest() {
    let (store, service, admin) = service().await;
    service
        .create_client(
            admin,
            None,
            NewClientInput {
                name: "bot".to_string(),
                redirect_uris: vec!["https://bot.example/cb".to_string()],
                allowed_scopes: vec!["openid".to_string()],
                raw_access: false,
                confidential: true,
                status: ClientStatus::Approved,
            },
        )
        .await
        .expect("create client");

    let id = store.clients().list(None, 10).await.expect("list")[0].id;
    let rotated = service
        .rotate_client_secret(admin, &id, None)
        .await
        .expect("rotate");
    assert!(!rotated.secret.is_empty(), "the plaintext is returned once");
    assert!(
        service.get_client(&id).await.expect("get").has_secret,
        "the hash is installed"
    );
}

#[tokio::test]
async fn an_admin_revoke_writes_a_fact_with_the_admin_as_actor() {
    let (store, service, admin) = service().await;
    let owner = UserId::new();
    store
        .users()
        .create(&User {
            id: owner,
            display_name: "owner".to_string(),
            role: UserRole::User,
            created_at: 1,
            updated_at: 1,
        })
        .await
        .expect("owner");
    let binding = Binding {
        id: BindingId::new(),
        user_id: owner,
        upstream_id: "phigros".to_string(),
        upstream_user_id: "player-1".to_string(),
        status: BindingStatus::Active,
        created_at: 1,
        updated_at: 1,
        last_refreshed_at: None,
        last_error_code: None,
    };
    store
        .bindings()
        .upsert(
            &binding,
            &SecurityFact::new(AuditAction::BindingCreated, 1, "binding"),
        )
        .await
        .expect("binding");

    service
        .revoke_binding(admin, binding.id, Some("req-1"))
        .await
        .expect("admin revoke");

    let rows = store
        .audits()
        .query(
            &AuditFilter {
                action: Some(AuditAction::BindingRevoked),
                actor: Some(admin),
                ..Default::default()
            },
            None,
            10,
        )
        .await
        .expect("audit query");
    assert_eq!(rows.len(), 1, "the killswitch is attributed to the admin");
    assert_eq!(rows[0].request_id.as_deref(), Some("req-1"));
}

#[tokio::test]
async fn a_page_is_only_cursored_when_it_is_full() {
    let (_store, service, _admin) = service().await;
    // One user exists; asking for two is a short (final) page.
    let short = service.list_users(None, Some(2)).await.expect("short page");
    assert_eq!(short.items.len(), 1);
    assert!(short.next_cursor.is_none(), "a short page ends the list");
    // Asking for one fills the page, so a cursor is offered.
    let full = service.list_users(None, Some(1)).await.expect("full page");
    assert_eq!(full.items.len(), 1);
    assert!(full.next_cursor.is_some());
}

async fn fact_count(store: &MemoryStore, action: AuditAction) -> usize {
    store
        .audits()
        .query(
            &AuditFilter {
                action: Some(action),
                ..Default::default()
            },
            None,
            100,
        )
        .await
        .expect("audit query")
        .len()
}

#[tokio::test]
async fn admin_client_mutations_write_security_facts() {
    let (store, service, admin) = service().await;
    service
        .create_client(
            admin,
            None,
            NewClientInput {
                name: "bot".to_string(),
                redirect_uris: vec![],
                allowed_scopes: vec![],
                raw_access: false,
                confidential: true,
                status: ClientStatus::Approved,
            },
        )
        .await
        .expect("create");
    let id = store.clients().list(None, 10).await.expect("list")[0].id;
    service
        .rotate_client_secret(admin, &id, None)
        .await
        .expect("rotate");

    assert_eq!(fact_count(&store, AuditAction::ClientCreated).await, 1);
    assert_eq!(
        fact_count(&store, AuditAction::ClientSecretRotated).await,
        1
    );

    // A role change is a security fact too.
    let target = UserId::new();
    store
        .users()
        .create(&User {
            id: target,
            display_name: "member".to_string(),
            role: UserRole::User,
            created_at: 1,
            updated_at: 1,
        })
        .await
        .expect("user");
    service
        .set_user_role(admin, target, UserRole::Admin, None)
        .await
        .expect("promote");
    assert_eq!(fact_count(&store, AuditAction::UserRoleChanged).await, 1);
}
