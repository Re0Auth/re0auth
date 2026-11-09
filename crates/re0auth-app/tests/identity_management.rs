//! 身份管理用例：解绑、最后一个身份的拒绝、注销账号。

use std::sync::Arc;

use re0auth_api::audit::AuditAction;
use re0auth_api::oauth::{AccessTokenClaims, ApprovalTicketClaims, IdTokenClaims, TokenSigner};
use re0auth_api::ports::{Identity, Storage, User, UserRole, UserStatus};
use re0auth_api::{Clock, IdentityId, Random, Re0Result, UserId};
use re0auth_app::auth::{AuthError, AuthService};
use re0auth_contract::MemoryStore;

const NOW: i64 = 1_000;

struct FixedClock(i64);

impl Clock for FixedClock {
    fn now(&self) -> i64 {
        self.0
    }
}

struct ZeroRandom;

impl Random for ZeroRandom {
    fn bytes(&self, len: usize) -> Vec<u8> {
        vec![7; len]
    }
}

struct UnusedSigner;

impl TokenSigner for UnusedSigner {
    fn sign_access(&self, _: &AccessTokenClaims) -> Re0Result<String> {
        panic!("not used")
    }
    fn sign_id(&self, _: &IdTokenClaims) -> Re0Result<String> {
        panic!("not used")
    }
    fn sign_approval_ticket(&self, _: &ApprovalTicketClaims) -> Re0Result<String> {
        panic!("not used")
    }
    fn verify_access(&self, _: &str) -> Re0Result<AccessTokenClaims> {
        panic!("not used")
    }
    fn verify_approval_ticket(&self, _: &str) -> Re0Result<ApprovalTicketClaims> {
        panic!("not used")
    }
    fn jwks(&self) -> String {
        panic!("not used")
    }
}

fn service(store: Arc<MemoryStore>) -> AuthService {
    AuthService::new(
        store,
        vec![],
        Arc::new(UnusedSigner),
        Arc::new(FixedClock(NOW)),
        Arc::new(ZeroRandom),
        "https://issuer.test",
    )
}

async fn seed_user(store: &MemoryStore, name: &str) -> UserId {
    let id = UserId::new();
    store
        .users()
        .create(&User {
            id,
            display_name: name.to_string(),
            role: UserRole::User,
            status: UserStatus::Active,
            created_at: NOW,
            updated_at: NOW,
        })
        .await
        .expect("create user");
    id
}

async fn attach(store: &MemoryStore, user: UserId, issuer: &str) -> IdentityId {
    let identity = Identity {
        id: IdentityId::new(),
        user_id: user,
        issuer: issuer.to_string(),
        subject: format!("subject-{issuer}"),
        created_at: NOW,
    };
    store
        .users()
        .link_identity(
            &identity,
            &re0auth_api::audit::SecurityFact::new(
                re0auth_api::audit::AuditAction::IdentityAttached,
                NOW,
                "identity",
            ),
        )
        .await
        .expect("link identity");
    identity.id
}

/// One of two identities can go; the account stays reachable from the other.
#[tokio::test]
async fn detaching_one_of_two_identities_works() {
    let store = Arc::new(MemoryStore::new());
    let auth = service(store.clone());
    let user = seed_user(&store, "two-logins").await;
    let first = attach(&store, user, "https://a.test").await;
    let second = attach(&store, user, "https://b.test").await;

    auth.detach_identity(user, first).await.expect("detach");

    let remaining = store.users().list_identities(&user).await.expect("list");
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, second);
}

/// The last identity is refused: removing it would lock the account out forever.
#[tokio::test]
async fn the_last_identity_is_refused() {
    let store = Arc::new(MemoryStore::new());
    let auth = service(store.clone());
    let user = seed_user(&store, "one-login").await;
    let only = attach(&store, user, "https://a.test").await;

    assert!(matches!(
        auth.detach_identity(user, only).await,
        Err(AuthError::LastIdentity)
    ));
    assert_eq!(
        store
            .users()
            .list_identities(&user)
            .await
            .expect("list")
            .len(),
        1,
        "the refusal must not delete anything"
    );
}

/// Detaching is scoped by the session's account, so a foreign id is a plain 404.
#[tokio::test]
async fn another_accounts_identity_cannot_be_detached() {
    let store = Arc::new(MemoryStore::new());
    let auth = service(store.clone());
    let owner = seed_user(&store, "owner").await;
    let intruder = seed_user(&store, "intruder").await;
    let owner_identity = attach(&store, owner, "https://a.test").await;
    attach(&store, owner, "https://b.test").await;
    attach(&store, intruder, "https://c.test").await;

    assert!(matches!(
        auth.detach_identity(intruder, owner_identity).await,
        Err(AuthError::NotFound)
    ));
    assert_eq!(
        store
            .users()
            .list_identities(&owner)
            .await
            .expect("list")
            .len(),
        2,
        "the owner's identities are untouched"
    );
}

/// Deleting the account removes the row and leaves a fact behind.
#[tokio::test]
async fn deleting_the_account_removes_it_and_records_the_fact() {
    let store = Arc::new(MemoryStore::new());
    let auth = service(store.clone());
    let user = seed_user(&store, "leaving").await;
    attach(&store, user, "https://a.test").await;

    auth.delete_account(user, Some("req-1"))
        .await
        .expect("delete");

    assert!(store.users().get(&user).await.expect("get").is_none());
    let facts = store.audits().recent(10).await.expect("audit");
    assert!(
        facts
            .iter()
            .any(|record| record.action == AuditAction::AccountDeleted),
        "the deletion must be recorded as a fact"
    );
    assert!(matches!(
        auth.delete_account(user, None).await,
        Err(AuthError::NotFound)
    ));
}
