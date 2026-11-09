//! 挂载登录方式的状态机（ADR-0050）。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use re0auth_api::idp::{IdpClient, IdpIdentity, IdpResult};
use re0auth_api::oauth::{AccessTokenClaims, ApprovalTicketClaims, IdTokenClaims, TokenSigner};
use re0auth_api::ports::{Identity, Storage, User, UserRole, UserStatus};
use re0auth_api::{Clock, IdentityId, Random, Re0Result, UserId};
use re0auth_app::auth::{AuthError, AuthService, LoginOutcome, NamedIdp};
use re0auth_contract::MemoryStore;

const NOW: i64 = 1_000;

struct FixedClock(i64);

impl Clock for FixedClock {
    fn now(&self) -> i64 {
        self.0
    }
}

struct CountingRandom(AtomicU64);

impl Random for CountingRandom {
    fn bytes(&self, len: usize) -> Vec<u8> {
        let step = self.0.fetch_add(1, Ordering::SeqCst);
        vec![(step % 251) as u8; len]
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

struct StubIdp {
    identity: IdpIdentity,
}

#[async_trait::async_trait]
impl IdpClient for StubIdp {
    fn authorization_url(&self, state: &str, _nonce: &str, _challenge: &str) -> String {
        format!("https://idp.test/authorize?state={state}")
    }

    async fn exchange_code(
        &self,
        _code: &str,
        _verifier: &str,
        _nonce: &str,
    ) -> IdpResult<IdpIdentity> {
        Ok(self.identity.clone())
    }
}

fn identity(issuer: &str, subject: &str) -> IdpIdentity {
    IdpIdentity {
        issuer: issuer.to_string(),
        subject: subject.to_string(),
        display_name: "player".to_string(),
    }
}

fn service(store: Arc<MemoryStore>, idp_identity: IdpIdentity) -> AuthService {
    AuthService::new(
        store,
        vec![NamedIdp {
            name: "test".to_string(),
            display_name: "Test".to_string(),
            client: Arc::new(StubIdp {
                identity: idp_identity,
            }),
        }],
        Arc::new(UnusedSigner),
        Arc::new(FixedClock(NOW)),
        Arc::new(CountingRandom(AtomicU64::new(0))),
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

async fn attach_directly(store: &MemoryStore, user: UserId, issuer: &str, subject: &str) {
    store
        .users()
        .link_identity(&Identity {
            id: IdentityId::new(),
            user_id: user,
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            created_at: NOW,
        })
        .await
        .expect("link identity");
}

/// The happy path: a never-seen identity joins the signed-in account.
#[tokio::test]
async fn attaching_an_unknown_identity_adds_it() {
    let store = Arc::new(MemoryStore::new());
    let auth = service(store.clone(), identity("https://idp.test", "new"));
    let user = seed_user(&store, "growing").await;

    let start = auth
        .start_attach(user, "/account", None)
        .await
        .expect("start attach");
    let outcome = auth
        .complete_login("code", &start.state, Some(user))
        .await
        .expect("complete attach");
    assert!(matches!(outcome, LoginOutcome::IdentityAttached));

    let identities = store.users().list_identities(&user).await.expect("list");
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].issuer, "https://idp.test");
}

/// An identity already owned by another account is refused: no merge, no hint
/// about the other account.
#[tokio::test]
async fn attaching_a_claimed_identity_is_refused() {
    let store = Arc::new(MemoryStore::new());
    let auth = service(store.clone(), identity("https://idp.test", "claimed"));
    let owner = seed_user(&store, "owner").await;
    let other = seed_user(&store, "other").await;
    attach_directly(&store, owner, "https://idp.test", "claimed").await;

    let start = auth
        .start_attach(other, "/account", None)
        .await
        .expect("start attach");
    assert!(matches!(
        auth.complete_login("code", &start.state, Some(other)).await,
        Err(AuthError::IdentityAlreadyBound)
    ));
    assert_eq!(
        store
            .users()
            .list_identities(&other)
            .await
            .expect("list")
            .len(),
        0,
        "nothing was attached"
    );
}

/// Asking twice for the same end state is not an error.
#[tokio::test]
async fn attaching_the_same_identity_twice_is_idempotent() {
    let store = Arc::new(MemoryStore::new());
    let auth = service(store.clone(), identity("https://idp.test", "again"));
    let user = seed_user(&store, "twice").await;

    for _ in 0..2 {
        let start = auth
            .start_attach(user, "/account", None)
            .await
            .expect("start attach");
        assert!(matches!(
            auth.complete_login("code", &start.state, Some(user)).await,
            Ok(LoginOutcome::IdentityAttached)
        ));
    }
    assert_eq!(
        store
            .users()
            .list_identities(&user)
            .await
            .expect("list")
            .len(),
        1
    );
}

/// The flow is bound to the account that started it, not to whoever holds the
/// browser when the callback lands.
#[tokio::test]
async fn attach_requires_the_initiating_session() {
    let store = Arc::new(MemoryStore::new());
    let auth = service(store.clone(), identity("https://idp.test", "bound"));
    let initiator = seed_user(&store, "initiator").await;
    let intruder = seed_user(&store, "intruder").await;

    let start = auth
        .start_attach(initiator, "/account", None)
        .await
        .expect("start attach");
    assert!(matches!(
        auth.complete_login("code", &start.state, Some(intruder))
            .await,
        Err(AuthError::LoginRequiresLogout)
    ));
    assert_eq!(
        store
            .users()
            .list_identities(&initiator)
            .await
            .expect("list")
            .len(),
        0
    );
}

/// A plain login with an unknown identity while signed in no longer creates a
/// second account; that is the whole point of the change.
#[tokio::test]
async fn login_with_an_unknown_identity_while_signed_in_is_refused() {
    let store = Arc::new(MemoryStore::new());
    let auth = service(store.clone(), identity("https://idp.test", "unseen"));
    let user = seed_user(&store, "signed-in").await;
    attach_directly(&store, user, "https://idp.test", "known").await;

    let start = auth
        .start_login("/account", None)
        .await
        .expect("start login");
    assert!(matches!(
        auth.complete_login("code", &start.state, Some(user)).await,
        Err(AuthError::LoginRequiresAttach)
    ));
}

/// Signing in as somebody else requires signing out first.
#[tokio::test]
async fn login_as_another_account_while_signed_in_is_refused() {
    let store = Arc::new(MemoryStore::new());
    let auth = service(store.clone(), identity("https://idp.test", "theirs"));
    let current = seed_user(&store, "current").await;
    let other = seed_user(&store, "other").await;
    attach_directly(&store, current, "https://idp.test", "mine").await;
    attach_directly(&store, other, "https://idp.test", "theirs").await;

    let start = auth
        .start_login("/account", None)
        .await
        .expect("start login");
    assert!(matches!(
        auth.complete_login("code", &start.state, Some(current))
            .await,
        Err(AuthError::LoginRequiresLogout)
    ));
}
