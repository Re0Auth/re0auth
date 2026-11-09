//! Storage-level guard regressions from the audit report.

use re0auth_adapters::storage::SqliteStore;
use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::ports::{
    AuditFilter, Binding, BindingStatus, Client, ClientStatus, RepoError, Storage, User, UserRole,
    UserStatus,
};
use re0auth_api::{BindingId, ClientId, UserId};

async fn store() -> SqliteStore {
    SqliteStore::connect("sqlite::memory:")
        .await
        .expect("SQLite store with migrations")
}

fn user_fact(action: AuditAction, now: i64) -> SecurityFact {
    SecurityFact::new(action, now, "user:test")
}

fn client_fact() -> SecurityFact {
    SecurityFact::new(AuditAction::ClientUpdated, 2_000, "client:test")
}

fn binding_fact() -> SecurityFact {
    SecurityFact::new(AuditAction::BindingCreated, 1_000, "binding:test")
}

fn revoke_fact(now: i64) -> SecurityFact {
    SecurityFact::new(AuditAction::BindingRevoked, now, "binding:test")
}

fn user(id: UserId, role: UserRole, status: UserStatus) -> User {
    User {
        id,
        display_name: "guard-test".to_string(),
        role,
        status,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn client(id: ClientId) -> Client {
    Client {
        id,
        name: "guard-client".to_string(),
        redirect_uris: vec!["https://client.example/callback".to_string()],
        allowed_scopes: vec!["openid".to_string()],
        raw_access: false,
        status: ClientStatus::Approved,
        secret_hash: None,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn binding(user_id: UserId) -> Binding {
    Binding {
        id: BindingId::new(),
        user_id,
        upstream_id: "phihub".to_string(),
        upstream_user_id: "player-1".to_string(),
        status: BindingStatus::Active,
        created_at: 1_000,
        updated_at: 1_000,
        last_refreshed_at: None,
        last_error_code: None,
    }
}

/// The guard is in the UPDATE, not in the caller: a direct port call must not
/// be able to remove the last active admin (two admins racing each other was
/// the original hole).
#[tokio::test]
async fn s07_last_active_admin_cannot_be_demoted_or_banned() {
    let store = store().await;
    let admin = user(UserId::new(), UserRole::Admin, UserStatus::Active);
    store.users().create(&admin).await.expect("admin");

    let demoted = store
        .users()
        .set_role(
            &admin.id,
            UserRole::User,
            &user_fact(AuditAction::UserRoleChanged, 2_000),
            2_000,
        )
        .await;
    assert!(
        matches!(demoted, Err(RepoError::Conflict(_))),
        "the only active admin must not be demoted: {demoted:?}"
    );

    let banned = store
        .users()
        .set_status(
            &admin.id,
            UserStatus::Banned,
            &user_fact(AuditAction::UserBanned, 2_000),
            2_000,
        )
        .await;
    assert!(
        matches!(banned, Err(RepoError::Conflict(_))),
        "the only active admin must not be banned: {banned:?}"
    );

    // A second active admin makes the same operations legal.
    let other = user(UserId::new(), UserRole::Admin, UserStatus::Active);
    store.users().create(&other).await.expect("second admin");
    store
        .users()
        .set_role(
            &admin.id,
            UserRole::User,
            &user_fact(AuditAction::UserRoleChanged, 2_000),
            2_000,
        )
        .await
        .expect("demotion is allowed while another active admin exists");
}

/// A stale `expected_updated_at` must fail even when both writes land in the
/// same wall-clock second; the returned row is the one that actually committed.
#[tokio::test]
async fn s08_client_update_is_compare_and_swap() {
    let store = store().await;
    let original = client(ClientId::new());
    store
        .clients()
        .insert(&original, &client_fact())
        .await
        .expect("client");

    let mut first = original.clone();
    first.name = "first".to_string();
    let expected = first.updated_at;
    first.updated_at = 2_000;
    store
        .clients()
        .update(&first, expected, &client_fact(), 2_000)
        .await
        .expect("first update");

    let mut stale = original.clone();
    stale.name = "stale".to_string();
    stale.updated_at = 2_000;
    let error = store
        .clients()
        .update(&stale, 1_000, &client_fact(), 2_000)
        .await
        .expect_err("stale write must be refused");
    assert!(matches!(error, RepoError::Conflict(_)), "{error:?}");

    let stored = store
        .clients()
        .get(&original.id)
        .await
        .expect("get")
        .expect("client exists");
    assert_eq!(stored.name, "first");
    assert_eq!(stored.updated_at, 2_000);
}

/// A retried DELETE is the state the caller asked for, but it must not append a
/// second "revoked" fact to the audit trail.
#[tokio::test]
async fn s24_revoking_a_binding_twice_writes_one_fact() {
    let store = store().await;
    let user = user(UserId::new(), UserRole::User, UserStatus::Active);
    store.users().create(&user).await.expect("user");
    let binding = binding(user.id);
    store
        .bindings()
        .upsert(&binding, &binding_fact())
        .await
        .expect("binding");

    store
        .bindings()
        .revoke(&binding.id, &revoke_fact(2_000), 2_000)
        .await
        .expect("first revoke");
    store
        .bindings()
        .revoke(&binding.id, &revoke_fact(3_000), 3_000)
        .await
        .expect("retry is idempotent");

    let facts = store
        .audits()
        .query(
            &AuditFilter {
                actor: None,
                client: None,
                action: Some(AuditAction::BindingRevoked),
                tier: None,
                from: None,
                to: None,
            },
            None,
            10,
        )
        .await
        .expect("audit query");
    assert_eq!(facts.len(), 1, "one revocation, one fact");
}

/// Retention anonymizes every matching row, including when the backlog exceeds
/// one batch; the loop must not stop after the first page.
#[tokio::test]
async fn p05_retention_anonymizes_the_whole_backlog() {
    let store = store().await;
    let user = user(UserId::new(), UserRole::User, UserStatus::Active);
    store.users().create(&user).await.expect("user");

    for index in 0..3 {
        let mut binding = binding(user.id);
        binding.upstream_id = format!("phihub-{index}");
        store
            .bindings()
            .upsert(&binding, &binding_fact())
            .await
            .expect("binding");
        store
            .bindings()
            .revoke(&binding.id, &revoke_fact(2_000), 2_000)
            .await
            .expect("revoke");
    }

    let anonymized = store
        .bindings()
        .anonymize_revoked_before(10_000)
        .await
        .expect("anonymize");
    assert_eq!(anonymized, 3);

    for binding in store.bindings().list_by_user(&user.id).await.expect("list") {
        assert_ne!(binding.upstream_user_id, "player-1");
    }
}

/// Purging a key deletes its row; a second purge reports NotFound rather than
/// silently succeeding.
#[tokio::test]
async fn s09_signing_key_purge_removes_the_row() {
    use re0auth_api::ports::SigningKeyRecord;

    let store = store().await;
    let record = SigningKeyRecord {
        kid: "kid-1".to_string(),
        alg: "RS256".to_string(),
        public_jwk_json: "{}".to_string(),
        created_at: 1_000,
        activated_at: 1_000,
        retired_at: None,
    };
    store
        .signing_keys()
        .publish(&record)
        .await
        .expect("publish");

    store.signing_keys().purge("kid-1").await.expect("purge");
    assert!(
        store
            .signing_keys()
            .published()
            .await
            .expect("list")
            .is_empty()
    );
    assert!(matches!(
        store.signing_keys().purge("kid-1").await,
        Err(RepoError::NotFound)
    ));
}
