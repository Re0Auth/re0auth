use re0auth_adapters::client_secret::HmacClientSecretHasher;
use re0auth_adapters::clock::SystemClock;
use re0auth_adapters::random::OsRandom;
use re0auth_adapters::storage::SqliteStore;
use re0auth_api::Clock;
use re0auth_api::ports::{ClientStatus, Storage, UserRole};
use re0auth_api::secret::ClientSecretHasher;
use re0auth_app::admin::{NewClient, create_client, create_session, create_user};
use re0auth_app::oauth::hash_secret;

const TEST_MASTER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn admin_creates_user_client_and_session() {
    let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
    let clock = SystemClock;
    let hasher = HmacClientSecretHasher::new(TEST_MASTER).expect("hasher");

    let user_id = create_user(&store, &clock, "Alice", UserRole::User)
        .await
        .unwrap();
    let created_client = create_client(
        &store,
        &clock,
        &OsRandom,
        &hasher,
        None,
        None,
        NewClient {
            name: "Test client",
            redirect_uris: vec!["https://client.example/callback".to_string()],
            allowed_scopes: vec!["openid".to_string(), "profile".to_string()],
            raw_access: false,
            status: ClientStatus::Approved,
            confidential: true,
        },
    )
    .await
    .unwrap();
    let client_id = created_client.id;
    let created = create_session(&store, &clock, &OsRandom, user_id)
        .await
        .unwrap();

    assert!(store.users().get(&user_id).await.unwrap().is_some());
    let client = store.clients().get(&client_id).await.unwrap().unwrap();
    assert_eq!(client.status, ClientStatus::Approved);

    // A confidential client stores only a hash — never the secret itself.
    let stored = client.secret_hash.as_ref().expect("confidential client");
    let secret = created_client.secret.expect("secret is returned once");
    assert!(!secret.is_empty());
    assert!(hasher.matches(&secret, stored));
    assert_ne!(stored.digest(), secret.as_bytes());

    let active = store
        .sessions()
        .find_active(&hash_secret(&created.cookie), clock.now())
        .await
        .unwrap()
        .expect("session is active");
    assert_eq!(active.user_id, user_id);
    assert_eq!(active.id, created.session.id);
    assert_eq!(hash_secret(&created.csrf_token), created.session.csrf_hash);
    assert!(created.session.absolute_expires_at > created.session.idle_expires_at);
}

/// The three commands B17 added, exercised through the same `AdminService` the
/// HTTP layer uses — otherwise the CLI would be a second implementation of the
/// same rules and the audit facts would diverge.
#[tokio::test]
async fn admin_rotates_secrets_changes_roles_and_revokes_tokens() {
    use re0auth_app::admin_service::AdminService;
    use std::sync::Arc;

    let store = Arc::new(SqliteStore::connect("sqlite::memory:").await.unwrap());
    let clock = Arc::new(SystemClock);
    let hasher = Arc::new(HmacClientSecretHasher::new(TEST_MASTER).expect("hasher"));
    let service = AdminService::new(
        store.clone(),
        clock.clone(),
        Arc::new(OsRandom),
        hasher.clone(),
    );

    let actor = create_user(store.as_ref(), clock.as_ref(), "Root", UserRole::Admin)
        .await
        .unwrap();
    let target = create_user(store.as_ref(), clock.as_ref(), "Bob", UserRole::User)
        .await
        .unwrap();
    let created = create_client(
        store.as_ref(),
        clock.as_ref(),
        &OsRandom,
        hasher.as_ref(),
        None,
        None,
        NewClient {
            name: "Clients",
            redirect_uris: vec!["https://client.example/callback".to_string()],
            allowed_scopes: vec!["openid".to_string()],
            raw_access: false,
            status: ClientStatus::Approved,
            confidential: true,
        },
    )
    .await
    .unwrap();
    let before = store
        .clients()
        .get(&created.id)
        .await
        .unwrap()
        .unwrap()
        .secret_hash
        .expect("confidential client");

    // rotate-client-secret: the new secret verifies, the old one no longer does.
    let rotated = service
        .rotate_client_secret(actor, &created.id, None)
        .await
        .expect("rotate");
    let after = store
        .clients()
        .get(&created.id)
        .await
        .unwrap()
        .unwrap()
        .secret_hash
        .expect("confidential client");
    assert!(hasher.matches(&rotated.secret, &after));
    assert_ne!(before.digest(), after.digest());

    // set-role: promotion works; demoting the last admin is refused.
    let promoted = service
        .set_user_role(actor, target, UserRole::Admin, None)
        .await
        .expect("promote");
    assert_eq!(promoted.role, "admin");
    assert!(
        service
            .set_user_role(actor, actor, UserRole::User, None)
            .await
            .is_err(),
        "self-demotion must be refused"
    );
    // Two admins now, so demoting the other one is allowed...
    service
        .set_user_role(actor, target, UserRole::User, None)
        .await
        .expect("demoting one of two admins is allowed");
    // ...which leaves a single admin, and that one cannot be demoted.
    let error = service
        .set_user_role(target, actor, UserRole::User, None)
        .await
        .expect_err("the last admin must not be demoted");
    assert!(error.to_string().contains("last admin"), "{error}");

    // revoke-token: recorded while the token could still be presented.
    let jti = "cli-revoked-jti";
    service
        .revoke_access_token(actor, jti, Some(created.id), clock.now() + 300, None)
        .await
        .expect("revoke");
    assert!(
        store
            .access_tokens()
            .is_revoked(jti, clock.now())
            .await
            .unwrap(),
        "the jti must be listed as revoked"
    );

    // An already-expired token is refused rather than silently recorded.
    let error = service
        .revoke_access_token(actor, "stale", Some(created.id), clock.now() - 1, None)
        .await
        .expect_err("an expired token cannot be presented, so it is refused");
    assert!(error.to_string().contains("expired"), "{error}");
}
