//! 一次性凭据与 refresh token 的提交原子性。
//!
//! 用 SQLite 触发器让 `refresh_tokens` 的 INSERT 失败，证明授权码/设备码的消费
//! 会随事务一起回滚：客户端拿到 500 之后仍能用同一个凭据重试。

use re0auth_adapters::storage::SqliteStore;
use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::ports::{
    AuthCode, Client, ClientStatus, ConsumeAuthCode, DeviceCode, DeviceCodeState, DeviceCodeStatus,
    DevicePoll, RefreshToken, RepoError, Storage, User, UserRole, UserStatus,
};
use re0auth_api::{AuthCodeId, ClientId, DeviceCodeId, FamilyId, RefreshTokenId, Unix, UserId};

const NOW: Unix = 1_000;

async fn file_store() -> (SqliteStore, sqlx::SqlitePool, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("re0auth-atomic-{}.db", uuid::Uuid::now_v7()));
    let url = format!("sqlite://{}", path.display());
    let store = SqliteStore::connect(&url).await.expect("file store");
    // A second pool only to install the fault-injection trigger: the store's own
    // pool is private and the trigger is schema state, not data.
    let pool = sqlx::SqlitePool::connect(&url).await.expect("trigger pool");
    (store, pool, path)
}

async fn install_failing_refresh_trigger(pool: &sqlx::SqlitePool) {
    sqlx::query(
        "CREATE TRIGGER fail_refresh_insert BEFORE INSERT ON refresh_tokens \
         BEGIN SELECT RAISE(ABORT, 'injected refresh failure'); END",
    )
    .execute(pool)
    .await
    .expect("create trigger");
}

async fn drop_failing_refresh_trigger(pool: &sqlx::SqlitePool) {
    sqlx::query("DROP TRIGGER fail_refresh_insert")
        .execute(pool)
        .await
        .expect("drop trigger");
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}

fn fact(action: AuditAction) -> SecurityFact {
    SecurityFact::new(action, NOW, "atomicity")
}

async fn seed_user_and_client(store: &SqliteStore) -> (UserId, ClientId) {
    let user = User {
        id: UserId::new(),
        display_name: "atomic-user".to_string(),
        role: UserRole::User,
        status: UserStatus::Active,
        created_at: NOW,
        updated_at: NOW,
    };
    store.users().create(&user).await.expect("seed user");
    let client = Client {
        id: ClientId::new(),
        name: "atomic-client".to_string(),
        redirect_uris: vec!["https://client.example/callback".to_string()],
        allowed_scopes: vec!["openid".to_string()],
        raw_access: false,
        status: ClientStatus::Approved,
        secret_hash: None,
        created_at: NOW,
        updated_at: NOW,
    };
    store
        .clients()
        .insert(&client, &fact(AuditAction::ClientCreated))
        .await
        .expect("seed client");
    (user.id, client.id)
}

fn auth_code(user: UserId, client: ClientId) -> AuthCode {
    AuthCode {
        id: AuthCodeId::new(),
        code_hash: vec![0x21; 32],
        client_id: client,
        user_id: user,
        redirect_uri: "https://client.example/callback".to_string(),
        scopes: vec!["openid".to_string()],
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        nonce: None,
        auth_time: NOW - 100,
        created_at: NOW,
        expires_at: NOW + 300,
        consumed_at: None,
        family_id: None,
    }
}

fn refresh(user: UserId, client: ClientId, family: FamilyId, hash: u8) -> RefreshToken {
    RefreshToken {
        id: RefreshTokenId::new(),
        token_hash: vec![hash; 32],
        family_id: family,
        client_id: client,
        user_id: user,
        scopes: vec!["openid".to_string()],
        created_at: NOW,
        family_created_at: NOW,
        auth_time: NOW - 100,
        expires_at: NOW + 10_000,
        consumed_at: None,
        revoked_at: None,
        replaced_by: None,
    }
}

fn device_code(client: ClientId) -> DeviceCode {
    DeviceCode {
        id: DeviceCodeId::new(),
        device_code_hash: vec![0x41; 32],
        user_code_hash: vec![0x42; 32],
        client_id: client,
        scopes: vec!["openid".to_string()],
        state: DeviceCodeState::Pending,
        interval_secs: 5,
        last_polled_at: None,
        poll_count: 0,
        user_code_misses: 0,
        created_at: NOW,
        expires_at: NOW + 600,
        consumed_at: None,
        family_id: None,
    }
}

#[tokio::test]
async fn failed_refresh_insert_does_not_consume_the_auth_code() {
    let (store, pool, path) = file_store().await;
    let (user, client) = seed_user_and_client(&store).await;
    let code = auth_code(user, client);
    store
        .auth_codes()
        .insert(&code, &fact(AuditAction::AuthCodeIssued))
        .await
        .expect("auth code");

    let family = FamilyId::new();
    let attempt = ConsumeAuthCode {
        code_hash: &code.code_hash,
        client_id: client,
        redirect_uri: &code.redirect_uri,
        code_challenge: Some("challenge"),
        code_challenge_method: Some("S256"),
        family_id: family,
    };
    let inspected = store
        .auth_codes()
        .inspect(&attempt, NOW)
        .await
        .expect("inspect code");
    assert_eq!(inspected.user_id, user);
    assert_eq!(inspected.auth_time, NOW - 100);

    let token = refresh(user, client, family, 0x31);
    install_failing_refresh_trigger(&pool).await;
    assert!(
        store
            .auth_codes()
            .consume_and_insert_refresh(attempt, &token, NOW)
            .await
            .is_err(),
        "the injected insert failure must surface"
    );

    // Nothing moved: the code is still redeemable and no refresh row exists.
    let retry = ConsumeAuthCode {
        code_hash: &code.code_hash,
        client_id: client,
        redirect_uri: &code.redirect_uri,
        code_challenge: Some("challenge"),
        code_challenge_method: Some("S256"),
        family_id: family,
    };
    assert_eq!(
        store
            .auth_codes()
            .inspect(&retry, NOW)
            .await
            .expect("inspect after rollback"),
        inspected
    );
    assert_eq!(
        store
            .refresh_tokens()
            .find(&token.token_hash)
            .await
            .expect("find refresh token"),
        None
    );

    drop_failing_refresh_trigger(&pool).await;
    let grant = store
        .auth_codes()
        .consume_and_insert_refresh(retry, &token, NOW)
        .await
        .expect("the retry must succeed");
    assert_eq!(grant.user_id, user);
    assert_eq!(
        store
            .refresh_tokens()
            .find(&token.token_hash)
            .await
            .expect("find refresh token"),
        Some(token.clone())
    );
    assert_eq!(
        store
            .auth_codes()
            .family_and_client_of(&code.code_hash)
            .await
            .expect("family"),
        Some((family, client))
    );
    let replay = ConsumeAuthCode {
        code_hash: &code.code_hash,
        client_id: client,
        redirect_uri: &code.redirect_uri,
        code_challenge: Some("challenge"),
        code_challenge_method: Some("S256"),
        family_id: FamilyId::new(),
    };
    assert!(matches!(
        store.auth_codes().inspect(&replay, NOW).await,
        Err(RepoError::AlreadyConsumed)
    ));

    drop(store);
    drop(pool);
    cleanup(&path);
}

#[tokio::test]
async fn failed_refresh_insert_does_not_consume_device_code() {
    let (store, pool, path) = file_store().await;
    let (user, client) = seed_user_and_client(&store).await;
    let code = device_code(client);
    store
        .device_codes()
        .insert(&code)
        .await
        .expect("device code");
    store
        .device_codes()
        .approve(&code.user_code_hash, user, NOW)
        .await
        .expect("approve");
    assert!(matches!(
        store
            .device_codes()
            .prepare_poll(&code.device_code_hash, NOW, client)
            .await
            .expect("prepare poll"),
        DevicePoll::Approved { .. }
    ));

    let family = FamilyId::new();
    let token = refresh(user, client, family, 0x51);
    install_failing_refresh_trigger(&pool).await;
    assert!(
        store
            .device_codes()
            .consume_and_insert_refresh(&code.device_code_hash, NOW, client, &family, &token)
            .await
            .is_err(),
        "the injected insert failure must surface"
    );

    // The code is still approved and no refresh row exists, so a retry works.
    let stored = store
        .device_codes()
        .find_by_device_hash(&code.device_code_hash)
        .await
        .expect("find device code")
        .expect("device code exists");
    assert_eq!(stored.state.status(), DeviceCodeStatus::Approved);
    assert_eq!(stored.consumed_at, None);
    assert_eq!(
        store
            .refresh_tokens()
            .find(&token.token_hash)
            .await
            .expect("find refresh token"),
        None
    );

    drop_failing_refresh_trigger(&pool).await;
    assert!(matches!(
        store
            .device_codes()
            .consume_and_insert_refresh(&code.device_code_hash, NOW, client, &family, &token)
            .await
            .expect("the retry must succeed"),
        DevicePoll::Approved { .. }
    ));
    let stored = store
        .device_codes()
        .find_by_device_hash(&code.device_code_hash)
        .await
        .expect("find device code")
        .expect("device code exists");
    assert_eq!(stored.state.status(), DeviceCodeStatus::Consumed);
    assert_eq!(stored.family_id, Some(family));
    assert_eq!(
        store
            .refresh_tokens()
            .find(&token.token_hash)
            .await
            .expect("find refresh token"),
        Some(token.clone())
    );

    drop(store);
    drop(pool);
    cleanup(&path);
}
