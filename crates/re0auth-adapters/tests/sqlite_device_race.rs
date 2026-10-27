//! SQLite device-code poll race behavior.

use std::sync::Arc;

use re0auth_adapters::storage::SqliteStore;
use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::ports::{
    Client, ClientStatus, DeviceCode, DeviceCodeState, DevicePoll, Storage, User, UserRole,
};
use re0auth_api::{ClientId, DeviceCodeId, UserId};
use tokio::sync::Barrier;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_device_polls_consume_once() {
    let path = std::env::temp_dir().join(format!("re0auth-device-{}.db", uuid::Uuid::now_v7()));
    let url = format!("sqlite://{}", path.display());
    let store = Arc::new(SqliteStore::connect(&url).await.expect("file store"));

    let user = User {
        id: UserId::new(),
        display_name: "device-race".to_string(),
        role: UserRole::User,
        created_at: 1_000,
        updated_at: 1_000,
    };
    store.users().create(&user).await.expect("user");
    let client = Client {
        id: ClientId::new(),
        name: "device-race-client".to_string(),
        redirect_uris: vec!["https://client.example/callback".to_string()],
        allowed_scopes: vec!["openid".to_string()],
        raw_access: false,
        status: ClientStatus::Approved,
        secret_hash: None,
        created_at: 1_000,
        updated_at: 1_000,
    };
    store
        .clients()
        .insert(
            &client,
            &SecurityFact::new(AuditAction::ClientCreated, 1_000, "client:race"),
        )
        .await
        .expect("client");

    let code = DeviceCode {
        id: DeviceCodeId::new(),
        device_code_hash: vec![0x11; 32],
        user_code_hash: vec![0x12; 32],
        client_id: client.id,
        scopes: vec!["openid".to_string()],
        state: DeviceCodeState::Pending,
        interval_secs: 5,
        last_polled_at: None,
        poll_count: 0,
        user_code_misses: 0,
        created_at: 1_000,
        expires_at: 10_000,
        consumed_at: None,
    };
    store
        .device_codes()
        .insert(&code)
        .await
        .expect("device code");
    store
        .device_codes()
        .approve(&code.user_code_hash, user.id, 1_000)
        .await
        .expect("approve");

    let barrier = Arc::new(Barrier::new(2));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let store = store.clone();
        let hash = code.device_code_hash.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.device_codes().poll(&hash, 1_001).await
        }));
    }

    let mut approved = 0;
    let mut consumed = 0;
    for task in tasks {
        match task.await.expect("join") {
            Ok(DevicePoll::Approved { .. }) => approved += 1,
            Ok(DevicePoll::Consumed) => consumed += 1,
            Ok(other) => panic!("unexpected poll outcome: {other:?}"),
            Err(error) => panic!("poll must not fail: {error:?}"),
        }
    }
    assert_eq!(approved, 1, "exactly one poll may issue the token");
    assert_eq!(consumed, 1, "the other poll must see a consumed code");

    let stored = store
        .device_codes()
        .find_by_device_hash(&code.device_code_hash)
        .await
        .expect("find device code")
        .expect("device code exists");
    assert_eq!(
        stored.state,
        DeviceCodeState::Consumed { approver: user.id }
    );
    assert!(stored.consumed_at.is_some());

    store.users().delete(&user.id).await.expect("cleanup");
    drop(store);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}
