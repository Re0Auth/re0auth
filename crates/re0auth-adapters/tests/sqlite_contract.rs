use re0auth_adapters::storage::SqliteStore;
use re0auth_api::ports::{Binding, BindingStatus, RepoError, Storage, User, UserRole};
use re0auth_api::secret::SecretSealer;
use re0auth_api::{BindingId, SecretString, UserId};
use re0auth_contract::{
    MockSealer, admin_query_contract, approval_ticket_contract, audit_contract, auth_code_contract,
    binding_contract, client_contract, consent_contract, device_attempt_contract,
    device_code_contract, login_transaction_contract, pending_authorization_contract,
    pending_binding_contract, refresh_token_contract, session_contract, storage_contract_suite,
    user_contract,
};

async fn store() -> SqliteStore {
    SqliteStore::connect("sqlite::memory:")
        .await
        .expect("SQLite store with migrations")
}

#[tokio::test]
async fn sub_credentials_are_stored_sealed_and_removed_on_revoke() {
    let store = store().await;
    let user = User {
        id: UserId::new(),
        display_name: "sealed-user".to_string(),
        role: UserRole::User,
        created_at: 1_000,
        updated_at: 1_000,
    };
    store.users().create(&user).await.expect("user");
    let binding = Binding {
        id: BindingId::new(),
        user_id: user.id,
        upstream_id: "phihub".to_string(),
        upstream_user_id: "player-1".to_string(),
        status: BindingStatus::Active,
        created_at: 1_000,
        updated_at: 1_000,
        last_refreshed_at: None,
        last_error_code: None,
    };
    store
        .bindings()
        .upsert(&binding, &fact_binding())
        .await
        .expect("binding");

    let plaintext = "sub-token-plaintext";
    let sealer = MockSealer::new();
    let sealed = sealer
        .seal(&binding.id, &SecretString::from(plaintext.to_string()))
        .expect("seal");
    store
        .bindings()
        .store_sub_credential(&binding.id, &sealed, 1_000)
        .await
        .expect("store");

    let loaded = store
        .bindings()
        .load_sub_credential(&binding.id)
        .await
        .expect("load")
        .expect("present");
    assert_eq!(loaded, sealed);
    assert!(
        !loaded
            .ciphertext()
            .windows(plaintext.len())
            .any(|window| window == plaintext.as_bytes()),
        "core storage must not contain the plaintext sub-token"
    );

    store
        .bindings()
        .revoke(&binding.id, &fact_binding(), 1_100)
        .await
        .expect("revoke");
    assert!(
        store
            .bindings()
            .load_sub_credential(&binding.id)
            .await
            .expect("load after revoke")
            .is_none(),
        "revoking a binding removes its sealed credential"
    );
}

#[tokio::test]
async fn sqlite_passes_user_contract() {
    user_contract(&store().await).await;
}

#[tokio::test]
async fn sqlite_passes_session_contract() {
    session_contract(&store().await).await;
}

#[tokio::test]
async fn sqlite_passes_auth_code_contract() {
    auth_code_contract(&store().await).await;
}

#[tokio::test]
async fn sqlite_passes_refresh_token_contract() {
    refresh_token_contract(&store().await).await;
}

#[tokio::test]
async fn sqlite_passes_login_transaction_contract() {
    login_transaction_contract(&store().await).await;
}

#[tokio::test]
async fn sqlite_passes_pending_binding_contract() {
    pending_binding_contract(&store().await).await;
}

#[tokio::test]
async fn sqlite_passes_approval_ticket_contract() {
    approval_ticket_contract(&store().await).await;
}

#[tokio::test]
async fn sqlite_passes_consent_contract() {
    consent_contract(&store().await).await;
}

#[tokio::test]
async fn sqlite_passes_pending_authorization_contract() {
    pending_authorization_contract(&store().await).await;
}

#[tokio::test]
async fn sqlite_passes_device_code_contract() {
    device_code_contract(&store().await).await;
}

#[tokio::test]
async fn sqlite_passes_device_attempt_contract() {
    device_attempt_contract(&store().await).await;
}

#[tokio::test]
async fn sqlite_passes_binding_contract() {
    binding_contract(&store().await).await;
}

#[tokio::test]
async fn sqlite_passes_audit_contract() {
    audit_contract(&store().await).await;
}

#[tokio::test]
async fn sqlite_passes_admin_query_contract() {
    admin_query_contract(&store().await).await;
}

#[tokio::test]
async fn sqlite_passes_client_contract() {
    client_contract(&store().await).await;
}

#[tokio::test]
async fn sqlite_passes_the_full_storage_contract() {
    storage_contract_suite(&store().await).await;
}

/// INV-BIND-01: `(user_id, upstream_id)` is unique, so a burst of concurrent
/// upserts for the same pair must converge on exactly one row. This needs a file
/// database: the in-memory pool is capped at one connection, which would hide any
/// real race.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_binding_upserts_converge_on_one_row() {
    let path = std::env::temp_dir().join(format!("re0auth-bind-{}.db", uuid::Uuid::now_v7()));
    let url = format!("sqlite://{}", path.display());
    let store = std::sync::Arc::new(SqliteStore::connect(&url).await.expect("file store"));

    let user = User {
        id: UserId::new(),
        display_name: "race".to_string(),
        role: UserRole::User,
        created_at: 1_000,
        updated_at: 1_000,
    };
    store.users().create(&user).await.expect("user");

    let mut tasks = Vec::new();
    for n in 0..16 {
        let store = store.clone();
        let user_id = user.id;
        tasks.push(tokio::spawn(async move {
            let binding = Binding {
                id: BindingId::new(),
                user_id,
                upstream_id: "phigros".to_string(),
                upstream_user_id: format!("player-{n}"),
                status: BindingStatus::Active,
                created_at: 1_000,
                updated_at: 1_000 + n,
                last_refreshed_at: None,
                last_error_code: None,
            };
            store.bindings().upsert(&binding, &fact_binding()).await
        }));
    }

    let mut failures = 0;
    for task in tasks {
        match task.await.expect("task join") {
            Ok(()) => {}
            // Losing a race to the unique constraint is acceptable as long as it
            // is reported as a conflict and never as a corrupt state.
            Err(RepoError::Conflict(_)) => failures += 1,
            Err(other) => panic!("unexpected upsert error: {other}"),
        }
    }

    let listed = store
        .bindings()
        .list_by_user(&user.id)
        .await
        .expect("list bindings");
    assert_eq!(
        listed.len(),
        1,
        "16 concurrent upserts must leave exactly one binding, not {} (conflicts: {failures})",
        listed.len()
    );
    assert_eq!(listed[0].upstream_id, "phigros");
    assert_eq!(listed[0].status, BindingStatus::Active);
    assert!(
        listed[0].upstream_user_id.starts_with("player-"),
        "the surviving row must carry one of the racing subjects"
    );

    store.users().delete(&user.id).await.expect("cleanup");
    drop(store);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}

fn fact_binding() -> re0auth_api::audit::SecurityFact {
    re0auth_api::audit::SecurityFact::new(
        re0auth_api::audit::AuditAction::BindingCreated,
        0,
        "binding".to_string(),
    )
}
