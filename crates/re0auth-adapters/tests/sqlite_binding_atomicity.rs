//! Binding + credential atomicity on SQLite.

use std::sync::Arc;

use re0auth_adapters::storage::SqliteStore;
use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::ports::{Binding, BindingStatus, RepoError, Storage, User, UserRole};
use re0auth_api::secret::SealedSecret;
use re0auth_api::{BindingId, UserId};
use tokio::sync::Barrier;

fn binding(user: UserId, id: BindingId, subject: &str) -> Binding {
    Binding {
        id,
        user_id: user,
        upstream_id: "phigros".to_string(),
        upstream_user_id: subject.to_string(),
        status: BindingStatus::Active,
        created_at: 1_000,
        updated_at: 1_000,
        last_refreshed_at: None,
        last_error_code: None,
    }
}

fn sealed(marker: u8) -> SealedSecret {
    SealedSecret::new(
        1,
        vec![0x10; 12],
        vec![0x20; 44],
        vec![0x30; 12],
        vec![marker; 32],
    )
    .expect("sealed secret")
}

fn fact() -> SecurityFact {
    SecurityFact::new(AuditAction::BindingCreated, 1_000, "binding")
}

async fn file_store() -> (Arc<SqliteStore>, std::path::PathBuf, String) {
    let path = std::env::temp_dir().join(format!("re0auth-binding-{}.db", uuid::Uuid::now_v7()));
    let url = format!("sqlite://{}", path.display());
    let store = Arc::new(SqliteStore::connect(&url).await.expect("file store"));
    (store, path, url)
}

async fn user(store: &SqliteStore) -> UserId {
    let user = User {
        id: UserId::new(),
        display_name: "binding-race".to_string(),
        role: UserRole::User,
        created_at: 1_000,
        updated_at: 1_000,
    };
    store.users().create(&user).await.expect("user");
    user.id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_rebinds_never_mix_subject_and_credential() {
    let (store, path, _) = file_store().await;
    let user = user(&store).await;

    let barrier = Arc::new(Barrier::new(2));
    let mut tasks = Vec::new();
    for (subject, marker) in [("A", 0x0a), ("B", 0x0b)] {
        let store = store.clone();
        let barrier = barrier.clone();
        let binding = binding(user, BindingId::new(), subject);
        let sealed = sealed(marker);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .bindings()
                .upsert_with_credential(&binding, &sealed, &fact(), 1_000)
                .await
        }));
    }

    let mut winners = 0;
    let mut conflicts = 0;
    for task in tasks {
        match task.await.expect("join") {
            Ok(binding) => {
                winners += 1;
                assert_eq!(binding.user_id, user);
            }
            Err(RepoError::Conflict("binding id")) => conflicts += 1,
            Err(error) => panic!("unexpected binding error: {error:?}"),
        }
    }
    assert_eq!(winners, 1, "exactly one binding write may win");
    assert_eq!(conflicts, 1, "the loser must not attach its credential");

    let stored = store
        .bindings()
        .find(&user, "phigros")
        .await
        .expect("find binding")
        .expect("binding exists");
    let credential = store
        .bindings()
        .load_sub_credential(&stored.id)
        .await
        .expect("load credential")
        .expect("credential exists");
    let marker = credential.ciphertext()[0];
    assert!(
        matches!(
            (stored.upstream_user_id.as_str(), marker),
            ("A", 0x0a) | ("B", 0x0b)
        ),
        "subject {:?} and credential marker {marker:#x} came from different requests",
        stored.upstream_user_id
    );

    store.users().delete(&user).await.expect("cleanup");
    drop(store);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}

#[tokio::test]
async fn a_failed_credential_write_rolls_back_the_binding() {
    let (store, path, url) = file_store().await;
    let user = user(&store).await;
    let id = BindingId::new();
    store
        .bindings()
        .upsert_with_credential(
            &binding(user, id, "old-subject"),
            &sealed(0x01),
            &fact(),
            1_000,
        )
        .await
        .expect("initial binding");

    let trigger_pool = sqlx::SqlitePool::connect(&url)
        .await
        .expect("trigger store");
    sqlx::query(
        "CREATE TRIGGER fail_sub_insert BEFORE INSERT ON sub_credentials \
         BEGIN SELECT RAISE(ABORT, 'injected credential failure'); END",
    )
    .execute(&trigger_pool)
    .await
    .expect("insert trigger");
    sqlx::query(
        "CREATE TRIGGER fail_sub_update BEFORE UPDATE ON sub_credentials \
         BEGIN SELECT RAISE(ABORT, 'injected credential failure'); END",
    )
    .execute(&trigger_pool)
    .await
    .expect("update trigger");

    let result = store
        .bindings()
        .upsert_with_credential(
            &binding(user, id, "new-subject"),
            &sealed(0x02),
            &fact(),
            1_100,
        )
        .await;
    assert!(result.is_err(), "the trigger must fail the write");

    let stored = store
        .bindings()
        .find(&user, "phigros")
        .await
        .expect("find after failure")
        .expect("old binding survives");
    assert_eq!(stored.upstream_user_id, "old-subject");
    let credential = store
        .bindings()
        .load_sub_credential(&id)
        .await
        .expect("load after failure")
        .expect("old credential survives");
    assert_eq!(credential.ciphertext()[0], 0x01);

    trigger_pool.close().await;
    store.users().delete(&user).await.expect("cleanup");
    drop(store);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}
