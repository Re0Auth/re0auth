//! INV-CONN-02: connector root credentials live in their own encrypted file,
//! never in the core database, and are bound to their key by the AEAD's AAD.

use std::path::PathBuf;
use std::sync::Arc;

use re0auth_api::connector::ConnectorSecretStore;
use re0auth_api::{Random, SecretString};
use re0auth_connectors::connector_secret::EncryptedFileSecretStore;

const MASTER: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

struct CounterRandom(std::sync::atomic::AtomicU8);

impl Random for CounterRandom {
    fn bytes(&self, len: usize) -> Vec<u8> {
        use std::sync::atomic::Ordering;
        let seed = self.0.fetch_add(1, Ordering::SeqCst);
        vec![seed; len]
    }
}

fn vault() -> (EncryptedFileSecretStore, PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "re0auth-connector-secret-{}.json",
        uuid::Uuid::now_v7()
    ));
    let store = EncryptedFileSecretStore::new(
        path.clone(),
        MASTER,
        Arc::new(CounterRandom(std::sync::atomic::AtomicU8::new(0))),
    )
    .expect("store");
    (store, path)
}

fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_string())
}

#[tokio::test]
async fn satisfies_the_port_contract() {
    let (store, path) = vault();
    re0auth_contract::connector_secret_store_contract(&store).await;
    let _ = std::fs::remove_file(path);
}

/// The file must not contain the plaintext. This is the whole point of the
/// vault: a leaked backup of the data directory must not hand over credentials.
#[tokio::test]
async fn the_stored_file_holds_no_plaintext() {
    let (store, path) = vault();
    store
        .put("connector/root", &secret("super-secret-root-token"))
        .await
        .expect("put");
    let raw = std::fs::read_to_string(&path).expect("read vault");
    assert!(
        !raw.contains("super-secret-root-token"),
        "plaintext leaked into {raw}"
    );
    assert!(raw.contains("ciphertext"), "{raw}");
    let _ = std::fs::remove_file(path);
}

/// AAD binds the ciphertext to its key name, so moving an entry to another key
/// must fail. Without this, one connector's credential could be transplanted
/// onto another connector's row by editing the file.
#[tokio::test]
async fn an_entry_cannot_be_moved_to_another_key() {
    let (store, path) = vault();
    store
        .put("connector/a", &secret("a-token"))
        .await
        .expect("put");

    let raw = std::fs::read_to_string(&path).expect("read");
    let moved = raw.replace("connector/a", "connector/b");
    std::fs::write(&path, moved).expect("write");

    assert!(
        store.get("connector/b").await.is_err(),
        "the key name is authenticated as AAD"
    );
    let _ = std::fs::remove_file(path);
}

/// Two concurrent writers must not lose each other's entry: the read-modify-write
/// cycle is serialized inside the store.
#[tokio::test]
async fn concurrent_writes_do_not_drop_entries() {
    let (store, path) = vault();
    let store = Arc::new(store);
    let mut tasks = Vec::new();
    for index in 0..12 {
        let store = Arc::clone(&store);
        tasks.push(tokio::spawn(async move {
            let key = format!("connector/{index}");
            store.put(&key, &secret("value")).await.expect("put");
        }));
    }
    for task in tasks {
        task.await.expect("join");
    }
    for index in 0..12 {
        let key = format!("connector/{index}");
        assert!(
            store.get(&key).await.expect("get").is_some(),
            "{key} was lost"
        );
    }
    let _ = std::fs::remove_file(path);
}

/// A corrupt vault must fail loudly. Treating it as empty would make the next
/// write silently destroy every credential it held.
#[tokio::test]
async fn a_corrupt_vault_is_an_error_not_an_empty_one() {
    let (store, path) = vault();
    store
        .put("connector/a", &secret("a-token"))
        .await
        .expect("put");
    std::fs::write(&path, b"{ this is not json").expect("corrupt");

    assert!(store.get("connector/a").await.is_err());
    assert!(
        store.put("connector/b", &secret("b-token")).await.is_err(),
        "refusing to write over an unreadable vault"
    );
    let _ = std::fs::remove_file(path);
}

/// Deleting an absent key is idempotent; the contract sends a delete for a key
/// that may already be gone during cleanup.
#[tokio::test]
async fn deleting_an_absent_key_succeeds() {
    let (store, path) = vault();
    store.delete("connector/never").await.expect("idempotent");
    let _ = std::fs::remove_file(path);
}

/// A missing file is an empty vault, not an error: a fresh deployment has
/// nothing stored yet.
#[tokio::test]
async fn a_missing_file_reads_as_empty() {
    let path = std::env::temp_dir().join(format!(
        "re0auth-connector-secret-absent-{}.json",
        uuid::Uuid::now_v7()
    ));
    let store = EncryptedFileSecretStore::new(
        path.clone(),
        MASTER,
        Arc::new(CounterRandom(std::sync::atomic::AtomicU8::new(0))),
    )
    .expect("store");
    assert!(store.get("connector/a").await.expect("get").is_none());
    assert!(!path.exists(), "reading must not create the file");
}

/// ADR-0039: the vault must not be the core database file. An operator who
/// points both at the same path would be silently mixing them.
#[tokio::test]
async fn the_vault_must_not_be_the_core_database() {
    let directory = std::env::temp_dir().join(format!("re0auth-vault-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&directory).expect("directory");
    let database = directory.join("re0auth.db");
    std::fs::write(&database, b"").expect("touch database");

    let same = EncryptedFileSecretStore::new(
        database.clone(),
        MASTER,
        Arc::new(CounterRandom(std::sync::atomic::AtomicU8::new(0))),
    )
    .expect("store");
    assert!(
        same.reject_core_database_path(Some(&database)).is_err(),
        "the vault must refuse to live inside the database file"
    );

    let separate = EncryptedFileSecretStore::new(
        directory.join("connector-secrets.json"),
        MASTER,
        Arc::new(CounterRandom(std::sync::atomic::AtomicU8::new(0))),
    )
    .expect("store");
    separate
        .reject_core_database_path(Some(&database))
        .expect("a separate file is fine");

    // A memory database has no file to collide with.
    separate
        .reject_core_database_path(None)
        .expect("a memory database has no file to collide with");
    let _ = std::fs::remove_dir_all(directory);
}
