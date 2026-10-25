//! Signing-key lifecycle invariants.
//!
//! The properties that matter are all about what happens *after* a rotation:
//! tokens stay verifiable, retired keys stay published, and a restart does not
//! forget either.

use re0auth_adapters::storage::SqliteStore;
use re0auth_api::ports::{SigningKeyRecord, Storage};
use re0auth_contract::memory::MemoryStore;

fn record(kid: &str, activated_at: i64, retired_at: Option<i64>) -> SigningKeyRecord {
    SigningKeyRecord {
        kid: kid.to_string(),
        alg: "RS256".to_string(),
        public_jwk_json: format!(r#"{{"kty":"RSA","kid":"{kid}"}}"#),
        created_at: activated_at,
        activated_at,
        retired_at,
    }
}

async fn sqlite() -> SqliteStore {
    SqliteStore::connect("sqlite::memory:")
        .await
        .expect("SQLite store")
}

#[tokio::test]
async fn publishing_twice_is_idempotent() {
    // A restart re-publishes the key it just loaded. Failing on the second start
    // would make every restart an outage.
    let store = sqlite().await;
    let key = record("aaaa", 100, None);
    store.signing_keys().publish(&key).await.expect("first");
    store.signing_keys().publish(&key).await.expect("second");
    assert_eq!(
        store.signing_keys().published().await.expect("list").len(),
        1
    );
}

#[tokio::test]
async fn republishing_does_not_unretire_a_key() {
    // A retired key must stay retired. Otherwise an operator who retires a key
    // and then restarts would silently start signing with it again.
    let store = sqlite().await;
    store
        .signing_keys()
        .publish(&record("aaaa", 100, None))
        .await
        .expect("publish");
    store
        .signing_keys()
        .retire("aaaa", 200)
        .await
        .expect("retire");

    // Re-publish as the loader would, carrying the stale record.
    store
        .signing_keys()
        .publish(&record("aaaa", 100, None))
        .await
        .expect("re-publish");

    let keys = store.signing_keys().published().await.expect("list");
    assert_eq!(keys.len(), 1);
    assert_eq!(
        keys[0].retired_at,
        Some(200),
        "re-publishing cleared the retirement"
    );
}

#[tokio::test]
async fn the_active_key_is_the_newest_unretired_one() {
    let store = sqlite().await;
    store
        .signing_keys()
        .publish(&record("old", 100, None))
        .await
        .expect("publish old");
    store
        .signing_keys()
        .publish(&record("new", 200, None))
        .await
        .expect("publish new");
    let active = store
        .signing_keys()
        .active()
        .await
        .expect("active")
        .expect("some key");
    assert_eq!(active.kid, "new");

    // Retiring the newest leaves the older one active again, which is what
    // makes a rollback possible.
    store
        .signing_keys()
        .retire("new", 300)
        .await
        .expect("retire");
    let active = store
        .signing_keys()
        .active()
        .await
        .expect("active")
        .expect("some key");
    assert_eq!(active.kid, "old");
}

#[tokio::test]
async fn retired_keys_stay_published() {
    // Dropping a retired key would make every unexpired token it signed fail
    // verification. This is the whole point of the `retired_at` column.
    let store = sqlite().await;
    store
        .signing_keys()
        .publish(&record("old", 100, None))
        .await
        .expect("publish");
    store
        .signing_keys()
        .retire("old", 200)
        .await
        .expect("retire");

    let published = store.signing_keys().published().await.expect("list");
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].kid, "old");
}

#[tokio::test]
async fn retiring_an_unknown_key_is_not_found() {
    let store = sqlite().await;
    assert!(matches!(
        store.signing_keys().retire("ghost", 100).await,
        Err(re0auth_api::ports::RepoError::NotFound)
    ));
}

#[tokio::test]
async fn retiring_twice_keeps_the_original_timestamp() {
    // The first retirement is the truth; a second call must not rewrite history.
    let store = sqlite().await;
    store
        .signing_keys()
        .publish(&record("aaaa", 100, None))
        .await
        .expect("publish");
    store
        .signing_keys()
        .retire("aaaa", 200)
        .await
        .expect("first");
    store
        .signing_keys()
        .retire("aaaa", 999)
        .await
        .expect("second");
    let keys = store.signing_keys().published().await.expect("list");
    assert_eq!(keys[0].retired_at, Some(200));
}

#[tokio::test]
async fn a_non_json_jwk_is_rejected_by_the_database() {
    // INV-JSON-01: the CHECK constraint is the thing that stops a malformed JWK
    // from reaching the JWKS endpoint.
    let store = sqlite().await;
    let mut bad = record("aaaa", 100, None);
    bad.public_jwk_json = "{not json".to_string();
    assert!(
        store.signing_keys().publish(&bad).await.is_err(),
        "the database accepted a malformed JWK"
    );
}

#[tokio::test]
async fn the_memory_store_matches_the_sqlite_semantics() {
    // The in-memory store is a test double, but its lifecycle rules must match or
    // tests will pass against behaviour production does not have.
    let memory = MemoryStore::new();
    memory
        .signing_keys()
        .publish(&record("old", 100, None))
        .await
        .expect("publish old");
    memory
        .signing_keys()
        .publish(&record("new", 200, None))
        .await
        .expect("publish new");
    assert_eq!(
        memory
            .signing_keys()
            .active()
            .await
            .expect("active")
            .expect("some key")
            .kid,
        "new"
    );

    memory
        .signing_keys()
        .retire("new", 300)
        .await
        .expect("retire");
    // Re-publishing must not un-retire, exactly as in SQL.
    memory
        .signing_keys()
        .publish(&record("new", 200, None))
        .await
        .expect("re-publish");
    let keys = memory.signing_keys().published().await.expect("list");
    let new = keys.iter().find(|key| key.kid == "new").expect("new key");
    assert_eq!(new.retired_at, Some(300));
}
