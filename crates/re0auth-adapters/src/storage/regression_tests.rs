//! Storage regressions from the audit report.

use super::*;

#[tokio::test]
async fn s22_repeated_startup_against_the_same_file_succeeds() {
    let path = std::env::temp_dir().join(format!("re0auth-migrate-{}.db", uuid::Uuid::now_v7()));
    let url = format!("sqlite://{}", path.display());
    let first = SqliteStore::connect_with(&url, DatabaseOptions::default())
        .await
        .expect("first startup");
    drop(first);
    let second = SqliteStore::connect_with(&url, DatabaseOptions::default())
        .await
        .expect("second startup sees the applied versions");
    drop(second);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn s23_legacy_expired_bindings_are_normalized() {
    let pool = SqlitePool::connect("sqlite::memory:").await.expect("pool");
    sqlx::query(
        "CREATE TABLE bindings (status TEXT NOT NULL \
         CHECK (status IN ('pending','active','needs_reauth','revoked','expired')))",
    )
    .execute(&pool)
    .await
    .expect("old table");
    sqlx::query("INSERT INTO bindings (status) VALUES ('expired')")
        .execute(&pool)
        .await
        .expect("legacy row");

    normalize_legacy_bindings(&pool).await.expect("normalize");
    let status: String = sqlx::query_scalar("SELECT status FROM bindings")
        .fetch_one(&pool)
        .await
        .expect("status");
    assert_eq!(status, "needs_reauth");
}

#[tokio::test]
async fn s23_missing_bindings_table_is_not_an_error() {
    let pool = SqlitePool::connect("sqlite::memory:").await.expect("pool");
    normalize_legacy_bindings(&pool)
        .await
        .expect("fresh database");
}

#[tokio::test]
async fn p04_cleanup_indexes_are_created() {
    let path = std::env::temp_dir().join(format!("re0auth-index-{}.db", uuid::Uuid::now_v7()));
    let url = format!("sqlite://{}", path.display());
    let store = SqliteStore::connect_with(&url, DatabaseOptions::default())
        .await
        .expect("store");
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'",
    )
    .fetch_all(&store.pool)
    .await
    .expect("indexes");
    for wanted in [
        "idx_sessions_absolute",
        "idx_sessions_revoked",
        "idx_auth_codes_consumed",
        "idx_refresh_consumed",
        "idx_refresh_revoked",
    ] {
        assert!(names.iter().any(|name| name == wanted), "missing {wanted}");
    }
    drop(store);
    let _ = std::fs::remove_file(&path);
}
