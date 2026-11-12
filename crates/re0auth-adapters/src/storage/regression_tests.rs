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
async fn baseline_tracking_rejects_untracked_business_tables() {
    let pool = SqlitePool::connect("sqlite::memory:").await.expect("pool");
    sqlx::query("CREATE TABLE untracked_business (id TEXT PRIMARY KEY)")
        .execute(&pool)
        .await
        .expect("business table");
    let before: String = sqlx::query_scalar(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'untracked_business'",
    )
    .fetch_one(&pool)
    .await
    .expect("schema before guard");

    let error = validate_baseline_tracking(&pool)
        .await
        .expect_err("untracked business tables must fail closed");
    assert!(error.to_string().contains("存在无迁移历史的业务库"));
    let after: String = sqlx::query_scalar(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'untracked_business'",
    )
    .fetch_one(&pool)
    .await
    .expect("schema after guard");
    assert_eq!(after, before);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
        )
        .fetch_one(&pool)
        .await
        .expect("tracking table count"),
        0
    );
}

#[tokio::test]
async fn baseline_tracking_allows_fresh_and_prepared_databases() {
    let fresh = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("fresh schema");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(&fresh.pool)
            .await
            .expect("fresh migration"),
        1
    );
    fresh.close().await;

    let path = std::env::temp_dir().join(format!("re0auth-baseline-{}.db", Uuid::now_v7()));
    let url = format!("sqlite://{}", path.display());
    let first = SqliteStore::connect_with(&url, DatabaseOptions::default())
        .await
        .expect("initial store");
    sqlx::query(
        "INSERT INTO users (id, display_name, role, created_at, updated_at) \
         VALUES ('prepared-user', 'prepared', 'user', 1, 1)",
    )
    .execute(&first.pool)
    .await
    .expect("business row");
    first.close().await;

    let pool = SqlitePool::connect(&url).await.expect("existing database");
    sqlx::query("DELETE FROM _sqlx_migrations")
        .execute(&pool)
        .await
        .expect("prepare controlled cutover");
    pool.close().await;

    let migrated = SqliteStore::connect_with(&url, DatabaseOptions::default())
        .await
        .expect("prepared cutover");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(&migrated.pool)
            .await
            .expect("cutover migration"),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT display_name FROM users WHERE id = 'prepared-user'"
        )
        .fetch_one(&migrated.pool)
        .await
        .expect("preserved business row"),
        "prepared"
    );
    migrated.close().await;
    let _ = std::fs::remove_file(&path);
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
