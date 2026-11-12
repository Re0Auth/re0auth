use super::*;
use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::oauth::ConsentVersion;
use re0auth_api::ports::{Consent, Storage};
use re0auth_api::{ClientId, ConsentId, UserId};
use sqlx::Row;

const BASELINE: &str = include_str!("../../migrations/0001_baseline.sql");
const LEGACY_SCOPES: [&str; 10] = [
    "phigros.query.save.read",
    "phigros.songs.read",
    "phigros.leaderboard.read",
    "phigros.verify.read",
    "phigros.stats.read",
    "phihub.save.read",
    "phihub.catalog.read",
    "phihub.rank.read",
    "phihub.charts.read",
    "phihub.comment.read",
];

fn user_id() -> UserId {
    UserId(Uuid::from_u128(1))
}

fn legacy_client() -> ClientId {
    ClientId(Uuid::from_u128(101))
}

fn oidc_client() -> ClientId {
    ClientId(Uuid::from_u128(102))
}

async fn execute_baseline(store: &SqliteStore) -> anyhow::Result<()> {
    let mut tx = store.pool.begin().await?;
    sqlx::raw_sql(BASELINE).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

async fn insert_client(store: &SqliteStore, id: ClientId, scopes: &[&str], updated_at: i64) {
    sqlx::query(
        "INSERT INTO clients \
         (id, name, redirect_uris, allowed_scopes, raw_access, status, created_at, updated_at) \
         VALUES (?, ?, '[]', ?, 1, 'approved', 1000, ?)",
    )
    .bind(id.0.to_string())
    .bind(format!("client-{}", id.0))
    .bind(serde_json::to_string(scopes).expect("scopes"))
    .bind(updated_at)
    .execute(&store.pool)
    .await
    .expect("client");
}

async fn client_row(store: &SqliteStore, id: ClientId) -> (String, i64, i64) {
    let row =
        sqlx::query("SELECT allowed_scopes, raw_access, updated_at FROM clients WHERE id = ?")
            .bind(id.0.to_string())
            .fetch_one(&store.pool)
            .await
            .expect("client row");
    (
        row.get("allowed_scopes"),
        row.get("raw_access"),
        row.get("updated_at"),
    )
}

#[tokio::test]
async fn baseline_migration_revokes_grants_and_maps_clients() {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("baseline store");
    sqlx::query(
        "INSERT INTO users (id, display_name, role, created_at, updated_at) \
         VALUES (?, 'baseline-user', 'user', 1000, 1000)",
    )
    .bind(user_id().0.to_string())
    .execute(&store.pool)
    .await
    .expect("user");
    insert_client(
        &store,
        legacy_client(),
        &[
            "openid",
            "phigros.stats.read",
            "profile",
            "phihub.save.read",
            "unknown.scope",
            "phigros-query.raw.read",
            "phigros-query.raw.read",
            "phigros.songs.read",
            "phigros.stats.read.extra",
            "phihub.catalog.read",
            "phigros.stats.read",
            "phihub.comment.read",
            "phigros.query.save.read",
            "phigros.leaderboard.read",
            "phigros.verify.read",
            "phihub.rank.read",
            "phihub.charts.read",
        ],
        1_000,
    )
    .await;
    insert_client(
        &store,
        oidc_client(),
        &[
            "openid",
            "profile",
            "phigros.stats.read.extra",
            "unknown.scope",
            "phigros-query.raw.read",
            "phigros-query.raw.read",
        ],
        2_222,
    )
    .await;

    let historical_scopes = serde_json::json!([
        "openid",
        "phigros.stats.read",
        "phihub.save.read",
        "phigros-query.raw.read"
    ])
    .to_string();
    sqlx::query(
        "INSERT INTO consents \
         (id, user_id, client_id, scopes, created_at, updated_at, version) \
         VALUES (?, ?, ?, ?, 1000, 1000, 4), (?, ?, ?, '[\"openid\",\"profile\"]', 2000, 2000, 2)",
    )
    .bind(Uuid::from_u128(201).to_string())
    .bind(user_id().0.to_string())
    .bind(legacy_client().0.to_string())
    .bind(&historical_scopes)
    .bind(Uuid::from_u128(202).to_string())
    .bind(user_id().0.to_string())
    .bind(oidc_client().0.to_string())
    .execute(&store.pool)
    .await
    .expect("consents");
    sqlx::query(
        "INSERT INTO refresh_tokens \
         (id, token_hash, family_id, client_id, user_id, scopes, created_at, expires_at, \
          family_created_at, auth_time) \
         VALUES (?, ?, ?, ?, ?, '[\"openid\"]', 100, 999999, 12345, 23456)",
    )
    .bind(Uuid::from_u128(301).to_string())
    .bind(vec![1_u8; 32])
    .bind(Uuid::from_u128(302).to_string())
    .bind(legacy_client().0.to_string())
    .bind(user_id().0.to_string())
    .execute(&store.pool)
    .await
    .expect("refresh token");
    sqlx::query(
        "INSERT INTO auth_codes \
         (id, code_hash, client_id, user_id, redirect_uri, scopes, created_at, expires_at, auth_time) \
         VALUES (?, ?, ?, ?, 'https://client.example/callback', '[\"openid\"]', 100, 999999, 34567)",
    )
    .bind(Uuid::from_u128(303).to_string())
    .bind(vec![2_u8; 32])
    .bind(legacy_client().0.to_string())
    .bind(user_id().0.to_string())
    .execute(&store.pool)
    .await
    .expect("auth code");

    execute_baseline(&store).await.expect("baseline update");

    let (scopes, raw_access, updated_at) = client_row(&store, legacy_client()).await;
    let scopes: Vec<String> = serde_json::from_str(&scopes).expect("mapped scopes");
    assert_eq!(
        scopes,
        [
            "openid",
            "profile",
            "unknown.scope",
            "phigros-query.raw.read",
            "phigros-query.raw.read",
            "phigros.stats.read.extra",
            "phigros.phihub.read",
            "phigros.xtower.read",
        ]
    );
    assert_eq!(
        scopes
            .iter()
            .filter(|scope| scope.as_str() == "phigros.phihub.read")
            .count(),
        1
    );
    assert_eq!(
        scopes
            .iter()
            .filter(|scope| scope.as_str() == "phigros.xtower.read")
            .count(),
        1
    );
    assert!(
        scopes
            .iter()
            .all(|scope| !LEGACY_SCOPES.contains(&scope.as_str()))
    );
    assert_eq!(raw_access, 1);
    assert!(updated_at > 1_000);
    assert_eq!(
        client_row(&store, oidc_client()).await,
        (
            serde_json::to_string(&[
                "openid",
                "profile",
                "phigros.stats.read.extra",
                "unknown.scope",
                "phigros-query.raw.read",
                "phigros-query.raw.read",
            ])
            .expect("unchanged scopes"),
            1,
            2_222,
        )
    );

    let consent = sqlx::query(
        "SELECT scopes, revoked_at, updated_at, version FROM consents WHERE client_id = ?",
    )
    .bind(legacy_client().0.to_string())
    .fetch_one(&store.pool)
    .await
    .expect("revoked consent");
    assert_eq!(consent.get::<String, _>("scopes"), historical_scopes);
    assert!(consent.get::<Option<i64>, _>("revoked_at").is_some());
    assert!(consent.get::<i64, _>("updated_at") > 1_000);
    assert_eq!(consent.get::<i64, _>("version"), 5);
    let oidc =
        sqlx::query("SELECT revoked_at, updated_at, version FROM consents WHERE client_id = ?")
            .bind(oidc_client().0.to_string())
            .fetch_one(&store.pool)
            .await
            .expect("OIDC consent");
    assert_eq!(oidc.get::<Option<i64>, _>("revoked_at"), None);
    assert_eq!(oidc.get::<i64, _>("updated_at"), 2_000);
    assert_eq!(oidc.get::<i64, _>("version"), 2);
    assert_eq!(
        sqlx::query_as::<_, (i64, i64)>("SELECT family_created_at, auth_time FROM refresh_tokens")
            .fetch_one(&store.pool)
            .await
            .expect("authentication times"),
        (12_345, 23_456)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT auth_time FROM auth_codes")
            .fetch_one(&store.pool)
            .await
            .expect("auth code time"),
        34_567
    );

    let before_rerun = client_row(&store, legacy_client()).await;
    execute_baseline(&store).await.expect("idempotent baseline");
    assert_eq!(client_row(&store, legacy_client()).await, before_rerun);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT version FROM consents WHERE client_id = ?")
            .bind(legacy_client().0.to_string())
            .fetch_one(&store.pool)
            .await
            .expect("stable consent version"),
        5
    );
    assert_eq!(
        sqlx::query_as::<_, (i64, i64)>("SELECT family_created_at, auth_time FROM refresh_tokens")
            .fetch_one(&store.pool)
            .await
            .expect("stable authentication times"),
        (12_345, 23_456)
    );

    let granted = store
        .consents()
        .grant(
            &Consent {
                id: ConsentId(Uuid::from_u128(203)),
                user_id: user_id(),
                client_id: legacy_client(),
                scopes: vec!["openid".to_string(), "phigros.xtower.read".to_string()],
                created_at: 3_000,
                updated_at: 3_000,
                revoked_at: None,
                version: ConsentVersion(1),
            },
            &SecurityFact::new(AuditAction::ConsentGranted, 3_000, "baseline"),
        )
        .await
        .expect("new grant");
    assert_eq!(granted.scopes, ["openid", "phigros.xtower.read"]);
    assert_eq!(granted.version, ConsentVersion(6));
    assert!(granted.revoked_at.is_none());
    assert!(!granted.scopes.contains(&"phigros.phihub.read".to_string()));
    assert!(
        granted
            .scopes
            .iter()
            .all(|scope| !LEGACY_SCOPES.contains(&scope.as_str()))
    );
}

#[tokio::test]
async fn baseline_json_failure_rolls_back_client_updates() {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("baseline store");
    insert_client(&store, legacy_client(), &["phigros.stats.read"], 1_000).await;
    insert_client(&store, oidc_client(), &["openid"], 2_000).await;
    sqlx::query("UPDATE clients SET allowed_scopes = '{' WHERE id = ?")
        .bind(oidc_client().0.to_string())
        .execute(&store.pool)
        .await
        .expect("invalid JSON fixture");

    assert!(execute_baseline(&store).await.is_err());
    assert_eq!(
        client_row(&store, legacy_client()).await,
        ("[\"phigros.stats.read\"]".to_string(), 1, 1_000)
    );
}
