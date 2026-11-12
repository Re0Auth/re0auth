use re0auth_adapters::storage::SqliteStore;
use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::ports::{
    Binding, BindingStatus, PendingBinding, RepoError, Storage, User, UserRole, UserStatus,
};
use re0auth_api::secret::SealedSecret;
use re0auth_api::{BindingId, Unix, UserId};

fn fact() -> SecurityFact {
    SecurityFact::new(AuditAction::BindingCreated, 1_000, "binding")
}

#[tokio::test]
async fn legacy_revoked_bindings_gain_a_generation_without_changing_old_flows() {
    let path = std::env::temp_dir().join(format!(
        "re0auth-binding-generation-{}.db",
        uuid::Uuid::now_v7()
    ));
    let url = format!("sqlite://{}", path.display());
    let store = SqliteStore::connect(&url).await.expect("version 1 schema");
    let user = User {
        id: UserId::new(),
        display_name: "legacy".to_string(),
        role: UserRole::User,
        status: UserStatus::Active,
        created_at: 1_000,
        updated_at: 1_000,
    };
    store.users().create(&user).await.expect("user");
    let binding = Binding {
        id: BindingId::new(),
        user_id: user.id,
        upstream_id: "phigros".to_string(),
        upstream_user_id: "subject".to_string(),
        status: BindingStatus::Revoked,
        created_at: 1_000,
        updated_at: 1_000,
        last_refreshed_at: None,
        last_error_code: None,
    };
    store
        .bindings()
        .upsert(&binding, &fact())
        .await
        .expect("binding");
    let now: Unix = 1_000;
    let pending = PendingBinding {
        state_hash: vec![7; 32],
        user_id: user.id,
        upstream_id: "phigros".to_string(),
        pkce_verifier: "verifier".to_string(),
        return_to: "/account".to_string(),
        revocation_generation: 0,
        created_at: now,
        expires_at: 9_000,
        consumed_at: None,
    };
    store
        .pending_bindings()
        .insert(&pending)
        .await
        .expect("legacy flow");
    let post_revoke_flow = PendingBinding {
        state_hash: vec![8; 32],
        created_at: 2_000,
        ..pending.clone()
    };
    store
        .pending_bindings()
        .insert(&post_revoke_flow)
        .await
        .expect("post-revoke legacy flow");
    store.close().await;

    let pool = sqlx::SqlitePool::connect(&url)
        .await
        .expect("legacy database");
    sqlx::query("UPDATE bindings SET revoked_at = 1000 WHERE id = ?")
        .bind(binding.id.0.to_string())
        .execute(&pool)
        .await
        .expect("legacy revocation timestamp");
    sqlx::query("DROP TABLE binding_revocation_epochs")
        .execute(&pool)
        .await
        .expect("drop new epoch table");
    sqlx::query("DROP TABLE pending_binding_epochs")
        .execute(&pool)
        .await
        .expect("drop new flow epoch table");
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 2")
        .execute(&pool)
        .await
        .expect("rollback migration history");
    pool.close().await;

    let migrated = SqliteStore::connect(&url)
        .await
        .expect("version 2 migration");
    assert_eq!(
        migrated
            .bindings()
            .revocation_generation(&user.id, "phigros")
            .await
            .expect("legacy generation"),
        1
    );
    let consumed = migrated
        .pending_bindings()
        .consume(&pending.state_hash, 2_000)
        .await
        .expect("legacy pending flow");
    assert_eq!(consumed.revocation_generation, 0);
    let sealed = SealedSecret::new(
        1,
        vec![0x10; 12],
        vec![0x20; 44],
        vec![0x30; 12],
        vec![0x40; 32],
    )
    .expect("sealed credential");
    assert!(matches!(
        migrated
            .bindings()
            .upsert_with_credential(&binding, &sealed, &fact(), 0, 2_000)
            .await,
        Err(RepoError::Conflict("binding revoked"))
    ));

    let post_revoke_flow = migrated
        .pending_bindings()
        .consume(&post_revoke_flow.state_hash, 2_000)
        .await
        .expect("post-revoke pending flow");
    assert_eq!(post_revoke_flow.revocation_generation, 1);
    let requested = Binding {
        status: BindingStatus::Active,
        ..binding
    };
    let rebound = migrated
        .bindings()
        .upsert_with_credential(
            &requested,
            &sealed,
            &fact(),
            post_revoke_flow.revocation_generation,
            2_000,
        )
        .await
        .expect("flow started after the old revoke");
    assert_eq!(rebound.status, BindingStatus::Active);

    migrated.users().delete(&user.id).await.expect("cleanup");
    migrated.close().await;
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}
