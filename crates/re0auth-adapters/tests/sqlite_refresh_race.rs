//! SQLite refresh-token race behavior.

use std::sync::Arc;

use re0auth_adapters::storage::SqliteStore;
use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::ports::{
    RefreshToken, RotateOutcome, RotateRefreshToken, Storage, User, UserRole,
};
use re0auth_api::{ClientId, FamilyId, RefreshTokenId, UserId};
use tokio::sync::Barrier;

fn token(user: UserId, client: ClientId, family: FamilyId, hash: u8) -> RefreshToken {
    RefreshToken {
        id: RefreshTokenId::new(),
        token_hash: vec![hash; 32],
        family_id: family,
        client_id: client,
        user_id: user,
        scopes: vec!["openid".to_string()],
        created_at: 1_000,
        expires_at: 10_000,
        consumed_at: None,
        revoked_at: None,
        replaced_by: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_refresh_rotates_once_and_revokes_the_family() {
    let path = std::env::temp_dir().join(format!("re0auth-refresh-{}.db", uuid::Uuid::now_v7()));
    let url = format!("sqlite://{}", path.display());
    let store = Arc::new(SqliteStore::connect(&url).await.expect("file store"));

    let user = User {
        id: UserId::new(),
        display_name: "refresh-race".to_string(),
        role: UserRole::User,
        created_at: 1_000,
        updated_at: 1_000,
    };
    store.users().create(&user).await.expect("user");
    let client = ClientId::new();
    let family = FamilyId::new();
    let old = token(user.id, client, family, 0x10);
    store
        .refresh_tokens()
        .insert(&old)
        .await
        .expect("old token");

    let barrier = Arc::new(Barrier::new(8));
    let mut tasks = Vec::new();
    for hash in 0x21..=0x28 {
        let store = store.clone();
        let old_hash = old.token_hash.clone();
        let new = token(user.id, client, family, hash);
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let fact = SecurityFact::new(AuditAction::RefreshTokenRotated, 1_000, "refresh:race");
            store
                .refresh_tokens()
                .rotate(
                    RotateRefreshToken {
                        old_hash: &old_hash,
                        new,
                    },
                    &fact,
                    1_000,
                )
                .await
        }));
    }

    let mut rotated = None;
    let mut rejected = 0;
    for task in tasks {
        match task.await.expect("join") {
            Ok(RotateOutcome::Rotated(token)) => {
                assert!(rotated.is_none(), "the same token rotated twice");
                rotated = Some(token);
            }
            Ok(RotateOutcome::ReuseDetected { .. } | RotateOutcome::Revoked) => rejected += 1,
            Ok(other) => panic!("unexpected rotate outcome: {other:?}"),
            Err(error) => panic!("rotate must not fail with BUSY/backend: {error:?}"),
        }
    }
    assert_eq!(rejected, 7, "the losing requests must be rejected");
    let rotated = rotated.expect("one request must rotate");

    for token in [&old, &rotated] {
        let stored = store
            .refresh_tokens()
            .find(&token.token_hash)
            .await
            .expect("find family member")
            .expect("family member exists");
        assert!(
            stored.revoked_at.is_some(),
            "reuse detection must revoke the whole family"
        );
    }

    store.users().delete(&user.id).await.expect("cleanup");
    drop(store);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn different_families_refresh_without_false_reuse() {
    let path = std::env::temp_dir().join(format!("re0auth-refresh-{}.db", uuid::Uuid::now_v7()));
    let url = format!("sqlite://{}", path.display());
    let store = Arc::new(SqliteStore::connect(&url).await.expect("file store"));

    let user = User {
        id: UserId::new(),
        display_name: "refresh-families".to_string(),
        role: UserRole::User,
        created_at: 1_000,
        updated_at: 1_000,
    };
    store.users().create(&user).await.expect("user");
    let client = ClientId::new();
    let first_family = FamilyId::new();
    let second_family = FamilyId::new();
    let first = token(user.id, client, first_family, 0x10);
    let second = token(user.id, client, second_family, 0x11);
    store.refresh_tokens().insert(&first).await.expect("first");
    store
        .refresh_tokens()
        .insert(&second)
        .await
        .expect("second");

    let barrier = Arc::new(Barrier::new(2));
    let mut tasks = Vec::new();
    for (old, hash) in [(&first, 0x21), (&second, 0x22)] {
        let store = store.clone();
        let old_hash = old.token_hash.clone();
        let new = token(user.id, client, old.family_id, hash);
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let fact = SecurityFact::new(AuditAction::RefreshTokenRotated, 1_000, "refresh:race");
            store
                .refresh_tokens()
                .rotate(
                    RotateRefreshToken {
                        old_hash: &old_hash,
                        new,
                    },
                    &fact,
                    1_000,
                )
                .await
        }));
    }

    let mut rotated = Vec::new();
    for task in tasks {
        match task.await.expect("join") {
            Ok(RotateOutcome::Rotated(token)) => rotated.push(token),
            Ok(other) => panic!("independent families must not reuse: {other:?}"),
            Err(error) => panic!("independent refresh must not fail: {error:?}"),
        }
    }
    assert_eq!(rotated.len(), 2);
    for new in &rotated {
        let stored = store
            .refresh_tokens()
            .find(&new.token_hash)
            .await
            .expect("find new")
            .expect("new token");
        assert!(stored.revoked_at.is_none());
    }
    for old in [&first, &second] {
        let stored = store
            .refresh_tokens()
            .find(&old.token_hash)
            .await
            .expect("find old")
            .expect("old token");
        assert!(stored.consumed_at.is_some());
        assert!(stored.revoked_at.is_none());
    }

    store.users().delete(&user.id).await.expect("cleanup");
    drop(store);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}
