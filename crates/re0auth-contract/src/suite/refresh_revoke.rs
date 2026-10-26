//! Refresh-token mass revocation contract.

use super::{fact, refresh};
use re0auth_api::FamilyId;
use re0auth_api::audit::AuditAction;
use re0auth_api::ports::{AuditFilter, Storage};

pub async fn revoke_all_for_client_contract<S: Storage>(store: &S) {
    let now = 1_000;
    let user = super::user(now);
    store.users().create(&user).await.expect("user");
    let client = super::client(now);
    store
        .clients()
        .insert(&client, &fact(AuditAction::ClientCreated, now, "client"))
        .await
        .expect("client");
    let other_user = super::user(now);
    store.users().create(&other_user).await.expect("other user");
    let other_client = super::client(now);
    store
        .clients()
        .insert(
            &other_client,
            &fact(AuditAction::ClientCreated, now, "other-client"),
        )
        .await
        .expect("other client");

    let first = refresh(user.id, client.id, FamilyId::new(), 40, 10_000);
    let second = refresh(user.id, client.id, FamilyId::new(), 41, 10_000);
    let other_users = refresh(other_user.id, client.id, FamilyId::new(), 42, 10_000);
    let other_clients = refresh(user.id, other_client.id, FamilyId::new(), 43, 10_000);
    for token in [&first, &second, &other_users, &other_clients] {
        store
            .refresh_tokens()
            .insert(token)
            .await
            .expect("insert refresh token");
    }

    let audit_fact = fact(AuditAction::RefreshTokenRevoked, 1_400, "consent")
        .actor(user.id)
        .client(client.id);
    assert_eq!(
        store
            .refresh_tokens()
            .revoke_all_for_client(&user.id, &client.id, &audit_fact, 1_400)
            .await
            .expect("revoke all for client"),
        2
    );
    for token in [&first, &second] {
        let stored = store
            .refresh_tokens()
            .find(&token.token_hash)
            .await
            .expect("find revoked")
            .expect("revoked token exists");
        assert!(
            stored.revoked_at.is_some(),
            "the target token must be revoked"
        );
    }
    for token in [&other_users, &other_clients] {
        let stored = store
            .refresh_tokens()
            .find(&token.token_hash)
            .await
            .expect("find untouched")
            .expect("untouched token exists");
        assert!(
            stored.revoked_at.is_none(),
            "another user or client must stay live"
        );
    }

    let records = store
        .audits()
        .query(
            &AuditFilter {
                actor: Some(user.id),
                action: Some(AuditAction::RefreshTokenRevoked),
                ..Default::default()
            },
            None,
            10,
        )
        .await
        .expect("audit query");
    assert_eq!(records.len(), 1, "one fact for the mass revocation");
    assert_eq!(records[0].actor_user_id, Some(user.id));
    assert_eq!(records[0].client_id, Some(client.id));
    assert_eq!(records[0].target, "consent");

    let no_op_fact = fact(AuditAction::RefreshTokenRevoked, 1_500, "consent");
    assert_eq!(
        store
            .refresh_tokens()
            .revoke_all_for_client(&user.id, &client.id, &no_op_fact, 1_500)
            .await
            .expect("repeat revoke"),
        0
    );
    let records = store
        .audits()
        .query(
            &AuditFilter {
                actor: Some(user.id),
                action: Some(AuditAction::RefreshTokenRevoked),
                ..Default::default()
            },
            None,
            10,
        )
        .await
        .expect("audit query after no-op");
    assert_eq!(records.len(), 1, "a no-op must not record a fact");
}
