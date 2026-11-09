//! User and identity contract.
//!
//! Split out of `suite.rs` to stay inside the per-file line budget; the
//! scenarios are unchanged.

use re0auth_api::audit::AuditAction;
use re0auth_api::ports::{
    BindingStatus, ConsumeAuthCode, Identity, RepoError, RotateOutcome, RotateRefreshToken, Storage,
};
use re0auth_api::{BindingId, ClientId, FamilyId, IdentityId, UserId};

use super::{auth_code, binding, fact, refresh, session, user};

pub async fn user_contract<S: Storage>(store: &S) {
    let now = 1_000;
    let user = user(now);
    store.users().create(&user).await.expect("create user");
    assert_eq!(
        store.users().get(&user.id).await.expect("get user"),
        Some(user.clone())
    );
    assert!(matches!(
        store.users().create(&user).await,
        Err(RepoError::Conflict(_))
    ));

    let identity = Identity {
        id: IdentityId::new(),
        user_id: user.id,
        issuer: "https://idp.example".to_string(),
        subject: "subject-1".to_string(),
        created_at: now,
    };
    store
        .users()
        .link_identity(&identity)
        .await
        .expect("link identity");
    assert_eq!(
        store
            .users()
            .find_by_identity("https://idp.example", "subject-1")
            .await
            .expect("find identity"),
        Some(user.clone())
    );
    assert!(matches!(
        store.users().link_identity(&identity).await,
        Err(RepoError::Conflict(_))
    ));

    // Attaching a second identity to an existing account is what the account
    // page will call; it must add a row without creating or stealing a user.
    let second = Identity {
        id: IdentityId::new(),
        user_id: user.id,
        issuer: "https://other.example".to_string(),
        subject: "subject-2".to_string(),
        created_at: now + 10,
    };
    store
        .users()
        .link_identity(&second)
        .await
        .expect("attach a second identity to an existing account");
    assert_eq!(
        store
            .users()
            .list_identities(&user.id)
            .await
            .expect("list identities"),
        vec![identity.clone(), second.clone()],
        "identities come back oldest first"
    );

    let detached = store
        .users()
        .unlink_identity(&UserId::new(), &identity.id)
        .await
        .expect("unlink from the wrong account");
    assert!(!detached, "an unlink is scoped to its owner");
    assert!(
        store
            .users()
            .unlink_identity(&user.id, &identity.id)
            .await
            .expect("unlink identity")
    );
    assert_eq!(
        store
            .users()
            .find_by_identity("https://idp.example", "subject-1")
            .await
            .expect("find detached identity"),
        None
    );
    assert_eq!(
        store
            .users()
            .list_identities(&user.id)
            .await
            .expect("list after unlink"),
        vec![second.clone()],
        "only the detached row is gone"
    );

    // The floor lives in the store, so a racing caller that already read
    // "two identities" still cannot remove the last one.
    let last = store
        .users()
        .unlink_identity(&user.id, &second.id)
        .await
        .expect("unlink the last identity");
    assert!(!last, "the store must keep at least one identity");
    assert_eq!(
        store
            .users()
            .list_identities(&user.id)
            .await
            .expect("list after refused unlink"),
        vec![second],
        "a refused unlink must not change the row"
    );

    let session = session(user.id, 1, now, 2_000, 5_000);
    let code = auth_code(user.id, ClientId::new(), 2, 2_000);
    let token = refresh(user.id, ClientId::new(), FamilyId::new(), 3, 5_000);
    let link = binding(user.id, BindingId::new(), BindingStatus::Active, now);
    store.sessions().create(&session).await.expect("session");
    store
        .auth_codes()
        .insert(&code, &fact(AuditAction::AuthCodeIssued, now, "code"))
        .await
        .expect("auth code");
    store
        .refresh_tokens()
        .insert(&token)
        .await
        .expect("refresh token");
    store
        .bindings()
        .upsert(&link, &fact(AuditAction::BindingCreated, now, "binding"))
        .await
        .expect("binding");

    // The app-level delete refuses while a live binding remains: deleting now
    // would drop the only credential that can still be revoked upstream.
    let guarded = store
        .users()
        .delete_with_fact(&user.id, &fact(AuditAction::AccountDeleted, now, "user"))
        .await
        .expect("guarded delete");
    assert!(!guarded, "a live binding must block delete_with_fact");
    assert!(
        store.users().get(&user.id).await.expect("get").is_some(),
        "a refused delete must keep the row"
    );

    assert!(store.users().delete(&user.id).await.expect("delete user"));
    assert_eq!(
        store.users().get(&user.id).await.expect("get deleted"),
        None
    );
    assert_eq!(
        store
            .sessions()
            .find_active(&session.id_hash, now)
            .await
            .expect("session after delete"),
        None
    );
    assert!(matches!(
        store
            .auth_codes()
            .consume(
                ConsumeAuthCode {
                    code_hash: &code.code_hash,
                    client_id: code.client_id,
                    redirect_uri: &code.redirect_uri,
                    code_challenge: code.code_challenge.as_deref(),
                    code_challenge_method: code.code_challenge_method.as_deref(),
                    family_id: FamilyId::new(),
                },
                now,
            )
            .await,
        Err(RepoError::NotFound)
    ));
    assert!(matches!(
        store
            .refresh_tokens()
            .rotate(
                RotateRefreshToken {
                    old_hash: &token.token_hash,
                    new: refresh(user.id, token.client_id, token.family_id, 4, 6_000),
                },
                &fact(AuditAction::RefreshTokenRotated, 1_000, "refresh"),
                now,
            )
            .await
            .expect("rotate after delete"),
        RotateOutcome::NotFound
    ));
    assert_eq!(
        store
            .bindings()
            .find(&user.id, "phigros")
            .await
            .expect("binding after delete"),
        None
    );
    assert!(!store.users().delete(&user.id).await.expect("delete again"));

    // The production deletion writes its fact in the same transaction, and a
    // missing row must not leave one behind.
    let extra = super::user(now + 1);
    store
        .users()
        .create(&extra)
        .await
        .expect("create extra user");
    assert!(
        store
            .users()
            .delete_with_fact(&extra.id, &fact(AuditAction::AccountDeleted, now, "user"))
            .await
            .expect("delete with fact")
    );
    assert!(
        !store
            .users()
            .delete_with_fact(&extra.id, &fact(AuditAction::AccountDeleted, now, "user"))
            .await
            .expect("delete a missing row with fact")
    );
}
