//! Access-token revocation persistence.
//!
//! The interesting cases are all about time: a revocation is only meaningful
//! while the token could still be presented, and the table must not grow past
//! that point.

use re0auth_adapters::storage::SqliteStore;
use re0auth_api::UserId;
use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::ports::{Storage, User, UserRole};

fn fact() -> SecurityFact {
    SecurityFact::new(
        AuditAction::AccessTokenRevoked,
        1_000,
        "jti:test".to_string(),
    )
}

async fn store_with_user() -> (SqliteStore, UserId) {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("store");
    let user = User {
        id: UserId::new(),
        display_name: "revoke-user".to_string(),
        role: UserRole::User,
        created_at: 1_000,
        updated_at: 1_000,
    };
    store.users().create(&user).await.expect("user");
    (store, user.id)
}

#[tokio::test]
async fn a_revoked_token_is_reported_until_it_expires() {
    let (store, user) = store_with_user().await;

    store
        .access_tokens()
        .revoke("jti-a", None, Some(user), 2_000, &fact(), 1_000)
        .await
        .expect("revoke");

    assert!(
        store
            .access_tokens()
            .is_revoked("jti-a", 1_500)
            .await
            .expect("check")
    );
    // Past the token's own expiry the row stops counting: the token cannot be
    // presented any more, so reporting "revoked" would be meaningless.
    assert!(
        !store
            .access_tokens()
            .is_revoked("jti-a", 2_001)
            .await
            .expect("check")
    );
}

#[tokio::test]
async fn an_unknown_jti_is_not_revoked() {
    let (store, _user) = store_with_user().await;
    assert!(
        !store
            .access_tokens()
            .is_revoked("never-seen", 1_000)
            .await
            .expect("check")
    );
}

/// Revoking twice must not fail: RFC 7009 makes the endpoint idempotent, and an
/// error would leak that the token was already known.
#[tokio::test]
async fn revoking_twice_is_idempotent_and_logs_twice() {
    let (store, user) = store_with_user().await;

    store
        .access_tokens()
        .revoke("jti-b", None, Some(user), 2_000, &fact(), 1_000)
        .await
        .expect("first revoke");
    store
        .access_tokens()
        .revoke("jti-b", None, Some(user), 2_000, &fact(), 1_050)
        .await
        .expect("second revoke");

    assert!(
        store
            .access_tokens()
            .is_revoked("jti-b", 1_100)
            .await
            .expect("check")
    );
    // Each revoke attempt is a separate fact; the audit trail records that the
    // caller asked twice, which is itself worth knowing.
    let audits = store.audits().recent(10).await.expect("audits");
    assert_eq!(audits.len(), 2, "both revoke attempts must be logged");
}

#[tokio::test]
async fn purge_removes_only_expired_revocations() {
    let (store, user) = store_with_user().await;

    store
        .access_tokens()
        .revoke("jti-expired", None, Some(user), 2_000, &fact(), 1_000)
        .await
        .expect("revoke expired");
    store
        .access_tokens()
        .revoke("jti-live", None, Some(user), 9_000, &fact(), 1_000)
        .await
        .expect("revoke live");

    let removed = store
        .access_tokens()
        .purge_expired(3_000)
        .await
        .expect("purge");
    assert_eq!(removed, 1);
    assert!(
        !store
            .access_tokens()
            .is_revoked("jti-expired", 2_500)
            .await
            .expect("check expired")
    );
    assert!(
        store
            .access_tokens()
            .is_revoked("jti-live", 2_500)
            .await
            .expect("check live")
    );
}

/// INV-AUDIT-01 applies here too: if the revocation row cannot be written, the
/// fact must not survive either. A duplicate fact id forces the second write to
/// fail after the row insert has succeeded.
#[tokio::test]
async fn a_failed_revocation_write_leaves_no_audit_row() {
    let (store, user) = store_with_user().await;

    let shared = fact();
    store
        .access_tokens()
        .revoke("jti-first", None, Some(user), 5_000, &shared, 1_000)
        .await
        .expect("first revoke");

    let outcome = store
        .access_tokens()
        .revoke("jti-second", None, Some(user), 5_000, &shared, 1_000)
        .await;
    assert!(outcome.is_err(), "duplicate fact id must fail the write");

    assert!(
        !store
            .access_tokens()
            .is_revoked("jti-second", 1_000)
            .await
            .expect("check"),
        "the revocation row must roll back with its fact"
    );
    assert_eq!(
        store.audits().recent(10).await.expect("audits").len(),
        1,
        "only the first fact should exist"
    );
}
