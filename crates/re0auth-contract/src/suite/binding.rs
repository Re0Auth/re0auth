//! Binding contract (INV-BIND-01).

use super::{binding, fact, user};
use re0auth_api::audit::AuditAction;
use re0auth_api::ports::{
    ANONYMIZED_UPSTREAM_USER_ID, Binding, BindingStatus, RepoError, Storage, User, UserRole,
};
use re0auth_api::secret::SealedSecret;
use re0auth_api::{BindingId, UserId};
pub async fn binding_contract<S: Storage>(store: &S) {
    let now = 1_000;
    let user = user(now);
    store.users().create(&user).await.expect("create user");

    let first = binding(user.id, BindingId::new(), BindingStatus::Pending, now);
    store
        .bindings()
        .upsert(&first, &fact(AuditAction::BindingCreated, now, "binding"))
        .await
        .expect("upsert binding");
    assert_eq!(
        store
            .bindings()
            .find(&user.id, "phigros")
            .await
            .expect("find binding"),
        Some(first.clone())
    );

    let replacement = Binding {
        id: BindingId::new(),
        status: BindingStatus::Active,
        upstream_user_id: "upstream-user-2".to_string(),
        updated_at: 1_100,
        ..first.clone()
    };
    store
        .bindings()
        .upsert(
            &replacement,
            &fact(AuditAction::BindingCreated, now, "binding"),
        )
        .await
        .expect("upsert replacement");
    let stored = store
        .bindings()
        .find(&user.id, "phigros")
        .await
        .expect("find replacement")
        .expect("binding exists");
    assert_eq!(stored.id, first.id, "upsert keeps the stored id");
    assert_eq!(stored.status, BindingStatus::Active);
    assert_eq!(stored.upstream_user_id, "upstream-user-2");

    let second = Binding {
        upstream_id: "phihub".to_string(),
        ..binding(user.id, BindingId::new(), BindingStatus::Active, now)
    };
    store
        .bindings()
        .upsert(&second, &fact(AuditAction::BindingCreated, now, "binding"))
        .await
        .expect("second binding");
    let listed = store
        .bindings()
        .list_by_user(&user.id)
        .await
        .expect("list bindings");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].upstream_id, "phigros");
    assert_eq!(listed[1].upstream_id, "phihub");

    store
        .bindings()
        .mark_needs_reauth(
            &first.id,
            "upstream_401",
            &fact(AuditAction::BindingNeedsReauth, 1_200, "binding"),
            1_200,
        )
        .await
        .expect("mark needs reauth");
    let needs_reauth = store
        .bindings()
        .find(&user.id, "phigros")
        .await
        .expect("find needs reauth")
        .expect("binding kept");
    assert_eq!(needs_reauth.status, BindingStatus::NeedsReauth);
    assert_eq!(
        needs_reauth.last_error_code.as_deref(),
        Some("upstream_401")
    );

    let sealed = SealedSecret::new(
        1,
        vec![0x10; 12],
        vec![0x33; 44],
        vec![0x11; 12],
        vec![0x22; 32],
    )
    .expect("sealed secret");
    store
        .bindings()
        .store_sub_credential(&first.id, &sealed, 1_250)
        .await
        .expect("store sub credential");
    assert_eq!(
        store
            .bindings()
            .load_sub_credential(&first.id)
            .await
            .expect("load sub credential"),
        Some(sealed.clone())
    );
    assert!(
        matches!(
            store
                .bindings()
                .store_sub_credential(&BindingId::new(), &sealed, 1_250)
                .await,
            Err(RepoError::NotFound)
        ),
        "a sealed credential requires an existing binding"
    );

    // Re-wrapping is a compare-and-swap on the envelope. This is what lets a
    // rotation be re-run: a record that moved on (another rotation, or a fresh
    // enrol) reports `false` instead of being overwritten with stale bytes.
    let rewrapped = SealedSecret::new(
        2,
        vec![0x10; 12],
        vec![0x44; 44],
        vec![0x11; 12],
        vec![0x22; 32],
    )
    .expect("rewrapped envelope");

    assert!(
        store
            .bindings()
            .rewrap_sub_credential(&first.id, &sealed, &rewrapped, 1_260)
            .await
            .expect("rewrap"),
        "the matching envelope is swapped"
    );
    assert_eq!(
        store
            .bindings()
            .load_sub_credential(&first.id)
            .await
            .expect("load after rewrap"),
        Some(rewrapped.clone()),
        "the payload survives the swap untouched"
    );
    assert!(
        !store
            .bindings()
            .rewrap_sub_credential(&first.id, &sealed, &rewrapped, 1_270)
            .await
            .expect("second rewrap"),
        "a stale expectation must report a miss, not overwrite the newer envelope"
    );
    assert_eq!(
        store
            .bindings()
            .load_sub_credential(&first.id)
            .await
            .expect("load after missed rewrap"),
        Some(rewrapped.clone()),
        "a missed swap leaves the record exactly as it was"
    );

    store
        .bindings()
        .revoke(
            &first.id,
            &fact(AuditAction::BindingRevoked, 1_300, "binding"),
            1_300,
        )
        .await
        .expect("revoke binding");
    assert_eq!(
        store
            .bindings()
            .load_sub_credential(&first.id)
            .await
            .expect("load after revoke"),
        None
    );
    let revoked = store
        .bindings()
        .find(&user.id, "phigros")
        .await
        .expect("find revoked")
        .expect("binding kept");
    assert_eq!(revoked.status, BindingStatus::Revoked);
    assert!(matches!(
        store
            .bindings()
            .mark_needs_reauth(
                &BindingId::new(),
                "missing",
                &fact(AuditAction::BindingNeedsReauth, 1_400, "binding"),
                1_400
            )
            .await,
        Err(RepoError::NotFound)
    ));

    // The batch killswitch: one transaction, every non-revoked binding of this
    // user, and nothing belonging to anyone else.
    let other_user = User {
        id: UserId::new(),
        display_name: "contract-user-2".to_string(),
        role: UserRole::User,
        created_at: 1_500,
        updated_at: 1_500,
    };
    store
        .users()
        .create(&other_user)
        .await
        .expect("create other user");
    let other = binding(
        other_user.id,
        BindingId::new(),
        BindingStatus::Active,
        1_500,
    );
    store
        .bindings()
        .upsert(&other, &fact(AuditAction::BindingCreated, 1_500, "binding"))
        .await
        .expect("other binding");
    let sealed_second = SealedSecret::new(
        1,
        vec![0x12; 12],
        vec![0x34; 44],
        vec![0x13; 12],
        vec![0x24; 32],
    )
    .expect("sealed secret");
    store
        .bindings()
        .store_sub_credential(&second.id, &sealed_second, 1_450)
        .await
        .expect("store second credential");

    let revoked_count = store
        .bindings()
        .revoke_all(
            &user.id,
            &fact(AuditAction::BindingRevoked, 1_500, "binding"),
            1_500,
        )
        .await
        .expect("revoke all");
    assert_eq!(
        revoked_count, 1,
        "only the still-active binding moves; the already-revoked one is skipped"
    );
    assert_eq!(
        store
            .bindings()
            .load_sub_credential(&second.id)
            .await
            .expect("load second after killswitch"),
        None,
        "the killswitch deletes every credential it covers"
    );
    assert_eq!(
        store
            .bindings()
            .find(&user.id, "phihub")
            .await
            .expect("find second")
            .expect("second kept")
            .status,
        BindingStatus::Revoked
    );
    assert_eq!(
        store
            .bindings()
            .find(&other_user.id, "phigros")
            .await
            .expect("find other")
            .expect("other kept")
            .status,
        BindingStatus::Active,
        "another user's binding must not be touched"
    );

    // Idempotent: a retry after an uncertain response reports zero, not an error.
    let again = store
        .bindings()
        .revoke_all(
            &user.id,
            &fact(AuditAction::BindingRevoked, 1_600, "binding"),
            1_600,
        )
        .await
        .expect("revoke all again");
    assert_eq!(again, 0);

    // Anonymization clears the upstream account identity from bindings revoked
    // long enough ago, leaves newer revocations and active bindings alone, and
    // is idempotent.
    let anonymized = store
        .bindings()
        .anonymize_revoked_before(1_400)
        .await
        .expect("anonymize");
    assert_eq!(
        anonymized, 1,
        "only the binding revoked at 1_300 is older than the 1_400 window"
    );
    assert_eq!(
        store
            .bindings()
            .find(&user.id, "phigros")
            .await
            .expect("find phigros")
            .expect("kept")
            .upstream_user_id,
        ANONYMIZED_UPSTREAM_USER_ID,
        "the upstream account identity must be gone"
    );
    assert_eq!(
        store
            .bindings()
            .find(&user.id, "phihub")
            .await
            .expect("find phihub")
            .expect("kept")
            .upstream_user_id,
        "upstream-user",
        "a revocation newer than the window is untouched"
    );
    assert_eq!(
        store
            .bindings()
            .find(&other_user.id, "phigros")
            .await
            .expect("find other")
            .expect("other kept")
            .upstream_user_id,
        "upstream-user",
        "an active binding is never anonymized"
    );
    let anonymized_again = store
        .bindings()
        .anonymize_revoked_before(1_400)
        .await
        .expect("anonymize again");
    assert_eq!(anonymized_again, 0, "a second sweep reports zero");

    assert!(store.users().delete(&user.id).await.expect("delete user"));
    assert_eq!(
        store
            .bindings()
            .find(&user.id, "phigros")
            .await
            .expect("binding after cascade"),
        None
    );
    assert_eq!(
        store
            .bindings()
            .find(&user.id, "phihub")
            .await
            .expect("second binding after cascade"),
        None
    );
}
