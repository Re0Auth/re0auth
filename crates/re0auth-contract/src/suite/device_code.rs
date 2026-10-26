//! Device authorization contract (RFC 8628).

use super::{client, device_code, fact, user};
use re0auth_api::audit::AuditAction;
use re0auth_api::ports::{DeviceCodeState, DevicePoll, RepoError, Storage};

pub async fn device_code_contract<S: Storage>(store: &S) {
    let now = 1_000;
    let user = user(now);
    let client = client(now);
    store.users().create(&user).await.expect("create user");
    store
        .clients()
        .insert(&client, &fact(AuditAction::ClientCreated, now, "client"))
        .await
        .expect("create client");

    let code = device_code(0x10, client.id, 2_000);
    store
        .device_codes()
        .insert(&code)
        .await
        .expect("insert device code");
    assert_eq!(
        store
            .device_codes()
            .find_by_device_hash(&code.device_code_hash)
            .await
            .expect("find device code"),
        Some(code.clone())
    );
    assert_eq!(
        store
            .device_codes()
            .find_by_user_code_hash(&code.user_code_hash)
            .await
            .expect("find user code"),
        Some(code.clone())
    );
    assert!(matches!(
        store.device_codes().insert(&code).await,
        Err(RepoError::UserCodeConflict)
    ));

    // The two unique columns mean different things to the caller: a user code is
    // redrawn, a device code is not. The store has to say which one collided, and
    // SQLite reports one unnamed violation for the statement, so this is the case
    // that proves the label is recovered correctly rather than guessed.
    let mut reused_user_code = device_code(0x20, client.id, 2_000);
    reused_user_code.user_code_hash = code.user_code_hash.clone();
    assert!(matches!(
        store.device_codes().insert(&reused_user_code).await,
        Err(RepoError::UserCodeConflict)
    ));

    let mut reused_device_code = device_code(0x30, client.id, 2_000);
    reused_device_code.device_code_hash = code.device_code_hash.clone();
    assert!(
        matches!(
            store.device_codes().insert(&reused_device_code).await,
            Err(RepoError::Conflict(_))
        ),
        "a device-code collision is not something the caller can redraw"
    );

    assert_eq!(
        store
            .device_codes()
            .poll(&code.device_code_hash, 1_000)
            .await
            .expect("first poll"),
        DevicePoll::Pending
    );
    assert_eq!(
        store
            .device_codes()
            .poll(&code.device_code_hash, 1_002)
            .await
            .expect("fast poll"),
        DevicePoll::SlowDown { interval_secs: 10 }
    );
    assert_eq!(
        store
            .device_codes()
            .poll(&code.device_code_hash, 1_012)
            .await
            .expect("poll after slow down"),
        DevicePoll::Pending
    );

    store
        .device_codes()
        .approve(&code.user_code_hash, user.id, 1_013)
        .await
        .expect("approve");
    assert_eq!(
        store
            .device_codes()
            .poll(&code.device_code_hash, 1_014)
            .await
            .expect("approved poll"),
        DevicePoll::Approved {
            client_id: client.id,
            user_id: user.id,
            scopes: vec!["phigros.stats.read".to_string()],
        }
    );
    assert_eq!(
        store
            .device_codes()
            .poll(&code.device_code_hash, 1_015)
            .await
            .expect("second poll"),
        DevicePoll::Consumed
    );

    // 只拒绝该用户在该 client 下的已批准设备码
    let revocable = device_code(0x40, client.id, 3_000);
    let other_user = super::user(1_000);
    store.users().create(&other_user).await.expect("other user");
    let other_user_code = device_code(0x50, client.id, 3_000);
    let other_client = super::client(1_000);
    store
        .clients()
        .insert(
            &other_client,
            &fact(AuditAction::ClientCreated, 1_000, "other-client"),
        )
        .await
        .expect("other client");
    let other_client_code = device_code(0x60, other_client.id, 3_000);
    for pending in [&revocable, &other_user_code, &other_client_code] {
        store
            .device_codes()
            .insert(pending)
            .await
            .expect("insert approved candidate");
    }
    store
        .device_codes()
        .approve(&revocable.user_code_hash, user.id, 1_010)
        .await
        .expect("approve revocable");
    store
        .device_codes()
        .approve(&other_user_code.user_code_hash, other_user.id, 1_010)
        .await
        .expect("approve other user");
    store
        .device_codes()
        .approve(&other_client_code.user_code_hash, user.id, 1_010)
        .await
        .expect("approve other client");

    assert_eq!(
        store
            .device_codes()
            .revoke_approved_for_client(&user.id, &client.id)
            .await
            .expect("revoke approved device codes"),
        1
    );
    assert_eq!(
        store
            .device_codes()
            .poll(&revocable.device_code_hash, 1_020)
            .await
            .expect("revoked poll"),
        DevicePoll::Denied
    );
    assert_eq!(
        store
            .device_codes()
            .find_by_device_hash(&other_user_code.device_code_hash)
            .await
            .expect("find other user code")
            .expect("other user code exists")
            .state,
        DeviceCodeState::Approved {
            approver: other_user.id
        }
    );
    assert_eq!(
        store
            .device_codes()
            .find_by_device_hash(&other_client_code.device_code_hash)
            .await
            .expect("find other client code")
            .expect("other client code exists")
            .state,
        DeviceCodeState::Approved { approver: user.id }
    );

    store.users().delete(&user.id).await.expect("delete user");
    assert!(
        store
            .device_codes()
            .find_by_device_hash(&code.device_code_hash)
            .await
            .expect("find after cascade")
            .is_none()
    );

    let denied = device_code(0x20, client.id, 2_000);
    store
        .device_codes()
        .insert(&denied)
        .await
        .expect("insert denied code");
    store
        .device_codes()
        .deny(&denied.user_code_hash, 1_001)
        .await
        .expect("deny");
    assert_eq!(
        store
            .device_codes()
            .poll(&denied.device_code_hash, 1_002)
            .await
            .expect("denied poll"),
        DevicePoll::Denied
    );

    let expired = device_code(0x30, client.id, 1_000);
    store
        .device_codes()
        .insert(&expired)
        .await
        .expect("insert expired code");
    assert_eq!(
        store
            .device_codes()
            .poll(&expired.device_code_hash, 1_000)
            .await
            .expect("expired poll"),
        DevicePoll::Expired
    );
    assert_eq!(
        store
            .device_codes()
            .poll(&[0xff; 32], 1_000)
            .await
            .expect("missing poll"),
        DevicePoll::NotFound
    );

    let purged = store
        .device_codes()
        .purge_expired(2_000)
        .await
        .expect("purge device codes");
    assert!(purged >= 1, "purge should remove expired rows");
}
