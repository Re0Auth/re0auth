//! A real rotation, not a fake sealer: v1 data must survive the move to v2 and
//! be readable only by a process that holds both keys.

use std::sync::Arc;

use re0auth_adapters::random::OsRandom;
use re0auth_adapters::sealer::AesGcmSealer;
use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::ports::{Binding, BindingStatus, Storage};
use re0auth_api::secret::SecretSealer;
use re0auth_api::{BindingId, SecretString, UserId};
use re0auth_app::rotation::rotate_credentials;
use re0auth_contract::MemoryStore;
use secrecy::ExposeSecret;

const V1: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const V2: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

async fn binding_with_v1_secret(sealer: &AesGcmSealer) -> (Arc<MemoryStore>, BindingId) {
    let store = Arc::new(MemoryStore::new());
    let user = UserId::new();
    store
        .users()
        .create(&re0auth_api::ports::User {
            id: user,
            display_name: "rotation".to_string(),
            role: re0auth_api::ports::UserRole::User,
            created_at: 1_000,
            updated_at: 1_000,
        })
        .await
        .expect("user");
    let id = BindingId::new();
    store
        .bindings()
        .upsert(
            &Binding {
                id,
                user_id: user,
                upstream_id: "upstream".to_string(),
                upstream_user_id: "subject".to_string(),
                status: BindingStatus::Active,
                created_at: 1_000,
                updated_at: 1_000,
                last_refreshed_at: None,
                last_error_code: None,
            },
            &SecurityFact::new(AuditAction::BindingCreated, 1_000, "binding"),
        )
        .await
        .expect("binding");
    let sealed = sealer
        .seal(&id, &SecretString::from("upstream-token".to_string()))
        .expect("seal v1");
    store
        .bindings()
        .store_sub_credential(&id, &sealed, 1_000)
        .await
        .expect("credential");
    (store, id)
}

#[tokio::test]
async fn a_real_v1_credential_is_rewrapped_and_stays_readable_under_v2() {
    let old = AesGcmSealer::new(V1, Arc::new(OsRandom)).expect("v1");
    let (store, id) = binding_with_v1_secret(&old).await;

    let rotated = AesGcmSealer::with_keys(2, [(1, V1), (2, V2)], Arc::new(OsRandom))
        .expect("v2 with retired v1");
    let before = store
        .bindings()
        .load_sub_credential(&id)
        .await
        .expect("load")
        .expect("present");
    assert_eq!(before.key_version(), 1);
    assert_eq!(
        rotated.open(&id, &before).expect("open v1").expose_secret(),
        "upstream-token"
    );

    let report = rotate_credentials(store.as_ref(), &rotated, 2_000)
        .await
        .expect("rotate");
    assert_eq!(report.rewrapped, 1);
    assert!(report.is_clean());

    let after = store
        .bindings()
        .load_sub_credential(&id)
        .await
        .expect("load")
        .expect("present");
    assert_eq!(after.key_version(), 2);
    assert_eq!(
        rotated.open(&id, &after).expect("open v2").expose_secret(),
        "upstream-token"
    );
    assert!(
        old.open(&id, &after).is_err(),
        "dropping v1 must make the re-wrapped record unreadable to a v1-only process"
    );
}
