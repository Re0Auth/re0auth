//! What a rotation does at its edges.
//!
//! The interesting cases are not "it re-wraps a record" — that is one line — but
//! the readings an operator acts on: whether an empty store counts as a clean
//! run, and whether a record that moved on mid-scan is a failure.

use std::sync::Arc;

use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::ports::{Binding, BindingStatus, Storage};
use re0auth_api::secret::{SealedSecret, SecretSealer};
use re0auth_api::{BindingId, Re0Error, Re0Result, SecretString, UserId};
use re0auth_contract::memory::MemoryStore;

use re0auth_app::rotation::{RotationReport, rotate_credentials};

/// A sealer that only knows the current version, mirroring a steady-state
/// deployment. Anything claiming another version fails, which is what makes the
/// "operator forgot to declare a retired key" case observable.
struct CurrentOnly;

impl SecretSealer for CurrentOnly {
    fn seal(&self, _binding: &BindingId, _plaintext: &SecretString) -> Re0Result<SealedSecret> {
        // The payload is irrelevant here: these tests care about the envelope and
        // the bookkeeping that decides whether an operator may drop an old key.
        Ok(SealedSecret::new(1, vec![1; 12], vec![2; 44], vec![3; 12], Vec::new()).expect("shape"))
    }

    fn open(&self, _binding: &BindingId, sealed: &SealedSecret) -> Re0Result<SecretString> {
        Ok(SecretString::from(
            String::from_utf8_lossy(sealed.ciphertext()).to_string(),
        ))
    }

    /// Moves version 1 to version 2. Version 2 is current, so it comes back
    /// unchanged — that is how a caller tells a no-op from a re-wrap.
    fn rewrap(&self, _binding: &BindingId, sealed: &SealedSecret) -> Re0Result<SealedSecret> {
        match sealed.key_version() {
            1 => Ok(SealedSecret::new(
                2,
                sealed.dek_nonce().to_vec(),
                vec![9; 44],
                sealed.nonce().to_vec(),
                sealed.ciphertext().to_vec(),
            )
            .expect("shape")),
            2 => Ok(sealed.clone()),
            other => Err(Re0Error::Internal(format!(
                "no encryption key is configured for version {other}; \
                 declare it as a retired key and run the rotation again"
            ))),
        }
    }
}

/// A sealer that refuses every record, standing in for one whose retired key was
/// not declared.
struct KnowsNothing;

impl SecretSealer for KnowsNothing {
    fn seal(&self, binding: &BindingId, plaintext: &SecretString) -> Re0Result<SealedSecret> {
        CurrentOnly.seal(binding, plaintext)
    }
    fn open(&self, binding: &BindingId, sealed: &SealedSecret) -> Re0Result<SecretString> {
        CurrentOnly.open(binding, sealed)
    }
    fn rewrap(&self, _binding: &BindingId, sealed: &SealedSecret) -> Re0Result<SealedSecret> {
        Err(Re0Error::Internal(format!(
            "no encryption key is configured for version {}",
            sealed.key_version()
        )))
    }
}

/// Creates `count` bindings and returns the store plus their ids.
///
/// A credential cannot be stored without a binding to hang off, and that is the
/// same constraint the rotation lives under — it walks bindings, never orphans.
async fn seeded_store(count: usize) -> (Arc<MemoryStore>, Vec<BindingId>) {
    let store = Arc::new(MemoryStore::new());
    let mut ids = Vec::with_capacity(count);
    for index in 0..count {
        let owner = UserId::new();
        store
            .users()
            .create(&re0auth_api::ports::User {
                id: owner,
                display_name: format!("rotation-user-{index}"),
                role: re0auth_api::ports::UserRole::User,
                created_at: 1_000,
                updated_at: 1_000,
            })
            .await
            .expect("insert user");
        let id = BindingId::new();
        let binding = Binding {
            id,
            user_id: owner,
            upstream_id: format!("upstream-{index}"),
            upstream_user_id: format!("subject-{index}"),
            status: BindingStatus::Active,
            created_at: 1_000,
            updated_at: 1_000,
            last_refreshed_at: None,
            last_error_code: None,
        };
        let fact = SecurityFact::new(AuditAction::BindingCreated, 1_000, "binding");
        store
            .bindings()
            .upsert(&binding, &fact)
            .await
            .expect("upsert");
        ids.push(id);
    }
    (store, ids)
}

#[tokio::test]
async fn an_empty_store_is_not_a_clean_rotation() {
    let store = MemoryStore::new();
    let report = rotate_credentials(&store, &CurrentOnly, 2_000)
        .await
        .expect("rotate");

    assert!(report.empty, "the store held nothing");
    assert_eq!(report.rewrapped, 0);
    assert!(
        !report.is_clean(),
        "an empty run reads identically to a finished one, so it must not \
         authorise dropping the retired key"
    );
    assert!(
        report.summary().contains("nothing was rotated"),
        "the summary must say why this is not a success: {}",
        report.summary()
    );
}

#[tokio::test]
async fn a_declared_key_re_wraps_and_reports_clean() {
    let (store, ids) = seeded_store(1).await;
    let id = ids[0];

    store
        .bindings()
        .store_sub_credential(
            &id,
            &SealedSecret::new(1, vec![1; 12], vec![2; 44], vec![3; 12], vec![4; 8])
                .expect("shape"),
            1_000,
        )
        .await
        .expect("store");

    let report = rotate_credentials(store.as_ref(), &CurrentOnly, 2_000)
        .await
        .expect("rotate");
    assert_eq!(report.rewrapped, 1);
    assert!(report.failed.is_empty());
    assert!(report.is_clean(), "one migrated record is a clean run");

    let after = store
        .bindings()
        .load_sub_credential(&id)
        .await
        .expect("load")
        .expect("present");
    assert_eq!(after.key_version(), 2, "the record moved onto the new key");
    assert_eq!(
        after.ciphertext(),
        &[4u8; 8],
        "the payload must not be touched by a rotation"
    );
}

#[tokio::test]
async fn an_undeclared_version_is_a_failure_not_a_skip() {
    let (store, ids) = seeded_store(1).await;
    let id = ids[0];
    store
        .bindings()
        .store_sub_credential(
            &id,
            &SealedSecret::new(1, vec![1; 12], vec![2; 44], vec![3; 12], vec![4; 8])
                .expect("shape"),
            1_000,
        )
        .await
        .expect("store");

    let report = rotate_credentials(store.as_ref(), &KnowsNothing, 2_000)
        .await
        .expect("rotate");
    assert_eq!(report.failed.len(), 1, "the record is counted, not ignored");
    assert!(
        report.failed[0].1.contains("version 1"),
        "the reason names the version the operator has to declare: {}",
        report.failed[0].1
    );
    assert!(
        !report.is_clean(),
        "a record that could not be migrated must block dropping the old key"
    );
}

#[tokio::test]
async fn a_record_that_moved_mid_scan_is_not_a_failure() {
    let (store, ids) = seeded_store(1).await;
    let id = ids[0];
    let original =
        SealedSecret::new(1, vec![1; 12], vec![2; 44], vec![3; 12], vec![4; 8]).expect("shape");
    store
        .bindings()
        .store_sub_credential(&id, &original, 1_000)
        .await
        .expect("store");

    // Someone re-wrote the record between the scan and the swap.
    let fresher =
        SealedSecret::new(2, vec![5; 12], vec![6; 44], vec![7; 12], vec![8; 8]).expect("shape");
    assert!(
        store
            .bindings()
            .rewrap_sub_credential(&id, &original, &fresher, 1_500)
            .await
            .expect("swap")
    );

    // Scanning now sees the fresher value, so this rotation is a no-op for it.
    let report = rotate_credentials(store.as_ref(), &CurrentOnly, 2_000)
        .await
        .expect("rotate");
    assert_eq!(report.already_current, 1);
    assert_eq!(report.rewrapped, 0);
    assert!(report.moved_on == 0, "the value read was already current");
    assert!(report.is_clean());
}

#[tokio::test]
async fn the_report_never_calls_an_empty_run_clean() {
    let empty = RotationReport {
        empty: true,
        ..RotationReport::default()
    };
    assert!(!empty.is_clean());

    let done = RotationReport {
        rewrapped: 3,
        empty: false,
        ..RotationReport::default()
    };
    assert!(done.is_clean());
    assert!(done.summary().contains("rewrapped=3"));
}
