//! INV-CACHE-02: revoking a binding sweeps its cached responses.
//!
//! Drives the real `AuthService::revoke_binding`, not the store directly, so the
//! test covers the line that performs the sweep. A version that revoked the
//! binding but forgot the cache passes every other test in the suite and fails
//! only here.

use std::sync::Arc;
use std::time::Duration;

use re0auth_api::cache::{Cache, CachedResponse, key};
use re0auth_api::oauth::{AccessTokenClaims, ApprovalTicketClaims, IdTokenClaims, TokenSigner};
use re0auth_api::ports::{Binding, BindingStatus, Storage, User, UserRole};
use re0auth_api::{BindingId, Clock, Random, Re0Result, UserId};
use re0auth_app::auth::AuthService;
use re0auth_contract::{ClockedCache, MemoryCache, MemoryStore};

struct FixedClock(i64);

impl Clock for FixedClock {
    fn now(&self) -> i64 {
        self.0
    }
}

struct ZeroRandom;

impl Random for ZeroRandom {
    fn bytes(&self, len: usize) -> Vec<u8> {
        vec![7; len]
    }
}

struct UnusedSigner;

impl TokenSigner for UnusedSigner {
    fn sign_access(&self, _: &AccessTokenClaims) -> Re0Result<String> {
        panic!("not used")
    }
    fn sign_id(&self, _: &IdTokenClaims) -> Re0Result<String> {
        panic!("not used")
    }
    fn sign_approval_ticket(&self, _: &ApprovalTicketClaims) -> Re0Result<String> {
        panic!("not used")
    }
    fn verify_access(&self, _: &str) -> Re0Result<AccessTokenClaims> {
        panic!("not used")
    }
    fn verify_approval_ticket(&self, _: &str) -> Re0Result<ApprovalTicketClaims> {
        panic!("not used")
    }
    fn jwks(&self) -> String {
        panic!("not used")
    }
}

struct Fixture {
    auth: AuthService,
    cache: Arc<ClockedCache>,
    store: Arc<MemoryStore>,
    user: UserId,
    binding: Binding,
}

async fn fixture() -> Fixture {
    let now = 1_000;
    let store = Arc::new(MemoryStore::new());
    let user = UserId::new();
    store
        .users()
        .create(&User {
            id: user,
            display_name: "cache-user".to_string(),
            role: UserRole::User,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("user");

    let binding = Binding {
        id: BindingId::new(),
        user_id: user,
        upstream_id: "phigros".to_string(),
        upstream_user_id: "player-1".to_string(),
        status: BindingStatus::Active,
        created_at: now,
        updated_at: now,
        last_refreshed_at: None,
        last_error_code: None,
    };
    store
        .bindings()
        .upsert(
            &binding,
            &re0auth_api::audit::SecurityFact::new(
                re0auth_api::audit::AuditAction::BindingCreated,
                now,
                format!("binding:{}", binding.id.0),
            ),
        )
        .await
        .expect("binding");
    store
        .bindings()
        .store_sub_credential(
            &binding.id,
            &re0auth_api::secret::SealedSecret::new(
                1,
                vec![0; 12],
                vec![0; 44],
                vec![0; 12],
                vec![0; 16],
            )
            .expect("sealed"),
            now,
        )
        .await
        .expect("credential");

    let clock = Arc::new(FixedClock(now));
    let cache = Arc::new(ClockedCache::new(MemoryCache::new(), clock.clone()));
    let auth = AuthService::new(
        store.clone(),
        vec![],
        Arc::new(UnusedSigner),
        clock,
        Arc::new(ZeroRandom),
        "https://issuer.test",
    )
    .with_cache(Arc::clone(&cache) as Arc<dyn Cache>);

    Fixture {
        auth,
        cache,
        store,
        user,
        binding,
    }
}

async fn warm(cache: &ClockedCache, binding: &Binding) {
    for resource in ["scores", "profile"] {
        cache
            .put(
                &key(&binding.id, "phigros", resource),
                &CachedResponse {
                    content_type: "application/json".to_string(),
                    body: format!(r#"{{"resource":"{resource}"}}"#).into_bytes(),
                    stale: false,
                },
                Duration::from_secs(300),
            )
            .await;
    }
}

#[tokio::test]
async fn revoking_a_binding_sweeps_its_cached_responses() {
    let f = fixture().await;
    warm(&f.cache, &f.binding).await;
    assert_eq!(
        f.cache.len(),
        2,
        "the fixture must actually cache something"
    );

    f.auth
        .revoke_binding(f.user, f.binding.id, None)
        .await
        .expect("revoke");

    assert_eq!(
        f.cache.len(),
        0,
        "the revoke did not sweep the binding's cached responses; they would keep being served"
    );
    for resource in ["scores", "profile"] {
        assert!(
            f.cache
                .get_any(&key(&f.binding.id, "phigros", resource))
                .await
                .is_none(),
            "resource {resource} survived the revoke"
        );
    }
}

#[tokio::test]
async fn revoking_leaves_other_bindings_cached() {
    // A sweep that dropped everything would pass the test above and wipe the
    // whole cache on every unbind, which is a denial of service on the cache.
    let f = fixture().await;
    let other = BindingId::new();
    let other_key = key(&other, "phigros", "scores");
    f.cache
        .put(
            &other_key,
            &CachedResponse {
                content_type: "application/json".to_string(),
                body: b"someone-else".to_vec(),
                stale: false,
            },
            Duration::from_secs(300),
        )
        .await;
    warm(&f.cache, &f.binding).await;

    f.auth
        .revoke_binding(f.user, f.binding.id, None)
        .await
        .expect("revoke");

    assert!(
        f.cache.get_any(&other_key).await.is_some(),
        "an unrelated binding lost its cache because of someone else's revoke"
    );
    // And the sweep really did scope to the revoked binding.
    assert!(
        !f.cache
            .get_any(&key(&f.binding.id, "phigros", "scores"))
            .await
            .is_some()
    );
    assert_eq!(f.cache.len(), 1);
}

#[tokio::test]
async fn the_binding_is_actually_revoked_in_storage() {
    // Guards the test above: if `revoke_binding` silently did nothing, the
    // cache would be empty for the wrong reason.
    let f = fixture().await;
    f.auth
        .revoke_binding(f.user, f.binding.id, None)
        .await
        .expect("revoke");
    let stored = f
        .store
        .bindings()
        .find(&f.user, "phigros")
        .await
        .expect("find")
        .expect("binding row");
    assert_eq!(stored.status, BindingStatus::Revoked);
    assert!(
        f.store
            .bindings()
            .load_sub_credential(&f.binding.id)
            .await
            .expect("credential")
            .is_none(),
        "the sealed credential must be gone too"
    );
}

#[tokio::test]
async fn a_failed_revoke_does_not_empty_the_cache() {
    // Sweeping before confirming the write would drop entries for a binding
    // that is still active, forcing an unnecessary upstream call.
    let f = fixture().await;
    warm(&f.cache, &f.binding).await;
    let stranger = UserId::new();
    let outcome = f.auth.revoke_binding(stranger, f.binding.id, None).await;
    assert!(outcome.is_err(), "a non-owner must not revoke");
    assert_eq!(
        f.cache.len(),
        2,
        "a refused revoke must leave the cache untouched"
    );
}
