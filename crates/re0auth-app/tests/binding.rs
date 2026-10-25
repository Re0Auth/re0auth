//! What binding orchestration must get right.
//!
//! Each test here corresponds to a way this feature is commonly built wrong:
//! echoing `return_to` from the callback, trusting the state alone to name the
//! user, and letting a re-bind look identical to a fresh bind in the audit trail.

use std::sync::Arc;

use async_trait::async_trait;
use re0auth_api::connector::{
    ConnectorAuth, ConnectorEndpoint, ConnectorRegistry, ExchangedCredential, UpstreamError,
};
use re0auth_api::ports::{BindingStatus, Storage, User, UserRole};
use re0auth_api::secret::{SealedSecret, SecretSealer};
use re0auth_api::{
    BindingId, Clock, ConnectorId, Random, Re0Error, Re0Result, SecretString, Unix, UserId,
};
use re0auth_contract::memory::MemoryStore;

use re0auth_app::binding::{BindingError, BindingService};
use re0auth_app::return_to::{self, FALLBACK};

const NOW: Unix = 10_000;

struct FixedClock(Unix);
impl Clock for FixedClock {
    fn now(&self) -> Unix {
        self.0
    }
}

/// Deterministic bytes, so a behaviour can be reproduced.
///
/// The counter matters: a fixed value would make two `start` calls produce the
/// same state, and the second would collide on the primary key. That is a real
/// constraint on the flow (states must be unique), not a quirk of this double.
struct CountingRandom(std::sync::atomic::AtomicU8);
impl Random for CountingRandom {
    fn bytes(&self, len: usize) -> Vec<u8> {
        let value = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut out = vec![0x11; len];
        if let Some(first) = out.first_mut() {
            *first = value;
        }
        out
    }
}

struct OneConnector(ConnectorEndpoint);

#[async_trait]
impl ConnectorRegistry for OneConnector {
    async fn resolve(&self, id: &ConnectorId) -> Re0Result<ConnectorEndpoint> {
        if *id == self.0.id {
            Ok(self.0.clone())
        } else {
            Err(Re0Error::Business("unknown connector".to_string()))
        }
    }
}

fn endpoint() -> ConnectorEndpoint {
    ConnectorEndpoint {
        // Derived from the name, exactly as production does: the resolver is
        // keyed by the derived id, and a test that made one up would pass while
        // the real lookup failed.
        id: re0auth_app::gateway::connector_id_for_name("phigros"),
        name: "phigros".to_string(),
        base_url: "https://api.example.test".to_string(),
        allow_private_net: false,
        allow_link_local_metadata: false,
        resources: Vec::new(),
    }
}

/// Records what the service asked for and returns a fixed credential.
struct RecordingAuth {
    last_challenge: std::sync::Mutex<Option<String>>,
    exchange_error: Option<&'static str>,
}

impl RecordingAuth {
    fn ok() -> Self {
        Self {
            last_challenge: std::sync::Mutex::new(None),
            exchange_error: None,
        }
    }

    fn rejecting() -> Self {
        Self {
            last_challenge: std::sync::Mutex::new(None),
            exchange_error: Some("code expired"),
        }
    }
}

#[async_trait]
impl ConnectorAuth for RecordingAuth {
    fn authorization_url(
        &self,
        endpoint: &ConnectorEndpoint,
        state: &str,
        _redirect_uri: &str,
        pkce_challenge: Option<&str>,
    ) -> Result<String, UpstreamError> {
        *self.last_challenge.lock().expect("lock") = pkce_challenge.map(str::to_string);
        Ok(format!(
            "{}/authorize?state={state}&challenge={}",
            endpoint.base_url,
            pkce_challenge.unwrap_or("none")
        ))
    }

    async fn exchange_code(
        &self,
        _endpoint: &ConnectorEndpoint,
        _code: &str,
        _redirect_uri: &str,
        _pkce_verifier: Option<&str>,
    ) -> Result<ExchangedCredential, UpstreamError> {
        if self.exchange_error.is_some() {
            return Err(UpstreamError::Rejected);
        }
        Ok(ExchangedCredential {
            credential: SecretString::from("upstream-token".to_string()),
            // Deliberately not the local user id: this is the value the gateway
            // will address every later read by, and a test that reused the local
            // id would pass on the old defect.
            subject: UPSTREAM_SUBJECT.to_string(),
        })
    }
}

/// The upstream account the mock credential speaks for.
const UPSTREAM_SUBJECT: &str = "upstream-player-42";

/// A sealer that stores the payload verbatim; these tests are about the flow,
/// not about cryptography.
struct PlainSealer;

impl SecretSealer for PlainSealer {
    fn seal(&self, _binding: &BindingId, _plaintext: &SecretString) -> Re0Result<SealedSecret> {
        Ok(SealedSecret::new(1, vec![1; 12], vec![2; 44], vec![3; 12], Vec::new()).expect("shape"))
    }

    fn open(&self, _binding: &BindingId, sealed: &SealedSecret) -> Re0Result<SecretString> {
        Ok(SecretString::from(
            String::from_utf8_lossy(sealed.ciphertext()).to_string(),
        ))
    }

    fn rewrap(&self, _binding: &BindingId, sealed: &SealedSecret) -> Re0Result<SealedSecret> {
        Ok(sealed.clone())
    }
}

async fn setup(auth: RecordingAuth) -> (Arc<MemoryStore>, BindingService, UserId) {
    let store = Arc::new(MemoryStore::new());
    let user = UserId::new();
    store
        .users()
        .create(&User {
            id: user,
            display_name: "binder".to_string(),
            role: UserRole::User,
            created_at: NOW,
            updated_at: NOW,
        })
        .await
        .expect("user");

    let endpoint = endpoint();
    let service = BindingService::new(
        store.clone(),
        Arc::new(OneConnector(endpoint)),
        Arc::new(auth),
        Arc::new(PlainSealer),
        Arc::new(FixedClock(NOW)),
        Arc::new(CountingRandom(std::sync::atomic::AtomicU8::new(1))),
        "https://auth.example.test/bind/callback",
    );
    (store, service, user)
}

#[test]
fn the_service_reports_what_can_be_bound() {
    // The portal's connect button is fed from this list; an empty one would leave
    // it with nothing to offer, and a made-up one would send users to a connector
    // we cannot redeem.
    let store = Arc::new(MemoryStore::new());
    let service = BindingService::new(
        store,
        Arc::new(OneConnector(endpoint())),
        Arc::new(RecordingAuth::ok()),
        Arc::new(PlainSealer),
        Arc::new(FixedClock(NOW)),
        Arc::new(CountingRandom(std::sync::atomic::AtomicU8::new(1))),
        "https://auth.example.test/bind/callback",
    )
    .with_bindable_upstreams(vec!["phigros".to_string()]);
    assert_eq!(service.bindable_upstreams(), ["phigros".to_string()]);
}

#[tokio::test]
async fn a_start_sends_pkce_and_records_the_flow() {
    let auth = RecordingAuth::ok();
    let (store, service, user) = setup(auth).await;

    let started = service
        .start(user, "phigros", "/account")
        .await
        .expect("start");
    assert!(
        started.authorization_url.contains(&started.state),
        "the upstream must receive the state we will match on"
    );

    // The state is stored hashed: a leaked row must not be replayable.
    let consumed = store
        .pending_bindings()
        .consume(
            &re0auth_domain::pkce::sha256(started.state.as_bytes()),
            NOW + 1,
        )
        .await
        .expect("the flow is stored under the hash of the state");
    assert_eq!(consumed.user_id, user);
    assert_eq!(consumed.upstream_id, "phigros");
    assert!(
        !consumed.pkce_verifier.is_empty(),
        "an OAuth2 upstream needs a verifier to redeem the code"
    );
}

#[tokio::test]
async fn completing_a_flow_creates_the_binding() {
    let (store, service, user) = setup(RecordingAuth::ok()).await;
    let started = service
        .start(user, "phigros", "/account")
        .await
        .expect("start");

    let done = service
        .complete(user, &started.state, "code")
        .await
        .expect("complete");
    assert!(!done.rebound, "there was nothing to replace");
    assert_eq!(done.binding.status, BindingStatus::Active);
    assert_eq!(done.return_to, "/account");

    let listed = store.bindings().list_by_user(&user).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0].upstream_user_id, UPSTREAM_SUBJECT,
        "the binding must name the upstream account, not ours: every later read \
         is addressed by this value, so filling it from the local user id would \
         make the gateway ask the source about the wrong player"
    );
    assert_ne!(
        listed[0].upstream_user_id,
        user.0.to_string(),
        "the local user id is not an upstream identity"
    );
    assert!(
        store
            .bindings()
            .load_sub_credential(&listed[0].id)
            .await
            .expect("load")
            .is_some(),
        "the credential must be stored, or the binding is useless"
    );
}

/// INV-BIND-04: completing a flow is session-bound, not state-bound.
///
/// The direction that matters here is the one the old comment missed: a visitor
/// who is handed someone else's authorization URL must not be able to attach the
/// account they authorize to the flow's starter.
#[tokio::test]
async fn complete_from_another_user_is_refused() {
    let (store, service, user) = setup(RecordingAuth::ok()).await;
    let started = service
        .start(user, "phigros", "/account")
        .await
        .expect("start");
    let other = UserId::new();

    let refused = service.complete(other, &started.state, "code").await;
    assert!(
        matches!(refused, Err(BindingError::FlowNotValid)),
        "another session must not be able to claim the flow: {refused:?}"
    );
    assert!(
        store
            .bindings()
            .list_by_user(&user)
            .await
            .expect("list")
            .is_empty(),
        "the starter must not end up with the account the other user authorized"
    );
    assert!(
        store
            .bindings()
            .list_by_user(&other)
            .await
            .expect("list")
            .is_empty(),
        "the other user must not end up with a binding either"
    );
}

#[tokio::test]
async fn a_replayed_state_cannot_bind_twice() {
    let (store, service, user) = setup(RecordingAuth::ok()).await;
    let started = service
        .start(user, "phigros", "/account")
        .await
        .expect("start");
    service
        .complete(user, &started.state, "code")
        .await
        .expect("first");

    let second = service.complete(user, &started.state, "code").await;
    assert!(
        matches!(second, Err(BindingError::FlowNotValid)),
        "a consumed state must not open a second binding: {second:?}"
    );
    assert_eq!(
        store
            .bindings()
            .list_by_user(&user)
            .await
            .expect("list")
            .len(),
        1
    );
}

#[tokio::test]
async fn a_rejected_code_does_not_leave_a_binding() {
    let (store, service, user) = setup(RecordingAuth::rejecting()).await;
    let started = service
        .start(user, "phigros", "/account")
        .await
        .expect("start");

    let done = service.complete(user, &started.state, "stale").await;
    assert!(
        matches!(done, Err(BindingError::UpstreamRejected(_))),
        "an upstream refusal is a business error, not an outage: {done:?}"
    );
    assert!(
        store
            .bindings()
            .list_by_user(&user)
            .await
            .expect("list")
            .is_empty(),
        "a failed exchange must not leave a usable binding behind"
    );
}

#[tokio::test]
async fn rebinding_keeps_the_id_and_says_so() {
    let (store, service, user) = setup(RecordingAuth::ok()).await;

    let first = service
        .start(user, "phigros", "/account")
        .await
        .expect("start");
    let created = service
        .complete(user, &first.state, "code-1")
        .await
        .expect("first");

    let second = service
        .start(user, "phigros", "/account")
        .await
        .expect("start");
    let replaced = service
        .complete(user, &second.state, "code-2")
        .await
        .expect("second");

    assert!(
        replaced.rebound,
        "switching accounts must be reported as a re-bind, not a fresh bind"
    );
    assert_eq!(
        replaced.binding.id, created.binding.id,
        "the binding id survives, so the credential hanging off it does too"
    );
    assert_eq!(
        store
            .bindings()
            .list_by_user(&user)
            .await
            .expect("list")
            .len(),
        1
    );
}

#[tokio::test]
async fn an_unknown_connector_fails_before_a_flow_exists() {
    let (store, service, user) = setup(RecordingAuth::ok()).await;
    let result = service.start(user, "not-configured", "/account").await;
    assert!(matches!(result, Err(BindingError::UnknownConnector)));

    let consumed = store.pending_bindings().consume(&[0x00; 32], NOW + 1).await;
    assert!(
        consumed.is_err(),
        "no flow may be recorded for a connector we cannot redeem"
    );
}

#[test]
fn return_to_is_confined_to_local_paths() {
    for good in [
        "/account",
        "/account?tab=bindings",
        "/oauth/authorize?client_id=x",
        // Same origin: the `://` is inside the query, not the redirect target.
        "/path?next=https://evil.example",
    ] {
        assert_eq!(return_to::or_fallback(good), good);
    }
    for bad in [
        "",
        "account",
        "//evil.example",
        "https://evil.example/",
        "/\\evil.example",
        // A browser strips tab before parsing, so this resolves as `//evil.example`.
        "/\t/evil.example",
        "/\n/evil.example",
    ] {
        assert_eq!(
            return_to::or_fallback(bad),
            FALLBACK,
            "{bad:?} must not become a redirect target"
        );
    }
}
