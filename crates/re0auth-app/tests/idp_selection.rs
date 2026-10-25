//! INV-IDP-01: a login is bound to the provider it started against, and the
//! callback follows that binding rather than anything the caller supplies.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use re0auth_api::Clock;
use re0auth_api::idp::{IdpClient, IdpError, IdpIdentity};
use re0auth_api::oauth::{AccessTokenClaims, ApprovalTicketClaims, IdTokenClaims, TokenSigner};
use re0auth_api::{Random, Re0Result};
use re0auth_app::auth::{AuthError, AuthService, NamedIdp};
use re0auth_contract::MemoryStore;

/// Deterministic stand-in: the paths under test only need distinct bytes.
struct CounterRandom(AtomicUsize);

impl Random for CounterRandom {
    fn bytes(&self, len: usize) -> Vec<u8> {
        let seed = self.0.fetch_add(1, Ordering::SeqCst) as u8;
        vec![seed; len]
    }
}

struct FixedClock(i64);

impl Clock for FixedClock {
    fn now(&self) -> i64 {
        self.0
    }
}

/// Never reached by the paths under test. Panicking keeps that explicit: if a
/// login starts signing tokens, this test should fail loudly rather than pass.
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

struct CountingIdp {
    name: &'static str,
    exchanges: Arc<AtomicUsize>,
    fails: bool,
}

#[async_trait::async_trait]
impl IdpClient for CountingIdp {
    fn authorization_url(&self, state: &str, _nonce: &str, _challenge: &str) -> String {
        format!("https://{}.example/authorize?state={state}", self.name)
    }

    async fn exchange_code(
        &self,
        _code: &str,
        _verifier: &str,
        _nonce: &str,
    ) -> Result<IdpIdentity, IdpError> {
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        if self.fails {
            return Err(IdpError::Protocol("wrong provider".to_string()));
        }
        Ok(IdpIdentity {
            issuer: format!("https://{}.example", self.name),
            subject: format!("subject-{}", self.name),
            display_name: "Alice".to_string(),
        })
    }
}

struct Harness {
    service: AuthService,
    first: Arc<AtomicUsize>,
    second: Arc<AtomicUsize>,
}

async fn harness() -> Harness {
    let first = Arc::new(AtomicUsize::new(0));
    let second = Arc::new(AtomicUsize::new(0));
    let idps = vec![
        NamedIdp {
            name: "first".to_string(),
            client: Arc::new(CountingIdp {
                name: "first",
                exchanges: Arc::clone(&first),
                fails: false,
            }),
        },
        NamedIdp {
            name: "second".to_string(),
            client: Arc::new(CountingIdp {
                name: "second",
                exchanges: Arc::clone(&second),
                fails: true,
            }),
        },
    ];
    let service = AuthService::new(
        Arc::new(MemoryStore::new()),
        idps,
        Arc::new(UnusedSigner),
        Arc::new(FixedClock(1_000)),
        Arc::new(CounterRandom(AtomicUsize::new(0))),
        "https://issuer.example",
    );
    Harness {
        service,
        first,
        second,
    }
}

fn state_of(url: &str) -> String {
    let parsed = url::Url::parse(url).expect("authorization url");
    parsed
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .expect("state parameter")
}

#[tokio::test]
async fn several_providers_require_an_explicit_choice() {
    let harness = harness().await;
    match harness.service.start_login("/", None).await {
        Err(AuthError::IdentityProviderRequired) => {}
        other => panic!("expected IdentityProviderRequired, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unknown_provider_name_is_refused() {
    let harness = harness().await;
    for name in ["nope", "First", "first-2"] {
        match harness.service.start_login("/", Some(name)).await {
            Err(AuthError::UnknownIdentityProvider) => {}
            other => panic!("{name}: expected UnknownIdentityProvider, got {other:?}"),
        }
    }
}

/// A padded selector resolves to the same provider. Trimming is deliberate: it
/// keeps a hand-edited link or a stray space from turning a valid name into an
/// error, and cannot select a different provider than the exact name would.
#[tokio::test]
async fn a_padded_selector_resolves_to_the_same_provider() {
    let harness = harness().await;
    for name in [" first", "first ", "\tfirst\n"] {
        let start = harness
            .service
            .start_login("/", Some(name))
            .await
            .unwrap_or_else(|error| panic!("{name:?}: {error:?}"));
        assert!(start.url.starts_with("https://first.example/authorize"));
    }
}

/// The core assertion: a login started against the second provider must
/// exchange there. Starting against the first would pass even if the callback
/// ignored the binding, so the non-default provider is the discriminating case.
#[tokio::test]
async fn the_callback_uses_the_provider_recorded_at_start() {
    let harness = harness().await;
    let start = harness
        .service
        .start_login("/", Some("second"))
        .await
        .expect("start");
    assert!(start.url.starts_with("https://second.example/authorize"));

    // `second` is wired to fail its exchange, so a success here also proves the
    // callback did not silently pick the first provider.
    match harness
        .service
        .complete_login("code", &state_of(&start.url))
        .await
    {
        Err(AuthError::Idp(IdpError::Protocol(message))) => {
            assert_eq!(message, "wrong provider");
        }
        other => panic!("expected the second provider's failure, got {other:?}"),
    }
    assert_eq!(harness.second.load(Ordering::SeqCst), 1);
    assert_eq!(
        harness.first.load(Ordering::SeqCst),
        0,
        "the other configured provider must not be contacted"
    );
}

/// `complete_login` takes no provider argument at all. This test documents the
/// consequence: a transaction bound to a provider that has since disappeared
/// must fail rather than fall back to whichever provider happens to be first.
#[tokio::test]
async fn a_vanished_provider_does_not_fall_back_to_the_first() {
    let first = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(MemoryStore::new());
    let with_both = AuthService::new(
        store.clone(),
        vec![
            NamedIdp {
                name: "first".to_string(),
                client: Arc::new(CountingIdp {
                    name: "first",
                    exchanges: Arc::clone(&first),
                    fails: false,
                }),
            },
            NamedIdp {
                name: "second".to_string(),
                client: Arc::new(CountingIdp {
                    name: "second",
                    exchanges: Arc::new(AtomicUsize::new(0)),
                    fails: false,
                }),
            },
        ],
        Arc::new(UnusedSigner),
        Arc::new(FixedClock(1_000)),
        Arc::new(CounterRandom(AtomicUsize::new(0))),
        "https://issuer.example",
    );
    let start = with_both
        .start_login("/", Some("second"))
        .await
        .expect("start");
    let state = state_of(&start.url);

    // Same storage, but the provider that this login was bound to is gone.
    let only_first = AuthService::new(
        store,
        vec![NamedIdp {
            name: "first".to_string(),
            client: Arc::new(CountingIdp {
                name: "first",
                exchanges: Arc::clone(&first),
                fails: false,
            }),
        }],
        Arc::new(UnusedSigner),
        Arc::new(FixedClock(1_000)),
        Arc::new(CounterRandom(AtomicUsize::new(0))),
        "https://issuer.example",
    );
    match only_first.complete_login("code", &state).await {
        Err(AuthError::UnknownIdentityProvider) => {}
        other => panic!("expected UnknownIdentityProvider, got {other:?}"),
    }
    assert_eq!(
        first.load(Ordering::SeqCst),
        0,
        "must not silently log the user in through a different provider"
    );
}
