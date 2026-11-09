//! Token-path baselines: what one code exchange, refresh, device poll and
//! gateway token verification cost, split by the work they share.
//!
//! The store is a real `SqliteStore`, so the numbers include the SQL round
//! trips the service really performs. Everything runs against an in-memory
//! database with one connection, which keeps the measurement about query
//! count and cryptography rather than disk latency.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use re0auth_adapters::client_secret::HmacClientSecretHasher;
use re0auth_adapters::crypto::RsaTokenSigner;
use re0auth_adapters::random::OsRandom;
use re0auth_adapters::storage::SqliteStore;
use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::oauth::{ACCESS_TOKEN_USE, AccessTokenClaims, ConsentVersion, TokenSigner};
use re0auth_api::ports::{
    AuthCode, Client, ClientStatus, Consent, DeviceCode, DeviceCodeState, RefreshToken, Storage,
    User, UserRole, UserStatus,
};
use re0auth_api::{
    AuthCodeId, ClientId, Clock, ConsentId, DeviceCodeId, FamilyId, RefreshTokenId, Unix, UserId,
};
use re0auth_app::oauth::{OAuthService, hash_secret};
use re0auth_domain::pkce;
use tokio::runtime::Runtime;

const ISSUER: &str = "https://auth.example.com";
const MASTER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const REDIRECT: &str = "https://client.example/callback";
const VERIFIER: &str = "verifier-0123456789-0123456789-0123456789-0123456789";
const DEVICE_CODE: &str = "device-code-under-benchmark";
const NOW: Unix = 1_000_000;

struct FixedClock(Unix);

impl Clock for FixedClock {
    fn now(&self) -> Unix {
        self.0
    }
}

/// Advances exactly one advertised interval per read, so a pending device poll
/// never falls into the slow-down branch.
struct StepClock(AtomicI64);

impl Clock for StepClock {
    fn now(&self) -> Unix {
        self.0.fetch_add(5, Ordering::Relaxed)
    }
}

fn fact(action: AuditAction) -> SecurityFact {
    SecurityFact::new(action, NOW, "bench")
}

async fn seed_user_and_client(store: &SqliteStore) -> (UserId, ClientId) {
    let user = User {
        id: UserId::new(),
        display_name: "bench".to_string(),
        role: UserRole::User,
        status: UserStatus::Active,
        created_at: NOW,
        updated_at: NOW,
    };
    store.users().create(&user).await.expect("seed user");

    let client = Client {
        id: ClientId::new(),
        name: "bench-client".to_string(),
        redirect_uris: vec![REDIRECT.to_string()],
        allowed_scopes: vec!["openid".to_string(), "profile".to_string()],
        raw_access: false,
        status: ClientStatus::Approved,
        secret_hash: None,
        created_at: NOW,
        updated_at: NOW,
    };
    store
        .clients()
        .insert(&client, &fact(AuditAction::ClientCreated))
        .await
        .expect("seed client");

    let consent = Consent {
        id: ConsentId::new(),
        user_id: user.id,
        client_id: client.id,
        scopes: vec!["openid".to_string(), "profile".to_string()],
        created_at: NOW,
        updated_at: NOW,
        revoked_at: None,
        version: ConsentVersion(0),
    };
    store
        .consents()
        .grant(&consent, &fact(AuditAction::ConsentGranted))
        .await
        .expect("seed consent");

    (user.id, client.id)
}

async fn seed_auth_code(store: &SqliteStore, user: UserId, client: ClientId, raw: &str) {
    let code = AuthCode {
        id: AuthCodeId::new(),
        code_hash: hash_secret(raw),
        client_id: client,
        user_id: user,
        redirect_uri: REDIRECT.to_string(),
        scopes: vec!["openid".to_string(), "profile".to_string()],
        code_challenge: Some(pkce::challenge_s256(VERIFIER)),
        code_challenge_method: Some("S256".to_string()),
        nonce: None,
        auth_time: NOW,
        created_at: NOW,
        expires_at: NOW + 10_000_000,
        consumed_at: None,
        family_id: None,
    };
    store
        .auth_codes()
        .insert(&code, &fact(AuditAction::AuthCodeIssued))
        .await
        .expect("seed auth code");
}

async fn seed_refresh_token(store: &SqliteStore, user: UserId, client: ClientId, raw: &str) {
    let token = RefreshToken {
        id: RefreshTokenId::new(),
        token_hash: hash_secret(raw),
        family_id: FamilyId::new(),
        client_id: client,
        user_id: user,
        scopes: vec!["openid".to_string(), "profile".to_string()],
        created_at: NOW,
        family_created_at: NOW,
        auth_time: NOW,
        expires_at: NOW + 10_000_000,
        consumed_at: None,
        revoked_at: None,
        replaced_by: None,
    };
    store
        .refresh_tokens()
        .insert(&token)
        .await
        .expect("seed refresh token");
}

async fn seed_device_code(store: &SqliteStore, client: ClientId) {
    let code = DeviceCode {
        id: DeviceCodeId::new(),
        device_code_hash: hash_secret(DEVICE_CODE),
        user_code_hash: hash_secret("BENCH-CODE"),
        client_id: client,
        scopes: vec!["openid".to_string()],
        state: DeviceCodeState::Pending,
        interval_secs: 5,
        last_polled_at: None,
        poll_count: 0,
        user_code_misses: 0,
        created_at: NOW,
        expires_at: NOW + 10_000_000,
        consumed_at: None,
        family_id: None,
    };
    store
        .device_codes()
        .insert(&code)
        .await
        .expect("seed device code");
}

struct Fixture {
    runtime: Runtime,
    store: SqliteStore,
    fixed: Arc<OAuthService>,
    step: Arc<OAuthService>,
    signer: Arc<dyn TokenSigner>,
    user: UserId,
    client: ClientId,
    access_token: String,
}

fn build() -> Fixture {
    let runtime = Runtime::new().expect("tokio runtime");
    let store = runtime
        .block_on(SqliteStore::connect("sqlite::memory:"))
        .expect("sqlite store");

    let key_path = std::env::temp_dir().join(format!("re0auth-bench-{}.pem", uuid::Uuid::now_v7()));
    let signer: Arc<dyn TokenSigner> =
        Arc::new(RsaTokenSigner::load_or_generate(&key_path, ISSUER, NOW, &[]).expect("signer"));

    let fixed = Arc::new(OAuthService::new(
        Arc::new(store.clone()),
        signer.clone(),
        Arc::new(FixedClock(NOW)),
        Arc::new(OsRandom),
        Arc::new(HmacClientSecretHasher::new(MASTER).expect("hasher")),
        ISSUER,
    ));
    let step = Arc::new(OAuthService::new(
        Arc::new(store.clone()),
        signer.clone(),
        Arc::new(StepClock(AtomicI64::new(NOW))),
        Arc::new(OsRandom),
        Arc::new(HmacClientSecretHasher::new(MASTER).expect("hasher")),
        ISSUER,
    ));

    let (user, client) = runtime.block_on(seed_user_and_client(&store));
    runtime.block_on(seed_device_code(&store, client));
    runtime.block_on(seed_auth_code(&store, user, client, "seed-code"));
    let response = runtime
        .block_on(fixed.exchange_code(client, None, "seed-code", REDIRECT, VERIFIER))
        .expect("seed exchange");

    Fixture {
        runtime,
        store,
        fixed,
        step,
        signer,
        user,
        client,
        access_token: response.access_token,
    }
}

fn benches(c: &mut Criterion) {
    let fixture = build();
    let rt = &fixture.runtime;
    let store = fixture.store.clone();
    let counter = Arc::new(AtomicU64::new(0));

    let mut group = c.benchmark_group("token_paths");
    group.sample_size(30);
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(3));

    group.bench_function("exchange_code", |b| {
        let counter = counter.clone();
        let store = store.clone();
        let svc = fixture.fixed.clone();
        let client = fixture.client;
        let user = fixture.user;
        b.to_async(rt).iter_custom(move |iters| {
            let counter = counter.clone();
            let store = store.clone();
            let svc = svc.clone();
            async move {
                let mut elapsed = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let n = counter.fetch_add(1, Ordering::Relaxed);
                    let raw = format!("code-{n}");
                    seed_auth_code(&store, user, client, &raw).await;
                    let start = std::time::Instant::now();
                    let response = svc
                        .exchange_code(client, None, &raw, REDIRECT, VERIFIER)
                        .await;
                    elapsed += start.elapsed();
                    black_box(response.is_ok());
                }
                elapsed
            }
        });
    });

    group.bench_function("refresh", |b| {
        let counter = counter.clone();
        let store = store.clone();
        let svc = fixture.fixed.clone();
        let client = fixture.client;
        let user = fixture.user;
        b.to_async(rt).iter_custom(move |iters| {
            let counter = counter.clone();
            let store = store.clone();
            let svc = svc.clone();
            async move {
                let mut elapsed = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let n = counter.fetch_add(1, Ordering::Relaxed);
                    let raw = format!("refresh-{n}");
                    seed_refresh_token(&store, user, client, &raw).await;
                    let start = std::time::Instant::now();
                    let response = svc.refresh(client, None, &raw, None, None).await;
                    elapsed += start.elapsed();
                    black_box(response.is_ok());
                }
                elapsed
            }
        });
    });

    group.bench_function("device_poll_pending", |b| {
        let svc = fixture.step.clone();
        let client = fixture.client;
        b.to_async(rt).iter(|| {
            let svc = svc.clone();
            async move {
                let outcome = svc
                    .exchange_device_code(client, None, DEVICE_CODE, None)
                    .await;
                black_box(outcome.is_err())
            }
        });
    });

    let token = fixture.access_token.clone();
    group.bench_function("verify_gateway_token", |b| {
        let svc = fixture.fixed.clone();
        b.to_async(rt).iter(|| {
            let svc = svc.clone();
            let token = token.clone();
            async move {
                let outcome = svc.verify_gateway_token(&token).await;
                black_box(outcome.is_ok())
            }
        });
    });

    let claims = AccessTokenClaims {
        iss: ISSUER.to_string(),
        sub: fixture.user.0.to_string(),
        aud: format!("{ISSUER}/api/v1"),
        client_id: fixture.client.0.to_string(),
        scope: "openid profile".to_string(),
        exp: NOW + 900,
        iat: NOW,
        jti: "bench-jti".to_string(),
        token_use: ACCESS_TOKEN_USE.to_string(),
        family_id: FamilyId::new().0.to_string(),
        consent_version: ConsentVersion(0),
    };
    let signer = fixture.signer.clone();
    group.bench_function("sign_access", |b| {
        let signer = signer.clone();
        let claims = claims.clone();
        b.iter(|| black_box(signer.sign_access(&claims).is_ok()));
    });

    group.finish();
}

criterion_group!(benches_group, benches);
criterion_main!(benches_group);
