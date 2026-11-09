use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use secrecy::ExposeSecret;

use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::connector::{
    ConnectorEndpoint, ConnectorRefresh, EgressPolicy, RefreshedCredential, UpstreamError,
};
use re0auth_api::ports::{Binding, BindingStatus, Storage, User, UserRole, UserStatus};
use re0auth_api::secret::SecretSealer;
use re0auth_api::{BindingId, Clock, SecretString, UserId};
use re0auth_app::credentials::{BindingCredentialService, CredentialSource, StoredCredential};
use re0auth_contract::{MemoryStore, MockConnector, MockSealer};

struct FixedClock(i64);

impl Clock for FixedClock {
    fn now(&self) -> i64 {
        self.0
    }
}

struct FakeRefresh {
    calls: AtomicUsize,
}

#[async_trait]
impl ConnectorRefresh for FakeRefresh {
    async fn refresh_token(
        &self,
        _endpoint: &ConnectorEndpoint,
        refresh_token: &SecretString,
    ) -> Result<Option<RefreshedCredential>, UpstreamError> {
        assert_eq!(refresh_token.expose_secret(), "refresh-token");
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(RefreshedCredential {
            credential: SecretString::from("fresh-token"),
            refresh_token: Some(SecretString::from("next-refresh")),
            expires_in: Some(3_600),
            refresh_expires_in: Some(86_400),
        }))
    }
}

#[tokio::test]
async fn provider_refreshes_near_expiry_and_cas_writes_the_bundle() {
    let now = 1_000;
    let store = Arc::new(MemoryStore::new());
    let user = UserId::new();
    store
        .users()
        .create(&User {
            id: user,
            display_name: "provider".to_string(),
            role: UserRole::User,
            status: UserStatus::Active,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("user");

    let binding = Binding {
        id: BindingId::new(),
        user_id: user,
        upstream_id: "phihub".to_string(),
        upstream_user_id: "player-1".to_string(),
        status: BindingStatus::Active,
        created_at: now,
        updated_at: now,
        last_refreshed_at: None,
        last_error_code: None,
    };
    let fact = SecurityFact::new(AuditAction::BindingCreated, now, "binding");
    store
        .bindings()
        .upsert(&binding, &fact)
        .await
        .expect("binding");

    let sealer = Arc::new(MockSealer::new());
    let initial = StoredCredential::from_exchange(
        &re0auth_api::connector::ExchangedCredential {
            credential: SecretString::from("stale-token"),
            refresh_token: Some(SecretString::from("refresh-token")),
            expires_in: Some(1),
            refresh_expires_in: Some(600),
            subject: "player-1".to_string(),
        },
        now,
    );
    let sealed = sealer
        .seal(&binding.id, &SecretString::from(initial.encode()))
        .expect("seal");
    store
        .bindings()
        .store_sub_credential(&binding.id, &sealed, now)
        .await
        .expect("store");

    let connector = Arc::new(MockConnector::new());
    let endpoint = ConnectorEndpoint {
        id: re0auth_app::gateway::connector_id_for_name("phihub"),
        name: "phihub".to_string(),
        base_url: "https://phib19.top:8080".to_string(),
        egress: EgressPolicy::Public,
        resources: Vec::new(),
    };
    re0auth_contract::ConnectorFixture::register(connector.as_ref(), endpoint);
    let refresh = Arc::new(FakeRefresh {
        calls: AtomicUsize::new(0),
    });
    let provider = BindingCredentialService::new(
        store.clone(),
        connector,
        refresh.clone(),
        sealer.clone(),
        Arc::new(FixedClock(now)),
    );

    let token = provider.access_token(&binding).await.expect("refresh");
    assert_eq!(token.expose_secret(), "fresh-token");
    assert_eq!(refresh.calls.load(Ordering::SeqCst), 1);

    let reloaded = store
        .bindings()
        .load_sub_credential(&binding.id)
        .await
        .expect("load")
        .expect("credential");
    let raw = sealer.open(&binding.id, &reloaded).expect("open");
    let stored = StoredCredential::decode(&raw);
    assert_eq!(stored.access_secret().expose_secret(), "fresh-token");

    // A second read uses the stored access token; it does not refresh again.
    let token = provider.access_token(&binding).await.expect("cached");
    assert_eq!(token.expose_secret(), "fresh-token");
    assert_eq!(refresh.calls.load(Ordering::SeqCst), 1);
}
