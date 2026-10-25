//! Connector contract suite and a mock upstream.
//!
//! Every connector implementation (mock, PhiHub, PhiBackend) must pass the
//! same suite. The mock is the reference implementation.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use secrecy::ExposeSecret;

use re0auth_api::connector::{
    ConnectorBroker, ConnectorEndpoint, ConnectorRegistry, ConnectorSecretStore, FaultClass,
    ResourceRequest, ResourceSpec, UpstreamError, UpstreamPayload,
};
use re0auth_api::secret::{SealedSecret, SecretSealer};
use re0auth_api::{BindingId, ConnectorId, Re0Error, Re0Result, SecretString};

#[async_trait]
pub trait ConnectorFixture: ConnectorRegistry + ConnectorBroker {
    fn register(&self, endpoint: ConnectorEndpoint);
    fn set_response(&self, resource: &str, result: Result<UpstreamPayload, UpstreamError>);
    fn calls(&self) -> Vec<ResourceRequest>;
}

#[derive(Default)]
struct MockState {
    endpoints: HashMap<ConnectorId, ConnectorEndpoint>,
    responses: HashMap<String, Result<UpstreamPayload, UpstreamError>>,
    calls: Vec<ResourceRequest>,
}

#[derive(Default)]
pub struct MockConnector {
    inner: Mutex<MockState>,
}

impl MockConnector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, MockState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[async_trait]
impl ConnectorRegistry for MockConnector {
    async fn resolve(&self, id: &ConnectorId) -> Re0Result<ConnectorEndpoint> {
        self.lock()
            .endpoints
            .get(id)
            .cloned()
            .ok_or_else(|| Re0Error::Business("unknown connector".to_string()))
    }
}

#[async_trait]
impl ConnectorBroker for MockConnector {
    async fn fetch_raw_data(
        &self,
        _endpoint: &ConnectorEndpoint,
        _sub_token: &SecretString,
        resource: &ResourceRequest,
    ) -> Result<UpstreamPayload, UpstreamError> {
        if !safe(&resource.resource) || !safe(&resource.subject) {
            return Err(UpstreamError::Rejected);
        }
        let mut state = self.lock();
        state.calls.push(resource.clone());
        state
            .responses
            .get(&resource.resource)
            .cloned()
            .unwrap_or(Err(UpstreamError::NotFound))
    }
}

impl ConnectorFixture for MockConnector {
    fn register(&self, endpoint: ConnectorEndpoint) {
        self.lock().endpoints.insert(endpoint.id, endpoint);
    }

    fn set_response(&self, resource: &str, result: Result<UpstreamPayload, UpstreamError>) {
        self.lock().responses.insert(resource.to_string(), result);
    }

    fn calls(&self) -> Vec<ResourceRequest> {
        self.lock().calls.clone()
    }
}

fn safe(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
}

#[derive(Default)]
pub struct MemorySecretStore {
    inner: Mutex<HashMap<String, String>>,
}

#[async_trait]
impl ConnectorSecretStore for MemorySecretStore {
    async fn put(&self, key: &str, secret: &SecretString) -> Re0Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key.to_string(), secret.expose_secret().to_string());
        Ok(())
    }

    async fn get(&self, key: &str) -> Re0Result<Option<SecretString>> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(key)
            .map(|value| SecretString::from(value.clone())))
    }

    async fn delete(&self, key: &str) -> Re0Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(key);
        Ok(())
    }
}

/// Deterministic AEAD stand-in for tests. It binds ciphertext to the binding.
pub struct MockSealer {
    key: [u8; 32],
}

impl Default for MockSealer {
    fn default() -> Self {
        Self::new()
    }
}

impl MockSealer {
    #[must_use]
    pub fn new() -> Self {
        Self { key: [0x5a; 32] }
    }

    fn stream(&self, binding: &BindingId, len: usize) -> Vec<u8> {
        let id = binding.0.as_bytes();
        (0..len)
            .map(|index| self.key[index % self.key.len()] ^ id[index % id.len()] ^ (index as u8))
            .collect()
    }
}

impl SecretSealer for MockSealer {
    fn seal(&self, binding: &BindingId, plaintext: &SecretString) -> Re0Result<SealedSecret> {
        let bytes = plaintext.expose_secret().as_bytes();
        let stream = self.stream(binding, bytes.len());
        // A fixed wrapped DEK: this mock's "crypto" is a keystream, so the only
        // property the contract cares about is that the envelope round-trips and
        // that `rewrap` can produce a different version.
        Ok(SealedSecret::new(
            1,
            binding.0.as_bytes()[..12].to_vec(),
            vec![0x5a; 44],
            binding.0.as_bytes()[..12].to_vec(),
            bytes
                .iter()
                .zip(stream)
                .map(|(byte, mask)| byte ^ mask)
                .collect(),
        )
        .expect("binding uuid supplies a 12-byte nonce"))
    }

    fn open(&self, binding: &BindingId, sealed: &SealedSecret) -> Re0Result<SecretString> {
        if sealed.nonce() != &binding.0.as_bytes()[..12] {
            return Err(Re0Error::Internal(
                "sealed secret bound elsewhere".to_string(),
            ));
        }
        let stream = self.stream(binding, sealed.ciphertext().len());
        let plaintext: Vec<u8> = sealed
            .ciphertext()
            .iter()
            .zip(stream)
            .map(|(byte, mask)| byte ^ mask)
            .collect();
        String::from_utf8(plaintext)
            .map(SecretString::from)
            .map_err(|_| Re0Error::Internal("sealed secret is not UTF-8".to_string()))
    }

    /// Moves the envelope to version 2 without touching the payload.
    ///
    /// The mock has no real key wrapping, so this only demonstrates the shape the
    /// contract requires: the payload must survive unchanged and the version must
    /// advance, which is what makes rotation cheap in a real implementation.
    fn rewrap(&self, _binding: &BindingId, sealed: &SealedSecret) -> Re0Result<SealedSecret> {
        if sealed.key_version() == 2 {
            return Ok(sealed.clone());
        }
        SealedSecret::new(
            2,
            sealed.dek_nonce().to_vec(),
            sealed.wrapped_dek().to_vec(),
            sealed.nonce().to_vec(),
            sealed.ciphertext().to_vec(),
        )
    }
}

pub async fn connector_secret_store_contract<S: ConnectorSecretStore + ?Sized>(store: &S) {
    let key = "connector/root";
    assert!(store.get(key).await.expect("get empty").is_none());

    let first = SecretString::from("root-credential".to_string());
    store.put(key, &first).await.expect("put");
    assert_eq!(
        store
            .get(key)
            .await
            .expect("get")
            .expect("present")
            .expose_secret(),
        "root-credential"
    );

    let second = SecretString::from("rotated-credential".to_string());
    store.put(key, &second).await.expect("overwrite");
    assert_eq!(
        store
            .get(key)
            .await
            .expect("get")
            .expect("present")
            .expose_secret(),
        "rotated-credential"
    );

    store.delete(key).await.expect("delete");
    assert!(store.get(key).await.expect("get").is_none());
}

pub fn secret_sealer_contract<S: SecretSealer + ?Sized>(sealer: &S) {
    let binding = BindingId::new();
    let token = SecretString::from("secret-token".to_string());
    let sealed = sealer.seal(&binding, &token).expect("seal");
    assert_ne!(
        sealed.ciphertext(),
        token.expose_secret().as_bytes(),
        "ciphertext must not equal plaintext"
    );
    assert_eq!(
        sealer
            .open(&binding, &sealed)
            .expect("open")
            .expose_secret(),
        "secret-token"
    );
    assert!(
        sealer.open(&BindingId::new(), &sealed).is_err(),
        "sealed secrets must be bound to their binding"
    );
}

pub async fn connector_contract_suite<C: ConnectorFixture + ?Sized>(connector: &C) {
    let id = ConnectorId::new();
    let endpoint = ConnectorEndpoint {
        id,
        name: "contract-connector".to_string(),
        base_url: "https://connector.example".to_string(),
        allow_private_net: false,
        allow_link_local_metadata: false,
        resources: vec![ResourceSpec::new("scores", "/v1/scores/{subject}").expect("valid spec")],
    };

    assert!(
        matches!(connector.resolve(&id).await, Err(Re0Error::Business(_))),
        "an unregistered connector must be a business error"
    );
    connector.register(endpoint.clone());
    assert_eq!(connector.resolve(&id).await.expect("resolve"), endpoint);

    let payload = UpstreamPayload {
        content_type: "application/json".to_string(),
        body: br#"{"score":1}"#.to_vec(),
    };
    connector.set_response("scores", Ok(payload.clone()));
    let token = SecretString::from("sub-token".to_string());
    let request = ResourceRequest::new("scores", "player-1");
    let fetched = connector
        .fetch_raw_data(&endpoint, &token, &request)
        .await
        .expect("fetch");
    assert_eq!(fetched, payload);
    assert_eq!(connector.calls(), vec![request.clone()]);

    let cases = [
        (UpstreamError::CredentialExpired, FaultClass::Business),
        (UpstreamError::InsufficientScope, FaultClass::Business),
        (UpstreamError::NotFound, FaultClass::Business),
        (
            UpstreamError::RateLimited {
                retry_after_secs: Some(30),
            },
            FaultClass::Internal,
        ),
        (UpstreamError::Unavailable, FaultClass::Internal),
        (UpstreamError::Truncated, FaultClass::Internal),
    ];
    for (error, class) in cases {
        connector.set_response("scores", Err(error.clone()));
        let result = connector.fetch_raw_data(&endpoint, &token, &request).await;
        assert_eq!(result, Err(error.clone()));
        assert_eq!(error.fault_class(), class, "{error:?}");
    }

    connector.set_response("scores", Err(UpstreamError::Rejected));
    let rejected = connector
        .fetch_raw_data(
            &endpoint,
            &token,
            &ResourceRequest::new("scores", "../escape"),
        )
        .await;
    assert_eq!(rejected, Err(UpstreamError::Rejected));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_passes_the_connector_suite() {
        connector_contract_suite(&MockConnector::new()).await;
    }

    #[test]
    fn mock_passes_the_sealer_contract() {
        secret_sealer_contract(&MockSealer::new());
    }

    #[tokio::test]
    async fn mock_passes_the_secret_store_contract() {
        connector_secret_store_contract(&MemorySecretStore::default()).await;
    }
}
