//! Upstream credential bundles and on-demand refresh.
//!
//! The gateway asks this module for a usable access token. Refresh is kept here
//! so the read path never reaches a connector's token-minting code directly.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use async_trait::async_trait;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use re0auth_api::connector::{
    ConnectorRefresh, ConnectorRegistry, ExchangedCredential, RefreshedCredential, UpstreamError,
};
use re0auth_api::ports::{Binding, Storage};
use re0auth_api::secret::{SealedSecret, SecretSealer};
use re0auth_api::{BindingId, Clock, SecretString, Unix};

use crate::gateway::connector_id_for_name;

const BUNDLE_VERSION: u8 = 1;
const REFRESH_SKEW_SECS: Unix = 300;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredCredential {
    #[serde(rename = "v", default)]
    version: u8,
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    access_expires_at: Option<Unix>,
    #[serde(default)]
    refresh_expires_at: Option<Unix>,
}

impl StoredCredential {
    #[must_use]
    pub fn decode(raw: &SecretString) -> Self {
        let text = raw.expose_secret();
        if let Ok(stored) = serde_json::from_str::<Self>(text)
            && stored.version == BUNDLE_VERSION
        {
            return stored;
        }
        // Legacy rows stored the access token as the whole sealed payload.
        Self {
            version: 0,
            access_token: text.to_string(),
            refresh_token: None,
            access_expires_at: None,
            refresh_expires_at: None,
        }
    }

    #[must_use]
    pub fn encode(&self) -> String {
        serde_json::to_string(self).expect("credential bundle serialises")
    }

    #[must_use]
    pub fn from_exchange(exchanged: &ExchangedCredential, now: Unix) -> Self {
        Self {
            version: BUNDLE_VERSION,
            access_token: exchanged.credential.expose_secret().to_string(),
            refresh_token: exchanged
                .refresh_token
                .as_ref()
                .map(|token| token.expose_secret().to_string()),
            access_expires_at: exchanged.expires_in.map(|ttl| now + ttl as Unix),
            refresh_expires_at: exchanged.refresh_expires_in.map(|ttl| now + ttl as Unix),
        }
    }

    #[must_use]
    pub fn from_refreshed(refreshed: &RefreshedCredential, now: Unix) -> Self {
        Self {
            version: BUNDLE_VERSION,
            access_token: refreshed.credential.expose_secret().to_string(),
            refresh_token: refreshed
                .refresh_token
                .as_ref()
                .map(|token| token.expose_secret().to_string()),
            access_expires_at: refreshed.expires_in.map(|ttl| now + ttl as Unix),
            refresh_expires_at: refreshed.refresh_expires_in.map(|ttl| now + ttl as Unix),
        }
    }

    pub fn inherit_refresh_from(&mut self, previous: &Self) {
        if self.refresh_token.is_none() {
            self.refresh_token = previous.refresh_token.clone();
        }
        if self.refresh_expires_at.is_none() {
            self.refresh_expires_at = previous.refresh_expires_at;
        }
    }

    #[must_use]
    pub fn access_secret(&self) -> SecretString {
        SecretString::from(self.access_token.clone())
    }

    #[must_use]
    pub fn revocation_token(&self) -> SecretString {
        self.refresh_token.as_ref().map_or_else(
            || self.access_secret(),
            |token| SecretString::from(token.clone()),
        )
    }

    fn refresh_secret(&self) -> Option<SecretString> {
        self.refresh_token
            .as_ref()
            .map(|token| SecretString::from(token.clone()))
    }

    fn needs_refresh(&self, now: Unix) -> bool {
        self.access_expires_at
            .is_some_and(|expires_at| now + REFRESH_SKEW_SECS >= expires_at)
    }

    fn access_expired(&self, now: Unix) -> bool {
        self.access_expires_at
            .is_some_and(|expires_at| now >= expires_at)
    }

    fn refresh_expired(&self, now: Unix) -> bool {
        self.refresh_expires_at
            .is_some_and(|expires_at| now >= expires_at)
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, Eq, PartialEq)]
pub enum CredentialError {
    #[error("binding needs reauthentication")]
    NeedsReauth,
    #[error("upstream credential refresh is temporarily unavailable")]
    Unavailable,
    #[error("credential storage error")]
    Internal,
}

/// A usable upstream access token, or a forced rotation.
#[async_trait]
pub trait CredentialSource: Send + Sync {
    async fn access_token(&self, binding: &Binding) -> Result<SecretString, CredentialError>;

    /// Refreshes unless another worker already replaced `stale_access`.
    async fn refresh(
        &self,
        binding: &Binding,
        stale_access: &str,
    ) -> Result<SecretString, CredentialError>;
}

struct LoadedCredential {
    stored: StoredCredential,
    sealed: SealedSecret,
}

/// Loads, refreshes, and compare-and-swaps one binding's credential.
pub struct BindingCredentialService {
    storage: Arc<dyn Storage>,
    registry: Arc<dyn ConnectorRegistry>,
    auth: Arc<dyn ConnectorRefresh>,
    sealer: Arc<dyn SecretSealer>,
    clock: Arc<dyn Clock>,
    locks: Mutex<HashMap<BindingId, Weak<tokio::sync::Mutex<()>>>>,
}

impl BindingCredentialService {
    #[must_use]
    pub fn new(
        storage: Arc<dyn Storage>,
        registry: Arc<dyn ConnectorRegistry>,
        auth: Arc<dyn ConnectorRefresh>,
        sealer: Arc<dyn SecretSealer>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            storage,
            registry,
            auth,
            sealer,
            clock,
            locks: Mutex::new(HashMap::new()),
        }
    }

    fn lock_for(&self, id: BindingId) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.locks.lock().expect("credential locks");
        if let Some(lock) = locks.get(&id).and_then(Weak::upgrade) {
            return lock;
        }
        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(id, Arc::downgrade(&lock));
        lock
    }

    async fn load(&self, binding: &Binding) -> Result<LoadedCredential, CredentialError> {
        let sealed = self
            .storage
            .bindings()
            .load_sub_credential(&binding.id)
            .await
            .map_err(|_| CredentialError::Internal)?
            .ok_or(CredentialError::NeedsReauth)?;
        let raw = self
            .sealer
            .open(&binding.id, &sealed)
            .map_err(|_| CredentialError::Internal)?;
        Ok(LoadedCredential {
            stored: StoredCredential::decode(&raw),
            sealed,
        })
    }

    fn seal(
        &self,
        binding: &Binding,
        stored: &StoredCredential,
    ) -> Result<SealedSecret, CredentialError> {
        let raw = SecretString::from(stored.encode());
        self.sealer
            .seal(&binding.id, &raw)
            .map_err(|_| CredentialError::Internal)
    }

    async fn refresh_locked(
        &self,
        binding: &Binding,
        loaded: &LoadedCredential,
        now: Unix,
    ) -> Result<SecretString, CredentialError> {
        let Some(refresh_token) = loaded.stored.refresh_secret() else {
            return Err(CredentialError::NeedsReauth);
        };
        if loaded.stored.refresh_expired(now) {
            return Err(CredentialError::NeedsReauth);
        }
        let endpoint = self
            .registry
            .resolve(&connector_id_for_name(&binding.upstream_id))
            .await
            .map_err(|_| CredentialError::Internal)?;
        let refreshed = self
            .auth
            .refresh_token(&endpoint, &refresh_token)
            .await
            .map_err(map_refresh_error)?
            .ok_or(CredentialError::NeedsReauth)?;
        let mut next = StoredCredential::from_refreshed(&refreshed, now);
        next.inherit_refresh_from(&loaded.stored);
        let sealed = self.seal(binding, &next)?;
        let replaced = self
            .storage
            .bindings()
            .replace_sub_credential(&binding.id, &loaded.sealed, &sealed, now)
            .await
            .map_err(|_| CredentialError::Internal)?;
        if !replaced {
            // Another worker won. Its credential is the one on disk; use it
            // rather than returning a token that was never persisted.
            let current = self.load(binding).await?;
            return Ok(current.stored.access_secret());
        }
        Ok(next.access_secret())
    }
}

#[async_trait]
impl CredentialSource for BindingCredentialService {
    async fn access_token(&self, binding: &Binding) -> Result<SecretString, CredentialError> {
        let loaded = self.load(binding).await?;
        let now = self.clock.now();
        if !loaded.stored.needs_refresh(now) {
            return Ok(loaded.stored.access_secret());
        }
        if loaded.stored.refresh_secret().is_none() {
            return if loaded.stored.access_expired(now) {
                Err(CredentialError::NeedsReauth)
            } else {
                Ok(loaded.stored.access_secret())
            };
        }

        let lock = self.lock_for(binding.id);
        let _guard = lock.lock().await;
        let loaded = self.load(binding).await?;
        if !loaded.stored.needs_refresh(now) {
            return Ok(loaded.stored.access_secret());
        }
        match self.refresh_locked(binding, &loaded, now).await {
            Ok(token) => Ok(token),
            // A transient refresh failure must not discard a still-valid access
            // token; only an expired one forces the caller to reauthorize.
            Err(CredentialError::Unavailable) if !loaded.stored.access_expired(now) => {
                Ok(loaded.stored.access_secret())
            }
            Err(error) => Err(error),
        }
    }

    async fn refresh(
        &self,
        binding: &Binding,
        stale_access: &str,
    ) -> Result<SecretString, CredentialError> {
        let lock = self.lock_for(binding.id);
        let _guard = lock.lock().await;
        let loaded = self.load(binding).await?;
        if loaded.stored.access_secret().expose_secret() != stale_access {
            return Ok(loaded.stored.access_secret());
        }
        if loaded.stored.refresh_secret().is_none() {
            return Err(CredentialError::NeedsReauth);
        }
        self.refresh_locked(binding, &loaded, self.clock.now())
            .await
    }
}

fn map_refresh_error(error: UpstreamError) -> CredentialError {
    match error {
        // `invalid_grant` and `invalid_client` are both 400/401 at the token
        // endpoint. A user reauthorization is the only recovery for the former;
        // the latter is operational, but treating it as transient would loop.
        UpstreamError::CredentialExpired | UpstreamError::Rejected => CredentialError::NeedsReauth,
        UpstreamError::RateLimited { .. }
        | UpstreamError::Unavailable
        | UpstreamError::Truncated
        | UpstreamError::Overloaded => CredentialError::Unavailable,
        UpstreamError::InsufficientScope | UpstreamError::NotFound | UpstreamError::Internal => {
            CredentialError::Internal
        }
        _ => CredentialError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_legacy_secret_is_read_as_an_access_token() {
        let stored = StoredCredential::decode(&SecretString::from("legacy-token"));
        assert_eq!(stored.access_secret().expose_secret(), "legacy-token");
        assert!(stored.refresh_token.is_none());
        assert!(!stored.needs_refresh(10_000));
    }

    #[test]
    fn a_v1_bundle_round_trips() {
        let raw = SecretString::from(
            r#"{"v":1,"access_token":"a","refresh_token":"r","access_expires_at":100,"refresh_expires_at":200}"#,
        );
        let stored = StoredCredential::decode(&raw);
        assert_eq!(stored.access_secret().expose_secret(), "a");
        assert_eq!(stored.refresh_token.as_deref(), Some("r"));
        assert_eq!(stored.access_expires_at, Some(100));
        assert_eq!(stored.refresh_expires_at, Some(200));
        assert_eq!(stored.encode(), raw.expose_secret());
    }

    #[test]
    fn refresh_starts_five_minutes_before_expiry() {
        let stored = StoredCredential {
            version: 1,
            access_token: "a".to_string(),
            refresh_token: Some("r".to_string()),
            access_expires_at: Some(400),
            refresh_expires_at: Some(1000),
        };
        assert!(!stored.needs_refresh(99));
        assert!(stored.needs_refresh(100));
        assert!(!stored.access_expired(399));
        assert!(stored.access_expired(400));
    }
}
