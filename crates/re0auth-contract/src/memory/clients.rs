//! Client repo for the in-memory store.
//!
//! Split out of `memory.rs` to keep that file within the line budget.

use super::MemoryStore;
use async_trait::async_trait;
use re0auth_api::audit::SecurityFact;
use re0auth_api::ports::{Client, ClientRepo, ClientStatus, RepoError, RepoResult};
use re0auth_api::secret::ClientSecretHash;
use re0auth_api::{ClientId, Unix};

#[async_trait]
impl ClientRepo for MemoryStore {
    async fn insert(&self, client: &Client, fact: &SecurityFact) -> RepoResult<()> {
        let mut inner = self.lock();
        if inner.clients.contains_key(&client.id) {
            return Err(RepoError::Conflict("client id"));
        }
        inner.clients.insert(client.id, client.clone());
        Self::push_fact(&mut inner, fact);
        Ok(())
    }

    async fn get(&self, id: &ClientId) -> RepoResult<Option<Client>> {
        Ok(self.lock().clients.get(id).cloned())
    }

    async fn set_status(&self, id: &ClientId, status: ClientStatus, now: Unix) -> RepoResult<()> {
        let mut inner = self.lock();
        let Some(client) = inner.clients.get_mut(id) else {
            return Err(RepoError::NotFound);
        };
        client.status = status;
        client.updated_at = now;
        Ok(())
    }

    async fn list(&self, before: Option<&ClientId>, limit: u32) -> RepoResult<Vec<Client>> {
        let inner = self.lock();
        let mut clients: Vec<Client> = inner
            .clients
            .values()
            .filter(|client| before.is_none_or(|cursor| client.id.0 < cursor.0))
            .cloned()
            .collect();
        clients.sort_by_key(|client| std::cmp::Reverse(client.id.0));
        clients.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(clients)
    }

    async fn update(&self, client: &Client, fact: &SecurityFact, now: Unix) -> RepoResult<()> {
        let mut inner = self.lock();
        let Some(stored) = inner.clients.get_mut(&client.id) else {
            return Err(RepoError::NotFound);
        };
        // `created_at` and the secret are not part of an edit.
        let created_at = stored.created_at;
        let secret_hash = stored.secret_hash.clone();
        *stored = Client {
            created_at,
            secret_hash,
            updated_at: now,
            ..client.clone()
        };
        Self::push_fact(&mut inner, fact);
        Ok(())
    }

    async fn set_secret_hash(
        &self,
        id: &ClientId,
        secret_hash: Option<&ClientSecretHash>,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()> {
        let mut inner = self.lock();
        let Some(client) = inner.clients.get_mut(id) else {
            return Err(RepoError::NotFound);
        };
        client.secret_hash = secret_hash.cloned();
        client.updated_at = now;
        Self::push_fact(&mut inner, fact);
        Ok(())
    }
}
