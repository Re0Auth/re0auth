//! Binding repo for the in-memory store.
//!
//! Split out of `memory.rs` to keep that file within the line budget.

use super::MemoryStore;
use async_trait::async_trait;
use re0auth_api::audit::SecurityFact;
use re0auth_api::ports::{
    ANONYMIZED_UPSTREAM_USER_ID, Binding, BindingQuery, BindingRepo, BindingStatus, RepoError,
    RepoResult,
};
use re0auth_api::secret::SealedSecret;
use re0auth_api::{BindingId, Unix, UserId};

#[async_trait]
impl BindingRepo for MemoryStore {
    async fn list_all(
        &self,
        before: Option<&BindingId>,
        query: &BindingQuery,
        limit: u32,
    ) -> RepoResult<Vec<Binding>> {
        let inner = self.lock();
        let mut bindings: Vec<Binding> = inner
            .bindings
            .values()
            .filter(|binding| {
                before.is_none_or(|cursor| binding.id.0 < cursor.0)
                    && query.user.is_none_or(|user| binding.user_id == user)
                    && query
                        .upstream
                        .as_ref()
                        .is_none_or(|upstream| binding.upstream_id == *upstream)
                    && query.status.is_none_or(|status| binding.status == status)
            })
            .cloned()
            .collect();
        bindings.sort_by_key(|binding| std::cmp::Reverse(binding.id.0));
        bindings.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(bindings)
    }
    async fn upsert(&self, binding: &Binding, fact: &SecurityFact) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.users.contains_key(&binding.user_id) {
            return Err(RepoError::NotFound);
        }
        let existing_id = inner
            .bindings
            .iter()
            .find(|(_, stored)| {
                stored.user_id == binding.user_id && stored.upstream_id == binding.upstream_id
            })
            .map(|(id, _)| *id);
        if let Some(existing_id) = existing_id {
            let stored = inner
                .bindings
                .get_mut(&existing_id)
                .expect("binding found by pair");
            let created_at = stored.created_at;
            *stored = Binding {
                id: existing_id,
                created_at,
                ..binding.clone()
            };
            // Re-binding replaces the account, so the old revoke clock is stale.
            inner.binding_revocations.remove(&existing_id);
            Self::push_fact(&mut inner, fact);
            return Ok(());
        }
        if inner.bindings.contains_key(&binding.id) {
            return Err(RepoError::Conflict("binding id"));
        }
        inner.bindings.insert(binding.id, binding.clone());
        Self::push_fact(&mut inner, fact);
        Ok(())
    }

    async fn upsert_with_credential(
        &self,
        binding: &Binding,
        sealed: &SealedSecret,
        fact: &SecurityFact,
        _now: Unix,
    ) -> RepoResult<Binding> {
        let mut inner = self.lock();
        if !inner.users.contains_key(&binding.user_id) {
            return Err(RepoError::NotFound);
        }
        let existing_id = inner
            .bindings
            .iter()
            .find(|(_, stored)| {
                stored.user_id == binding.user_id && stored.upstream_id == binding.upstream_id
            })
            .map(|(id, _)| *id);
        let stored = match existing_id {
            Some(existing_id) => {
                if existing_id != binding.id {
                    return Err(RepoError::Conflict("binding id"));
                }
                Binding {
                    created_at: inner
                        .bindings
                        .get(&existing_id)
                        .expect("binding found by pair")
                        .created_at,
                    ..binding.clone()
                }
            }
            None => {
                if inner.bindings.contains_key(&binding.id) {
                    return Err(RepoError::Conflict("binding id"));
                }
                binding.clone()
            }
        };
        inner.bindings.insert(stored.id, stored.clone());
        inner.binding_revocations.remove(&stored.id);
        inner.sub_credentials.insert(stored.id, sealed.clone());
        let mut fact = fact.clone();
        fact.target = format!("binding:{}", stored.id.0);
        Self::push_fact(&mut inner, &fact);
        Ok(stored)
    }

    async fn find(&self, user: &UserId, upstream: &str) -> RepoResult<Option<Binding>> {
        let inner = self.lock();
        Ok(inner
            .bindings
            .values()
            .find(|binding| binding.user_id == *user && binding.upstream_id == upstream)
            .cloned())
    }

    async fn list_by_user(&self, user: &UserId) -> RepoResult<Vec<Binding>> {
        let inner = self.lock();
        let mut bindings: Vec<_> = inner
            .bindings
            .values()
            .filter(|binding| binding.user_id == *user)
            .cloned()
            .collect();
        bindings.sort_by(|left, right| left.upstream_id.cmp(&right.upstream_id));
        Ok(bindings)
    }

    async fn mark_needs_reauth(
        &self,
        id: &BindingId,
        reason: &str,
        fact: &SecurityFact,
        now: Unix,
    ) -> RepoResult<()> {
        let mut inner = self.lock();
        let Some(binding) = inner.bindings.get_mut(id) else {
            return Err(RepoError::NotFound);
        };
        binding.status = BindingStatus::NeedsReauth;
        binding.last_error_code = Some(reason.to_string());
        binding.updated_at = now;
        Self::push_fact(&mut inner, fact);
        Ok(())
    }

    async fn revoke(&self, id: &BindingId, fact: &SecurityFact, now: Unix) -> RepoResult<()> {
        let mut inner = self.lock();
        let Some(binding) = inner.bindings.get_mut(id) else {
            return Err(RepoError::NotFound);
        };
        binding.status = BindingStatus::Revoked;
        binding.updated_at = now;
        inner.sub_credentials.remove(id);
        inner.binding_revocations.insert(*id, now);
        Self::push_fact(&mut inner, fact);
        Ok(())
    }

    async fn revoke_all(&self, user: &UserId, fact: &SecurityFact, now: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let ids: Vec<BindingId> = inner
            .bindings
            .iter()
            .filter(|(_, binding)| {
                binding.user_id == *user && binding.status != BindingStatus::Revoked
            })
            .map(|(id, _)| *id)
            .collect();
        if ids.is_empty() {
            return Ok(0);
        }
        for id in &ids {
            let binding = inner.bindings.get_mut(id).expect("selected binding");
            binding.status = BindingStatus::Revoked;
            binding.updated_at = now;
            inner.sub_credentials.remove(id);
            inner.binding_revocations.insert(*id, now);
        }
        Self::push_fact(&mut inner, fact);
        Ok(ids.len() as u64)
    }

    async fn anonymize_revoked_before(&self, before: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let targets: Vec<BindingId> = inner
            .bindings
            .iter()
            .filter(|(id, binding)| {
                binding.status == BindingStatus::Revoked
                    && binding.upstream_user_id != ANONYMIZED_UPSTREAM_USER_ID
                    && inner
                        .binding_revocations
                        .get(id)
                        .is_some_and(|at| *at <= before)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &targets {
            let binding = inner.bindings.get_mut(id).expect("selected binding");
            binding.upstream_user_id = ANONYMIZED_UPSTREAM_USER_ID.to_string();
        }
        Ok(targets.len() as u64)
    }

    async fn store_sub_credential(
        &self,
        binding: &BindingId,
        sealed: &SealedSecret,
        _now: Unix,
    ) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.bindings.contains_key(binding) {
            return Err(RepoError::NotFound);
        }
        inner.sub_credentials.insert(*binding, sealed.clone());
        Ok(())
    }

    async fn load_sub_credential(&self, binding: &BindingId) -> RepoResult<Option<SealedSecret>> {
        Ok(self.lock().sub_credentials.get(binding).cloned())
    }

    async fn delete_sub_credential(&self, binding: &BindingId) -> RepoResult<()> {
        self.lock().sub_credentials.remove(binding);
        Ok(())
    }

    async fn rewrap_sub_credential(
        &self,
        binding: &BindingId,
        expect: &SealedSecret,
        new: &SealedSecret,
        _now: Unix,
    ) -> RepoResult<bool> {
        let mut inner = self.lock();
        match inner.sub_credentials.get(binding) {
            Some(current) if current == expect => {
                inner.sub_credentials.insert(*binding, new.clone());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn scan_sub_credentials(
        &self,
        after: Option<&BindingId>,
        limit: u32,
    ) -> RepoResult<Vec<(BindingId, SealedSecret)>> {
        let inner = self.lock();
        let mut ids: Vec<&BindingId> = inner.sub_credentials.keys().collect();
        ids.sort_by_key(|id| id.0);
        Ok(ids
            .into_iter()
            .filter(|id| after.is_none_or(|cursor| id.0 > cursor.0))
            .take(limit as usize)
            .map(|id| (*id, inner.sub_credentials[id].clone()))
            .collect())
    }
}
