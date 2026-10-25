//! Turns a requested scope set into "you have not connected this yet".

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;

use re0auth_api::UserId;
use re0auth_api::ports::{BindingHints, BindingStatus, MissingBinding, RepoResult, Storage};

/// Reads the answer off configuration plus the user's own bindings.
pub struct ScopeBindingHints {
    storage: Arc<dyn Storage>,
    /// Scope → the connectors whose resources require it.
    ///
    /// Built at startup from the same configuration the gateway's registry is
    /// built from, so the two cannot disagree about which scope reaches which
    /// upstream. A `ConnectorRegistry` cannot answer this: it resolves by id and
    /// cannot enumerate, and this is the reverse direction.
    required_by: BTreeMap<String, Vec<String>>,
}

impl ScopeBindingHints {
    #[must_use]
    pub fn new(storage: Arc<dyn Storage>, required_by: BTreeMap<String, Vec<String>>) -> Self {
        Self {
            storage,
            required_by,
        }
    }

    /// The scopes in `requested` that reach `upstream`, in request order.
    fn needing(&self, upstream: &str, requested: &[String]) -> Vec<String> {
        requested
            .iter()
            .filter(|scope| {
                self.required_by
                    .get(*scope)
                    .is_some_and(|upstreams| upstreams.iter().any(|name| name == upstream))
            })
            .cloned()
            .collect()
    }
}

#[async_trait]
impl BindingHints for ScopeBindingHints {
    async fn missing(&self, user: &UserId, scopes: &[String]) -> RepoResult<Vec<MissingBinding>> {
        if scopes.is_empty() || self.required_by.is_empty() {
            return Ok(Vec::new());
        }
        let bindings = self.storage.bindings().list_by_user(user).await?;

        let mut missing = Vec::new();
        for upstream in self.required_by.values().flatten() {
            let needed = self.needing(upstream, scopes);
            if needed.is_empty() {
                continue;
            }
            // Only `Active` counts as connected. `NeedsReauth` is precisely the
            // state the portal should offer to fix, so it stays on the list.
            let connected = bindings.iter().any(|binding| {
                binding.upstream_id == *upstream && binding.status == BindingStatus::Active
            });
            if !connected
                && !missing
                    .iter()
                    .any(|hint: &MissingBinding| hint.upstream_id == *upstream)
            {
                missing.push(MissingBinding {
                    upstream_id: upstream.clone(),
                    scopes: needed,
                });
            }
        }
        missing.sort_by(|a, b| a.upstream_id.cmp(&b.upstream_id));
        Ok(missing)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use re0auth_api::BindingId;
    use re0auth_api::audit::{AuditAction, SecurityFact};
    use re0auth_api::ports::{Binding, Storage, User, UserRole};
    use re0auth_contract::memory::MemoryStore;

    use super::*;

    fn index(entries: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(scope, upstreams)| {
                (
                    (*scope).to_string(),
                    upstreams.iter().map(|name| (*name).to_string()).collect(),
                )
            })
            .collect()
    }

    async fn store_with(user: &UserId, upstream: &str, status: BindingStatus) -> MemoryStore {
        let store = MemoryStore::new();
        // A binding cannot exist without its user: the schema has the foreign key,
        // and the in-memory store enforces it the same way.
        store
            .users()
            .create(&User {
                id: *user,
                display_name: "Alice".to_string(),
                role: UserRole::User,
                created_at: 1_000,
                updated_at: 1_000,
            })
            .await
            .expect("seed a user");
        let fact = SecurityFact::new(AuditAction::BindingCreated, 1_000, upstream);
        store
            .bindings()
            .upsert(
                &Binding {
                    id: BindingId::new(),
                    user_id: *user,
                    upstream_id: upstream.to_string(),
                    upstream_user_id: "upstream-account".to_string(),
                    status,
                    created_at: 1_000,
                    updated_at: 1_000,
                    last_refreshed_at: None,
                    last_error_code: None,
                },
                &fact,
            )
            .await
            .expect("seed a binding");
        store
    }

    fn hints(store: MemoryStore, index: BTreeMap<String, Vec<String>>) -> ScopeBindingHints {
        ScopeBindingHints::new(Arc::new(store), index)
    }

    fn scopes(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[tokio::test]
    async fn a_scope_nobody_requires_asks_for_nothing() {
        let user = UserId::new();
        let hints = hints(
            MemoryStore::new(),
            index(&[("phigros.stats.read", &["phigros"])]),
        );
        let missing = hints
            .missing(&user, &scopes(&["openid", "profile"]))
            .await
            .expect("answer");
        assert!(missing.is_empty(), "identity scopes need no upstream");
    }

    #[tokio::test]
    async fn an_unconnected_upstream_is_named() {
        let user = UserId::new();
        let hints = hints(
            MemoryStore::new(),
            index(&[("phigros.stats.read", &["phigros"])]),
        );
        let missing = hints
            .missing(&user, &scopes(&["openid", "phigros.stats.read"]))
            .await
            .expect("answer");
        assert_eq!(
            missing,
            vec![MissingBinding {
                upstream_id: "phigros".to_string(),
                scopes: scopes(&["phigros.stats.read"]),
            }]
        );
    }

    #[tokio::test]
    async fn an_active_binding_satisfies_its_scopes() {
        let user = UserId::new();
        let hints = hints(
            store_with(&user, "phigros", BindingStatus::Active).await,
            index(&[("phigros.stats.read", &["phigros"])]),
        );
        let missing = hints
            .missing(&user, &scopes(&["phigros.stats.read"]))
            .await
            .expect("answer");
        assert!(missing.is_empty(), "a connected upstream is not a hint");
    }

    #[tokio::test]
    async fn a_binding_needing_reauth_stays_on_the_list() {
        let user = UserId::new();
        let hints = hints(
            store_with(&user, "phigros", BindingStatus::NeedsReauth).await,
            index(&[("phigros.stats.read", &["phigros"])]),
        );
        let missing = hints
            .missing(&user, &scopes(&["phigros.stats.read"]))
            .await
            .expect("answer");
        assert_eq!(
            missing.len(),
            1,
            "needs-reauth is exactly the state the portal should offer to fix"
        );
        assert_eq!(missing[0].upstream_id, "phigros");
    }

    #[tokio::test]
    async fn a_revoked_binding_is_not_a_connection() {
        let user = UserId::new();
        let hints = hints(
            store_with(&user, "phigros", BindingStatus::Revoked).await,
            index(&[("phigros.stats.read", &["phigros"])]),
        );
        let missing = hints
            .missing(&user, &scopes(&["phigros.stats.read"]))
            .await
            .expect("answer");
        assert_eq!(missing.len(), 1, "a revoked binding grants nothing");
    }

    #[tokio::test]
    async fn one_upstream_is_reported_once_across_resources() {
        let user = UserId::new();
        let hints = hints(
            MemoryStore::new(),
            index(&[
                ("phigros.stats.read", &["phigros"]),
                ("phigros.records.read", &["phigros"]),
            ]),
        );
        let missing = hints
            .missing(
                &user,
                &scopes(&["phigros.stats.read", "phigros.records.read"]),
            )
            .await
            .expect("answer");
        assert_eq!(missing.len(), 1, "two resources, one upstream, one hint");
        assert_eq!(missing[0].scopes.len(), 2);
    }
}
