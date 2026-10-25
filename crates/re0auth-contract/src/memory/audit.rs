//! Audit repo for the in-memory store.
//!
//! Split out of `memory.rs` to keep that file within the line budget.

use super::MemoryStore;
use async_trait::async_trait;
use re0auth_api::audit::{AuditRecord, AuditTier};
use re0auth_api::ports::{AuditFilter, AuditRepo, RepoResult};
use re0auth_api::{AuditId, Unix, UserId};

#[async_trait]
impl AuditRepo for MemoryStore {
    async fn recent(&self, limit: u32) -> RepoResult<Vec<AuditRecord>> {
        let inner = self.lock();
        let mut records = inner.audits.clone();
        records.sort_by(|left, right| {
            right
                .occurred_at
                .cmp(&left.occurred_at)
                .then_with(|| right.id.0.cmp(&left.id.0))
        });
        records.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(records)
    }

    async fn by_actor(&self, user: &UserId, limit: u32) -> RepoResult<Vec<AuditRecord>> {
        let inner = self.lock();
        let mut records: Vec<_> = inner
            .audits
            .iter()
            .filter(|record| record.actor_user_id == Some(*user))
            .cloned()
            .collect();
        records.sort_by(|left, right| {
            right
                .occurred_at
                .cmp(&left.occurred_at)
                .then_with(|| right.id.0.cmp(&left.id.0))
        });
        records.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(records)
    }

    async fn append(&self, record: &AuditRecord) -> RepoResult<()> {
        // Forced, not taken from the record: this is the telemetry path, and
        // accepting a fact here would put a security fact on the lossy lane.
        let mut record = record.clone();
        record.tier = AuditTier::Telemetry;
        self.lock().audits.push(record);
        Ok(())
    }

    async fn purge_tier_before(&self, tier: AuditTier, before: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let before_len = inner.audits.len();
        inner
            .audits
            .retain(|record| !(record.tier == tier && record.occurred_at <= before));
        Ok((before_len - inner.audits.len()) as u64)
    }

    async fn query(
        &self,
        filter: &AuditFilter,
        before: Option<&AuditId>,
        limit: u32,
    ) -> RepoResult<Vec<AuditRecord>> {
        let inner = self.lock();
        let mut records: Vec<AuditRecord> = inner
            .audits
            .iter()
            .filter(|record| {
                before.is_none_or(|cursor| record.id.0 < cursor.0)
                    && filter
                        .actor
                        .is_none_or(|actor| record.actor_user_id == Some(actor))
                    && filter
                        .client
                        .is_none_or(|client| record.client_id == Some(client))
                    && filter.action.is_none_or(|action| record.action == action)
                    && filter.tier.is_none_or(|tier| record.tier == tier)
                    && filter.from.is_none_or(|from| record.occurred_at >= from)
                    && filter.to.is_none_or(|to| record.occurred_at <= to)
            })
            .cloned()
            .collect();
        records.sort_by_key(|record| std::cmp::Reverse(record.id.0));
        records.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(records)
    }
}
