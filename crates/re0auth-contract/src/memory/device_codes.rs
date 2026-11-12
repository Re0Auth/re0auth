//! Device-code repo for the in-memory store.
//!
//! Split out of `memory.rs` to keep that file within the line budget.

use super::MemoryStore;
use async_trait::async_trait;
use re0auth_api::ports::{
    DeviceCode, DeviceCodeRepo, DeviceCodeState, DeviceCodeStatus, DevicePoll, RefreshToken,
    RepoError, RepoResult,
};
use re0auth_api::{ClientId, FamilyId, Unix, UserId};

#[async_trait]
impl DeviceCodeRepo for MemoryStore {
    async fn insert(&self, code: &DeviceCode) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.clients.contains_key(&code.client_id) {
            return Err(RepoError::NotFound);
        }
        if let Some(user) = code.state.approver()
            && !inner.users.contains_key(&user)
        {
            return Err(RepoError::NotFound);
        }
        // The user code is the one the caller redraws, so it gets its own signal;
        // the device code is 8 random bytes and a collision there is a defect, not
        // a retry.
        if inner
            .device_codes
            .values()
            .any(|existing| existing.user_code_hash == code.user_code_hash)
        {
            return Err(RepoError::UserCodeConflict);
        }
        if inner.device_codes.contains_key(&code.device_code_hash) {
            return Err(RepoError::Conflict("device code hash"));
        }
        inner
            .device_codes
            .insert(code.device_code_hash.clone(), code.clone());
        Ok(())
    }

    async fn find_by_device_hash(&self, hash: &[u8]) -> RepoResult<Option<DeviceCode>> {
        Ok(self.lock().device_codes.get(hash).cloned())
    }

    async fn find_by_user_code_hash(&self, hash: &[u8]) -> RepoResult<Option<DeviceCode>> {
        Ok(self
            .lock()
            .device_codes
            .values()
            .find(|code| code.user_code_hash == hash)
            .cloned())
    }

    async fn approve(&self, user_code_hash: &[u8], user_id: UserId, now: Unix) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.users.contains_key(&user_id) {
            return Err(RepoError::NotFound);
        }
        let Some(code) = inner
            .device_codes
            .values_mut()
            .find(|code| code.user_code_hash == user_code_hash)
        else {
            return Err(RepoError::NotFound);
        };
        if code.expires_at <= now {
            code.state = DeviceCodeState::Expired;
            return Err(RepoError::Expired);
        }
        if !code.state.is_pending() {
            return Err(RepoError::Conflict("device code is not pending"));
        }
        code.state = DeviceCodeState::Approved { approver: user_id };
        Ok(())
    }

    async fn deny(&self, user_code_hash: &[u8], now: Unix) -> RepoResult<()> {
        let mut inner = self.lock();
        let Some(code) = inner
            .device_codes
            .values_mut()
            .find(|code| code.user_code_hash == user_code_hash)
        else {
            return Err(RepoError::NotFound);
        };
        if code.expires_at <= now {
            code.state = DeviceCodeState::Expired;
            return Err(RepoError::Expired);
        }
        if !code.state.is_pending() {
            return Err(RepoError::Conflict("device code is not pending"));
        }
        // This path has no authenticated actor, so it records no approver.
        code.state = DeviceCodeState::Denied { approver: None };
        Ok(())
    }

    async fn revoke_approved_for_client(
        &self,
        user: &UserId,
        client: &ClientId,
    ) -> RepoResult<u64> {
        let mut inner = self.lock();
        let mut revoked = 0;
        for code in inner.device_codes.values_mut() {
            if code.client_id == *client
                && matches!(
                    &code.state,
                    DeviceCodeState::Approved { approver } if *approver == *user
                )
            {
                code.state = DeviceCodeState::Denied {
                    approver: Some(*user),
                };
                revoked += 1;
            }
        }
        Ok(revoked)
    }

    async fn prepare_poll(
        &self,
        device_code_hash: &[u8],
        now: Unix,
        client_id: ClientId,
    ) -> RepoResult<DevicePoll> {
        let mut inner = self.lock();
        let Some(code) = inner.device_codes.get_mut(device_code_hash) else {
            return Ok(DevicePoll::NotFound);
        };

        if code.client_id != client_id {
            return Ok(DevicePoll::ClientMismatch);
        }

        if code.state.status() == DeviceCodeStatus::Consumed {
            return Ok(DevicePoll::Consumed {
                family: code.family_id,
            });
        }
        if code.state.status() == DeviceCodeStatus::Denied {
            return Ok(DevicePoll::Denied);
        }
        if code.state.status() == DeviceCodeStatus::Expired || code.expires_at <= now {
            code.state = DeviceCodeState::Expired;
            return Ok(DevicePoll::Expired);
        }

        // No defensive `else` here any more: an approved code always carries
        // its approver, so the polling path cannot invent an expired code from
        // a half-written row. Nothing is consumed here: the code has to survive
        // a signing failure so the client can retry.
        if let DeviceCodeState::Approved { approver: user_id } = code.state {
            return Ok(DevicePoll::Approved {
                client_id: code.client_id,
                user_id,
                scopes: code.scopes.clone(),
                created_at: code.created_at,
            });
        }

        if let Some(last) = code.last_polled_at
            && now < last + i64::from(code.interval_secs)
        {
            code.interval_secs += 5;
            code.last_polled_at = Some(now);
            return Ok(DevicePoll::SlowDown {
                interval_secs: code.interval_secs,
            });
        }

        code.last_polled_at = Some(now);
        code.poll_count += 1;
        Ok(DevicePoll::Pending)
    }

    async fn consume_and_insert_refresh(
        &self,
        device_code_hash: &[u8],
        now: Unix,
        client_id: ClientId,
        family_id: &FamilyId,
        refresh: &RefreshToken,
    ) -> RepoResult<DevicePoll> {
        let mut inner = self.lock();
        let Some(code) = inner.device_codes.get(device_code_hash).cloned() else {
            return Ok(DevicePoll::NotFound);
        };
        if code.client_id != client_id {
            return Ok(DevicePoll::ClientMismatch);
        }
        if code.state.status() == DeviceCodeStatus::Consumed {
            return Ok(DevicePoll::Consumed {
                family: code.family_id,
            });
        }
        if code.state.status() == DeviceCodeStatus::Denied {
            return Ok(DevicePoll::Denied);
        }
        if code.state.status() == DeviceCodeStatus::Expired || code.expires_at <= now {
            return Ok(DevicePoll::Expired);
        }
        let DeviceCodeState::Approved { approver: user_id } = code.state else {
            return Ok(DevicePoll::Pending);
        };
        // Same preconditions as `RefreshTokenRepo::insert`; checked before the
        // device code moves so a refused insert changes nothing.
        if !inner.users.contains_key(&refresh.user_id) {
            return Err(RepoError::NotFound);
        }
        if inner.refresh_tokens.contains_key(&refresh.token_hash) {
            return Err(RepoError::Conflict("refresh token hash"));
        }
        inner
            .refresh_tokens
            .insert(refresh.token_hash.clone(), refresh.clone());
        if let Some(stored) = inner.device_codes.get_mut(device_code_hash) {
            stored.state = DeviceCodeState::Consumed { approver: user_id };
            stored.consumed_at = Some(now);
            stored.last_polled_at = Some(now);
            stored.family_id = Some(*family_id);
        }
        Ok(DevicePoll::Approved {
            client_id: code.client_id,
            user_id,
            scopes: code.scopes,
            created_at: code.created_at,
        })
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let before_len = inner.device_codes.len();
        inner.device_codes.retain(|_, code| {
            !(code.expires_at <= before || code.consumed_at.is_some_and(|at| at <= before))
        });
        Ok((before_len - inner.device_codes.len()) as u64)
    }
}
