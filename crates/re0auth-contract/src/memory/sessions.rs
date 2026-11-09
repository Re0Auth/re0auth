//! Session repository for the in-memory store, split out for the line budget.

use async_trait::async_trait;

use super::*;

#[async_trait]
impl SessionRepo for MemoryStore {
    async fn create(&self, session: &Session) -> RepoResult<()> {
        let mut inner = self.lock();
        if !inner.users.contains_key(&session.user_id) {
            return Err(RepoError::NotFound);
        }
        if inner.sessions.contains_key(&session.id_hash) {
            return Err(RepoError::Conflict("session hash"));
        }
        inner
            .sessions
            .insert(session.id_hash.clone(), session.clone());
        Ok(())
    }

    async fn find_active(&self, id_hash: &[u8], now: Unix) -> RepoResult<Option<Session>> {
        let inner = self.lock();
        let Some(session) = inner.sessions.get(id_hash) else {
            return Ok(None);
        };
        let active = session.revoked_at.is_none()
            && now < session.idle_expires_at
            && now < session.absolute_expires_at;
        Ok(active.then(|| session.clone()))
    }

    async fn touch(&self, id_hash: &[u8], now: Unix, idle_expires_at: Unix) -> RepoResult<()> {
        let mut inner = self.lock();
        let Some(session) = inner.sessions.get_mut(id_hash) else {
            return Err(RepoError::NotFound);
        };
        if session.revoked_at.is_some() {
            return Err(RepoError::Revoked);
        }
        if now >= session.idle_expires_at || now >= session.absolute_expires_at {
            return Err(RepoError::NotFound);
        }
        session.last_seen_at = now;
        session.idle_expires_at = idle_expires_at;
        Ok(())
    }

    async fn revoke(&self, id_hash: &[u8], now: Unix) -> RepoResult<()> {
        let mut inner = self.lock();
        let Some(session) = inner.sessions.get_mut(id_hash) else {
            return Err(RepoError::NotFound);
        };
        session.revoked_at = Some(now);
        Ok(())
    }

    async fn revoke_all(&self, user: &UserId, now: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let mut revoked = 0;
        for session in inner.sessions.values_mut() {
            if session.user_id == *user && session.revoked_at.is_none() {
                session.revoked_at = Some(now);
                revoked += 1;
            }
        }
        Ok(revoked)
    }

    async fn purge_expired(&self, before: Unix) -> RepoResult<u64> {
        let mut inner = self.lock();
        let previous = inner.sessions.len();
        inner.sessions.retain(|_, session| {
            !(session.idle_expires_at <= before
                || session.absolute_expires_at <= before
                || session.revoked_at.is_some_and(|at| at <= before))
        });
        Ok((previous - inner.sessions.len()) as u64)
    }
}
