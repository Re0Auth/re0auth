//! Which repositories this store exposes.
//!
//! Pure delegation: the trait exists so callers depend on `Storage` rather
//! than on `SqliteStore`. Kept apart from the store itself so the file that
//! implements the repositories stays under the line budget.

use re0auth_api::ports::{
    AccessTokenRepo, ApprovalTicketRepo, AuditRepo, AuthCodeRepo, BindingRepo, ClientRepo,
    ConnectorRepo, ConsentRepo, DeviceAttemptRepo, DeviceCodeRepo, LoginTransactionRepo,
    PendingAuthorizationRepo, PendingBindingRepo, RefreshTokenRepo, RepoResult, SessionRepo,
    SigningKeyRepo, Storage, UserRepo,
};

use super::{SqliteStore, db_error};

#[async_trait::async_trait]
impl Storage for SqliteStore {
    async fn ping(&self) -> RepoResult<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    fn access_tokens(&self) -> &dyn AccessTokenRepo {
        self
    }

    fn users(&self) -> &dyn UserRepo {
        self
    }

    fn audits(&self) -> &dyn AuditRepo {
        self
    }

    fn signing_keys(&self) -> &dyn SigningKeyRepo {
        self
    }

    fn sessions(&self) -> &dyn SessionRepo {
        self
    }

    fn auth_codes(&self) -> &dyn AuthCodeRepo {
        self
    }

    fn refresh_tokens(&self) -> &dyn RefreshTokenRepo {
        self
    }

    fn connectors(&self) -> &dyn ConnectorRepo {
        self
    }

    fn bindings(&self) -> &dyn BindingRepo {
        self
    }

    fn clients(&self) -> &dyn ClientRepo {
        self
    }

    fn device_codes(&self) -> &dyn DeviceCodeRepo {
        self
    }

    fn device_attempts(&self) -> &dyn DeviceAttemptRepo {
        self
    }

    fn login_transactions(&self) -> &dyn LoginTransactionRepo {
        self
    }

    fn pending_bindings(&self) -> &dyn PendingBindingRepo {
        self
    }

    fn approval_tickets(&self) -> &dyn ApprovalTicketRepo {
        self
    }

    fn consents(&self) -> &dyn ConsentRepo {
        self
    }

    fn pending_authorizations(&self) -> &dyn PendingAuthorizationRepo {
        self
    }
}
