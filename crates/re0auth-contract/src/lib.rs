#![forbid(unsafe_code)]

//! Generic storage contract suite.
//!
//! A storage adapter is only complete when it passes every suite here. The
//! in-memory implementation is the reference implementation and the suite's
//! own regression test.
//!
//! An adapter adds one dev-dependency and one test:
//!
//! ```ignore
//! #[tokio::test]
//! async fn sqlite_passes_storage_contract() {
//!     let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
//!     re0auth_contract::storage_contract_suite(&store).await;
//! }
//! ```

pub mod cache;
pub mod connector;
pub mod memory;
pub mod memory_cache;
pub mod suite;

pub use cache::cache_contract_suite;
pub use memory_cache::{ClockedCache, MemoryCache};

pub use connector::{
    ConnectorFixture, MemorySecretStore, MockConnector, MockSealer, connector_contract_suite,
    connector_secret_store_contract, secret_sealer_contract,
};
pub use memory::MemoryStore;
pub use suite::{
    admin_query_contract, approval_ticket_contract, audit_contract, auth_code_contract,
    binding_contract, client_contract, consent_contract, device_attempt_contract,
    device_code_contract, login_transaction_contract, pending_authorization_contract,
    pending_binding_contract, refresh_token_contract, revoke_all_for_client_contract,
    session_contract, storage_contract_suite, user_contract,
};
