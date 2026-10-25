use re0auth_contract::{
    MemoryStore, admin_query_contract, approval_ticket_contract, audit_contract,
    auth_code_contract, binding_contract, client_contract, consent_contract,
    device_attempt_contract, device_code_contract, login_transaction_contract,
    pending_authorization_contract, refresh_token_contract, session_contract,
    storage_contract_suite, user_contract,
};

#[tokio::test]
async fn memory_store_passes_user_contract() {
    user_contract(&MemoryStore::new()).await;
}

#[tokio::test]
async fn memory_store_passes_session_contract() {
    session_contract(&MemoryStore::new()).await;
}

#[tokio::test]
async fn memory_store_passes_auth_code_contract() {
    auth_code_contract(&MemoryStore::new()).await;
}

#[tokio::test]
async fn memory_store_passes_refresh_token_contract() {
    refresh_token_contract(&MemoryStore::new()).await;
}

#[tokio::test]
async fn memory_store_passes_login_transaction_contract() {
    login_transaction_contract(&MemoryStore::new()).await;
}

#[tokio::test]
async fn memory_store_passes_approval_ticket_contract() {
    approval_ticket_contract(&MemoryStore::new()).await;
}

#[tokio::test]
async fn memory_store_passes_consent_contract() {
    consent_contract(&MemoryStore::new()).await;
}

#[tokio::test]
async fn memory_store_passes_pending_authorization_contract() {
    pending_authorization_contract(&MemoryStore::new()).await;
}

#[tokio::test]
async fn memory_store_passes_device_code_contract() {
    device_code_contract(&MemoryStore::new()).await;
}

#[tokio::test]
async fn memory_store_passes_device_attempt_contract() {
    device_attempt_contract(&MemoryStore::new()).await;
}

#[tokio::test]
async fn memory_store_passes_binding_contract() {
    binding_contract(&MemoryStore::new()).await;
}

#[tokio::test]
async fn memory_store_passes_audit_contract() {
    audit_contract(&MemoryStore::new()).await;
}

#[tokio::test]
async fn memory_store_passes_admin_query_contract() {
    admin_query_contract(&MemoryStore::new()).await;
}

#[tokio::test]
async fn memory_store_passes_client_contract() {
    client_contract(&MemoryStore::new()).await;
}

#[tokio::test]
async fn memory_store_passes_the_full_storage_contract() {
    storage_contract_suite(&MemoryStore::new()).await;
}
