use re0auth_contract::{
    MemorySecretStore, MockConnector, MockSealer, connector_contract_suite,
    connector_secret_store_contract, secret_sealer_contract,
};

#[tokio::test]
async fn mock_connector_passes_the_contract_suite() {
    connector_contract_suite(&MockConnector::new()).await;
}

#[tokio::test]
async fn mock_secret_store_passes_the_contract_suite() {
    connector_secret_store_contract(&MemorySecretStore::default()).await;
}

#[test]
fn mock_sealer_passes_the_contract_suite() {
    secret_sealer_contract(&MockSealer::new());
}
