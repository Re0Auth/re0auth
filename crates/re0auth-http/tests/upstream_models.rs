//! The data models in the OpenAPI document must round-trip the shapes the
//! gateway actually stores in `Envelope.data`.
//!
//! These fixtures are DTO/view-derived when a production sample is unavailable:
//! `phihub_*` follows the upstream `saveInfo` / `saves` / `historyV4` JSON, and
//! `phigros_query_*` follows the parsed save DTO. A future production sample
//! should replace the fixture without changing the model.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

fn round_trip<T>(raw: &str)
where
    T: DeserializeOwned + Serialize,
{
    let expected: Value = serde_json::from_str(raw).expect("fixture is valid JSON");
    let typed: T = serde_json::from_value(expected.clone()).expect("fixture fits the model");
    assert_eq!(
        serde_json::to_value(typed).expect("model serialises"),
        expected,
        "model fields must match the fixture exactly"
    );
}

#[test]
fn phihub_models_match_their_payloads() {
    round_trip::<re0auth_app::upstream_models::PhihubSaveInfoData>(include_str!(
        "fixtures/upstream_models/phihub_save_info.json"
    ));
    round_trip::<re0auth_app::upstream_models::PhihubSaveData>(include_str!(
        "fixtures/upstream_models/phihub_save.json"
    ));
    round_trip::<re0auth_app::upstream_models::PhihubHistoryData>(include_str!(
        "fixtures/upstream_models/phihub_history.json"
    ));
}

#[test]
fn phigros_query_models_match_their_payloads() {
    round_trip::<re0auth_app::upstream_models::PhigrosQuerySaveData>(include_str!(
        "fixtures/upstream_models/phigros_query_save.json"
    ));
    round_trip::<re0auth_app::upstream_models::PhigrosQuerySaveRksData>(include_str!(
        "fixtures/upstream_models/phigros_query_save_rks.json"
    ));
}
