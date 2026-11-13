//! The OpenAPI document.
//!
//! Derived by `utoipa` from the handlers' own attributes, never written by hand:
//! a path that existed only here would be a second copy of the router.
//! `the_openapi_document_matches_the_router` (archtest) compares this document
//! with `re0auth_http::router()`, so a route added without a declaration fails
//! the build instead of drifting.

use std::fmt::Write as _;

use axum::Json;
use axum::extract::State;
use serde_json::{Map, Value, json};
use utoipa::OpenApi;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, Http, HttpAuthScheme, SecurityScheme};

use crate::catalog::{Catalog, CatalogParam};
use crate::routes::{device, gateway, oauth, session};
use crate::{AppState, admin, binding_routes};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Re0Auth",
        version = env!("CARGO_PKG_VERSION"),
        description = "OAuth 2.0 authorization server plus the music-data gateway it fronts. Two error shapes coexist: the OAuth protocol lanes answer the RFC 6749 flat form, everything else answers RFC 9457 problem details whose stable identifier is code."
    ),
    paths(
        crate::healthz,
        crate::readyz,
        crate::metrics::endpoint,
        session::providers,
        session::login,
        session::auth_callback,
        session::me,
        session::delete_account,
        session::detach_identity,
        session::identities,
        session::begin_identity_attach,
        session::authorizations,
        session::revoke_authorization,
        session::logout,
        session::logout_all,
        binding_routes::begin,
        binding_routes::upstreams,
        binding_routes::complete,
        binding_routes::bindings,
        binding_routes::revoke_binding,
        binding_routes::revoke_all_bindings,
        oauth::discovery,
        oauth::jwks,
        oauth::authorize,
        oauth::authorize_post,
        oauth::oauth_pending,
        oauth::oauth_consent,
        oauth::device_authorization,
        oauth::token,
        oauth::introspect,
        oauth::userinfo,
        oauth::userinfo_post,
        oauth::revoke,
        device::device_start,
        device::device_qr,
        device::device_approve,
        device::device_deny,
        serve_document,
        gateway::list_upstreams,
        gateway::resource_schema,
        gateway::fetch_upstream,
        gateway::fetch_asset,
        gateway::fetch_raw,
        admin::stats,
        admin::list_clients,
        admin::create_client,
        admin::get_client,
        admin::update_client,
        admin::rotate_client_secret,
        admin::list_users,
        admin::update_user,
        admin::list_connectors,
        admin::get_connector,
        admin::list_bindings,
        admin::revoke_binding,
        admin::killswitch,
        admin::list_audit,
    ),
    components(schemas(
        crate::ProblemBody,
        crate::OAuthErrorBody,
        session::ProvidersResponse,
        session::MeView,
        session::MeUserView,
        session::IdentityView,
        session::AttachBody,
        session::AttachStartView,
        binding_routes::BeginBody,
        binding_routes::BeginView,
        binding_routes::BindableUpstreamsView,
        binding_routes::BindableUpstreamView,
        oauth::ConsentBody,
        oauth::DiscoveryDocument,
        oauth::JwksDocument,
        oauth::DeviceAuthorizationForm,
        oauth::TokenForm,
        oauth::RevokeForm,
        device::DeviceDecisionForm,
        admin::CreateClientBody,
        admin::UpdateClientBody,
        admin::UpdateUserBody,
        admin::KillswitchBody,
        re0auth_app::auth::ProviderView,
        re0auth_app::auth::AuthorizationView,
        re0auth_app::auth::BindingView,
        re0auth_app::auth::BindingRevocationSummary,
        re0auth_app::auth::FailedRevocation,
        re0auth_app::oauth::PendingConsentView,
        re0auth_app::oauth::ConsentOutcome,
        re0auth_app::oauth::TokenResponse,
        re0auth_app::oauth::UserInfo,
        re0auth_app::oauth::DeviceAuthorizationResponse,
        re0auth_app::admin_service::AdminClientView,
        re0auth_app::admin_service::AdminUserView,
        re0auth_app::admin_service::AdminResourceView,
        re0auth_app::admin_service::AdminConnectorView,
        re0auth_app::admin_service::AdminBindingView,
        re0auth_app::admin_service::AdminAuditView,
        re0auth_app::admin_service::CreatedClientView,
        re0auth_app::admin_service::RotatedSecretView,
        re0auth_app::gateway::Envelope,
        re0auth_app::gateway::PageBody,
        crate::catalog::Catalog,
        crate::catalog::CatalogConnector,
        crate::catalog::CatalogResource,
        re0auth_app::upstream_models::UpstreamData,
        re0auth_app::upstream_models::PhihubSaveInfoData,
        re0auth_app::upstream_models::PhihubSaveData,
        re0auth_app::upstream_models::PhihubHistoryData,
        re0auth_app::upstream_models::PhihubSongData,
        re0auth_app::upstream_models::PhihubHistoryV3Data,
        re0auth_app::upstream_models::PhihubRksPoint,
        re0auth_app::upstream_models::PhihubChallengeRankPoint,
        re0auth_app::upstream_models::PhihubClearCountPoint,
        re0auth_app::upstream_models::PhihubRecordV3Data,
        re0auth_app::upstream_models::PhihubRecordV4Data,
        re0auth_app::upstream_models::PhihubRecordV4Payload,
        re0auth_app::upstream_models::PhigrosQuerySaveData,
        re0auth_app::upstream_models::PhigrosQuerySaveRksData,
        re0auth_app::upstream_models::PhigrosQueryParsedSave,
        re0auth_app::upstream_models::PhigrosDifficultyRecord,
        re0auth_app::upstream_models::PhigrosDifficulty,
        re0auth_app::upstream_models::PhigrosPushAccHint,
        re0auth_app::upstream_models::PhigrosGameProgress,
        re0auth_app::upstream_models::PhigrosUser,
        re0auth_app::upstream_models::PhigrosSettings,
        re0auth_app::upstream_models::PhigrosSummary,
        re0auth_app::upstream_models::PhigrosGameKey,
        re0auth_app::upstream_models::PhigrosPlayerRks,
        re0auth_app::upstream_models::PhigrosChartRankingScore,
        re0auth_app::upstream_models::PhigrosGradeCounts,
        re0auth_app::upstream_models::PhigrosCfcPCounts,
        re0auth_app::upstream_models::PhihubInfoFileData,
        re0auth_app::upstream_models::PhihubChartInfo,
        re0auth_app::upstream_models::PhihubChartDifficulty,
        re0auth_app::upstream_models::PhihubInfoFileVersionData,
        re0auth_app::upstream_models::PhihubPlayerIdsData,
        re0auth_app::upstream_models::PhihubPlayerId,
        re0auth_app::upstream_models::PhihubRankData,
        re0auth_app::upstream_models::PhihubRankSummaryData,
        re0auth_app::upstream_models::PhihubRksRankData,
        re0auth_app::upstream_models::PhihubRankStatsData,
        re0auth_app::upstream_models::PhihubSongAccAvgData,
        re0auth_app::upstream_models::PhihubAllAccAvgData,
        re0auth_app::upstream_models::PhihubAllAccAvgDualData,
        re0auth_app::upstream_models::PhihubTagCountsData,
        re0auth_app::upstream_models::PhihubAccAvg,
        re0auth_app::upstream_models::PhihubCommentsData,
        re0auth_app::upstream_models::PhihubComment,
        re0auth_app::upstream_models::PhihubTagTreeData,
        re0auth_app::upstream_models::PhihubTagNode,
        re0auth_app::upstream_models::PhihubAliasPage,
        re0auth_app::upstream_models::PhihubAliasItem,
        re0auth_app::upstream_models::PhihubTagNamesData,
        re0auth_app::upstream_models::PhihubRankUser,
        re0auth_app::upstream_models::PhihubRankGameUser,
        re0auth_app::upstream_models::PhihubRankSaveInfo,
        re0auth_app::upstream_models::PhihubRankSummary,
        re0auth_app::upstream_models::PhihubRankModifiedAt,
        re0auth_app::upstream_models::PhigrosVerifyPublicKeyData,
        re0auth_app::upstream_models::PhigrosStatsSummaryData,
        re0auth_app::upstream_models::PhigrosFeatureUsage,
        re0auth_app::upstream_models::PhigrosLeaderboardPage,
        re0auth_app::upstream_models::PhigrosLeaderboardItem,
        re0auth_app::upstream_models::PhigrosChartText,
        re0auth_app::upstream_models::PhigrosSongInfo,
        re0auth_app::upstream_models::PhigrosSongSearchPage,
        re0auth_app::upstream_models::PhihubRankDetailData,
        re0auth_app::upstream_models::PhihubRankDetailSummary,
        re0auth_app::upstream_models::PhihubSongAccListData,
    ))
)]
pub struct ApiDoc;

/// `GET /openapi.json`: the deployment-specific document.
#[utoipa::path(
    get,
    path = "/openapi.json",
    tag = "gateway",
    responses((status = 200, description = "The deployment-specific OpenAPI document."))
)]
pub(crate) async fn serve_document(State(state): State<AppState>) -> Json<Value> {
    let base = serde_json::to_value(document()).expect("the document serialises");
    Json(augment_document(base, &state.catalog))
}

/// Adds one concrete GET path per public resource and removes the generic
/// wildcard paths so strict OpenAPI consumers never see both shapes.
#[must_use]
pub(crate) fn augment_document(mut base: Value, catalog: &Catalog) -> Value {
    let Some(paths) = base.get_mut("paths").and_then(Value::as_object_mut) else {
        return base;
    };
    paths.remove("/api/v1/upstreams/{connector}/{resource}");
    paths.remove("/api/v1/raw/{connector}/{resource}");
    paths.remove("/api/v1/assets/{connector}/{resource}");

    for connector in &catalog.connectors {
        if !connector.openapi_public {
            continue;
        }
        for resource in &connector.resources {
            let mut parameters = Vec::new();
            for param in &resource.params {
                let mut entry = json!({
                    "name": param.name,
                    "in": "query",
                    "required": param.required,
                    "schema": param_schema(param),
                });
                if param.location == "path" {
                    entry["required"] = json!(true);
                    entry["description"] = json!(
                        "Substituted into the upstream path as one percent-encoded segment; supplied here as a query parameter."
                    );
                    entry["schema"]["type"] = json!("string");
                }
                if param.array {
                    // Repeated keys are the HTML form spelling: form + explode.
                    entry["style"] = json!("form");
                    entry["explode"] = json!(true);
                    let mut schema = json!({
                        "type": "array",
                        "items": param_schema(param),
                    });
                    if let Some(max) = param.max_items {
                        schema["maxItems"] = json!(max);
                    }
                    entry["schema"] = schema;
                }
                parameters.push(entry);
            }
            if resource.paginated && resource.response != "binary" {
                parameters.push(json!({
                    "name": "limit", "in": "query", "required": false,
                    "schema": {"type": "integer", "format": "int32", "minimum": 1, "maximum": 100}
                }));
                parameters.push(json!({
                    "name": "cursor", "in": "query", "required": false,
                    "schema": {"type": "string"}
                }));
            }
            let success = if resource.response == "binary" {
                let content = resource
                    .content_types
                    .iter()
                    .map(|content_type| {
                        (
                            content_type.clone(),
                            json!({"schema": {"type": "string", "format": "binary"}}),
                        )
                    })
                    .collect::<Map<String, Value>>();
                json!({"description": "The binary asset.", "content": content})
            } else {
                json!({"description": "The normalized envelope.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Envelope"}}}})
            };
            let mut operation = json!({
                "tags": ["gateway"],
                "summary": format!("Fetch {}/{}", connector.id, resource.name),
                "operationId": format!(
                    "fetch_upstream_{}_{}",
                    hex_name(&connector.id),
                    hex_name(&resource.name)
                ),
                "security": [{"bearer": []}],
                "parameters": parameters,
                "responses": {
                    "200": success,
                    "400": {"description": "Invalid request."},
                    "401": {"description": "Invalid or missing token."},
                    "403": {"description": "Insufficient scope or raw access."},
                    "404": {"description": "Unknown connector or resource."},
                    "502": {"description": "Upstream contract changed or unavailable."}
                }
            });
            if resource.response != "binary"
                && let Some(schema) = &resource.data_schema
            {
                operation
                    .as_object_mut()
                    .expect("operation is an object")
                    .insert(
                        "x-re0auth-data-schema".to_string(),
                        Value::String(format!("#/components/schemas/{schema}")),
                    );
            }
            paths.insert(resource.path.clone(), json!({"get": operation}));
        }
    }
    base
}

fn param_schema(param: &CatalogParam) -> Value {
    let mut schema = Map::new();
    match param.kind.as_str() {
        "string" => {
            schema.insert("type".to_string(), Value::String("string".into()));
            if let Some(min) = param.min_len {
                schema.insert("minLength".to_string(), json!(min));
            }
            if let Some(max) = param.max_len {
                schema.insert("maxLength".to_string(), json!(max));
            }
        }
        "enum" => {
            schema.insert("type".to_string(), Value::String("string".into()));
            schema.insert("enum".to_string(), json!(param.values));
        }
        "integer" => {
            schema.insert("type".to_string(), Value::String("integer".into()));
            if let Some(min) = param.min {
                schema.insert("minimum".to_string(), json!(min));
            }
            if let Some(max) = param.max {
                schema.insert("maximum".to_string(), json!(max));
            }
        }
        "number" => {
            schema.insert("type".to_string(), Value::String("number".into()));
            if let Some(min) = param.min {
                schema.insert("minimum".to_string(), json!(min));
            }
            if let Some(max) = param.max {
                schema.insert("maximum".to_string(), json!(max));
            }
        }
        "boolean" => {
            schema.insert("type".to_string(), Value::String("boolean".into()));
        }
        _ => {
            schema.insert("type".to_string(), Value::String("string".into()));
        }
    }
    Value::Object(schema)
}

fn hex_name(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value.bytes() {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

/// The document, built from the same declarations the router serves.
///
/// The two security schemes are added here rather than declared per operation
/// twice: `session` is the browser cookie, `bearer` is the gateway token. The
/// cookie is named `re0auth_session`; a deployment with secure cookies serves
/// the same cookie under the `__Host-` prefix, which browsers treat as a
/// different name, so the scheme documents the unprefixed one.
#[must_use]
pub fn document() -> utoipa::openapi::OpenApi {
    let mut document = ApiDoc::openapi();
    let components = document.components.get_or_insert_with(Default::default);
    components.add_security_scheme(
        "session",
        SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new("re0auth_session"))),
    );
    components.add_security_scheme(
        "bearer",
        SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
    );
    document
}

/// The document as it is committed: pretty JSON, path order preserved by the
/// `preserve_path_order` feature so a regenerated file diffs cleanly.
#[must_use]
pub fn render() -> String {
    let mut text = serde_json::to_string_pretty(&document()).expect("the document serialises");
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    fn committed_path() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("openapi.json")
    }

    /// The document must serialise: a spec that cannot be written is not a spec.
    #[test]
    fn the_document_serialises_with_its_paths() {
        let json = serde_json::to_value(super::document()).expect("the document serialises");
        let paths = json
            .get("paths")
            .and_then(|value| value.as_object())
            .expect("paths is an object");
        assert!(paths.contains_key("/api/me"), "the spec kept GET /api/me");
        assert!(
            json.get("components")
                .and_then(|value| value.get("schemas"))
                .and_then(|value| value.as_object())
                .is_some_and(|schemas| !schemas.is_empty()),
            "the spec carries component schemas"
        );
    }

    /// Every operation declares at least one response. An operation with none is
    /// a placeholder that tells a consumer nothing about what comes back.
    #[test]
    fn every_operation_declares_a_response() {
        let json = serde_json::to_value(super::document()).expect("the document serialises");
        let paths = json["paths"].as_object().expect("paths is an object");
        let mut bare = Vec::new();
        for (path, item) in paths {
            for (method, operation) in item.as_object().expect("a path item is an object") {
                let responses = operation
                    .get("responses")
                    .and_then(|value| value.as_object());
                if responses.is_none_or(|responses| responses.is_empty()) {
                    bare.push(format!("{} {}", method.to_uppercase(), path));
                }
            }
        }
        assert!(bare.is_empty(), "operations without responses: {bare:?}");
    }

    /// A committed spec that no longer matches the code is the same class of
    /// defect as a stale appendix: it reads as truth and is not. Regenerating is
    /// one command, and the failure message names it.
    #[test]
    fn the_committed_spec_matches_the_code() {
        let path = committed_path();
        let rendered = super::render();
        if std::env::var_os("UPDATE_OPENAPI").is_some() {
            std::fs::write(&path, &rendered).expect("write openapi.json");
            return;
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "cannot read {}: {error}. Regenerate with: \
                 UPDATE_OPENAPI=1 cargo test -p re0auth-http --lib openapi",
                path.display()
            )
        });
        if committed != rendered {
            let first = committed
                .lines()
                .zip(rendered.lines())
                .enumerate()
                .find(|(_, (a, b))| a != b)
                .map(|(index, (a, b))| (index + 1, a.to_string(), b.to_string()));
            panic!(
                "openapi.json is stale: the committed copy differs from the code.\n\
                 first difference at line {}\n  committed: {}\n  generated: {}\n\
                 Regenerate with: UPDATE_OPENAPI=1 cargo test -p re0auth-http --lib openapi",
                first.as_ref().map_or(0, |(line, _, _)| *line),
                first.as_ref().map_or("<none>", |(_, a, _)| a.as_str()),
                first.as_ref().map_or("<none>", |(_, _, b)| b.as_str()),
            );
        }
    }

    #[test]
    fn gateway_data_is_a_union_of_declared_models() {
        let json = serde_json::to_value(super::document()).expect("the document serialises");
        let envelope = &json["components"]["schemas"]["Envelope"]["properties"]["data"];
        assert_eq!(
            envelope["$ref"], "#/components/schemas/UpstreamData",
            "Envelope.data must point at the declared union"
        );
        let schemas = json["components"]["schemas"]
            .as_object()
            .expect("components schemas");
        for name in [
            "PhihubSaveInfoData",
            "PhihubSaveData",
            "PhihubHistoryData",
            "PhihubSongData",
            "PhihubHistoryV3Data",
            "PhihubRecordV3Data",
            "PhihubRecordV4Data",
            "PhigrosQuerySaveData",
            "PhigrosQuerySaveRksData",
            "PhihubInfoFileData",
            "PhihubInfoFileVersionData",
            "PhihubPlayerIdsData",
            "PhihubRankData",
            "PhihubRankSummaryData",
            "PhihubRksRankData",
            "PhihubRankStatsData",
            "PhihubSongAccAvgData",
            "PhihubAllAccAvgData",
            "PhihubAllAccAvgDualData",
            "PhihubTagCountsData",
            "PhihubCommentsData",
            "PhihubTagTreeData",
            "PhihubAliasPage",
            "PhihubTagNamesData",
            "PhigrosVerifyPublicKeyData",
            "PhigrosStatsSummaryData",
            "PhigrosLeaderboardPage",
            "PhigrosSongInfo",
            "PhigrosSongSearchPage",
            "PhihubRankDetailData",
            "PhihubSongAccListData",
            "LxnsPlayerData",
            "LxnsScorePage",
            "LxnsUserProfileData",
            "LxnsBestsData",
            "LxnsSongListData",
            "LxnsAliasListData",
            "LxnsRatingTrendData",
            "LxnsHeatmapData",
            "LxnsScoreHistoryData",
            "LxnsRankingScorePage",
            "LxnsCollectionListData",
            "LxnsCollection",
            "DivingFishRecordsData",
            "DivingFishQueryPlayerData",
            "DivingFishMusicData",
            "DivingFishPlayerRecordData",
            "DivingFishPlateData",
            "DivingFishRatingRankingData",
            "DivingFishChartStatsData",
        ] {
            assert!(schemas.contains_key(name), "missing schema {name}");
        }
        let union = &json["components"]["schemas"]["UpstreamData"]["oneOf"];
        assert_eq!(
            union.as_array().map(Vec::len),
            Some(51),
            "the union carries fifty resource models plus PageBody"
        );
    }

    #[test]
    fn the_deployment_document_exposes_only_public_concrete_paths() {
        use crate::catalog::{Catalog, CatalogConnector, CatalogParam, CatalogResource};

        let catalog = Catalog::new(vec![
            CatalogConnector {
                id: "phigros".to_string(),
                display_name: "Phigros Query".to_string(),
                bindable: true,
                openapi_public: true,
                resources: vec![
                    CatalogResource {
                        name: "save".to_string(),
                        method: "get".to_string(),
                        upstream_method: "post".to_string(),
                        scope: "phigros.save.read".to_string(),
                        path: "/api/v1/upstreams/phigros/save".to_string(),
                        raw_path: "/api/v1/raw/phigros/save".to_string(),
                        data_schema: Some("PhigrosQuerySaveData".to_string()),
                        schema_url: Some("/api/v1/upstreams/phigros/save/schema".to_string()),
                        response: "json".to_string(),
                        content_types: Vec::new(),
                        max_bytes: None,
                        shared: false,
                        params: vec![
                            CatalogParam {
                                name: "song_id".to_string(),
                                location: "query".to_string(),
                                upstream: "song_id".to_string(),
                                kind: "string".to_string(),
                                required: true,
                                min_len: Some(1),
                                max_len: Some(64),
                                min: None,
                                max: None,
                                values: Vec::new(),
                                array: false,
                                max_items: None,
                            },
                            CatalogParam {
                                name: "request".to_string(),
                                location: "query".to_string(),
                                upstream: "request".to_string(),
                                kind: "enum".to_string(),
                                required: false,
                                min_len: None,
                                max_len: None,
                                min: None,
                                max: None,
                                values: vec!["data".to_string(), "rks".to_string()],
                                array: true,
                                max_items: Some(8),
                            },
                            CatalogParam {
                                name: "song".to_string(),
                                location: "path".to_string(),
                                upstream: "song".to_string(),
                                kind: "string".to_string(),
                                required: true,
                                min_len: Some(1),
                                max_len: Some(64),
                                min: None,
                                max: None,
                                values: Vec::new(),
                                array: false,
                                max_items: None,
                            },
                        ],
                        paginated: true,
                    },
                    CatalogResource {
                        name: "jacket".to_string(),
                        method: "get".to_string(),
                        upstream_method: "get".to_string(),
                        scope: "phigros.jacket.read".to_string(),
                        path: "/api/v1/assets/phigros/jacket".to_string(),
                        raw_path: String::new(),
                        data_schema: None,
                        schema_url: None,
                        response: "binary".to_string(),
                        content_types: vec!["image/png".to_string(), "image/webp".to_string()],
                        max_bytes: Some(1_048_576),
                        shared: true,
                        params: Vec::new(),
                        paginated: true,
                    },
                ],
            },
            CatalogConnector {
                id: "private".to_string(),
                display_name: "private".to_string(),
                bindable: false,
                openapi_public: false,
                resources: Vec::new(),
            },
        ]);
        let document = super::augment_document(
            serde_json::to_value(super::document()).expect("document"),
            &catalog,
        );
        let paths = document["paths"].as_object().expect("paths");
        assert!(!paths.contains_key("/api/v1/upstreams/{connector}/{resource}"));
        assert!(!paths.contains_key("/api/v1/raw/{connector}/{resource}"));
        assert!(!paths.contains_key("/api/v1/assets/{connector}/{resource}"));
        let asset = &paths["/api/v1/assets/phigros/jacket"]["get"];
        let content = asset["responses"]["200"]["content"]
            .as_object()
            .expect("asset content");
        assert_eq!(content.len(), 2);
        for content_type in ["image/png", "image/webp"] {
            assert_eq!(
                content[content_type]["schema"],
                serde_json::json!({"type": "string", "format": "binary"})
            );
        }
        assert!(!content.contains_key("application/json"));
        assert!(!content.contains_key("application/octet-stream"));
        assert!(asset.get("x-re0auth-data-schema").is_none());
        let asset_parameters = asset["parameters"].as_array().expect("asset parameters");
        assert!(!asset_parameters.iter().any(|p| p["name"] == "limit"));
        assert!(!asset_parameters.iter().any(|p| p["name"] == "cursor"));
        let operation = &paths["/api/v1/upstreams/phigros/save"]["get"];
        assert_eq!(
            operation["operationId"],
            "fetch_upstream_70686967726f73_73617665"
        );
        assert_eq!(
            operation["x-re0auth-data-schema"],
            "#/components/schemas/PhigrosQuerySaveData"
        );
        let parameters = operation["parameters"].as_array().expect("parameters");
        assert!(parameters.iter().any(|p| p["name"] == "song_id"));
        assert_eq!(parameters[0]["schema"]["maxLength"], 64);
        assert!(parameters.iter().any(|p| p["name"] == "limit"));
        assert!(parameters.iter().any(|p| p["name"] == "cursor"));
        let request = parameters
            .iter()
            .find(|p| p["name"] == "request")
            .expect("request parameter");
        assert_eq!(request["style"], "form");
        assert_eq!(request["explode"], true);
        assert_eq!(request["schema"]["type"], "array");
        assert_eq!(request["schema"]["maxItems"], 8);
        assert_eq!(request["schema"]["items"]["type"], "string");
        assert_eq!(request["schema"]["items"]["enum"][0], "data");
        let song = parameters
            .iter()
            .find(|parameter| parameter["name"] == "song")
            .expect("dynamic path parameter");
        assert_eq!(song["in"], "query");
        assert_eq!(song["required"], true);
        assert_eq!(song["schema"]["type"], "string");
        assert!(
            song["description"]
                .as_str()
                .expect("path parameter description")
                .contains("upstream path")
        );
        assert!(!paths.keys().any(|path| path.contains("private")));
    }

    #[test]
    fn operation_ids_are_unambiguous_and_private_resources_are_hidden() {
        use crate::catalog::{Catalog, CatalogConnector, CatalogResource};

        fn resource(connector: &str, name: &str) -> CatalogResource {
            CatalogResource {
                name: name.to_string(),
                method: "get".to_string(),
                upstream_method: "get".to_string(),
                scope: format!("{connector}.read"),
                path: format!("/api/v1/upstreams/{connector}/{name}"),
                raw_path: format!("/api/v1/raw/{connector}/{name}"),
                data_schema: None,
                schema_url: None,
                response: "json".to_string(),
                content_types: Vec::new(),
                max_bytes: None,
                shared: false,
                params: Vec::new(),
                paginated: false,
            }
        }

        let catalog = Catalog::new(vec![
            CatalogConnector {
                id: "a".to_string(),
                display_name: "a".to_string(),
                bindable: false,
                openapi_public: true,
                resources: vec![resource("a", "bc")],
            },
            CatalogConnector {
                id: "ab".to_string(),
                display_name: "ab".to_string(),
                bindable: false,
                openapi_public: true,
                resources: vec![resource("ab", "c")],
            },
            CatalogConnector {
                id: "private".to_string(),
                display_name: "private".to_string(),
                bindable: false,
                openapi_public: false,
                resources: vec![resource("private", "save")],
            },
        ]);
        let document = super::augment_document(
            serde_json::to_value(super::document()).expect("document"),
            &catalog,
        );
        let paths = document["paths"].as_object().expect("paths");
        let first = &paths["/api/v1/upstreams/a/bc"]["get"]["operationId"];
        let second = &paths["/api/v1/upstreams/ab/c"]["get"]["operationId"];
        assert_ne!(
            first, second,
            "hex encoding must avoid simple concatenation collisions"
        );
        assert!(!paths.contains_key("/api/v1/upstreams/private/save"));
    }
}
