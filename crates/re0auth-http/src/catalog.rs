//! Machine-readable catalog of the configured upstream resources.
//!
//! `openapi.json` is static, but `[[connectors]]` is deployment configuration.
//! This catalog is the runtime bridge: it names every resource, its public path,
//! its required scope, and the schema that the normalized `data` field follows.

use serde::Serialize;
use serde_json::Value;
use utoipa::{PartialSchema, ToSchema};

#[derive(Clone, Debug, Default, Serialize, ToSchema)]
pub struct Catalog {
    pub connectors: Vec<CatalogConnector>,
}

impl Catalog {
    #[must_use]
    pub fn new(connectors: Vec<CatalogConnector>) -> Self {
        Self { connectors }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.connectors.is_empty()
    }

    #[must_use]
    pub fn contains(&self, connector: &str, resource: &str) -> bool {
        self.connectors.iter().any(|entry| {
            entry.id == connector && entry.resources.iter().any(|item| item.name == resource)
        })
    }
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CatalogConnector {
    pub id: String,
    /// Label for people; `id` remains the key in URLs and bindings.
    pub display_name: String,
    /// Whether this deployment exposes a binding flow for the connector.
    pub bindable: bool,
    /// Whether the connector may appear in the public OpenAPI document.
    pub openapi_public: bool,
    pub resources: Vec<CatalogResource>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CatalogResource {
    pub name: String,
    /// The public downstream method. The gateway always exposes GET; the
    /// upstream method is an implementation detail.
    pub method: String,
    pub upstream_method: String,
    pub scope: String,
    pub path: String,
    pub raw_path: String,
    /// Name of the schema in `openapi.json` components, if one is declared.
    pub data_schema: Option<String>,
    /// Where the schema can be fetched directly, if one is declared.
    pub schema_url: Option<String>,
    pub params: Vec<CatalogParam>,
    pub paginated: bool,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CatalogParam {
    pub name: String,
    #[serde(rename = "in")]
    pub location: String,
    pub upstream: String,
    pub kind: String,
    pub required: bool,
    pub min_len: Option<usize>,
    pub max_len: Option<usize>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub values: Vec<String>,
    /// Whether the caller repeats the key to supply a set.
    pub array: bool,
    /// Member cap for arrays.
    pub max_items: Option<usize>,
}

/// Maps a configured connector/resource pair to the OpenAPI data model.
///
/// This is deliberately documentation metadata, not request routing: the
/// broker remains connector-agnostic. A resource without a known model still
/// appears in the catalog with `data_schema: null`.
#[must_use]
pub fn schema_name(connector: &str, resource: &str) -> Option<&'static str> {
    match (connector, resource) {
        ("phihub", "save_info") => Some("PhihubSaveInfoData"),
        ("phihub", "save") => Some("PhihubSaveData"),
        ("phihub", "history") => Some("PhihubHistoryData"),
        ("phihub", "song") => Some("PhihubSongData"),
        ("phihub", "history_v3") => Some("PhihubHistoryV3Data"),
        ("phihub", "record_v3") => Some("PhihubRecordV3Data"),
        ("phihub", "record_v4") => Some("PhihubRecordV4Data"),
        ("phigros-query", "save") => Some("PhigrosQuerySaveData"),
        ("phigros-query", "save_rks") => Some("PhigrosQuerySaveRksData"),
        _ => None,
    }
}

/// Returns the concrete OpenAPI schema for one resource's `data` field.
#[must_use]
pub fn schema_json(connector: &str, resource: &str) -> Option<Value> {
    let name = schema_name(connector, resource)?;
    let schema = match name {
        "PhihubSaveInfoData" => schema_value::<re0auth_app::upstream_models::PhihubSaveInfoData>(),
        "PhihubSaveData" => schema_value::<re0auth_app::upstream_models::PhihubSaveData>(),
        "PhihubHistoryData" => schema_value::<re0auth_app::upstream_models::PhihubHistoryData>(),
        "PhihubSongData" => schema_value::<re0auth_app::upstream_models::PhihubSongData>(),
        "PhihubHistoryV3Data" => {
            schema_value::<re0auth_app::upstream_models::PhihubHistoryV3Data>()
        }
        "PhihubRecordV3Data" => {
            schema_value::<re0auth_app::upstream_models::PhihubRecordV3Data>()
        }
        "PhihubRecordV4Data" => {
            schema_value::<re0auth_app::upstream_models::PhihubRecordV4Data>()
        }
        "PhigrosQuerySaveData" => {
            schema_value::<re0auth_app::upstream_models::PhigrosQuerySaveData>()
        }
        "PhigrosQuerySaveRksData" => {
            schema_value::<re0auth_app::upstream_models::PhigrosQuerySaveRksData>()
        }
        _ => return None,
    };
    Some(schema)
}

fn schema_value<T: PartialSchema>() -> Value {
    serde_json::to_value(T::schema()).expect("a derived schema serialises")
}

#[cfg(test)]
mod tests {
    use super::{Catalog, CatalogConnector, CatalogResource, schema_json, schema_name};

    #[test]
    fn catalog_resources_are_named_in_the_public_contract() {
        let catalog = Catalog::new(vec![CatalogConnector {
            id: "phigros-query".to_string(),
            display_name: "Phigros Query".to_string(),
            bindable: true,
            openapi_public: true,
            resources: vec![CatalogResource {
                name: "save".to_string(),
                method: "get".to_string(),
                upstream_method: "post".to_string(),
                scope: "phigros.query.save.read".to_string(),
                path: "/api/v1/upstreams/phigros-query/save".to_string(),
                raw_path: "/api/v1/raw/phigros-query/save".to_string(),
                data_schema: Some("PhigrosQuerySaveData".to_string()),
                schema_url: Some("/api/v1/upstreams/phigros-query/save/schema".to_string()),
                params: Vec::new(),
                paginated: false,
            }],
        }]);
        assert_eq!(catalog.connectors[0].resources[0].name, "save");
        assert!(catalog.contains("phigros-query", "save"));
        assert!(!catalog.contains("phigros-query", "unknown"));
        assert_eq!(
            schema_name("phigros-query", "save"),
            Some("PhigrosQuerySaveData")
        );
        let save_schema = schema_json("phigros-query", "save").expect("schema");
        assert!(save_schema.get("properties").is_some());
        assert!(schema_json("phigros-query", "unknown").is_none());
    }
}
