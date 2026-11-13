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
    /// The public response representation: `json` or `binary`.
    pub response: String,
    /// Media types accepted and emitted by a binary resource.
    pub content_types: Vec<String>,
    /// Per-resource binary body cap, when configured.
    pub max_bytes: Option<u64>,
    /// Whether the resource uses a binding-free shared cache key.
    pub shared: bool,
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
        ("phihub", "info_file") => Some("PhihubInfoFileData"),
        ("phihub", "info_file_version") => Some("PhihubInfoFileVersionData"),
        ("phihub", "player_ids") => Some("PhihubPlayerIdsData"),
        ("phihub", "rank_by_rank") => Some("PhihubRankData"),
        ("phihub", "rank_by_rks") => Some("PhihubRksRankData"),
        ("phihub", "rank_stats") => Some("PhihubRankStatsData"),
        ("phihub", "rank_summary") => Some("PhihubRankSummaryData"),
        ("phihub", "song_acc_avg") => Some("PhihubSongAccAvgData"),
        ("phihub", "all_acc_avg") => Some("PhihubAllAccAvgData"),
        ("phihub", "all_acc_avg_dual") => Some("PhihubAllAccAvgDualData"),
        ("phihub", "all_acc_avg_b30") => Some("PhihubAllAccAvgData"),
        ("phihub", "tags_by_song_rank") => Some("PhihubTagCountsData"),
        ("phihub", "comments_by_song") => Some("PhihubCommentsData"),
        ("phihub", "tag_tree") => Some("PhihubTagTreeData"),
        ("phihub", "aliases") => Some("PhihubAliasPage"),
        ("phihub", "aliases_resolve") => Some("PhihubAliasPage"),
        ("phihub", "aliases_list") => Some("PhihubAliasPage"),
        ("phihub", "tag_names") => Some("PhihubTagNamesData"),
        ("phigros-query", "verify_public_key") => Some("PhigrosVerifyPublicKeyData"),
        ("phigros-query", "stats_summary") => Some("PhigrosStatsSummaryData"),
        ("phigros-query", "leaderboard_top") => Some("PhigrosLeaderboardPage"),
        ("phigros-query", "leaderboard_by_rank") => Some("PhigrosLeaderboardPage"),
        ("phigros-query", "songs_search") => Some("PhigrosSongSearchPage"),
        ("phigros-query", "songs_search_unique") => Some("PhigrosSongInfo"),
        ("phihub", "rank_detail") => Some("PhihubRankDetailData"),
        ("phihub", "song_acc_list") => Some("PhihubSongAccListData"),
        ("lxns", "player") => Some("LxnsPlayerData"),
        ("lxns", "scores") => Some("LxnsScorePage"),
        ("lxns", "user_profile") => Some("LxnsUserProfileData"),
        ("lxns", "bests") => Some("LxnsBestsData"),
        ("lxns", "song_list") => Some("LxnsSongListData"),
        ("lxns", "alias_list") => Some("LxnsAliasListData"),
        ("lxns", "trend") => Some("LxnsRatingTrendData"),
        ("lxns", "heatmap") => Some("LxnsHeatmapData"),
        ("lxns", "score_history") => Some("LxnsScoreHistoryData"),
        ("lxns", "score_ranking") => Some("LxnsRankingScorePage"),
        ("lxns", "collections") => Some("LxnsCollectionListData"),
        ("lxns", "collection") => Some("LxnsCollection"),
        ("diving-fish", "records") => Some("DivingFishRecordsData"),
        ("diving-fish", "query_player") => Some("DivingFishQueryPlayerData"),
        ("diving-fish", "music_data") => Some("DivingFishMusicData"),
        ("diving-fish", "player_record") => Some("DivingFishPlayerRecordData"),
        ("diving-fish", "player_plate") => Some("DivingFishPlateData"),
        ("diving-fish", "rating_ranking") => Some("DivingFishRatingRankingData"),
        ("diving-fish", "chart_stats") => Some("DivingFishChartStatsData"),
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
        "PhihubRecordV3Data" => schema_value::<re0auth_app::upstream_models::PhihubRecordV3Data>(),
        "PhihubRecordV4Data" => schema_value::<re0auth_app::upstream_models::PhihubRecordV4Data>(),
        "PhigrosQuerySaveData" => {
            schema_value::<re0auth_app::upstream_models::PhigrosQuerySaveData>()
        }
        "PhigrosQuerySaveRksData" => {
            schema_value::<re0auth_app::upstream_models::PhigrosQuerySaveRksData>()
        }
        "PhihubInfoFileData" => schema_value::<re0auth_app::upstream_models::PhihubInfoFileData>(),
        "PhihubInfoFileVersionData" => {
            schema_value::<re0auth_app::upstream_models::PhihubInfoFileVersionData>()
        }
        "PhihubPlayerIdsData" => {
            schema_value::<re0auth_app::upstream_models::PhihubPlayerIdsData>()
        }
        "PhihubRankData" => schema_value::<re0auth_app::upstream_models::PhihubRankData>(),
        "PhihubRksRankData" => schema_value::<re0auth_app::upstream_models::PhihubRksRankData>(),
        "PhihubRankStatsData" => {
            schema_value::<re0auth_app::upstream_models::PhihubRankStatsData>()
        }
        "PhihubSongAccAvgData" => {
            schema_value::<re0auth_app::upstream_models::PhihubSongAccAvgData>()
        }
        "PhihubAllAccAvgData" => {
            schema_value::<re0auth_app::upstream_models::PhihubAllAccAvgData>()
        }
        "PhihubAllAccAvgDualData" => {
            schema_value::<re0auth_app::upstream_models::PhihubAllAccAvgDualData>()
        }
        "PhihubTagCountsData" => {
            schema_value::<re0auth_app::upstream_models::PhihubTagCountsData>()
        }
        "PhihubCommentsData" => schema_value::<re0auth_app::upstream_models::PhihubCommentsData>(),
        "PhihubTagTreeData" => schema_value::<re0auth_app::upstream_models::PhihubTagTreeData>(),
        "PhihubAliasPage" => schema_value::<re0auth_app::upstream_models::PhihubAliasPage>(),
        "PhihubRankSummaryData" => {
            schema_value::<re0auth_app::upstream_models::PhihubRankSummaryData>()
        }
        "PhihubTagNamesData" => schema_value::<re0auth_app::upstream_models::PhihubTagNamesData>(),
        "PhigrosVerifyPublicKeyData" => {
            schema_value::<re0auth_app::upstream_models::PhigrosVerifyPublicKeyData>()
        }
        "PhigrosStatsSummaryData" => {
            schema_value::<re0auth_app::upstream_models::PhigrosStatsSummaryData>()
        }
        "PhigrosLeaderboardPage" => {
            schema_value::<re0auth_app::upstream_models::PhigrosLeaderboardPage>()
        }
        "PhigrosSongSearchPage" => {
            schema_value::<re0auth_app::upstream_models::PhigrosSongSearchPage>()
        }
        "PhigrosSongInfo" => schema_value::<re0auth_app::upstream_models::PhigrosSongInfo>(),
        "PhihubRankDetailData" => {
            schema_value::<re0auth_app::upstream_models::PhihubRankDetailData>()
        }
        "PhihubSongAccListData" => {
            schema_value::<re0auth_app::upstream_models::PhihubSongAccListData>()
        }
        "LxnsPlayerData" => schema_value::<re0auth_app::upstream_models::LxnsPlayerData>(),
        "LxnsScorePage" => schema_value::<re0auth_app::upstream_models::LxnsScorePage>(),
        "LxnsUserProfileData" => {
            schema_value::<re0auth_app::upstream_models::LxnsUserProfileData>()
        }
        "LxnsBestsData" => schema_value::<re0auth_app::upstream_models::LxnsBestsData>(),
        "LxnsSongListData" => schema_value::<re0auth_app::upstream_models::LxnsSongListData>(),
        "LxnsAliasListData" => schema_value::<re0auth_app::upstream_models::LxnsAliasListData>(),
        "LxnsRatingTrendData" => {
            schema_value::<re0auth_app::upstream_models::LxnsRatingTrendData>()
        }
        "LxnsHeatmapData" => schema_value::<re0auth_app::upstream_models::LxnsHeatmapData>(),
        "LxnsScoreHistoryData" => {
            schema_value::<re0auth_app::upstream_models::LxnsScoreHistoryData>()
        }
        "LxnsRankingScorePage" => {
            schema_value::<re0auth_app::upstream_models::LxnsRankingScorePage>()
        }
        "LxnsCollectionListData" => {
            schema_value::<re0auth_app::upstream_models::LxnsCollectionListData>()
        }
        "LxnsCollection" => schema_value::<re0auth_app::upstream_models::LxnsCollection>(),
        "DivingFishRecordsData" => {
            schema_value::<re0auth_app::upstream_models::DivingFishRecordsData>()
        }
        "DivingFishQueryPlayerData" => {
            schema_value::<re0auth_app::upstream_models::DivingFishQueryPlayerData>()
        }
        "DivingFishMusicData" => {
            schema_value::<re0auth_app::upstream_models::DivingFishMusicData>()
        }
        "DivingFishPlayerRecordData" => {
            schema_value::<re0auth_app::upstream_models::DivingFishPlayerRecordData>()
        }
        "DivingFishPlateData" => {
            schema_value::<re0auth_app::upstream_models::DivingFishPlateData>()
        }
        "DivingFishRatingRankingData" => {
            schema_value::<re0auth_app::upstream_models::DivingFishRatingRankingData>()
        }
        "DivingFishChartStatsData" => {
            schema_value::<re0auth_app::upstream_models::DivingFishChartStatsData>()
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
                scope: "phigros.xtower.read".to_string(),
                path: "/api/v1/upstreams/phigros-query/save".to_string(),
                raw_path: "/api/v1/raw/phigros-query/save".to_string(),
                data_schema: Some("PhigrosQuerySaveData".to_string()),
                schema_url: Some("/api/v1/upstreams/phigros-query/save/schema".to_string()),
                response: "json".to_string(),
                content_types: Vec::new(),
                max_bytes: None,
                shared: false,
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

    #[test]
    fn public_batch_resources_declare_a_schema() {
        for (connector, resource) in [
            ("phihub", "info_file"),
            ("phihub", "info_file_version"),
            ("phihub", "player_ids"),
            ("phihub", "rank_by_rank"),
            ("phihub", "rank_by_rks"),
            ("phihub", "rank_stats"),
            ("phihub", "song_acc_avg"),
            ("phihub", "all_acc_avg"),
            ("phihub", "all_acc_avg_dual"),
            ("phihub", "all_acc_avg_b30"),
            ("phihub", "tags_by_song_rank"),
            ("phihub", "comments_by_song"),
            ("phihub", "tag_tree"),
            ("phihub", "aliases"),
            ("phihub", "aliases_resolve"),
            ("phihub", "aliases_list"),
            ("phihub", "rank_summary"),
            ("phihub", "tag_names"),
            ("phigros-query", "verify_public_key"),
            ("phigros-query", "stats_summary"),
            ("phigros-query", "leaderboard_top"),
            ("phigros-query", "leaderboard_by_rank"),
            ("phigros-query", "songs_search"),
            ("phigros-query", "songs_search_unique"),
            ("phihub", "rank_detail"),
            ("phihub", "song_acc_list"),
            ("lxns", "player"),
            ("lxns", "scores"),
            ("lxns", "user_profile"),
            ("lxns", "bests"),
            ("lxns", "song_list"),
            ("lxns", "alias_list"),
            ("lxns", "trend"),
            ("lxns", "heatmap"),
            ("lxns", "score_history"),
            ("lxns", "score_ranking"),
            ("lxns", "collections"),
            ("lxns", "collection"),
            ("diving-fish", "records"),
            ("diving-fish", "query_player"),
            ("diving-fish", "music_data"),
            ("diving-fish", "player_record"),
            ("diving-fish", "player_plate"),
            ("diving-fish", "rating_ranking"),
            ("diving-fish", "chart_stats"),
        ] {
            assert!(
                schema_name(connector, resource).is_some(),
                "{connector}/{resource} has no schema name"
            );
            assert!(
                schema_json(connector, resource).is_some(),
                "{connector}/{resource} has no schema document"
            );
        }
        assert_eq!(
            schema_json("phihub", "info_file").expect("schema")["type"],
            "object"
        );
        assert_eq!(
            schema_json("phihub", "player_ids").expect("schema")["type"],
            "array"
        );
    }
}
