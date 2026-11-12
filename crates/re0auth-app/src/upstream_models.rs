//! OpenAPI-only data models for the connectors this deployment ships.
//!
//! These types describe the `data` field of the normalized envelope. They are
//! not used on the request path: the gateway still forwards the upstream JSON
//! byte-for-byte through the configured view. Keeping the models here gives
//! downstream OpenAPI consumers concrete field names without teaching the
//! broker about individual upstreams.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// One of the normalized data shapes exposed by `/api/v1/upstreams/*`.
#[derive(Serialize, ToSchema)]
#[serde(untagged)]
#[schema(title = "UpstreamData")]
pub enum UpstreamData {
    PhihubSaveInfo(PhihubSaveInfoData),
    PhihubSave(PhihubSaveData),
    PhihubHistory(PhihubHistoryData),
    PhihubSong(PhihubSongData),
    PhihubHistoryV3(PhihubHistoryV3Data),
    PhihubRecordV3(PhihubRecordV3Data),
    PhihubRecordV4(PhihubRecordV4Data),
    PhigrosQuerySave(PhigrosQuerySaveData),
    PhigrosQuerySaveRks(PhigrosQuerySaveRksData),
    PhihubInfoFileVersion(PhihubInfoFileVersionData),
    PhihubPlayerIds(PhihubPlayerIdsData),
    PhihubRank(PhihubRankData),
    PhigrosVerifyPublicKey(PhigrosVerifyPublicKeyData),
    PhigrosStatsSummary(PhigrosStatsSummaryData),
    PhigrosLeaderboard(PhigrosLeaderboardPage),
    Page(crate::gateway::PageBody),
}

// ---------------------------------------------------------------------------
// PhiHub
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubSaveInfoData {
    pub player_id: String,
    pub updated_at: String,
    pub rks: f64,
    pub challenge_mode_rank: u32,
    pub avatar: String,
    pub game_version: u32,
    pub save_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubSaveData {
    pub player_id: String,
    pub updated_at: String,
    pub rks: f64,
    pub challenge_mode_rank: u32,
    pub avatar: String,
    pub game_user: PhihubGameUser,
    pub records: HashMap<String, Vec<Option<PhihubRecord>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PhihubGameUser {
    pub name: String,
    pub version: u32,
    pub show_player_id: bool,
    pub self_intro: String,
    pub avatar: String,
    pub background: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubRecord {
    pub score: u32,
    pub acc: f64,
    pub fc: bool,
}

/// PhiHub's v4 history is date-bucket encoded; the exact bucket shape is
/// upstream-owned, so its arrays stay as JSON while the top-level fields are
/// declared.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubHistoryData {
    pub version: u32,
    pub timezone: String,
    pub rks: Vec<Value>,
    pub data: Vec<Value>,
    #[serde(rename = "challengeModeRank")]
    pub challenge_mode_rank: Vec<Value>,
    #[serde(rename = "scoreHistory")]
    pub score_history: HashMap<String, HashMap<String, Vec<Value>>>,
}

/// `POST /get/cloud/song`: every difficulty of one song, or one difficulty.
///
/// Upstream returns a four-slot array (missing difficulties are `null`) when
/// `difficulty` is absent, and a single record when it is present.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum PhihubSongData {
    All(Vec<Option<PhihubRecord>>),
    One(PhihubRecord),
}

/// One v3 history point whose value is the player's RKS.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubRksPoint {
    pub date: String,
    pub value: f64,
}

/// One v3 history point whose value is the challenge-mode rank.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubChallengeRankPoint {
    pub date: String,
    pub value: u32,
}

/// One v3 history point whose value is the five cleared/full-combo/phi counters.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubClearCountPoint {
    pub date: String,
    pub value: [u32; 5],
}

/// `POST /get/history/history`: the legacy v3 history document.
///
/// `score_history` rows are upstream-owned positional arrays
/// `[acc, score, date, full_combo]`; the bucket shape is not a JSON object, so
/// it stays `Value` rather than pretending to be a struct.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PhihubHistoryV3Data {
    pub challenge_mode_rank: Vec<PhihubChallengeRankPoint>,
    pub data: Vec<PhihubClearCountPoint>,
    pub rks: Vec<PhihubRksPoint>,
    pub score_history: HashMap<String, HashMap<String, Vec<Value>>>,
    pub version: u32,
}

/// `POST /get/history/record`: whole history, one song, or one difficulty's rows.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum PhihubRecordV3Data {
    /// Song id → difficulty → rows.
    All(HashMap<String, HashMap<String, Vec<Value>>>),
    /// Difficulty → rows.
    Song(HashMap<String, Vec<Value>>),
    /// Rows only.
    Rows(Vec<Value>),
}

/// `POST /get/history/recordV4`: the v4 envelope carries `version` and `timezone`
/// beside `data`, so the declared view keeps all three.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubRecordV4Data {
    pub data: Option<PhihubRecordV4Payload>,
    pub version: u32,
    pub timezone: String,
}

/// The v4 sibling of [`PhihubRecordV3Data`]; series are `dateValue` buckets.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum PhihubRecordV4Payload {
    /// Song id → difficulty → series.
    All(HashMap<String, HashMap<String, Vec<Value>>>),
    /// Difficulty → series.
    Song(HashMap<String, Vec<Value>>),
    /// One series.
    Series(Vec<Value>),
}

// ---------------------------------------------------------------------------
// Phigros Query
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosQuerySaveData {
    pub data: PhigrosQueryParsedSave,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosQuerySaveRksData {
    pub save: PhigrosQueryParsedSave,
    pub rks: PhigrosPlayerRks,
    #[serde(rename = "gradeCounts")]
    pub grade_counts: PhigrosGradeCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosQueryParsedSave {
    pub game_record: HashMap<String, Vec<PhigrosDifficultyRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub game_progress: Option<PhigrosGameProgress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<PhigrosUser>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<PhigrosSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub game_key: Option<PhigrosGameKey>,
    #[serde(rename = "summaryParsed", skip_serializing_if = "Option::is_none")]
    pub summary_parsed: Option<PhigrosSummary>,
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosDifficultyRecord {
    pub difficulty: PhigrosDifficulty,
    pub score: u32,
    pub accuracy: f64,
    pub is_full_combo: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chart_constant: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_acc: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_acc_hint: Option<PhigrosPushAccHint>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub enum PhigrosDifficulty {
    EZ,
    HD,
    IN,
    AT,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PhigrosPushAccHint {
    TargetAcc { acc: f64 },
    PhiOnly,
    Unreachable,
    AlreadyPhi,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosGameProgress {
    pub version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_first_run: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_chapter_finished: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub already_show_collection_tip: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub already_show_auto_unlock_in_tip: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub song_update_info: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_mode_rank: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub money: Option<[i32; 5]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlock_flag_of_spasmodic: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlock_flag_of_igallta: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlock_flag_of_rrharil: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flag_of_song_record_key: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub random_version_unlocked: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chapter8_unlock_begin: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chapter8_unlock_second_phase: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chapter8_passed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chapter8_song_unlocked: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flag_of_song_record_key_takumi: Option<[bool; 3]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overflow: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosUser {
    pub show_player_id: bool,
    pub self_intro: String,
    pub avatar: String,
    pub background: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosSettings {
    pub chord_support: bool,
    pub fc_ap_indicator: bool,
    pub enable_hit_sound: bool,
    pub low_resolution_mode: bool,
    pub device_name: String,
    pub bright: f64,
    pub music_volume: f64,
    pub effect_volume: f64,
    pub hit_sound_volume: f64,
    pub sound_offset: f64,
    pub note_scale: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosSummary {
    pub save_version: u8,
    pub challenge_mode_rank: u16,
    pub ranking_score: f64,
    pub game_version: u8,
    pub avatar: String,
    pub progress: [u16; 12],
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosGameKey {
    pub version: u8,
    pub keys: HashMap<String, Value>,
    pub lanota_read_keys: Option<u8>,
    pub camellia_read_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side_story4_begin_read_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_score_cleared_v390: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overflow: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PhigrosPlayerRks {
    pub total_rks: f64,
    pub b30_charts: Vec<PhigrosChartRankingScore>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PhigrosChartRankingScore {
    pub song_id: String,
    pub difficulty: PhigrosDifficulty,
    pub rks: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosGradeCounts {
    #[serde(rename = "EZ")]
    pub ez: PhigrosCfcPCounts,
    #[serde(rename = "HD")]
    pub hd: PhigrosCfcPCounts,
    #[serde(rename = "IN")]
    pub in_: PhigrosCfcPCounts,
    #[serde(rename = "AT")]
    pub at: PhigrosCfcPCounts,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub struct PhigrosCfcPCounts {
    #[serde(rename = "C")]
    pub c: u32,
    #[serde(rename = "FC")]
    pub fc: u32,
    #[serde(rename = "P")]
    pub p: u32,
}

// ---------------------------------------------------------------------------
// PhiHub: public catalog, player directory, and rank list
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubInfoFileVersionData {
    pub version: u64,
    pub version_code: u64,
    pub version_label: String,
    pub update_date: i64,
    pub whatsnew: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct PhihubPlayerIdsData(pub Vec<PhihubPlayerId>);

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubPlayerId {
    pub api_id: String,
    pub player_id: String,
    pub rks: f64,
    pub avatar: String,
    pub clg_mode: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubRankData {
    pub total: i64,
    pub users: Vec<PhihubRankUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubRankUser {
    pub gameuser: PhihubRankGameUser,
    #[serde(rename = "saveInfo")]
    pub save_info: PhihubRankSaveInfo,
    pub index: i64,
    pub me: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubRankGameUser {
    pub background: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubRankSaveInfo {
    pub summary: PhihubRankSummary,
    #[serde(rename = "modifiedAt")]
    pub modified_at: PhihubRankModifiedAt,
    #[serde(rename = "PlayerId")]
    pub player_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubRankSummary {
    #[serde(rename = "rankingScore")]
    pub ranking_score: f64,
    #[serde(rename = "challengeModeRank")]
    pub challenge_mode_rank: i64,
    pub avatar: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubRankModifiedAt {
    pub iso: String,
}

// ---------------------------------------------------------------------------
// Phigros Query: public metadata, stats, and leaderboard
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosVerifyPublicKeyData {
    pub version: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosStatsSummaryData {
    pub timezone: String,
    pub config_start_at: Option<String>,
    pub first_event_at: Option<String>,
    pub last_event_at: Option<String>,
    pub range_start_at: Option<String>,
    pub features: Vec<PhigrosFeatureUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PhigrosFeatureUsage {
    pub feature: String,
    pub count: i64,
    pub last_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosLeaderboardPage {
    pub items: Vec<PhigrosLeaderboardItem>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PhigrosLeaderboardItem {
    pub rank: i64,
    pub alias: Option<String>,
    pub user: String,
    pub score: f64,
    pub updated_at: String,
    pub best_top3: Option<Vec<PhigrosChartText>>,
    pub ap_top3: Option<Vec<PhigrosChartText>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosChartText {
    pub song: String,
    pub difficulty: String,
    pub acc: f64,
    pub rks: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> T {
        serde_json::from_value(value).expect("sample matches the declared schema")
    }

    #[test]
    fn info_file_version_sample_matches() {
        let data: PhihubInfoFileVersionData = decode(json!({
            "version": 159,
            "version_code": 159,
            "version_label": "4.0.1.1",
            "update_date": 1792338235,
            "whatsnew": "更新"
        }));
        assert_eq!(data.version, 159);
        assert_eq!(data.version_label, "4.0.1.1");
    }

    #[test]
    fn player_ids_sample_matches() {
        let data: PhihubPlayerIdsData = decode(json!([{
            "api_id": "1974933332",
            "player_id": "ax",
            "rks": 15.77,
            "avatar": "Oblivion: PHIN",
            "clg_mode": 348
        }]));
        assert_eq!(data.0[0].api_id, "1974933332");
        assert_eq!(data.0[0].clg_mode, 348);
    }

    #[test]
    fn rank_sample_matches() {
        let data: PhihubRankData = decode(json!({
            "total": 152735,
            "users": [{
                "gameuser": {"background": "Rrharil.TeamGrimoire.0"},
                "saveInfo": {
                    "summary": {
                        "rankingScore": 17.32,
                        "challengeModeRank": 551,
                        "avatar": "Gino-AprilFool"
                    },
                    "modifiedAt": {"iso": "2026-10-24T23:07:40.987Z"},
                    "PlayerId": "TEN—风风"
                },
                "index": 1,
                "me": true
            }]
        }));
        assert_eq!(data.total, 152735);
        assert_eq!(data.users[0].save_info.summary.challenge_mode_rank, 551);
    }

    #[test]
    fn verify_public_key_sample_matches() {
        let data: PhigrosVerifyPublicKeyData = decode(json!({
            "version": "v4-beta",
            "public_key": "d43a0647"
        }));
        assert_eq!(data.version, "v4-beta");
        assert_eq!(data.public_key, "d43a0647");
    }

    #[test]
    fn stats_summary_sample_matches() {
        let data: PhigrosStatsSummaryData = decode(json!({
            "timezone": "Asia/Shanghai",
            "config_start_at": null,
            "first_event_at": "2026-05-16T08:00:00+08:00",
            "last_event_at": "2026-11-12T08:00:36+08:00",
            "range_start_at": "2026-05-16T00:00:00+08:00",
            "features": [{"feature": "save", "count": 253774, "lastAt": "2026-11-12T08:00:32+08:00"}]
        }));
        assert_eq!(data.features[0].feature, "save");
        assert_eq!(data.config_start_at, None);
    }

    #[test]
    fn leaderboard_page_sample_matches() {
        let data: PhigrosLeaderboardPage = decode(json!({
            "items": [{
                "rank": 1,
                "alias": "The_Only_Love",
                "user": "27b6****",
                "score": 17.316,
                "updatedAt": "2026-10-03T13:21:28+00:00",
                "bestTop3": [{"song": "Desultory Signals", "difficulty": "AT", "acc": 100.0, "rks": 18.0}],
                "apTop3": []
            }],
            "next_cursor": "cursor"
        }));
        assert_eq!(data.items[0].rank, 1);
        assert_eq!(data.items[0].best_top3.as_ref().map(Vec::len), Some(1));
        assert_eq!(data.next_cursor.as_deref(), Some("cursor"));
    }
}
