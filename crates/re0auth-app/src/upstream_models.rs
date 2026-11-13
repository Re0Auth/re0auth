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
    PhihubInfoFile(PhihubInfoFileData),
    PhihubInfoFileVersion(PhihubInfoFileVersionData),
    PhihubPlayerIds(PhihubPlayerIdsData),
    PhihubRank(PhihubRankData),
    PhihubRankSummary(PhihubRankSummaryData),
    PhihubRksRank(PhihubRksRankData),
    PhihubRankStats(PhihubRankStatsData),
    PhihubSongAccAvg(PhihubSongAccAvgData),
    PhihubAllAccAvg(PhihubAllAccAvgData),
    PhihubAllAccAvgDual(PhihubAllAccAvgDualData),
    PhihubTagCounts(PhihubTagCountsData),
    PhihubComments(PhihubCommentsData),
    PhihubTagTree(PhihubTagTreeData),
    PhihubAliasPage(PhihubAliasPage),
    PhihubTagNames(PhihubTagNamesData),
    PhigrosVerifyPublicKey(PhigrosVerifyPublicKeyData),
    PhigrosStatsSummary(PhigrosStatsSummaryData),
    PhigrosLeaderboard(PhigrosLeaderboardPage),
    PhigrosSongSearch(PhigrosSongSearchPage),
    PhigrosSong(PhigrosSongInfo),
    PhihubRankDetail(PhihubRankDetailData),
    PhihubSongAccList(PhihubSongAccListData),
    LxnsPlayer(LxnsPlayerData),
    LxnsScores(LxnsScorePage),
    LxnsUserProfile(LxnsUserProfileData),
    LxnsBests(LxnsBestsData),
    LxnsSongList(LxnsSongListData),
    LxnsAliasList(LxnsAliasListData),
    LxnsTrend(LxnsRatingTrendData),
    LxnsHeatmap(LxnsHeatmapData),
    LxnsScoreHistory(LxnsScoreHistoryData),
    LxnsScoreRanking(LxnsRankingScorePage),
    LxnsCollectionList(LxnsCollectionListData),
    LxnsCollection(LxnsCollection),
    DivingFishRecords(DivingFishRecordsData),
    DivingFishQueryPlayer(DivingFishQueryPlayerData),
    DivingFishMusic(DivingFishMusicData),
    DivingFishPlayerRecord(DivingFishPlayerRecordData),
    DivingFishPlate(DivingFishPlateData),
    DivingFishRatingRanking(DivingFishRatingRankingData),
    DivingFishChartStats(DivingFishChartStatsData),
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
#[serde(transparent)]
pub struct PhihubInfoFileData(pub HashMap<String, PhihubChartInfo>);

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubChartInfo {
    pub id: String,
    pub song: String,
    pub composer: String,
    pub illustrator: String,
    pub chart: HashMap<String, PhihubChartDifficulty>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubChartDifficulty {
    pub charter: String,
    pub difficulty: f64,
}

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
pub struct PhihubRankSummaryData {
    pub total: i64,
    pub start_rank: i64,
    pub end_rank: i64,
    pub users: Vec<PhihubRankUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct PhihubTagNamesData(pub Vec<String>);

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
    fn rank_summary_sample_matches() {
        let data: PhihubRankSummaryData = decode(json!({
            "total": 152769,
            "start_rank": 1,
            "end_rank": 5,
            "users": [{
                "gameuser": {"background": "Rrharil.TeamGrimoire.0"},
                "saveInfo": {
                    "summary": {"rankingScore": 17.32, "challengeModeRank": 551, "avatar": "Gino-AprilFool"},
                    "modifiedAt": {"iso": "2026-10-24T23:07:40.987Z"},
                    "PlayerId": "TEN—风风"
                },
                "index": 1,
                "me": false
            }]
        }));
        assert_eq!(data.start_rank, 1);
        assert_eq!(data.users[0].index, 1);
    }

    #[test]
    fn tag_names_sample_matches() {
        let data: PhihubTagNamesData = decode(json!(["差速", "脑裂"]));
        assert_eq!(data.0.len(), 2);
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

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubRksRankData {
    pub total: i64,
    pub rks_rank: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubRankStatsData {}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubSongAccAvgData {
    pub acc_avg: f64,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct PhihubAllAccAvgData(pub HashMap<String, HashMap<String, PhihubAccAvg>>);

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubAccAvg {
    #[serde(rename = "accAvg")]
    pub acc_avg: Option<f64>,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct PhihubCommentsData(pub Vec<PhihubComment>);

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubComment {
    pub id: i64,
    #[serde(rename = "songId")]
    pub song_id: String,
    pub rank: String,
    #[serde(rename = "apiUserId")]
    pub api_user_id: String,
    pub rks: f64,
    pub score: i64,
    pub acc: f64,
    pub fc: i64,
    #[serde(rename = "spInfo")]
    pub sp_info: Option<String>,
    pub challenge: i64,
    pub comment: String,
    pub time: String,
    #[serde(rename = "PlayerId")]
    pub player_id: String,
    pub avatar: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct PhihubTagTreeData(pub Vec<PhihubTagNode>);

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PhihubTagNode {
    pub id: i64,
    pub name: String,
    pub parent_id: Option<i64>,
    pub parent_ids: Vec<i64>,
    pub description: String,
    pub icon: Option<String>,
    pub sort_order: i64,
    pub status: i64,
    #[schema(no_recursion)]
    pub children: Vec<PhihubTagNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubAliasPage {
    pub items: Vec<PhihubAliasItem>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PhihubAliasItem {
    pub id: String,
    pub alias: String,
    pub song_id: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub review_note: Option<String>,
    pub votes_up: i64,
    pub votes_down: i64,
    pub vote_score: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubAllAccAvgDualData {
    pub all: PhihubAllAccAvgData,
    pub b30: PhihubAllAccAvgData,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct PhihubTagCountsData(pub HashMap<String, i64>);

#[cfg(test)]
mod moderate_samples {
    use super::*;
    use serde_json::json;

    fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> T {
        serde_json::from_value(value).expect("sample matches the declared schema")
    }

    #[test]
    fn rks_rank_sample_matches() {
        let data: PhihubRksRankData = decode(json!({"total": 152769, "rks_rank": 0}));
        assert_eq!(data.total, 152769);
    }

    #[test]
    fn rank_stats_empty_object_matches() {
        let data: PhihubRankStatsData = decode(json!({}));
        let _ = data;
    }

    #[test]
    fn song_acc_avg_sample_matches() {
        let data: PhihubSongAccAvgData = decode(json!({"acc_avg": 99.42, "count": 102374}));
        assert_eq!(data.count, 102374);
    }

    #[test]
    fn all_acc_avg_map_sample_matches() {
        let data: PhihubAllAccAvgData = decode(json!({
            "Glaciaxion.SunsetRay.0": {
                "EZ": {"accAvg": 97.29, "count": 8135},
                "AT": {"accAvg": null, "count": 0}
            }
        }));
        assert_eq!(data.0["Glaciaxion.SunsetRay.0"]["EZ"].count, 8135);
        assert_eq!(data.0["Glaciaxion.SunsetRay.0"]["AT"].acc_avg, None);
    }

    #[test]
    fn all_acc_avg_dual_sample_matches() {
        let data: PhihubAllAccAvgDualData = decode(json!({
            "all": {"song": {"IN": {"accAvg": 99.5, "count": 10}}},
            "b30": {"song": {"IN": {"accAvg": null, "count": 0}}}
        }));
        assert_eq!(data.all.0["song"]["IN"].count, 10);
    }

    #[test]
    fn tag_counts_sample_matches() {
        let data: PhihubTagCountsData = decode(json!({"差速": 0, "双押海": 12}));
        assert_eq!(data.0["双押海"], 12);
    }

    #[test]
    fn comments_sample_matches() {
        let data: PhihubCommentsData = decode(json!([{
            "id": 829,
            "songId": "Glaciaxion.SunsetRay.0",
            "rank": "EZ",
            "apiUserId": "2552785765",
            "rks": 15.9,
            "score": 1000000,
            "acc": 100.0,
            "fc": 1,
            "spInfo": "All Perfect",
            "challenge": 524,
            "comment": "梦开始的地方",
            "time": "2025-05-03T13:58:27.000Z",
            "PlayerId": "picea asperata",
            "avatar": "Snow Desert"
        }]));
        assert_eq!(data.0[0].id, 829);
        assert_eq!(data.0[0].sp_info.as_deref(), Some("All Perfect"));
    }

    #[test]
    fn tag_tree_sample_matches() {
        let data: PhihubTagTreeData = decode(json!([{
            "id": 152,
            "name": "读谱",
            "parentId": null,
            "parentIds": [],
            "description": "读谱相关难点",
            "icon": null,
            "sortOrder": 10,
            "status": 1,
            "children": [{
                "id": 156,
                "name": "差速",
                "parentId": 152,
                "parentIds": [152],
                "description": "同一时刻下落速度不同",
                "icon": null,
                "sortOrder": 10,
                "status": 1,
                "children": []
            }]
        }]));
        assert_eq!(data.0[0].children[0].name, "差速");
    }

    #[test]
    fn alias_page_sample_matches() {
        let data: PhihubAliasPage = decode(json!({
            "items": [{
                "id": "ae3ca779",
                "alias": "000",
                "songId": "000AinSophAur.Yumeji.0",
                "status": "approved",
                "createdAt": "2026-07-16T15:47:24.639Z",
                "updatedAt": "2026-09-16T00:17:23.934Z",
                "reviewNote": null,
                "votesUp": 0,
                "votesDown": 0,
                "voteScore": 0
            }],
            "next_cursor": "cursor"
        }));
        assert_eq!(data.items[0].alias, "000");
        assert_eq!(data.next_cursor.as_deref(), Some("cursor"));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosSongInfo {
    pub id: String,
    pub name: String,
    pub composer: String,
    pub illustrator: String,
    #[serde(rename = "chartConstants")]
    pub chart_constants: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhigrosSongSearchPage {
    pub items: Vec<PhigrosSongInfo>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubRankDetailData {
    pub rank: i64,
    pub summary: PhihubRankDetailSummary,
    pub save: serde_json::Value,
    pub index: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PhihubRankDetailSummary {
    pub gameuser: PhihubRankGameUser,
    #[serde(rename = "saveInfo")]
    pub save_info: PhihubRankSaveInfo,
    pub index: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct PhihubSongAccListData(pub Vec<Vec<serde_json::Value>>);

// ---------------------------------------------------------------------------
// LXNS
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsPlayerData {
    pub name: String,
    pub rating: i32,
    pub friend_code: i64,
    pub course_rank: i32,
    pub class_rank: i32,
    pub star: i32,
    pub upload_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsScorePage {
    pub items: Vec<LxnsScore>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsScore {
    pub id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub song_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    pub level_index: i32,
    pub achievements: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fc: Option<LxnsFcType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs: Option<LxnsFsType>,
    pub dx_score: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dx_star: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dx_rating: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate: Option<LxnsRateType>,
    #[serde(rename = "type")]
    pub song_type: LxnsSongType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub play_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_played_time: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LxnsFcType {
    App,
    Ap,
    Fcp,
    Fc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LxnsFsType {
    Fsdp,
    Fsd,
    Fsp,
    Fs,
    Sync,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LxnsRateType {
    Sssp,
    Sss,
    Ssp,
    Ss,
    Sp,
    S,
    Aaa,
    Aa,
    A,
    Bbb,
    Bb,
    B,
    C,
    D,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LxnsSongType {
    Standard,
    Dx,
    Utage,
}

/// `GET /api/v0/user/profile` after the OAuth API's envelope is unwrapped.
///
/// Live shape: id, name, email, email_verified, email_verified_time,
/// permission, register_time. `bind`, `avatar_url` and `token` are not returned
/// by this endpoint, even though the website's User object can carry them.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsUserProfileData {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified_time: Option<String>,
    pub permission: u32,
    pub register_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsBestsData {
    pub standard_total: i64,
    pub dx_total: i64,
    pub standard: Vec<LxnsScore>,
    pub dx: Vec<LxnsScore>,
    pub standard_selections: Vec<LxnsScore>,
    pub dx_selections: Vec<LxnsScore>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsSongListData {
    pub songs: Vec<LxnsSong>,
    pub genres: Vec<LxnsGenre>,
    pub versions: Vec<LxnsVersion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsSong {
    pub id: i64,
    pub title: String,
    pub artist: String,
    pub genre: String,
    pub bpm: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub map: Option<String>,
    pub version: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rights: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    pub difficulties: LxnsSongDifficulties,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsSongDifficulties {
    pub standard: Vec<LxnsSongDifficulty>,
    pub dx: Vec<LxnsSongDifficulty>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utage: Option<Vec<LxnsSongDifficultyUtage>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsSongDifficulty {
    #[serde(rename = "type")]
    pub song_type: LxnsSongType,
    pub difficulty: i32,
    pub level: String,
    pub level_value: f64,
    pub note_designer: String,
    pub version: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<LxnsNotes>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsSongDifficultyUtage {
    pub kanji: String,
    pub description: String,
    pub is_buddy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<LxnsUtageNotes>,
    #[serde(rename = "type")]
    pub song_type: LxnsSongType,
    pub difficulty: i32,
    pub level: String,
    pub level_value: f64,
    pub note_designer: String,
    pub version: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum LxnsUtageNotes {
    Notes(LxnsNotes),
    Buddy(LxnsBuddyNotes),
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsNotes {
    pub total: i64,
    pub tap: i64,
    pub hold: i64,
    pub slide: i64,
    pub touch: i64,
    #[serde(rename = "break")]
    pub break_notes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsBuddyNotes {
    pub left: LxnsNotes,
    pub right: LxnsNotes,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsGenre {
    pub id: i32,
    pub title: String,
    pub genre: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsVersion {
    pub id: i32,
    pub title: String,
    pub version: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsAliasListData {
    pub aliases: Vec<LxnsAlias>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsAlias {
    pub song_id: i64,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct LxnsRatingTrendData(pub Vec<LxnsRatingTrend>);

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsRatingTrend {
    pub total: i64,
    pub standard_total: i64,
    pub dx_total: i64,
    pub date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct LxnsHeatmapData(pub HashMap<String, i64>);

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct LxnsScoreHistoryData(pub Option<Vec<LxnsScore>>);

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsRankingScorePage {
    pub items: Vec<LxnsRankingScore>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsRankingScore {
    pub ranking: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub player_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub achievements: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dx_score: Option<i64>,
    pub upload_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct LxnsCollectionListData(pub Vec<LxnsCollection>);

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsCollection {
    pub id: i64,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genre: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_favorite: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<LxnsCollectionRequired>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsCollectionRequired {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub difficulties: Option<Vec<i32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate: Option<LxnsRateType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fc: Option<LxnsFcType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs: Option<LxnsFsType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub songs: Option<Vec<LxnsCollectionRequiredSong>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LxnsCollectionRequiredSong {
    pub id: i64,
    pub title: String,
    #[serde(rename = "type")]
    pub song_type: LxnsSongType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_difficulties: Option<Vec<i32>>,
}

// ---------------------------------------------------------------------------
// DivingFish
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DivingFishRecordsData {
    pub additional_rating: i64,
    pub nickname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plate: Option<String>,
    pub rating: i64,
    pub records: Vec<DivingFishRecord>,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DivingFishQueryPlayerData {
    pub additional_rating: i64,
    pub charts: DivingFishCharts,
    pub nickname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plate: Option<String>,
    pub rating: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_general_data: Option<serde_json::Value>,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DivingFishCharts {
    pub dx: Vec<DivingFishRecord>,
    pub sd: Vec<DivingFishRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DivingFishRecord {
    pub achievements: f64,
    pub ds: f64,
    #[serde(rename = "dxScore")]
    pub dx_score: i64,
    pub fc: DivingFishFcType,
    pub fs: DivingFishFsType,
    pub level: String,
    pub level_index: i64,
    pub level_label: String,
    pub ra: i64,
    pub rate: DivingFishRateType,
    pub song_id: i64,
    pub title: String,
    #[serde(rename = "type")]
    pub song_type: DivingFishSheetType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum DivingFishSheetType {
    #[serde(rename = "SD")]
    Sd,
    #[serde(rename = "DX")]
    Dx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum DivingFishFcType {
    #[serde(rename = "")]
    Blank,
    #[serde(rename = "fc")]
    Fc,
    #[serde(rename = "fcp")]
    Fcp,
    #[serde(rename = "ap")]
    Ap,
    #[serde(rename = "app")]
    App,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum DivingFishFsType {
    #[serde(rename = "")]
    Blank,
    #[serde(rename = "sync")]
    Sync,
    #[serde(rename = "fs")]
    Fs,
    #[serde(rename = "fsp")]
    Fsp,
    #[serde(rename = "fsd")]
    Fsd,
    #[serde(rename = "fsdp")]
    Fsdp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum DivingFishRateType {
    #[serde(rename = "sssp")]
    Sssp,
    #[serde(rename = "sss")]
    Sss,
    #[serde(rename = "ssp")]
    Ssp,
    #[serde(rename = "ss")]
    Ss,
    #[serde(rename = "sp")]
    Sp,
    #[serde(rename = "s")]
    S,
    #[serde(rename = "aaa")]
    Aaa,
    #[serde(rename = "aa")]
    Aa,
    #[serde(rename = "a")]
    A,
    #[serde(rename = "bbb")]
    Bbb,
    #[serde(rename = "bb")]
    Bb,
    #[serde(rename = "b")]
    B,
    #[serde(rename = "c")]
    C,
    #[serde(rename = "d")]
    D,
}

/// `GET /api/maimaidxprober/music_data`. Live response has song ids as strings.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct DivingFishMusicData(pub Vec<DivingFishSong>);

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DivingFishSong {
    pub id: String,
    pub title: String,
    #[serde(rename = "type")]
    pub song_type: DivingFishSheetType,
    pub ds: Vec<f64>,
    pub level: Vec<String>,
    pub cids: Vec<i64>,
    pub charts: Vec<DivingFishChartInfo>,
    pub basic_info: DivingFishBasicInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DivingFishChartInfo {
    pub notes: Vec<i64>,
    pub charter: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DivingFishBasicInfo {
    pub title: String,
    pub artist: String,
    pub genre: String,
    pub bpm: i64,
    pub release_date: String,
    pub from: String,
    pub is_new: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct DivingFishPlayerRecordData(pub HashMap<String, Vec<DivingFishRecord>>);

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DivingFishPlateData {
    pub verlist: Vec<DivingFishRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct DivingFishRatingRankingData(pub Vec<DivingFishRatingRank>);

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DivingFishRatingRank {
    pub ra: i64,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DivingFishChartStatsData {
    pub charts: HashMap<String, Vec<DivingFishChartStat>>,
    pub diff_data: HashMap<String, DivingFishDiffStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DivingFishChartStat {
    pub cnt: f64,
    pub diff: String,
    pub fit_diff: f64,
    pub avg: f64,
    pub avg_dx: f64,
    pub std_dev: f64,
    pub dist: Vec<i64>,
    pub fc_dist: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DivingFishDiffStat {
    pub achievements: f64,
    pub dist: Vec<f64>,
    pub fc_dist: Vec<f64>,
}

#[cfg(test)]
mod remaining_samples {
    use super::*;
    use serde_json::json;

    fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> T {
        serde_json::from_value(value).expect("sample matches the declared schema")
    }

    #[test]
    fn song_search_page_sample_matches() {
        let data: PhigrosSongSearchPage = decode(json!({
            "items": [],
            "next_cursor": "cursor"
        }));
        assert!(data.items.is_empty());
        assert_eq!(data.next_cursor.as_deref(), Some("cursor"));
    }

    #[test]
    fn song_info_sample_matches() {
        let data: PhigrosSongInfo = decode(json!({
            "id": "97f9466b2e77",
            "name": "Arcahv",
            "composer": "Feryquitous",
            "illustrator": "Catrong",
            "chartConstants": {"ez": 4.5, "hd": 7.9, "in": 9.6, "at": 12.3}
        }));
        assert_eq!(data.chart_constants["at"], 12.3);
    }

    #[test]
    fn rank_detail_sample_matches() {
        let data: PhihubRankDetailData = decode(json!({
            "rank": 1,
            "summary": {
                "gameuser": {"background": "Rrharil.TeamGrimoire.0"},
                "saveInfo": {
                    "summary": {"rankingScore": 17.32, "challengeModeRank": 551, "avatar": "Gino-AprilFool"},
                    "modifiedAt": {"iso": "2026-10-24T23:07:40.987Z"},
                    "PlayerId": "TEN—风风"
                },
                "index": 1
            },
            "save": {"apiId": "3650267223"},
            "index": 1
        }));
        assert_eq!(data.rank, 1);
        assert_eq!(data.summary.save_info.player_id, "TEN—风风");
        assert_eq!(data.save["apiId"], "3650267223");
    }

    #[test]
    fn song_acc_list_table_sample_matches() {
        let data: PhihubSongAccListData = decode(json!([
            ["acc", "rksWhenInsert"],
            [99.6, 0.41],
            [97.8, 0.59]
        ]));
        assert_eq!(data.0.len(), 3);
        assert_eq!(data.0[1][0], 99.6);
    }
}

#[cfg(test)]
mod lxns_samples {
    use super::*;
    use serde_json::json;

    fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> T {
        serde_json::from_value(value).expect("sample matches the declared schema")
    }

    #[test]
    fn player_sample_matches() {
        let data: LxnsPlayerData = decode(json!({
            "name": "player",
            "rating": 15000,
            "friend_code": 123456789012345i64,
            "course_rank": 1,
            "class_rank": 2,
            "star": 3,
            "upload_time": "2026-11-13T14:20:00Z"
        }));
        assert_eq!(data.rating, 15000);
        assert_eq!(data.friend_code, 123456789012345);
    }

    #[test]
    fn score_page_sample_matches() {
        let data: LxnsScorePage = decode(json!({
            "items": [{
                "id": 834,
                "song_name": "Song",
                "level": "14+",
                "level_index": 4,
                "achievements": 100.5,
                "fc": "app",
                "fs": "fsdp",
                "dx_score": 1234,
                "dx_star": 5,
                "dx_rating": 300.1,
                "rate": "sssp",
                "type": "dx",
                "play_time": "2026-11-13T14:00:00Z",
                "upload_time": "2026-11-13T14:20:00Z",
                "last_played_time": "2026-11-13T14:00:00Z"
            }],
            "next_cursor": "cursor"
        }));
        assert_eq!(data.items[0].song_type, LxnsSongType::Dx);
        assert_eq!(data.items[0].fc, Some(LxnsFcType::App));
        assert_eq!(data.next_cursor.as_deref(), Some("cursor"));
    }

    #[test]
    fn user_profile_sample_matches_live_shape() {
        let data: LxnsUserProfileData = decode(json!({
            "id": 12345,
            "name": "user",
            "email": "user@example.com",
            "email_verified": true,
            "email_verified_time": "2026-11-13T14:20:00Z",
            "permission": 1,
            "register_time": "2025-01-02T03:04:05.123456789Z"
        }));
        assert_eq!(data.id, 12345);
        assert!(data.email_verified);
        assert_eq!(data.permission, 1);
    }

    #[test]
    fn bests_sample_matches() {
        let data: LxnsBestsData = decode(json!({
            "standard_total": 1000,
            "dx_total": 2000,
            "standard": [],
            "dx": [],
            "standard_selections": [],
            "dx_selections": []
        }));
        assert_eq!(data.standard_total, 1000);
        assert_eq!(data.dx_total, 2000);
        assert!(data.standard.is_empty());
    }

    #[test]
    fn song_list_sample_matches() {
        let data: LxnsSongListData = decode(json!({
            "songs": [{
                "id": 8,
                "title": "True Love Song",
                "artist": "Kai",
                "genre": "maimai",
                "bpm": 150,
                "version": 10000,
                "release_date": "2019-12-05",
                "difficulties": {
                    "standard": [{
                        "type": "standard",
                        "difficulty": 0,
                        "level": "5",
                        "level_value": 5.0,
                        "note_designer": "-",
                        "version": 10000,
                        "release_date": "2019-12-05"
                    }],
                    "dx": []
                }
            }],
            "genres": [{"id": 1, "title": "maimai", "genre": "maimai"}],
            "versions": [{"id": 1, "title": "maimai", "version": 10000}]
        }));
        assert_eq!(data.songs[0].id, 8);
        assert_eq!(data.songs[0].difficulties.standard.len(), 1);
        assert!(data.songs[0].difficulties.dx.is_empty());
    }

    #[test]
    fn alias_list_sample_matches() {
        let data: LxnsAliasListData = decode(json!({
            "aliases": [{"song_id": 8, "aliases": ["真爱歌", "真爱"]}]
        }));
        assert_eq!(data.aliases[0].song_id, 8);
        assert_eq!(data.aliases[0].aliases.len(), 2);
    }

    #[test]
    fn trend_sample_matches() {
        let data: LxnsRatingTrendData = decode(json!([{
            "total": 15000,
            "standard_total": 10000,
            "dx_total": 5000,
            "date": "2026-11-13"
        }]));
        assert_eq!(data.0[0].total, 15000);
        assert_eq!(data.0[0].date, "2026-11-13");
    }

    #[test]
    fn heatmap_sample_matches() {
        let data: LxnsHeatmapData = decode(json!({"2026-11-13": 3}));
        assert_eq!(data.0["2026-11-13"], 3);
    }

    #[test]
    fn score_history_sample_matches() {
        let data: LxnsScoreHistoryData = decode(json!([]));
        assert_eq!(data.0.as_ref().map(Vec::len), Some(0));
        let empty: LxnsScoreHistoryData = decode(json!(null));
        assert!(empty.0.is_none());
    }

    #[test]
    fn score_ranking_page_sample_matches() {
        let data: LxnsRankingScorePage = decode(json!({
            "items": [{
                "ranking": 1,
                "player_name": "player",
                "achievements": 100.5,
                "dx_score": 1234,
                "upload_time": "2026-11-13T14:00:00Z"
            }],
            "next_cursor": null
        }));
        assert_eq!(data.items[0].ranking, 1);
        assert!(data.next_cursor.is_none());
    }

    #[test]
    fn collection_samples_match() {
        let list: LxnsCollectionListData = decode(json!([{
            "id": 1,
            "name": "trophy",
            "color": "Gold",
            "genre": "maimai",
            "is_favorite": true
        }]));
        assert_eq!(list.0[0].id, 1);
        assert_eq!(list.0[0].is_favorite, Some(true));

        let one: LxnsCollection = decode(json!({
            "id": 1,
            "name": "trophy",
            "color": "Gold",
            "description": "desc",
            "genre": "maimai",
            "release_date": "2026-11-13"
        }));
        assert_eq!(one.description.as_deref(), Some("desc"));
    }
}

#[cfg(test)]
mod diving_fish_samples {
    use super::*;
    use serde_json::json;

    fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> T {
        serde_json::from_value(value).expect("sample matches the declared schema")
    }

    #[test]
    fn records_sample_matches() {
        let data: DivingFishRecordsData = decode(json!({
            "additional_rating": 13,
            "nickname": "sample",
            "plate": "輝将",
            "rating": 15932,
            "records": [{
                "achievements": 91.6265,
                "ds": 6.0,
                "dxScore": 520,
                "fc": "",
                "fs": "",
                "level": "6",
                "level_index": 1,
                "level_label": "Advanced",
                "ra": 83,
                "rate": "aa",
                "song_id": 11115,
                "title": "song",
                "type": "DX"
            }],
            "username": "sample_username"
        }));
        assert_eq!(data.rating, 15932);
        assert_eq!(data.records[0].dx_score, 520);
        assert_eq!(data.records[0].song_type, DivingFishSheetType::Dx);
        assert_eq!(data.records[0].rate, DivingFishRateType::Aa);
        assert_eq!(data.records[0].fc, DivingFishFcType::Blank);
    }

    #[test]
    fn query_player_sample_matches() {
        let data: DivingFishQueryPlayerData = decode(json!({
            "additional_rating": 13,
            "charts": {"dx": [], "sd": []},
            "nickname": "sample",
            "plate": null,
            "rating": 15932,
            "user_general_data": null,
            "username": "sample_username"
        }));
        assert_eq!(data.rating, 15932);
        assert!(data.charts.dx.is_empty());
        assert!(data.user_general_data.is_none());
    }

    #[test]
    fn music_data_sample_matches() {
        let data: DivingFishMusicData = decode(json!([{
            "id": "8",
            "title": "True Love Song",
            "type": "SD",
            "ds": [5.0, 7.2, 10.2, 12.4],
            "level": ["5", "7", "10", "12"],
            "cids": [1, 2, 3, 4],
            "charts": [{"notes": [63, 23, 8, 2], "charter": "-"}],
            "basic_info": {
                "title": "True Love Song",
                "artist": "Kai",
                "genre": "舞萌",
                "bpm": 150,
                "release_date": "",
                "from": "maimai",
                "is_new": false
            }
        }]));
        assert_eq!(data.0[0].id, "8");
        assert_eq!(data.0[0].song_type, DivingFishSheetType::Sd);
        assert_eq!(data.0[0].charts[0].notes.len(), 4);
    }

    fn record() -> serde_json::Value {
        json!({
            "achievements": 91.6265,
            "ds": 6.0,
            "dxScore": 520,
            "fc": "",
            "fs": "",
            "level": "6",
            "level_index": 1,
            "level_label": "Advanced",
            "ra": 83,
            "rate": "aa",
            "song_id": 11115,
            "title": "song",
            "type": "DX"
        })
    }

    #[test]
    fn player_record_sample_matches() {
        let data: DivingFishPlayerRecordData = decode(json!({"11568": [record()]}));
        assert_eq!(data.0["11568"].len(), 1);
    }

    #[test]
    fn plate_sample_matches() {
        let data: DivingFishPlateData = decode(json!({"verlist": [record()]}));
        assert_eq!(data.verlist.len(), 1);
    }

    #[test]
    fn rating_ranking_sample_matches() {
        let data: DivingFishRatingRankingData = decode(json!([{
            "ra": 15000,
            "username": "player"
        }]));
        assert_eq!(data.0[0].ra, 15000);
    }

    #[test]
    fn chart_stats_sample_matches() {
        let data: DivingFishChartStatsData = decode(json!({
            "charts": {
                "8": [{
                    "cnt": 5463.0,
                    "diff": "5",
                    "fit_diff": 5.02,
                    "avg": 100.05,
                    "avg_dx": 11181.5,
                    "std_dev": 0.97,
                    "dist": [21, 2, 3],
                    "fc_dist": [225.0, 1242.0]
                }]
            },
            "diff_data": {
                "1": {
                    "achievements": 96.5,
                    "dist": [0.03, 0.01],
                    "fc_dist": [0.14, 0.11]
                }
            }
        }));
        assert_eq!(data.charts["8"][0].cnt, 5463.0);
        assert_eq!(data.diff_data["1"].dist.len(), 2);
    }
}
