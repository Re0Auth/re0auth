
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
