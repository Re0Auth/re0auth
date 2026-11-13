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
