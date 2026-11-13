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
