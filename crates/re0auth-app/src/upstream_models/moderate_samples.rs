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
