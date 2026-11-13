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
