use re0auth_api::ports::MissingBinding;

/// The schema twin must stay field-for-field equal to the port type it
/// stands in for; nothing else can catch the two drifting apart.
#[test]
fn missing_bindings_shape_matches_the_port() {
    let port = MissingBinding {
        upstream_id: "phihub".to_string(),
        scopes: vec!["save_info".to_string()],
    };
    let shape = super::MissingBindingShape {
        upstream_id: port.upstream_id.clone(),
        scopes: port.scopes.clone(),
    };
    assert_eq!(
        serde_json::to_value(&port).expect("the port serialises"),
        serde_json::to_value(&shape).expect("the shape serialises"),
    );
}

use super::*;

#[test]
fn busy_maps_to_temporarily_unavailable() {
    assert!(matches!(
        map_repo(RepoError::Busy),
        OAuthError::TemporarilyUnavailable
    ));
}
