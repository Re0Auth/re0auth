use super::super::connector::{ResourceConfig, ViewConfig};
use super::super::validate;
use super::{example, phihub_resource, resource_with_view, string_param};
use figment::providers::Format;

fn body_resource() -> ResourceConfig {
    phihub_resource("sync_read", "/get/cloud/sync", &[])
}

#[test]
fn body_json_is_an_authoritative_typed_object() {
    let mut resource = body_resource();
    resource.body = Some(std::collections::BTreeMap::from([(
        "legacy".to_string(),
        serde_json::json!("mirror"),
    )]));
    resource.body_json = Some(
        serde_json::json!({
            "history": null,
            "auth": {"token": "Bearer {credential}"},
            "enabled": false,
            "labels": ["a", "b"]
        })
        .to_string(),
    );
    let spec = resource.to_spec().expect("recursive body");
    assert!(spec.body.is_empty());
    assert_eq!(
        spec.raw_body,
        Some(serde_json::json!({
            "history": null,
            "auth": {"token": "Bearer {credential}"},
            "enabled": false,
            "labels": ["a", "b"]
        }))
    );
}

#[test]
fn typed_toml_body_values_remain_literals() {
    let mut resource = body_resource();
    resource.body = Some(std::collections::BTreeMap::from([
        ("enabled".to_string(), serde_json::json!(false)),
        ("limit".to_string(), serde_json::json!(30)),
        ("labels".to_string(), serde_json::json!(["a", "b"])),
        ("nested".to_string(), serde_json::json!({"mode": "x"})),
    ]));
    let spec = resource.to_spec().expect("typed body");
    let values = spec
        .body
        .iter()
        .map(|field| (field.name.as_str(), &field.value))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        values["enabled"],
        &re0auth_api::connector::BodyValue::Literal(serde_json::json!(false))
    );
    assert_eq!(
        values["nested"],
        &re0auth_api::connector::BodyValue::Literal(serde_json::json!({"mode": "x"}))
    );
}

#[test]
fn body_json_rejects_invalid_json_and_nonobjects() {
    for raw in ["{", "[]", "null"] {
        let mut resource = body_resource();
        resource.body_json = Some(raw.to_string());
        assert!(resource.to_spec().is_err(), "body_json = {raw}");
    }
}

#[test]
fn body_placeholders_are_whitelisted_at_config_load() {
    for (raw, token) in [
        (r#"{"token":"Bearer {credntial}"}"#, "credntial"),
        (r#"{"id":"{subject:interger}"}"#, "subject:interger"),
        (r#"{"id":"prefix-{subject:int}"}"#, "subject:int"),
        (r#"{"empty":"{}"}"#, "unknown body placeholder"),
        (r#"{"open":"{subject"}"#, "unmatched"),
        (r#"{"close":"}"}"#, "unmatched"),
    ] {
        let mut resource = body_resource();
        resource.body_json = Some(raw.to_string());
        let error = resource.to_spec().expect_err("invalid placeholder");
        assert!(error.to_string().contains(token), "{raw}: {error}");
    }

    let mut escaped = body_resource();
    escaped.body_json = Some(r#"{"literal":"{{credntial}}"}"#.to_string());
    let spec = escaped.to_spec().expect("escaped typo is literal");
    assert_eq!(spec.raw_body.expect("raw")["literal"], "{{credntial}}");
}

/// The document is inline because the real `config.phihub.toml` is
/// operator-local and excluded from the repository, so a checkout has no
/// such file and the test failed on "missing field `server`".
#[test]
fn phihub_sync_read_preserves_null_and_is_not_idempotent() {
    let raw = r#"
name = "sync_read"
path = "/get/cloud/sync"
scope = "phihub.save.read"
method = "post"
idempotent = false
body = {}
body_json = '{"history": null}'
"#;
    let resource: ResourceConfig = figment::Figment::from(figment::providers::Toml::string(raw))
        .extract()
        .expect("sync_read document");
    let spec = resource.to_spec().expect("sync_read spec");
    assert_eq!(spec.raw_body, Some(serde_json::json!({"history": null})));
    assert!(!spec.idempotent);
}

#[test]
fn legacy_body_is_validated_even_when_body_json_wins() {
    let mut resource = body_resource();
    resource.body_json = Some(r#"{"history":null}"#.to_string());
    resource.body = Some(std::collections::BTreeMap::from([(
        "legacy".to_string(),
        serde_json::json!("{credntial}"),
    )]));
    let error = resource.to_spec().expect_err("legacy placeholder typo");
    assert!(error.to_string().contains("credntial"), "{error}");
}

pub(super) fn binary_resource() -> ResourceConfig {
    let mut resource = resource_with_view(None);
    resource.path = "/jackets/{subject}".to_string();
    resource.response = Some("binary".to_string());
    resource.content_types = vec!["image/png".to_string(), "image/jpeg".to_string()];
    resource
}

#[test]
fn binary_resources_require_concrete_supported_image_types() {
    let spec = binary_resource().to_spec().expect("binary resource");
    assert_eq!(spec.response, re0auth_api::connector::ResponseKind::Binary);
    assert_eq!(spec.content_types, ["image/png", "image/jpeg"]);

    for content_type in ["image/svg+xml", "image/*", "application/octet-stream"] {
        let mut resource = binary_resource();
        resource.content_types = vec![content_type.to_string()];
        assert!(resource.to_spec().is_err(), "{content_type}");
    }
    let mut empty = binary_resource();
    empty.content_types.clear();
    assert!(empty.to_spec().is_err());

    let mut viewed = binary_resource();
    viewed.view = Some(ViewConfig::default());
    assert!(viewed.to_spec().is_err());
}

#[test]
fn asset_max_bytes_is_capped_by_the_global_response_limit() {
    let mut cfg = example();
    let mut resource = binary_resource();
    resource.max_bytes = Some(2048);
    cfg.limits.upstream_response_bytes = 1024;
    cfg.connectors = vec![super::connector::ConnectorConfig {
        id: "assets".to_string(),
        display_name: "Assets".to_string(),
        base_url: "https://assets.example.com".to_string(),
        allow_private_net: false,
        allow_link_local_metadata: false,
        allow_loopback: false,
        expose_in_openapi: true,
        resources: vec![resource],
        oauth: None,
    }];
    let error = validate(&cfg).expect_err("per-resource cap exceeds global cap");
    assert!(error.to_string().contains("max_bytes"), "{error}");
}

#[test]
fn shared_resources_reject_binding_placeholders_everywhere() {
    let valid = || {
        let mut resource = binary_resource();
        resource.path = "/jackets/song".to_string();
        resource.shared = true;
        resource
    };
    assert!(valid().to_spec().expect("shared jacket").shared);

    let mut path = valid();
    path.path = "/jackets/{subject}".to_string();
    assert!(
        path.to_spec()
            .expect_err("subject path")
            .to_string()
            .contains("{subject}")
    );

    let mut body = valid();
    body.method = Some("post".to_string());
    body.body = Some(std::collections::BTreeMap::new());
    body.body_json = Some(r#"{"token":"Bearer {credential}"}"#.to_string());
    assert!(
        body.to_spec()
            .expect_err("credential body")
            .to_string()
            .contains("{credential}")
    );

    let mut query = valid();
    let mut param = string_param("song", "query");
    param.upstream = Some("song{credential}".to_string());
    query.params = vec![param];
    assert!(query.to_spec().is_err());

    let mut enumeration = valid();
    let mut param = string_param("song", "query");
    param.kind = Some("enum".to_string());
    param.max_len = None;
    param.values = vec!["{subject}".to_string()];
    enumeration.params = vec![param];
    assert!(
        enumeration
            .to_spec()
            .expect_err("subject enum")
            .to_string()
            .contains("{subject}")
    );
}
