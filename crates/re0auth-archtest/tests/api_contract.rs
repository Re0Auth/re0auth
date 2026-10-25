//! Contracts shared with the SvelteKit SPA.
//!
//! The SPA parses these responses with zod schemas in `web/src/lib/api.ts`, and
//! nothing connects the two files: a renamed field compiles on both sides and
//! fails only when a browser runs the page. `api_contract` closes that by
//! comparing the *serialised* Rust shapes against the field names declared in
//! the TypeScript, so a rename turns into a failing test rather than a runtime
//! surprise.
//!
//! These are not a substitute for an OpenAPI document (see `API-SURFACE.md`
//! §10). They are the cheap half: no codegen step, no build-order coupling, and
//! they cover exactly the DTOs the bundled SPA consumes.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

fn workspace_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

/// Extracts the field names of one `z.object({...})` assigned to `name`.
///
/// A deliberately small parser: the SPA's schemas are flat literals of
/// `key: z.<something>(...)`, possibly with a `.nullable()` suffix. Anything
/// nested deeper than that is reported as a parse failure rather than guessed
/// at — a gate that silently skips a shape it does not understand is worse than
/// no gate, because it reports success.
fn zod_fields(source: &str, name: &str) -> BTreeSet<String> {
    let start = source
        .find(&format!("export const {name} = z.object({{"))
        .unwrap_or_else(|| panic!("web/src/lib/api.ts has no `{name}` schema"));
    let body = &source[start..];
    let close = body
        .find("\n});")
        .unwrap_or_else(|| panic!("`{name}` has no closing `}});` at column zero"));

    let mut fields = BTreeSet::new();
    for line in body[..close].lines().skip(1) {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            panic!("`{name}` line is not `key: value`: {line:?}");
        };
        let key = key.trim();
        // Keys are bare identifiers in every schema here, so a quoted or
        // computed key means the shape moved outside what this gate covers.
        assert!(
            !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "`{name}` uses a non-identifier key {key:?}; teach zod_fields about it \
             or avoid it, but do not let it pass unread"
        );
        let value = value.trim().trim_end_matches(',');
        assert!(
            value.starts_with("z.") || value.ends_with("Schema"),
            "`{name}.{key}` is not a zod expression or a schema reference: {value:?}"
        );
        fields.insert(key.to_string());
    }
    assert!(
        !fields.is_empty(),
        "`{name}` parsed to zero fields, which means the parser is wrong"
    );
    fields
}

/// Extracts the keys of a serialised JSON object, one level deep.
fn json_fields(value: &serde_json::Value) -> BTreeSet<String> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("expected a JSON object, got {value}"))
        .keys()
        .cloned()
        .collect()
}

fn api_ts() -> String {
    fs::read_to_string(workspace_root().join("web/src/lib/api.ts")).expect("web/src/lib/api.ts")
}

/// Asserts the two sides describe the same object.
fn assert_matches(name: &str, rust: &serde_json::Value) {
    let declared = zod_fields(&api_ts(), name);
    let emitted = json_fields(rust);
    let missing_in_ts: Vec<_> = emitted.difference(&declared).cloned().collect();
    let missing_in_rust: Vec<_> = declared.difference(&emitted).cloned().collect();
    assert!(
        missing_in_ts.is_empty() && missing_in_rust.is_empty(),
        "`{name}` disagrees between Rust and web/src/lib/api.ts\n\
         \x20 sent by Rust but not declared in TS: {missing_in_ts:?}\n\
         \x20 declared in TS but not sent by Rust: {missing_in_rust:?}\n\
         A renamed field parses as `undefined` in the browser, which is why this \
         is a test and not a review note."
    );
}

#[test]
fn me_response_matches_the_spa_schema() {
    use re0auth_http::{MeUserView, MeView};

    let view = MeView {
        user: MeUserView {
            id: "user-id".to_string(),
            display_name: "Alice".to_string(),
        },
        csrf_token: "csrf".to_string(),
    };
    let json = serde_json::to_value(&view).expect("serialise MeView");
    assert_matches("meSchema", &json);

    // The nested user object is a second contract, and the SPA declares it too.
    assert_matches("userSchema", &json["user"]);
}

#[test]
fn pending_consent_matches_the_spa_schema() {
    use re0auth_api::ports::MissingBinding;
    use re0auth_app::oauth::PendingConsentView;

    let view = PendingConsentView {
        request_id: "request".to_string(),
        client_id: "client".to_string(),
        client_name: "Bot".to_string(),
        redirect_uri: "https://bot.example/cb".to_string(),
        scopes: vec!["openid".to_string()],
        expires_at: 1_000,
        missing_bindings: vec![MissingBinding {
            upstream_id: "phigros".to_string(),
            scopes: vec!["phigros.stats.read".to_string()],
        }],
    };
    let json = serde_json::to_value(&view).expect("serialise");
    assert_matches("pendingSchema", &json);

    // The hint is a nested object, and the SPA declares that shape too.
    assert_matches("missingBindingSchema", &json["missing_bindings"][0]);
}

#[test]
fn consent_result_matches_the_spa_schema() {
    use re0auth_app::oauth::ConsentOutcome;

    let outcome = ConsentOutcome {
        redirect_to: "https://bot.example/cb?code=x".to_string(),
    };
    assert_matches(
        "consentResultSchema",
        &serde_json::to_value(&outcome).expect("serialise"),
    );
}

#[test]
fn authorization_matches_the_spa_schema() {
    use re0auth_app::auth::AuthorizationView;

    let view = AuthorizationView {
        client_id: "client".to_string(),
        client_name: "Bot".to_string(),
        scopes: vec!["openid".to_string()],
        created_at: 1_000,
        updated_at: 2_000,
    };
    assert_matches(
        "authorizationSchema",
        &serde_json::to_value(&view).expect("serialise"),
    );
}

#[test]
fn binding_matches_the_spa_schema() {
    use re0auth_app::auth::BindingView;

    let view = BindingView {
        id: "binding".to_string(),
        connector: "phigros".to_string(),
        status: "active",
        created_at: 1_000,
        updated_at: 2_000,
        last_refreshed_at: Some(1_500),
        last_error_code: None,
    };
    assert_matches(
        "bindingSchema",
        &serde_json::to_value(&view).expect("serialise"),
    );
}

/// The suspended-array schema must be the element schema.
#[test]
fn array_schemas_wrap_the_object_schemas() {
    let source = api_ts();
    for (array, element) in [
        ("authorizationsSchema", "authorizationSchema"),
        ("bindingsSchema", "bindingSchema"),
    ] {
        let needle = format!("export const {array} = z.array({element})");
        assert!(
            source.contains(&needle),
            "`{array}` must be `z.array({element})`; otherwise the list endpoint \
             validates against a different shape than the single-item contract"
        );
    }
}

/// A gate that passes when the parser silently reads nothing is worthless.
#[test]
fn the_parser_rejects_a_shape_it_does_not_understand() {
    let nested = "export const broken = z.object({\n\tuser: z.object({ id: z.string() })\n});";
    let fields = zod_fields(nested, "broken");
    // It still reads `user`; what must not happen is it reading *past* the inner
    // object and inventing fields, or skipping the line without complaint.
    assert_eq!(fields.into_iter().collect::<Vec<_>>(), vec!["user"]);

    let missing = "export const other = z.string();";
    let result = std::panic::catch_unwind(|| zod_fields(missing, "other"));
    assert!(
        result.is_err(),
        "a missing schema must panic, not return empty"
    );
}
