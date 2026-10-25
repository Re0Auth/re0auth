//! Fixtures and golden files must not carry real secrets.
//!
//! Oracle tests compare against recorded upstream responses, which is exactly
//! where a live token would leak if someone committed the raw body. ADR-0035
//! splits the job: the connector-fields scanner (`connector_ports_do_not_name…`)
//! forbids game root-credential *field names* in production code; this gate
//! forbids real *values* in `fixtures/` and `golden/`.
//!
//! The convention (see `fixtures/README.md`): field names stay, sensitive values
//! become the placeholder `"<redacted>"`. Nothing here needs a live upstream, so
//! it runs today even though no golden exists yet — an empty tree passes, and the
//! first real recording is checked before it can be committed.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// The placeholder every sensitive value must be replaced with.
const PLACEHOLDER: &str = "<redacted>";

/// Field names whose value is sensitive wherever they appear.
///
/// Two groups: game root credentials (the same set the production scanner
/// guards) and generic credential spellings. Matching is case-insensitive so
/// `sessionToken` and `sessiontoken` cannot slip past one spelling.
const SENSITIVE_KEYS: &[&str] = &[
    // Game / session root credentials.
    "stoken",
    "session_token",
    "session_cookie",
    "sessioncookie",
    "sessiontoken",
    "game_password",
    "tap_password",
    "taptap_password",
    // Generic credentials.
    "password",
    "secret",
    "client_secret",
    "token",
    "access_token",
    "refresh_token",
    "api_token",
    "authorization",
    "cookie",
];

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEYS.contains(&lower.as_str())
}

/// Tokens that look like live credentials regardless of their field name.
///
/// Conservative on purpose: a false positive on legitimate golden data is a
/// cheaper failure than a committed token, and the fix (redact it) is trivial.
fn secret_shapes(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for token in text.split(|c: char| {
        !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == ':')
    }) {
        if token.len() < 12 {
            continue;
        }
        if looks_like_jwt(token) || looks_like_leancloud(token) || looks_like_hex(token) {
            found.push(token.to_string());
        }
    }
    found
}

fn looks_like_jwt(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    header.starts_with("eyJ")
        && header.len() >= 10
        && payload.len() >= 10
        && signature.len() >= 10
        && token.len() >= 40
}

fn looks_like_leancloud(token: &str) -> bool {
    token.starts_with("r:")
        && token.len() >= 12
        && token[2..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn looks_like_hex(token: &str) -> bool {
    token.len() >= 32 && token.chars().all(|c| c.is_ascii_hexdigit())
}

/// Every sensitive JSON value must be the placeholder.
fn unsafe_json_values(text: &str) -> Vec<String> {
    let Ok(document) = serde_json::from_str::<serde_json::Value>(text) else {
        // Not JSON: shape scanning above still applies, and the file may be a
        // raw body. Missing a parse here cannot hide a JSON secret from the
        // shape scan, which sees the raw text.
        return Vec::new();
    };
    let mut found = Vec::new();
    walk(&document, "", &mut found);
    found
}

fn walk(value: &serde_json::Value, path: &str, found: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if is_sensitive_key(key) {
                    let redacted = child.as_str().is_some_and(|text| text == PLACEHOLDER);
                    if !redacted {
                        found.push(child_path.clone());
                    }
                }
                walk(child, &child_path, found);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                walk(child, &format!("{path}[{index}]"), found);
            }
        }
        _ => {}
    }
}

/// Recursively lists regular files under `dir`; missing directories are empty.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else if path.is_file() {
            out.push(path);
        }
    }
    out
}

#[test]
fn fixtures_and_golden_carry_no_live_secrets() {
    let mut problems = Vec::new();
    let mut scanned = 0usize;
    for dir in ["fixtures", "golden"] {
        for path in files_under(&root().join(dir)) {
            // README and other prose are not recorded responses.
            if path.extension().is_some_and(|ext| ext == "md") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            scanned += 1;
            for shape in secret_shapes(&text) {
                problems.push(format!("{}: secret-shaped value {shape:?}", path.display()));
            }
            for key in unsafe_json_values(&text) {
                problems.push(format!(
                    "{}: sensitive field {key} is not {PLACEHOLDER}",
                    path.display()
                ));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "fixtures/golden must be sanitized before commit (ADR-0035):\n  {}",
        problems.join("\n  ")
    );
    let _ = scanned;
}

/// A gate that cannot detect a planted secret is worthless.
#[test]
fn the_scan_detects_a_planted_secret_and_clears_a_sanitized_one() {
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.s3cr3tsignaturevalue";
    assert!(
        !secret_shapes(jwt).is_empty(),
        "a JWT must be detected whatever its field is called"
    );
    assert!(
        !secret_shapes("r:abcdefghijklmnop").is_empty(),
        "a LeanCloud session token must be detected"
    );
    assert!(
        !secret_shapes("d41d8cd98f00b204e9800998ecf8427e").is_empty(),
        "a long hex id must be detected"
    );

    let planted = r#"{"data":{"sessionToken":"r:realtokenvalue123"}}"#;
    assert!(
        !unsafe_json_values(planted).is_empty(),
        "a sensitive field with a real value must fail"
    );

    let clean =
        format!(r#"{{"data":{{"sessionToken":{PLACEHOLDER:?},"api_user_id":{PLACEHOLDER:?}}}}}"#);
    assert!(
        unsafe_json_values(&clean).is_empty(),
        "field names stay, placeholder values pass"
    );
    assert!(secret_shapes(&clean).is_empty());
}
