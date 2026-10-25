//! Environment overrides for the list-shaped config entries.
//!
//! `Env::prefixed(..).split("__")` turns `IDENTITY_PROVIDERS__0__CLIENT_SECRET`
//! into `identity_providers.0.client_secret`, a *map*, while the schema wants a
//! `Vec`. figment then fails the whole extract with `invalid type: found map,
//! expected a sequence` — so the documented way to keep a secret out of the file
//! simply did not work for `[[identity_providers]]` (ISSUE-0007).
//!
//! Emitting an array from a custom figment provider cannot fix it either: figment
//! replaces arrays wholesale (`Coalescible for Value`), so the array built from
//! environment variables would drop every field the file sets.
//!
//! The overrides are therefore applied to the parsed struct, field by field. The
//! parser lives here rather than in `config.rs` so it can be tested as a pure
//! function over `(key, value)` pairs, without touching the process environment —
//! which edition 2024 makes `unsafe` to write to anyway.

use crate::config::{Config, IdentityProviderConfig, IdentityProviderKind};

/// Prefix (after `RE0AUTH_`) that marks a per-provider override.
const PROVIDERS: &str = "identity_providers";

/// Scalar fields an operator may override.
///
/// `scopes` is deliberately absent: it is a list, and any separator we picked
/// would be ambiguous because RFC 6749 allows `,` inside a scope token. Set it
/// in the file instead.
const SCALAR_FIELDS: &[&str] = &[
    "name",
    "issuer",
    "kind",
    "client_id",
    "client_secret",
    "client_secret_file",
    "redirect_uri",
    "discovery_url",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "userinfo_endpoint",
];

/// True when `key` (already stripped of `RE0AUTH_`) is a provider override.
///
/// Used to keep these keys away from the generic `Env` provider, which would
/// otherwise fail the extract before the overrides get a chance to apply.
pub fn is_provider_override_key(key: &str) -> bool {
    key.split("__")
        .next()
        .is_some_and(|head| head.eq_ignore_ascii_case(PROVIDERS))
}

/// One parsed `identity_providers__<index>__<field>=<value>` assignment.
#[derive(Debug, Eq, PartialEq)]
struct Override {
    index: usize,
    field: String,
    value: String,
}

/// Applies provider overrides to `cfg`.
///
/// Keys are expected without the `RE0AUTH_` prefix and in the `__`-separated
/// form. Every malformed key is an error: silently ignoring a typo would leave
/// the operator believing a secret had been rotated when it had not.
pub fn apply_provider_overrides(cfg: &mut Config, vars: &[(String, String)]) -> anyhow::Result<()> {
    let overrides = parse_overrides(vars)?;
    for entry in overrides {
        let providers = &mut cfg.identity_providers;
        let count = providers.len();
        let slot = providers.get_mut(entry.index).ok_or_else(|| {
            anyhow::anyhow!(
                "RE0AUTH_{}__{}__{} refers to provider index {}, but the file defines {}",
                PROVIDERS.to_uppercase(),
                entry.index,
                entry.field.to_uppercase(),
                entry.index,
                count
            )
        })?;
        set_field(slot, &entry.field, &entry.value)?;
    }
    Ok(())
}

fn parse_overrides(vars: &[(String, String)]) -> anyhow::Result<Vec<Override>> {
    let mut out = Vec::new();
    for (key, value) in vars {
        if !is_provider_override_key(key) {
            continue;
        }
        let mut parts = key.splitn(3, "__");
        let _head = parts.next();
        let index = parts.next().unwrap_or_default();
        let field = parts.next().unwrap_or_default();
        let index: usize = index.parse().map_err(|_| {
            anyhow::anyhow!(
                "RE0AUTH_{}__{index}__… needs a numeric provider index, got {index:?}",
                PROVIDERS.to_uppercase()
            )
        })?;
        if field.is_empty() {
            anyhow::bail!(
                "RE0AUTH_{}__{index}__ is missing a field name; expected one of {}",
                PROVIDERS.to_uppercase(),
                SCALAR_FIELDS.join(", ")
            );
        }
        let field = field.to_ascii_lowercase();
        if !SCALAR_FIELDS.contains(&field.as_str()) {
            anyhow::bail!(
                "RE0AUTH_{}__{index}__{} is not an overridable field; expected one of {} \
                 (scopes must be set in the file)",
                PROVIDERS.to_uppercase(),
                field.to_uppercase(),
                SCALAR_FIELDS.join(", ")
            );
        }
        out.push(Override {
            index,
            field,
            value: value.clone(),
        });
    }
    Ok(out)
}

fn set_field(idp: &mut IdentityProviderConfig, field: &str, value: &str) -> anyhow::Result<()> {
    match field {
        "name" => idp.name = value.to_string(),
        "issuer" => idp.issuer = value.to_string(),
        "kind" => idp.kind = parse_kind(value)?,
        "client_id" => idp.client_id = value.to_string(),
        "client_secret" => idp.client_secret = value.to_string(),
        "client_secret_file" => idp.client_secret_file = Some(value.to_string()),
        "redirect_uri" => idp.redirect_uri = value.to_string(),
        "discovery_url" => idp.discovery_url = Some(value.to_string()),
        "authorization_endpoint" => idp.authorization_endpoint = Some(value.to_string()),
        "token_endpoint" => idp.token_endpoint = Some(value.to_string()),
        "jwks_uri" => idp.jwks_uri = Some(value.to_string()),
        "userinfo_endpoint" => idp.userinfo_endpoint = Some(value.to_string()),
        other => unreachable!("field {other} passed the allowlist but has no setter"),
    }
    Ok(())
}

fn parse_kind(raw: &str) -> anyhow::Result<IdentityProviderKind> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "oidc" => Ok(IdentityProviderKind::Oidc),
        "github" => Ok(IdentityProviderKind::Github),
        "qq" => Ok(IdentityProviderKind::Qq),
        other => anyhow::bail!("idp kind {other:?} is unknown; expected oidc, github or qq"),
    }
}

/// Collects `RE0AUTH_`-prefixed variables, stripped of the prefix.
///
/// Only `identity_providers` keys are returned, so the caller never has to
/// filter again.
pub fn provider_override_vars() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(key, value)| {
            let key = key.to_string_lossy();
            let stripped = key.strip_prefix("RE0AUTH_")?;
            is_provider_override_key(stripped)
                .then(|| (stripped.to_string(), value.to_string_lossy().into_owned()))
        })
        .collect()
}

/// Reads a provider secret from a file and stores it on the provider.
///
/// Separate from the plain `client_secret` override so a deployment can mount a
/// secret instead of putting it in an environment variable, which leaks through
/// `/proc/<pid>/environ` and container inspect output.
pub fn resolve_secret_files(cfg: &mut Config) -> anyhow::Result<()> {
    for (index, idp) in cfg.identity_providers.iter_mut().enumerate() {
        let Some(path) = idp
            .client_secret_file
            .as_deref()
            .filter(|p| !p.trim().is_empty())
        else {
            continue;
        };
        if !idp.client_secret.trim().is_empty() {
            anyhow::bail!(
                "identity_providers[{index}] sets both client_secret and client_secret_file; \
                 keep exactly one"
            );
        }
        let raw = std::fs::read_to_string(path).map_err(|error| {
            anyhow::anyhow!("identity_providers[{index}].client_secret_file {path:?}: {error}")
        })?;
        // Trailing newline is normal in a mounted secret; nothing else is trimmed,
        // because a secret is exact and silently altering it would be worse than
        // failing an authentication later.
        let secret = raw.trim_end_matches(['\r', '\n']).to_string();
        if secret.is_empty() {
            anyhow::bail!("identity_providers[{index}].client_secret_file {path:?} is empty");
        }
        idp.client_secret = secret;
        idp.client_secret_file = None;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::Figment;
    use figment::providers::{Format, Toml};

    fn two_providers() -> Config {
        let raw = r#"
[server]
bind = "127.0.0.1:8080"
issuer = "https://auth.example.com"

[database]
url = "sqlite://data/re0auth.db"

[crypto]
master_key_file = "data/master.key"
signing_key_file = "data/signing-key.pem"

[limits]
upstream_response_bytes = 4194304
upstream_inflight_bytes = 67108864
inbound_body_bytes = 1048576

[[identity_providers]]
name = "corp"
issuer = "https://corp-idp.example.com"
client_id = "re0auth"
redirect_uri = "https://auth.example.com/auth/callback"
scopes = ["openid"]

[[identity_providers]]
name = "guild"
issuer = "https://guild-idp.example.com"
client_id = "re0auth"
redirect_uri = "https://auth.example.com/auth/callback"
scopes = ["openid"]
"#;
        Figment::from(Toml::string(raw)).extract().expect("config")
    }

    fn pairs(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// The whole point of ISSUE-0007: the secret reaches the second provider
    /// without the file listing it and without disturbing anything else.
    #[test]
    fn a_secret_is_overridden_on_the_indexed_provider_only() {
        let mut cfg = two_providers();
        apply_provider_overrides(
            &mut cfg,
            &pairs(&[("identity_providers__1__client_secret", "from-env")]),
        )
        .expect("override applies");

        assert_eq!(cfg.identity_providers[1].client_secret, "from-env");
        assert!(
            cfg.identity_providers[0].client_secret.is_empty(),
            "the other provider must be untouched"
        );
        assert_eq!(
            cfg.identity_providers[1].name, "guild",
            "other fields survive"
        );
        assert_eq!(
            cfg.identity_providers[1].issuer,
            "https://guild-idp.example.com"
        );
    }

    #[test]
    fn every_scalar_field_can_be_overridden() {
        let mut cfg = two_providers();
        apply_provider_overrides(
            &mut cfg,
            &pairs(&[
                ("identity_providers__0__kind", "github"),
                ("identity_providers__0__client_id", "abc"),
                (
                    "identity_providers__0__redirect_uri",
                    "https://x.example/cb",
                ),
                (
                    "identity_providers__0__token_endpoint",
                    "https://x.example/token",
                ),
                (
                    "identity_providers__0__userinfo_endpoint",
                    "https://x.example/user",
                ),
            ]),
        )
        .expect("overrides apply");

        let idp = &cfg.identity_providers[0];
        assert_eq!(idp.kind, IdentityProviderKind::Github);
        assert_eq!(idp.client_id, "abc");
        assert_eq!(idp.redirect_uri, "https://x.example/cb");
        assert_eq!(
            idp.token_endpoint.as_deref(),
            Some("https://x.example/token")
        );
        assert_eq!(
            idp.userinfo_endpoint.as_deref(),
            Some("https://x.example/user")
        );
    }

    /// An index past the end is almost always a stale deployment manifest. It
    /// must fail loudly; accepting it would look like the override took effect.
    #[test]
    fn an_out_of_range_index_is_an_error() {
        let mut cfg = two_providers();
        let error = apply_provider_overrides(
            &mut cfg,
            &pairs(&[("identity_providers__5__client_secret", "x")]),
        )
        .expect_err("index 5 does not exist");
        assert!(error.to_string().contains("index 5"), "{error}");
    }

    #[test]
    fn a_typo_in_the_field_name_is_an_error() {
        let mut cfg = two_providers();
        let error = apply_provider_overrides(
            &mut cfg,
            &pairs(&[("identity_providers__0__client_secert", "x")]),
        )
        .expect_err("a typo must not be ignored");
        assert!(error.to_string().contains("CLIENT_SECERT"), "{error}");
    }

    #[test]
    fn a_non_numeric_index_is_an_error() {
        let mut cfg = two_providers();
        let error = apply_provider_overrides(
            &mut cfg,
            &pairs(&[("identity_providers__first__client_secret", "x")]),
        )
        .expect_err("the index must be numeric");
        assert!(error.to_string().contains("numeric"), "{error}");
    }

    /// `scopes` is a list. Any separator would be ambiguous, because a scope
    /// token may itself contain a comma, so the override is refused rather than
    /// guessed at.
    #[test]
    fn the_scopes_list_is_refused_by_name() {
        let mut cfg = two_providers();
        let error = apply_provider_overrides(
            &mut cfg,
            &pairs(&[("identity_providers__0__scopes", "openid,profile")]),
        )
        .expect_err("scopes is not overridable");
        assert!(error.to_string().contains("scopes"), "{error}");
    }

    #[test]
    fn unrelated_variables_are_ignored() {
        let mut cfg = two_providers();
        apply_provider_overrides(
            &mut cfg,
            &pairs(&[
                ("server__bind", "0.0.0.0:1"),
                ("database__url", "sqlite::memory:"),
            ]),
        )
        .expect("no provider keys, nothing to do");
        assert_eq!(cfg.server.bind, "127.0.0.1:8080");
    }

    #[test]
    fn keys_are_recognized_case_insensitively() {
        assert!(is_provider_override_key(
            "identity_providers__0__client_secret"
        ));
        assert!(is_provider_override_key(
            "IDENTITY_PROVIDERS__0__CLIENT_SECRET"
        ));
        assert!(!is_provider_override_key(
            "identity_provider__client_secret"
        ));
        assert!(!is_provider_override_key("identity_providers_extra__0__x"));
    }

    #[test]
    fn a_secret_file_is_read_and_stripped_of_the_trailing_newline() {
        let dir = std::env::temp_dir().join(format!("re0auth-secret-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("secret");
        std::fs::write(&path, "s3cr3t\n").expect("write");

        let mut cfg = two_providers();
        cfg.identity_providers[0].client_secret_file = Some(path.to_string_lossy().into_owned());
        resolve_secret_files(&mut cfg).expect("resolve");

        assert_eq!(cfg.identity_providers[0].client_secret, "s3cr3t");
        assert!(
            cfg.identity_providers[0].client_secret_file.is_none(),
            "the path is not needed once the value is loaded"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn setting_both_secret_sources_is_an_error() {
        let mut cfg = two_providers();
        cfg.identity_providers[0].client_secret = "inline".to_string();
        cfg.identity_providers[0].client_secret_file = Some("/nonexistent".to_string());
        let error = resolve_secret_files(&mut cfg).expect_err("both sources set");
        assert!(error.to_string().contains("exactly one"), "{error}");
    }

    #[test]
    fn a_missing_secret_file_names_the_provider() {
        let mut cfg = two_providers();
        cfg.identity_providers[1].client_secret_file = Some("/definitely/not/here".to_string());
        let error = resolve_secret_files(&mut cfg).expect_err("missing file");
        assert!(
            error.to_string().contains("identity_providers[1]"),
            "{error}"
        );
    }
}
