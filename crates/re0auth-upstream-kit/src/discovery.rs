use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

pub const PROTOCOL_VERSION: u8 = 1;
pub const ACCOUNT_SCOPE: &str = "account.read";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenClass {
    Revocable,
    LongLived,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    pub name: String,
    pub schema: String,
    pub scope: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RawSpec {
    pub base: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openapi: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OAuthEndpoints {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cascade_revocation_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Discovery {
    pub re0auth_upstream_version: u8,
    pub game: String,
    pub source: String,
    pub display_name: String,
    pub oauth: OAuthEndpoints,
    pub token_class: TokenClass,
    pub scopes_supported: Vec<String>,
    pub resources: Vec<Resource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<RawSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub game: String,
    pub source: String,
    pub display_name: String,
    pub issuer: String,
    pub token_class: TokenClass,
    pub resources: Vec<Resource>,
    pub raw: Option<RawSpec>,
    pub contact: Option<String>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DiscoveryError {
    #[error("{0} is required")]
    Missing(&'static str),
    #[error("invalid issuer: {0}")]
    Issuer(String),
    #[error("invalid resource {0}: {1}")]
    Resource(String, String),
    #[error("duplicate resource name: {0}")]
    DuplicateResource(String),
    #[error("invalid scope: {0}")]
    Scope(String),
    #[error("invalid raw base: {0}")]
    Raw(String),
}

pub fn new_discovery(cfg: Config) -> Result<Discovery, DiscoveryError> {
    require_non_empty("game", &cfg.game)?;
    require_non_empty("source", &cfg.source)?;
    require_non_empty("display_name", &cfg.display_name)?;

    let issuer = validate_issuer(&cfg.issuer)?;
    let mut names = BTreeSet::new();
    let mut scopes = vec![ACCOUNT_SCOPE.to_string()];
    let mut seen = BTreeSet::new();
    seen.insert(ACCOUNT_SCOPE.to_string());

    for resource in &cfg.resources {
        require_non_empty("resource.name", &resource.name)?;
        if !names.insert(resource.name.clone()) {
            return Err(DiscoveryError::DuplicateResource(resource.name.clone()));
        }
        if !is_canonical_scope(&resource.scope) {
            return Err(DiscoveryError::Scope(resource.scope.clone()));
        }
        if !is_canonical_schema(&resource.schema) {
            return Err(DiscoveryError::Resource(
                resource.name.clone(),
                format!(
                    "schema must look like re0auth.<game>.<resource>/1: {}",
                    resource.schema
                ),
            ));
        }
        if seen.insert(resource.scope.clone()) {
            scopes.push(resource.scope.clone());
        }
    }

    let raw = match &cfg.raw {
        Some(raw) => Some(RawSpec {
            base: validate_http_url(&raw.base).map_err(DiscoveryError::Raw)?,
            openapi: raw.openapi.clone(),
        }),
        None => None,
    };

    let issuer_base = issuer.as_str().trim_end_matches('/').to_string();
    let oauth = OAuthEndpoints {
        issuer: issuer_base,
        authorization_endpoint: endpoint(&issuer, &["oauth", "authorize"]),
        token_endpoint: endpoint(&issuer, &["oauth", "token"]),
        revocation_endpoint: endpoint(&issuer, &["oauth", "revoke"]),
        cascade_revocation_endpoint: None,
        jwks_uri: Some(endpoint(&issuer, &[".well-known", "jwks.json"])),
    };

    Ok(Discovery {
        re0auth_upstream_version: PROTOCOL_VERSION,
        game: cfg.game,
        source: cfg.source,
        display_name: cfg.display_name,
        oauth,
        token_class: cfg.token_class,
        scopes_supported: scopes,
        resources: cfg.resources,
        raw,
        contact: cfg.contact,
    })
}

pub fn is_canonical_scope(scope: &str) -> bool {
    if scope == ACCOUNT_SCOPE {
        return true;
    }
    let mut parts = scope.split('.');
    let Some(game) = parts.next() else {
        return false;
    };
    let Some(resource) = parts.next() else {
        return false;
    };
    let Some(action) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && is_segment(game)
        && is_segment(resource)
        && matches!(action, "read" | "write")
}

pub fn is_canonical_schema(schema: &str) -> bool {
    let Some(rest) = schema.strip_prefix("re0auth.") else {
        return false;
    };
    let Some((path, version)) = rest.rsplit_once('/') else {
        return false;
    };
    if version != "1" || path.is_empty() {
        return false;
    }
    let parts: Vec<&str> = path.split('.').collect();
    parts.len() >= 2 && parts.iter().all(|part| is_segment(part))
}

fn is_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), DiscoveryError> {
    if value.trim().is_empty() {
        Err(DiscoveryError::Missing(field))
    } else {
        Ok(())
    }
}

/// The one reading of "https, or loopback http for local development".
///
/// Shared by both validators below: a copy per call site is how `[::1]` came to be
/// accepted in one place and rejected in another.
fn parse_https_or_loopback(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|error| error.to_string())?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.scheme() != "https" && !(url.scheme() == "http" && local) {
        return Err("must be https (http is allowed only for localhost)".to_string());
    }
    if url.host_str().is_none() {
        return Err("must have a host".to_string());
    }
    Ok(url)
}

fn validate_issuer(raw: &str) -> Result<Url, DiscoveryError> {
    let url = parse_https_or_loopback(raw)
        .map_err(|error| DiscoveryError::Issuer(format!("issuer {raw:?} {error}")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(DiscoveryError::Issuer(
            "issuer must not contain userinfo".to_string(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(DiscoveryError::Issuer(
            "issuer must not contain query or fragment".to_string(),
        ));
    }
    Ok(url)
}

fn validate_http_url(raw: &str) -> Result<String, String> {
    let url = parse_https_or_loopback(raw)?;
    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn endpoint(base: &Url, segments: &[&str]) -> String {
    let mut url = base.clone();
    {
        let mut path = url.path_segments_mut().expect("issuer must be a base URL");
        for segment in segments {
            path.push(segment);
        }
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One rule, one implementation: `[::1]` is loopback and must be accepted
    /// wherever `127.0.0.1` is. It used to be accepted by the server's config
    /// validator and rejected here.
    #[test]
    fn loopback_forms_are_accepted_for_http() {
        for raw in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "https://api.example.com",
        ] {
            assert!(
                parse_https_or_loopback(raw).is_ok(),
                "{raw} must be accepted"
            );
        }
    }

    #[test]
    fn plain_http_on_a_public_host_is_rejected() {
        for raw in ["http://api.example.com", "http://10.0.0.5"] {
            let error = parse_https_or_loopback(raw).expect_err("must be refused");
            assert!(error.contains("https"), "{error}");
        }
    }

    /// The issuer keeps its extra rules; the shared helper must not have dropped
    /// them while removing the duplicated scheme check.
    #[test]
    fn the_issuer_still_rejects_userinfo_and_query() {
        for raw in [
            "https://user:pass@api.example.com",
            "https://api.example.com?x=1",
            "https://api.example.com#frag",
        ] {
            assert!(validate_issuer(raw).is_err(), "{raw} must be refused");
        }
        assert!(validate_issuer("https://api.example.com").is_ok());
    }
}
