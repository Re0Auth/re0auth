//! Authorization-code exchange against a configured upstream (INV-BIND-03).
//!
//! Kept separate from [`crate::connector::HttpBroker`]: the broker reads data with
//! a credential that already exists, this mints one. The separation is structural
//! rather than stylistic — the gateway must not be able to reach a
//! credential-minting call at all.
//!
//! Configuration lives here rather than on `ConnectorEndpoint` because the
//! registry answers "where may this connector fetch", and the endpoints below are
//! not fetch targets: they are navigated to by a browser and called once during a
//! bind.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use secrecy::ExposeSecret;
use serde::Deserialize;
use url::Url;

use re0auth_api::SecretString;
use re0auth_api::connector::{
    ConnectorAuth, ConnectorEndpoint, ExchangedCredential, UpstreamError,
};
use re0auth_runtime::http_client::GuardedClient;

/// One connector's authorization-code endpoints and client identity.
#[derive(Clone, Debug)]
pub struct ConnectorOAuthConfig {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub client_secret: SecretString,
    pub scopes: Vec<String>,
    /// Where the upstream account is read after the exchange.
    ///
    /// Required, not optional: the exchange yields a credential but not whose it
    /// is, and the gateway's `subject` must name the upstream account. A
    /// configuration that omits this cannot produce a usable binding, so
    /// `validate` rejects it rather than letting a bind store a credential
    /// nobody can address.
    pub userinfo_endpoint: String,
    /// The JSON field in the userinfo document that names the account.
    ///
    /// A field name rather than a JSON path: `INV-CONN-01` forbids digging
    /// through an undeclared document, and every upstream worth binding has a
    /// flat identifier here (`id`, `openid`, `uid`).
    pub subject_field: String,
}

/// Exchanges codes for credentials for every connector that declares endpoints.
pub struct ConfiguredConnectorAuth {
    http: Arc<GuardedClient>,
    configs: HashMap<String, ConnectorOAuthConfig>,
}

impl ConfiguredConnectorAuth {
    #[must_use]
    pub fn new(http: Arc<GuardedClient>, configs: HashMap<String, ConnectorOAuthConfig>) -> Self {
        Self { http, configs }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }

    fn config(&self, endpoint: &ConnectorEndpoint) -> Result<&ConnectorOAuthConfig, UpstreamError> {
        self.configs
            .get(&endpoint.name)
            .ok_or(UpstreamError::NotFound)
    }
}

/// The token response, as far as we care.
///
/// `access_token` only: a refresh token is a separate concern (`OPEN-014`), and
/// pretending to store one we cannot use would be worse than not storing it.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Builds the browser-facing authorization URL.
///
/// The query is assembled by `url`'s serialiser rather than by `format!`: a
/// template has to remember to escape every value, and it silently yields two
/// `?` when the configured endpoint already carries a query.
fn authorization_url(
    endpoint: &str,
    client_id: &str,
    state: &str,
    redirect_uri: &str,
    scopes: &[String],
    pkce_challenge: Option<&str>,
) -> Result<String, UpstreamError> {
    let mut url = Url::parse(endpoint).map_err(|_| UpstreamError::Unavailable)?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("state", state)
            .append_pair("redirect_uri", redirect_uri);
        if !scopes.is_empty() {
            pairs.append_pair("scope", &scopes.join(" "));
        }
        if let Some(challenge) = pkce_challenge {
            pairs
                .append_pair("code_challenge", challenge)
                .append_pair("code_challenge_method", "S256");
        }
    }
    Ok(url.to_string())
}

#[async_trait]
impl ConnectorAuth for ConfiguredConnectorAuth {
    fn authorization_url(
        &self,
        endpoint: &ConnectorEndpoint,
        state: &str,
        redirect_uri: &str,
        pkce_challenge: Option<&str>,
    ) -> Result<String, UpstreamError> {
        let config = self.config(endpoint)?;
        authorization_url(
            &config.authorization_endpoint,
            &config.client_id,
            state,
            redirect_uri,
            &config.scopes,
            pkce_challenge,
        )
    }

    async fn exchange_code(
        &self,
        endpoint: &ConnectorEndpoint,
        code: &str,
        redirect_uri: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<ExchangedCredential, UpstreamError> {
        let config = self.config(endpoint)?;
        let mut form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", redirect_uri.to_string()),
            ("client_id", config.client_id.clone()),
            (
                "client_secret",
                config.client_secret.expose_secret().to_string(),
            ),
        ];
        if let Some(verifier) = pkce_verifier {
            form.push(("code_verifier", verifier.to_string()));
        }

        // Goes through the outbound guard: a connector's token endpoint is as
        // capable of pointing at the metadata service as any other URL, and being
        // configured does not make it trusted.
        let response: TokenResponse = self
            .http
            .post_form(&config.token_endpoint, &form)
            .await
            .map_err(|_| UpstreamError::Unavailable)?;
        let credential = SecretString::from(response.access_token);

        let subject = self
            .subject(
                &config.userinfo_endpoint,
                config.subject_field.as_str(),
                &credential,
            )
            .await?;
        Ok(ExchangedCredential {
            credential,
            subject,
        })
    }
}

/// The userinfo document, restricted to the fields a bind may read.
///
/// Deliberately a declared shape rather than a `serde_json::Map`: `INV-CONN-01`
/// forbids reaching into an undeclared document, and listing the fields is what
/// makes "this connector reads exactly these" true by construction instead of by
/// a reviewer noticing that some lookup happened to be harmless.
///
/// `id` is untagged because sources disagree on whether it is a number (GitHub)
/// or a string (`"openid"`, `"uid"`).
#[derive(Debug, Deserialize)]
struct UserInfo {
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default)]
    openid: Option<String>,
    #[serde(default)]
    login: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

impl UserInfo {
    /// Reads `wanted`, which must be one of the declared identifiers.
    ///
    /// Returns nothing for an unknown field rather than falling back to another
    /// one: a document whose identifier is `login` must not be silently accepted
    /// because the configuration asked for `id`. Binding to the wrong account is
    /// worse than failing the bind.
    fn read(&self, wanted: &str) -> Option<String> {
        match wanted {
            "id" => self.id.as_ref().and_then(|value| match value {
                serde_json::Value::String(text) => Some(text.clone()),
                serde_json::Value::Number(number) => Some(number.to_string()),
                _ => None,
            }),
            "openid" => self.openid.clone(),
            "login" => self.login.clone(),
            "name" => self.name.clone(),
            _ => None,
        }
    }
}

impl ConfiguredConnectorAuth {
    /// Reads the upstream account this credential speaks for.
    ///
    /// A failure here fails the bind. Storing a credential whose owner we could
    /// not establish would leave a binding the gateway cannot address — every
    /// later read would send the wrong subject upstream — so the exchange is
    /// treated as incomplete rather than partially successful.
    async fn subject(
        &self,
        userinfo_endpoint: &str,
        field: &str,
        credential: &SecretString,
    ) -> Result<String, UpstreamError> {
        let document: UserInfo = self
            .http
            .get_json_with_bearer(userinfo_endpoint, credential.expose_secret())
            .await
            .map_err(|_| UpstreamError::Unavailable)?;
        let subject = document.read(field).ok_or(UpstreamError::NotFound)?;
        let subject = subject.trim();
        if subject.is_empty() {
            return Err(UpstreamError::NotFound);
        }
        Ok(subject.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(url: &str) -> Vec<(String, String)> {
        Url::parse(url)
            .expect("an authorization url")
            .query_pairs()
            .into_owned()
            .collect()
    }

    #[test]
    fn every_value_is_escaped_and_survives_a_round_trip() {
        let url = authorization_url(
            "https://upstream.example/oauth/authorize",
            "client id&x=1",
            "st ate",
            "https://re0auth.example/binding/callback?x=1",
            &["read".to_string(), "profile extra".to_string()],
            Some("chal/enge+="),
        )
        .expect("url");
        assert_eq!(
            pairs(&url),
            [
                ("response_type".to_string(), "code".to_string()),
                ("client_id".to_string(), "client id&x=1".to_string()),
                ("state".to_string(), "st ate".to_string()),
                (
                    "redirect_uri".to_string(),
                    "https://re0auth.example/binding/callback?x=1".to_string()
                ),
                ("scope".to_string(), "read profile extra".to_string()),
                ("code_challenge".to_string(), "chal/enge+=".to_string()),
                ("code_challenge_method".to_string(), "S256".to_string()),
            ]
        );
    }

    /// A template string produced `endpoint?tenant=a?response_type=code` here.
    #[test]
    fn an_endpoint_that_already_has_a_query_keeps_one_question_mark() {
        let url = authorization_url(
            "https://upstream.example/auth?tenant=a",
            "client",
            "state",
            "https://re0auth.example/cb",
            &[],
            None,
        )
        .expect("url");
        assert_eq!(url.matches('?').count(), 1, "{url}");
        let pairs = pairs(&url);
        assert!(pairs.contains(&("tenant".to_string(), "a".to_string())));
        assert!(pairs.contains(&("state".to_string(), "state".to_string())));
        assert!(!pairs.iter().any(|(key, _)| key == "scope"));
        assert!(!pairs.iter().any(|(key, _)| key == "code_challenge"));
    }

    #[test]
    fn an_endpoint_that_is_not_an_absolute_url_is_refused() {
        for endpoint in ["", "not-a-url", "/relative"] {
            assert!(
                authorization_url(endpoint, "c", "s", "r", &[], None).is_err(),
                "{endpoint:?}"
            );
        }
    }

    fn parse(json: &str) -> UserInfo {
        serde_json::from_str(json).expect("a userinfo document")
    }

    #[test]
    fn a_numeric_id_is_read_as_the_subject() {
        // GitHub's `id` is a number; storing it must not require a string field.
        let document = parse(r#"{"id": 12345, "login": "someone"}"#);
        assert_eq!(document.read("id").as_deref(), Some("12345"));
    }

    #[test]
    fn a_string_id_is_read_as_the_subject() {
        let document = parse(r#"{"id": "abc"}"#);
        assert_eq!(document.read("id").as_deref(), Some("abc"));
    }

    #[test]
    fn openid_is_read_when_that_is_the_configured_field() {
        let document = parse(r#"{"openid": "qq-openid", "name": "nick"}"#);
        assert_eq!(document.read("openid").as_deref(), Some("qq-openid"));
    }

    #[test]
    fn an_undeclared_field_is_never_read() {
        // INV-CONN-01: the document may carry anything, but only the declared
        // fields are addressable. `sub` is a plausible identifier that this
        // connector does not declare, so it must not be readable by name.
        let document = parse(r#"{"sub": "other", "id": 7}"#);
        assert_eq!(document.read("sub"), None);
        assert_eq!(document.read("id").as_deref(), Some("7"));
    }

    #[test]
    fn a_document_without_the_configured_field_yields_nothing() {
        // Not a fallback to `login`: binding to the wrong account is worse than
        // failing the bind, and a source that stops returning `id` would
        // otherwise start binding by handle.
        let document = parse(r#"{"login": "someone"}"#);
        assert_eq!(document.read("id"), None);
    }
}
