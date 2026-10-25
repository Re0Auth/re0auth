//! OAuth 2.0 providers that do not implement OpenID Connect.
//!
//! GitHub and QQ issue a bearer token but no `id_token` and publish no JWKS, so
//! there is nothing to verify offline: identity has to be read from a userinfo
//! endpoint over the token we just obtained. That is a materially weaker shape
//! than OIDC — the token endpoint response *is* the authentication — so the two
//! providers are kept in their own module instead of being threaded through the
//! OIDC verifier, and each one's quirks stay in one place.

use async_trait::async_trait;
use serde::Deserialize;
use url::Url;

use re0auth_api::idp::{IdpClient, IdpError, IdpIdentity, IdpResult};

use crate::transport_error;
use re0auth_runtime::http_client::GuardedClient;

/// The provider a `OAuth2Provider` talks to.
///
/// The variant fixes every wire detail that differs between them: where identity
/// comes from, which parameter names the provider insists on, and the namespace
/// its subjects are stored under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuth2Kind {
    GitHub,
    Qq,
}

impl OAuth2Kind {
    /// The `issuer` recorded in the `identities` table.
    ///
    /// Neither provider issues an `iss` claim, so this value is ours. It is a
    /// namespace, not a protocol fact: changing it would orphan every existing
    /// account, which is why the config layer refuses any other value.
    #[must_use]
    pub fn namespace(self) -> &'static str {
        match self {
            Self::GitHub => "https://github.com",
            Self::Qq => "https://graph.qq.com",
        }
    }
}

#[derive(Clone)]
pub struct OAuth2Config {
    pub kind: OAuth2Kind,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// Where the identity document is read from after the token exchange.
    pub userinfo_endpoint: String,
}

impl std::fmt::Debug for OAuth2Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2Config")
            .field("kind", &self.kind)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("userinfo_endpoint", &self.userinfo_endpoint)
            .finish()
    }
}

#[derive(Clone)]
pub struct OAuth2Provider {
    config: OAuth2Config,
    http: GuardedClient,
}

impl OAuth2Provider {
    /// Builds a provider, validating that the endpoints are absolute URLs.
    pub fn new(config: OAuth2Config, http: GuardedClient) -> anyhow::Result<Self> {
        for endpoint in [
            &config.authorization_endpoint,
            &config.token_endpoint,
            &config.userinfo_endpoint,
        ] {
            Url::parse(endpoint).map_err(|error| {
                anyhow::anyhow!("invalid OAuth2 endpoint {endpoint:?}: {error}")
            })?;
        }
        // Both providers authenticate the token request with a client secret.
        // Without one the exchange cannot succeed, and failing at startup is far
        // clearer than failing on the first login.
        if config.client_secret.trim().is_empty() {
            anyhow::bail!(
                "{:?} requires a client_secret; the token endpoint cannot be called without one",
                config.kind
            );
        }
        Ok(Self { config, http })
    }

    /// Exchanges the authorization code for an access token.
    async fn access_token(&self, code: &str) -> IdpResult<String> {
        match self.config.kind {
            OAuth2Kind::GitHub => self.github_access_token(code).await,
            OAuth2Kind::Qq => self.qq_access_token(code).await,
        }
    }

    async fn github_access_token(&self, code: &str) -> IdpResult<String> {
        // GitHub answers with form encoding unless asked for JSON. The Accept
        // header is part of the protocol, not an optimisation.
        let body = self
            .http
            .post_form_text(
                &self.config.token_endpoint,
                &[
                    ("client_id", self.config.client_id.as_str()),
                    ("client_secret", self.config.client_secret.as_str()),
                    ("code", code),
                    ("redirect_uri", self.config.redirect_uri.as_str()),
                ],
                "application/json",
            )
            .await
            .map_err(transport_error)?;
        let response: GitHubTokenResponse = serde_json::from_str(&body)
            .map_err(|error| IdpError::Protocol(format!("github token response: {error}")))?;
        if let Some(error) = response.error {
            return Err(IdpError::Protocol(format!(
                "github token endpoint rejected the exchange: {error}"
            )));
        }
        response
            .access_token
            .filter(|token| !token.trim().is_empty())
            .ok_or_else(|| {
                IdpError::Protocol("github token response has no access_token".to_string())
            })
    }

    async fn qq_access_token(&self, code: &str) -> IdpResult<String> {
        // QQ answers the token endpoint with `application/x-www-form-urlencoded`
        // (`access_token=...&expires_in=...`), never JSON.
        let body = self
            .http
            .post_form_text(
                &self.config.token_endpoint,
                &[
                    ("grant_type", "authorization_code"),
                    ("client_id", self.config.client_id.as_str()),
                    ("client_secret", self.config.client_secret.as_str()),
                    ("code", code),
                    ("redirect_uri", self.config.redirect_uri.as_str()),
                    ("fmt", "json"),
                ],
                "application/x-www-form-urlencoded",
            )
            .await
            .map_err(transport_error)?;
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        if let Some((_, error)) = pairs.iter().find(|(key, _)| key == "error") {
            return Err(IdpError::Protocol(format!(
                "qq token endpoint rejected the exchange: {error}"
            )));
        }
        pairs
            .into_iter()
            .find(|(key, _)| key == "access_token")
            .map(|(_, value)| value)
            .filter(|token| !token.trim().is_empty())
            .ok_or_else(|| IdpError::Protocol("qq token response has no access_token".to_string()))
    }

    async fn github_identity(&self, token: &str) -> IdpResult<IdpIdentity> {
        let user: GitHubUser = self
            .http
            .get_json_with_bearer(&self.config.userinfo_endpoint, token)
            .await
            .map_err(transport_error)?;
        // `login` is a mutable handle; only the numeric id is stable, so it is
        // what the identity is keyed on.
        let display_name = user
            .name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or(user.login);
        Ok(IdpIdentity {
            issuer: self.config.kind.namespace().to_string(),
            subject: user.id.to_string(),
            display_name,
        })
    }

    async fn qq_identity(&self, token: &str) -> IdpResult<IdpIdentity> {
        let openid = self.qq_openid(token).await?;
        let mut url = Url::parse(&self.config.userinfo_endpoint)
            .map_err(|error| IdpError::Protocol(error.to_string()))?;
        url.query_pairs_mut()
            .append_pair("access_token", token)
            // QQ names the client id `oauth_consumer_key` here, unlike everywhere
            // else in its API.
            .append_pair("oauth_consumer_key", &self.config.client_id)
            .append_pair("openid", &openid);
        let body = self
            .http
            .get_text(url.as_str(), "application/json")
            .await
            .map_err(transport_error)?;
        let user: QqUser = serde_json::from_str(&body)
            .map_err(|error| IdpError::Protocol(format!("qq userinfo response: {error}")))?;
        if user.ret != 0 {
            return Err(IdpError::Protocol(format!(
                "qq userinfo returned ret={} ({})",
                user.ret, user.msg
            )));
        }
        let display_name = if user.nickname.trim().is_empty() {
            openid.clone()
        } else {
            user.nickname
        };
        Ok(IdpIdentity {
            issuer: self.config.kind.namespace().to_string(),
            subject: openid,
            display_name,
        })
    }

    async fn qq_openid(&self, token: &str) -> IdpResult<String> {
        let mut url = Url::parse(&self.config.userinfo_endpoint)
            .map_err(|error| IdpError::Protocol(error.to_string()))?;
        // The openid endpoint is a sibling of `user/get_user_info`.
        url.set_path("/oauth2.0/me");
        url.set_query(None);
        url.query_pairs_mut().append_pair("access_token", token);
        let body = self
            .http
            .get_text(url.as_str(), "text/plain")
            .await
            .map_err(transport_error)?;
        let document: QqOpenId = serde_json::from_str(strip_jsonp(&body)?)
            .map_err(|error| IdpError::Protocol(format!("qq openid response: {error}")))?;
        if let Some(error) = document.error {
            return Err(IdpError::Protocol(format!(
                "qq openid endpoint returned error {error}: {}",
                document.error_description.unwrap_or_default()
            )));
        }
        document
            .openid
            .filter(|openid| !openid.trim().is_empty())
            .ok_or_else(|| IdpError::Protocol("qq openid response has no openid".to_string()))
    }
}

#[async_trait]
impl IdpClient for OAuth2Provider {
    fn authorization_url(&self, state: &str, _nonce: &str, _code_challenge: &str) -> String {
        let mut url = Url::parse(&self.config.authorization_endpoint)
            .expect("OAuth2 authorization endpoint was validated");
        {
            let mut pairs = url.query_pairs_mut();
            pairs
                .append_pair("response_type", "code")
                .append_pair("client_id", &self.config.client_id)
                .append_pair("redirect_uri", &self.config.redirect_uri)
                .append_pair("state", state);
            if !self.config.scopes.is_empty() {
                pairs.append_pair("scope", &self.config.scopes.join(" "));
            }
        }
        url.to_string()
    }

    async fn exchange_code(
        &self,
        code: &str,
        _code_verifier: &str,
        _nonce: &str,
    ) -> IdpResult<IdpIdentity> {
        // `code_verifier` and `nonce` are OIDC-flow parameters. Neither provider
        // implements them, so they are ignored rather than sent as noise.
        let token = self.access_token(code).await?;
        match self.config.kind {
            OAuth2Kind::GitHub => self.github_identity(&token).await,
            OAuth2Kind::Qq => self.qq_identity(&token).await,
        }
    }
}

#[derive(Debug, Deserialize)]
struct GitHubTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: u64,
    login: String,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct QqOpenId {
    openid: Option<String>,
    error: Option<i64>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct QqUser {
    ret: i64,
    #[serde(default)]
    msg: String,
    #[serde(default)]
    nickname: String,
}

/// Removes QQ's JSONP wrapper from an openid response.
///
/// QQ answers `/oauth2.0/me` with `callback( {...} );`. The wrapper has to be
/// removed exactly — a `trim_start_matches` or a slice at the first `{` would
/// happily accept a truncated or extra-content body and hand back something
/// parseable. Every step below is therefore a strict prefix/suffix match, and a
/// body that does not fit is an error rather than a best-effort parse.
fn strip_jsonp(body: &str) -> IdpResult<&str> {
    let trimmed = body.trim();
    let inner = trimmed.strip_prefix("callback(").ok_or_else(|| {
        IdpError::Protocol("qq openid response is not a JSONP callback".to_string())
    })?;
    // The semicolon comes after the paren, so it has to be removed first.
    let inner = inner
        .trim_end()
        .strip_suffix(';')
        .unwrap_or(inner.trim_end());
    let inner = inner
        .trim_end()
        .strip_suffix(')')
        .ok_or_else(|| IdpError::Protocol("qq openid response has no closing paren".to_string()))?;
    let inner = inner.trim();
    if !inner.starts_with('{') || !inner.ends_with('}') {
        return Err(IdpError::Protocol(
            "qq openid callback does not contain a JSON object".to_string(),
        ));
    }
    Ok(inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_well_formed_jsonp_body_is_unwrapped() {
        let body = "callback( {\"client_id\":\"123\",\"openid\":\"abc\"} );";
        assert_eq!(
            strip_jsonp(body).expect("unwraps"),
            "{\"client_id\":\"123\",\"openid\":\"abc\"}"
        );
    }

    #[test]
    fn a_jsonp_body_without_the_trailing_semicolon_is_accepted() {
        let body = "callback({\"openid\":\"abc\"})";
        assert_eq!(strip_jsonp(body).expect("unwraps"), "{\"openid\":\"abc\"}");
    }

    /// Each of these used to be a way to get a partly-wrong document parsed.
    #[test]
    fn malformed_jsonp_bodies_are_rejected() {
        for body in [
            "{\"openid\":\"abc\"}",
            "callback({\"openid\":\"abc\"}",
            "callback(\"a string\");",
            "callback();",
            "callback([1,2]);",
            "callback({\"openid\":\"abc\"}); trailing",
            "",
        ] {
            assert!(
                strip_jsonp(body).is_err(),
                "{body:?} must not be accepted as a JSONP callback"
            );
        }
    }

    #[test]
    fn the_namespace_is_fixed_per_kind() {
        assert_eq!(OAuth2Kind::GitHub.namespace(), "https://github.com");
        assert_eq!(OAuth2Kind::Qq.namespace(), "https://graph.qq.com");
    }
}
