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

use async_trait::async_trait;
use secrecy::ExposeSecret;
use serde::Deserialize;
use std::collections::HashMap;
use url::Url;

use crate::connector::ConnectorClients;
use re0auth_api::SecretString;
use re0auth_api::connector::{
    ConnectorAuth, ConnectorEndpoint, ConnectorRefresh, ExchangedCredential, RefreshedCredential,
    UpstreamError,
};

/// One connector's authorization-code endpoints and client identity.
#[derive(Clone, Debug)]
pub struct ConnectorOAuthConfig {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// Optional refresh endpoint. Without it, the connector never issues a
    /// refresh token and an expired credential requires reauthorization.
    pub refresh_endpoint: Option<String>,
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
    /// Where a credential is invalidated when its binding is revoked.
    ///
    /// Optional: an upstream that offers no revocation endpoint leaves the
    /// credential valid until it expires, and the local revocation still happens.
    pub revocation_endpoint: Option<String>,
    /// The JSON field in the userinfo document that names the account.
    ///
    /// A field name rather than a JSON path: `INV-CONN-01` forbids digging
    /// through an undeclared document, and every upstream worth binding has a
    /// flat identifier here (`id`, `openid`, `uid`).
    pub subject_field: String,
}

/// Exchanges codes for credentials for every connector that declares endpoints.
pub struct ConfiguredConnectorAuth {
    clients: ConnectorClients,
    configs: HashMap<String, ConnectorOAuthConfig>,
}

impl ConfiguredConnectorAuth {
    #[must_use]
    pub fn new(clients: ConnectorClients, configs: HashMap<String, ConnectorOAuthConfig>) -> Self {
        Self { clients, configs }
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
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_expires_in: Option<u64>,
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
        let client = self.clients.get(endpoint)?;
        let response: TokenResponse = client
            .post_form(&config.token_endpoint, &form)
            .await
            .map_err(|_| UpstreamError::Unavailable)?;
        let credential = SecretString::from(response.access_token);
        let refresh_token = response.refresh_token.map(SecretString::from);

        let subject = self
            .subject(
                client.as_ref(),
                &config.userinfo_endpoint,
                config.subject_field.as_str(),
                &credential,
            )
            .await?;
        Ok(ExchangedCredential {
            credential,
            refresh_token,
            expires_in: response.expires_in,
            refresh_expires_in: response.refresh_expires_in,
            subject,
        })
    }

    async fn revoke_token(
        &self,
        endpoint: &ConnectorEndpoint,
        credential: &SecretString,
    ) -> Result<(), UpstreamError> {
        let config = self.config(endpoint)?;
        let Some(url) = config.revocation_endpoint.as_deref() else {
            // Nothing to call: the credential dies on its own expiry. Not an
            // error, because the connector never promised revocation.
            return Ok(());
        };
        // 配置的地址不等于可信地址，出网守卫同样生效。
        let form = [
            ("token", credential.expose_secret().to_string()),
            ("client_id", config.client_id.clone()),
            (
                "client_secret",
                config.client_secret.expose_secret().to_string(),
            ),
        ];
        let pairs: Vec<(&str, &str)> = form
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect();
        let client = self.clients.get(endpoint)?;
        client
            .post_form_text(url, &pairs, "application/json")
            .await
            .map_err(|_| UpstreamError::Unavailable)?;
        Ok(())
    }
}

fn refresh_transport_error(error: anyhow::Error) -> UpstreamError {
    use re0auth_runtime::http_client::UpstreamStatus;
    let Some(status) = error.downcast_ref::<UpstreamStatus>() else {
        return UpstreamError::Unavailable;
    };
    match status.status {
        // Only `invalid_grant` means the user must reauthorize. A 401/403 or an
        // `invalid_client` from a rotated secret is an operator problem, and
        // flipping the binding to `needs_reauth` would make it permanent.
        400 | 401 | 403 => match status.error_code.as_deref() {
            Some("invalid_grant") => UpstreamError::Rejected,
            _ => UpstreamError::Unavailable,
        },
        429 => UpstreamError::RateLimited {
            retry_after_secs: status.retry_after_secs,
        },
        500 => UpstreamError::Internal,
        _ => UpstreamError::Unavailable,
    }
}

#[async_trait]
impl ConnectorRefresh for ConfiguredConnectorAuth {
    async fn refresh_token(
        &self,
        endpoint: &ConnectorEndpoint,
        refresh_token: &SecretString,
    ) -> Result<Option<RefreshedCredential>, UpstreamError> {
        let config = self.config(endpoint)?;
        let Some(url) = config.refresh_endpoint.as_deref() else {
            return Ok(None);
        };
        let form = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token.expose_secret().to_string()),
            ("client_id", config.client_id.clone()),
            (
                "client_secret",
                config.client_secret.expose_secret().to_string(),
            ),
        ];
        let client = self.clients.get(endpoint)?;
        let response: TokenResponse = client
            .post_form(url, &form)
            .await
            .map_err(refresh_transport_error)?;
        Ok(Some(RefreshedCredential {
            credential: SecretString::from(response.access_token),
            refresh_token: response.refresh_token.map(SecretString::from),
            expires_in: response.expires_in,
            refresh_expires_in: response.refresh_expires_in,
        }))
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
        client: &re0auth_runtime::http_client::GuardedClient,
        userinfo_endpoint: &str,
        field: &str,
        credential: &SecretString,
    ) -> Result<String, UpstreamError> {
        let document: UserInfo = client
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

    #[tokio::test]
    async fn refresh_exchanges_a_form_and_returns_the_rotated_pair() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        use re0auth_api::ConnectorId;
        use re0auth_api::connector::EgressPolicy;
        use re0auth_runtime::tls::TlsConfig;

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let seen = Arc::new(Mutex::new(String::new()));
        let server_seen = Arc::clone(&seen);
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            let header_end = loop {
                let read = stream.read(&mut chunk).expect("read");
                if read == 0 {
                    panic!("request ended before headers");
                }
                request.extend_from_slice(&chunk[..read]);
                if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    break position + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]).to_lowercase();
            let content_length = headers
                .split("\r\n")
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let read = stream.read(&mut chunk).expect("body");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            *server_seen.lock().expect("seen") = String::from_utf8_lossy(&request).to_string();
            let body = r#"{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600,"refresh_expires_in":86400}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            stream.write_all(response.as_bytes()).expect("write");
        });

        let endpoint = ConnectorEndpoint {
            id: ConnectorId::new(),
            name: "phihub".to_string(),
            base_url: format!("http://{address}"),
            egress: EgressPolicy::Loopback,
            resources: Vec::new(),
        };
        let clients = ConnectorClients::new(
            std::slice::from_ref(&endpoint),
            TlsConfig::default(),
            Duration::from_secs(5),
        )
        .expect("clients");
        let config = ConnectorOAuthConfig {
            authorization_endpoint: "http://example.invalid/authorize".to_string(),
            token_endpoint: "http://example.invalid/token".to_string(),
            refresh_endpoint: Some(format!("http://{address}/refresh")),
            client_id: "re0auth".to_string(),
            client_secret: SecretString::from("secret"),
            scopes: vec!["phihub.save.read".to_string()],
            userinfo_endpoint: "http://example.invalid/me".to_string(),
            revocation_endpoint: None,
            subject_field: "id".to_string(),
        };
        let auth =
            ConfiguredConnectorAuth::new(clients, HashMap::from([("phihub".to_string(), config)]));
        let refreshed = auth
            .refresh_token(&endpoint, &SecretString::from("old-refresh"))
            .await
            .expect("refresh")
            .expect("configured");
        assert_eq!(refreshed.credential.expose_secret(), "new-access");
        assert_eq!(
            refreshed
                .refresh_token
                .as_ref()
                .map(secrecy::ExposeSecret::expose_secret),
            Some("new-refresh")
        );
        assert_eq!(refreshed.expires_in, Some(3_600));
        assert_eq!(refreshed.refresh_expires_in, Some(86_400));
        let seen = seen.lock().expect("seen");
        assert!(seen.contains("refresh_token=old-refresh"), "{seen}");
        assert!(seen.contains("client_id=re0auth"), "{seen}");
        assert!(seen.contains("client_secret=secret"), "{seen}");
    }
}

#[cfg(test)]
mod s11_tests {
    use super::*;
    use re0auth_runtime::http_client::UpstreamStatus;

    fn status(code: Option<&str>) -> UpstreamStatus {
        UpstreamStatus {
            status: 400,
            retry_after_secs: None,
            error_code: code.map(str::to_string),
        }
    }

    #[test]
    fn s11_only_invalid_grant_forces_reauthorization() {
        assert_eq!(
            refresh_transport_error(status(Some("invalid_grant")).into()),
            UpstreamError::Rejected
        );
        for code in [Some("invalid_client"), Some("invalid_request"), None] {
            assert_eq!(
                refresh_transport_error(status(code).into()),
                UpstreamError::Unavailable,
                "{code:?} must not flip the binding"
            );
        }
    }
}
