#![forbid(unsafe_code)]

//! Identity-plane adapters: external IdP federation.
//!
//! This crate talks to identity providers and produces an [`IdpIdentity`]. It
//! knows nothing about users, sessions, storage or the data plane (ADR-0021);
//! `re0auth-connectors` is its sibling, not its dependency.

pub mod oauth2;

use re0auth_runtime::http_client::{GuardedClient, UpstreamStatus};

pub use oauth2::{OAuth2Config, OAuth2Kind, OAuth2Provider};

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use chrono::Utc;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, decode_header};
use openidconnect::core::{CoreIdToken, CoreJsonWebKey, CoreProviderMetadata};
use openidconnect::{
    AccessToken, AccessTokenHash, ClaimsVerificationError, ClientId, ClientSecret, IdTokenVerifier,
    IssuerUrl, JsonWebKeySet, Nonce,
};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use re0auth_api::Clock;
use re0auth_api::idp::{IdpClient, IdpError, IdpIdentity, IdpResult};

/// Classifies a failed IdP request, keeping a refusal distinct from an outage.
///
/// The guard now preserves the status code rather than flattening it into a
/// message, so this is a typed decision: 4xx means the provider answered and
/// said no, everything else (transport, timeout, 5xx) means we could not get an
/// answer. Only the second one is worth retrying unchanged.
pub(crate) fn transport_error(error: anyhow::Error) -> IdpError {
    match error.downcast_ref::<UpstreamStatus>() {
        Some(status) if (400..500).contains(&status.status) => IdpError::Rejected {
            status: status.status,
            detail: status.to_string(),
        },
        Some(status) => IdpError::Unavailable(status.to_string()),
        None => IdpError::Unavailable(error.to_string()),
    }
}

/// How long an unknown `kid` suppresses another JWKS fetch (INV-TOKEN-02).
///
/// Without a floor, any caller who can present an unsigned token with a random
/// `kid` would make us fetch from the IdP once per request — turning the service
/// into an amplifier pointed at its own identity provider. IdPs rotate keys on
/// the order of days, so a one-minute floor costs nothing real.
const JWKS_REFRESH_COOLDOWN_SECS: i64 = 60;

/// Clock skew tolerated on `exp` and `nbf`.
///
/// `jsonwebtoken` also defaults to 60, but a default that is not written down is
/// not a decision: this is the number an operator is relying on, so it is stated
/// here and set explicitly on every `Validation`.
const ID_TOKEN_LEEWAY_SECS: u64 = 60;

/// The only signature algorithm accepted from an identity provider.
///
/// Pinned as a named constant rather than repeated inline, because `Validation`
/// would reject any other algorithm with a generic message: "which algorithms do
/// we accept" has to be answerable from the source, and answerable by a test.
/// Widening this (ES256 for Apple, EdDSA) is a decision, not an edit.
const ACCEPTED_ALG: Algorithm = Algorithm::RS256;

#[derive(Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub discovery_url: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    access_token: Option<String>,
}

#[derive(Clone)]
pub struct OidcProvider {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: Vec<String>,
    /// INV-TOKEN-02: refreshed on an unknown `kid`, so an IdP key rotation does
    /// not require a restart. `std::sync::RwLock` rather than `tokio`'s because
    /// the critical section is a clone and holds no await point.
    jwks: Arc<RwLock<JwkSet>>,
    /// Unix time of the last refresh attempt, success or failure. Set before the
    /// fetch starts so a burst of unknown kids collapses into one request.
    /// `None` means "never refreshed", which always permits a fetch.
    last_refresh: Arc<RwLock<Option<i64>>>,
    clock: Arc<dyn Clock>,
    http: GuardedClient,
}

impl OidcProvider {
    /// Builds a provider, fetching JWKS once up front.
    ///
    /// `clock` is injected because the refresh cooldown must be testable without
    /// sleeping: a real `SystemClock` makes the negative test (two unknown kids
    /// in quick succession produce one fetch) take a minute to prove.
    pub async fn discover(
        config: OidcConfig,
        http: GuardedClient,
        clock: Arc<dyn Clock>,
    ) -> anyhow::Result<Self> {
        let issuer = config.issuer.trim_end_matches('/').to_string();
        let issuer_url = Url::parse(&issuer).map_err(|error| {
            anyhow::anyhow!("configured issuer {issuer:?} is not a URL: {error}")
        })?;
        let discovery_url = config
            .discovery_url
            .clone()
            .unwrap_or_else(|| format!("{issuer}/.well-known/openid-configuration"));

        let (authorization_endpoint, token_endpoint, jwks_uri) =
            if let (Some(authorization_endpoint), Some(token_endpoint), Some(jwks_uri)) = (
                config.authorization_endpoint.clone(),
                config.token_endpoint.clone(),
                config.jwks_uri.clone(),
            ) {
                (authorization_endpoint, token_endpoint, jwks_uri)
            } else {
                // 库的严格解析替换自研反序列化
                let metadata: CoreProviderMetadata = http.get_json(&discovery_url).await?;
                if metadata.issuer().as_str().trim_end_matches('/') != issuer {
                    anyhow::bail!(
                        "OIDC discovery issuer mismatch: configured {issuer}, got {}",
                        metadata.issuer().as_str()
                    );
                }
                // ADR-0036: an outbound target must come from the registry, not
                // from a response body. `issuer` is a config value, so requiring
                // the same origin makes a discovered endpoint a function of
                // configuration. A field the operator spelled out explicitly is
                // taken as-is — that is the escape hatch for a provider whose
                // JWKS lives on a CDN.
                let authorization_endpoint = match config.authorization_endpoint {
                    Some(value) => value,
                    None => discovered(
                        &issuer_url,
                        metadata.authorization_endpoint().url().to_string(),
                        "authorization_endpoint",
                    )?,
                };
                let token_endpoint = match config.token_endpoint {
                    Some(value) => value,
                    None => {
                        let endpoint = metadata.token_endpoint().ok_or_else(|| {
                            anyhow::anyhow!("discovery document has no token_endpoint")
                        })?;
                        discovered(&issuer_url, endpoint.url().to_string(), "token_endpoint")?
                    }
                };
                let jwks_uri = match config.jwks_uri {
                    Some(value) => value,
                    None => discovered(
                        &issuer_url,
                        metadata.jwks_uri().url().to_string(),
                        "jwks_uri",
                    )?,
                };
                (authorization_endpoint, token_endpoint, jwks_uri)
            };

        for endpoint in [&authorization_endpoint, &token_endpoint, &jwks_uri] {
            Url::parse(endpoint)
                .map_err(|error| anyhow::anyhow!("invalid OIDC endpoint {endpoint:?}: {error}"))?;
        }
        let jwks: JwkSet = http.get_json(&jwks_uri).await?;

        Ok(Self {
            issuer,
            authorization_endpoint,
            token_endpoint,
            jwks_uri,
            client_id: config.client_id,
            client_secret: config.client_secret,
            redirect_uri: config.redirect_uri,
            scopes: config.scopes,
            jwks: Arc::new(RwLock::new(jwks)),
            // Deliberately not seeded with the discover time: a rotation that
            // happens right after startup must be picked up on the first unknown
            // kid, not blocked for a cooldown we never needed. The cooldown only
            // has to separate *consecutive* unknown-kid refreshes.
            last_refresh: Arc::new(RwLock::new(None)),
            clock,
            http,
        })
    }

    #[must_use]
    pub fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }

    /// Resolves the signing key for `kid`, refreshing JWKS once if needed.
    ///
    /// INV-TOKEN-02: the refresh is triggered by an unknown `kid` and bounded by
    /// a cooldown. A token that is still unverifiable after a refresh is a real
    /// rejection, not a stale-cache artefact.
    async fn signing_key(&self, kid: &str) -> IdpResult<jsonwebtoken::jwk::Jwk> {
        if let Some(jwk) = self.cached_key(kid)? {
            return Ok(jwk);
        }
        self.refresh_jwks().await?;
        self.cached_key(kid)?
            .ok_or_else(|| IdpError::InvalidToken(format!("unknown kid {kid}")))
    }

    /// Reads the cached JWKS under the lock and delegates to [`unique_key`].
    fn cached_key(&self, kid: &str) -> IdpResult<Option<Jwk>> {
        let jwks = self
            .jwks
            .read()
            .map_err(|_| IdpError::Unavailable("JWKS lock poisoned".to_string()))?;
        unique_key(&jwks.keys, kid).map(|found| found.cloned())
    }

    /// Fetches JWKS unless the cooldown has not elapsed.
    ///
    /// The timestamp is written *before* the request: if two callers race on an
    /// unknown kid, the loser sees a fresh timestamp and skips the fetch instead
    /// of doubling the load on the IdP.
    async fn refresh_jwks(&self) -> IdpResult<()> {
        let now = self.clock.now();
        {
            let mut last = self
                .last_refresh
                .write()
                .map_err(|_| IdpError::Unavailable("JWKS refresh lock poisoned".to_string()))?;
            if last
                .is_some_and(|previous| now.saturating_sub(previous) < JWKS_REFRESH_COOLDOWN_SECS)
            {
                return Ok(());
            }
            *last = Some(now);
        }
        let jwks: JwkSet = self
            .http
            .get_json(&self.jwks_uri)
            .await
            .map_err(transport_error)?;
        let mut cached = self
            .jwks
            .write()
            .map_err(|_| IdpError::Unavailable("JWKS lock poisoned".to_string()))?;
        *cached = jwks;
        Ok(())
    }

    async fn verify_id_token(
        &self,
        token: &str,
        expected_nonce: &str,
        access_token: Option<&str>,
    ) -> IdpResult<IdpIdentity> {
        // INV-TOKEN-01：id_token 与 access token 不可互换
        let header =
            decode_header(token).map_err(|error| IdpError::InvalidToken(error.to_string()))?;
        // 方案甲：自研头检查保留在库之前
        reject_unsupported_header(&header)?;
        let kid = header
            .kid
            .ok_or_else(|| IdpError::InvalidToken("id token has no kid".to_string()))?;
        let jwk = self.signing_key(&kid).await?;

        // 只喂这一把 key，缓存与 unique_key 仍归本仓
        let keys: JsonWebKeySet<CoreJsonWebKey> = serde_json::from_value(serde_json::json!({
            "keys": [jwk]
        }))
        .map_err(|error| IdpError::InvalidToken(format!("jwk conversion failed: {error}")))?;

        let client_id = ClientId::new(self.client_id.clone());
        let issuer = IssuerUrl::new(self.issuer.clone())
            .map_err(|error| IdpError::InvalidToken(format!("issuer is not a URL: {error}")))?;
        let verifier = if self.client_secret.is_empty() {
            IdTokenVerifier::new_public_client(client_id, issuer, keys)
        } else {
            IdTokenVerifier::new_confidential_client(
                client_id,
                ClientSecret::new(self.client_secret.clone()),
                issuer,
                keys,
            )
        };

        // 时钟回拨以复现原有容差
        let verifier = verifier
            .set_time_fn(|| Utc::now() - chrono::Duration::seconds(ID_TOKEN_LEEWAY_SECS as i64));

        let id_token: CoreIdToken = token
            .parse()
            .map_err(|error| IdpError::InvalidToken(format!("undecodable id token: {error}")))?;
        let claims = id_token
            .claims(&verifier, &Nonce::new(expected_nonce.to_string()))
            .map_err(claims_error)?;

        // 方案甲：库之外再跑一次本仓的 aud 判据
        let audiences = serde_json::to_value(claims.audiences()).unwrap_or(Value::Null);
        if !audience_is_only(&audiences, &self.client_id) {
            return Err(IdpError::InvalidToken("audience mismatch".to_string()));
        }
        // 库也不自动校验 at_hash
        if let Some(expected) = claims.access_token_hash() {
            let Some(raw) = access_token else {
                return Err(IdpError::InvalidToken(
                    "id token carries at_hash but the response has no access token".to_string(),
                ));
            };
            let alg = id_token.signing_alg().map_err(|error| {
                IdpError::InvalidToken(format!("id token alg unavailable: {error}"))
            })?;
            let key = id_token.signing_key(&verifier).map_err(|error| {
                IdpError::InvalidToken(format!("signing key unavailable: {error}"))
            })?;
            let actual = AccessTokenHash::from_token(&AccessToken::new(raw.to_string()), alg, key)
                .map_err(|error| {
                    IdpError::InvalidToken(format!("cannot hash access token: {error}"))
                })?;
            if actual != *expected {
                return Err(IdpError::InvalidToken("at_hash mismatch".to_string()));
            }
        }

        // 库明确不做 azp 校验
        let azp = claims.authorized_party().map(|value| value.as_str());
        if !azp_is_acceptable(azp, &self.client_id) {
            return Err(IdpError::InvalidToken(
                "azp does not name this client".to_string(),
            ));
        }

        let subject = claims.subject().as_str().to_string();
        if subject.trim().is_empty() {
            return Err(IdpError::InvalidToken("missing subject".to_string()));
        }
        let display_name = claims
            .name()
            .and_then(|localized| localized.get(None))
            .map(|value| value.as_str().to_string())
            .or_else(|| {
                claims
                    .preferred_username()
                    .map(|value| value.as_str().to_string())
            })
            .or_else(|| claims.email().map(|value| value.as_str().to_string()))
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| subject.clone());
        Ok(IdpIdentity {
            issuer: self.issuer.clone(),
            subject,
            display_name,
        })
    }
}

/// 库的错误按语义映射回既有变体
fn claims_error(error: ClaimsVerificationError) -> IdpError {
    match error {
        ClaimsVerificationError::InvalidNonce(_) => IdpError::NonceMismatch,
        ClaimsVerificationError::InvalidIssuer(_) => IdpError::IssuerMismatch,
        other => IdpError::InvalidToken(other.to_string()),
    }
}

#[async_trait]
impl IdpClient for OidcProvider {
    fn authorization_url(&self, state: &str, nonce: &str, code_challenge: &str) -> String {
        let mut url = Url::parse(&self.authorization_endpoint)
            .expect("OIDC authorization endpoint was validated");
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &self.scopes.join(" "))
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256");
        url.to_string()
    }

    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        nonce: &str,
    ) -> IdpResult<IdpIdentity> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("client_id", self.client_id.as_str()),
            ("code_verifier", code_verifier),
        ];
        if !self.client_secret.is_empty() {
            form.push(("client_secret", self.client_secret.as_str()));
        }
        let response: TokenResponse = self
            .http
            .post_form_json(&self.token_endpoint, &form)
            .await
            .map_err(transport_error)?;
        let id_token = response
            .id_token
            .ok_or_else(|| IdpError::InvalidToken("token response has no id_token".to_string()))?;
        self.verify_id_token(&id_token, nonce, response.access_token.as_deref())
            .await
    }
}

/// azp 若存在，必须指向本客户端
fn azp_is_acceptable(azp: Option<&str>, client_id: &str) -> bool {
    azp.is_none_or(|value| value == client_id)
}

/// 同一 kid 命中多把钥匙时必须拒绝
fn unique_key<'a>(keys: &'a [Jwk], kid: &str) -> IdpResult<Option<&'a Jwk>> {
    let mut matches = keys
        .iter()
        .filter(|jwk| jwk.common.key_id.as_deref() == Some(kid));
    let first = matches.next();
    if matches.next().is_some() {
        return Err(IdpError::InvalidToken(format!(
            "ambiguous kid {kid}: the JWKS publishes more than one key under it"
        )));
    }
    Ok(first)
}

/// Accepts an endpoint taken from the discovery document only if it lives on the
/// configured issuer's origin.
///
/// `url::Origin` normalises default ports, so `https://idp.example` and
/// `https://idp.example:443` are one origin. Refusing a foreign origin here is
/// what stops a compromised or misconfigured provider from redirecting our JWKS
/// fetch — and therefore "which signature counts" — to a host of its choosing.
fn discovered(issuer: &Url, endpoint: String, field: &'static str) -> anyhow::Result<String> {
    let url = Url::parse(&endpoint)
        .map_err(|error| anyhow::anyhow!("invalid {field} {endpoint:?}: {error}"))?;
    if url.origin() != issuer.origin() {
        anyhow::bail!(
            "{field} {endpoint:?} is not on the issuer's origin {}; \
         configure {field} explicitly if the provider really serves it elsewhere",
            issuer.origin().ascii_serialization()
        );
    }
    Ok(endpoint)
}

/// Accepts the token's `aud` only when it names this client and nothing else.
///
/// `jsonwebtoken`'s own audience check asks whether the two sets *intersect*, so
/// a token carrying `["re0auth", "some-other-client"]` passes as long as ours is
/// in the list. OIDC Core 3.1.3.7 only makes that tolerable when `azp` is
/// verified, which this provider does not do — so the extra audience is refused
/// instead. Every IdP supported here issues a single-audience id token, so the
/// strict form costs nothing and closes the gap without an `azp` implementation.
fn audience_is_only(value: &Value, client_id: &str) -> bool {
    match value {
        Value::String(audience) => audience == client_id,
        Value::Array(audiences) => {
            !audiences.is_empty()
                && audiences
                    .iter()
                    .all(|audience| audience.as_str() == Some(client_id))
        }
        _ => false,
    }
}

/// Rejects JOSE header parameters we would otherwise silently ignore.
///
/// `jsonwebtoken` deserializes `typ`, `crit` and `zip` but never validates them
/// (checked against 11.1.0: `crit` appears only as a field and its `None`
/// default). RFC 7515 §4.1.6 requires rejecting an unknown `crit` value, and a
/// `zip` payload is compressed, which no part of this verifier can read.
fn reject_unsupported_header(header: &jsonwebtoken::Header) -> IdpResult<()> {
    // Checked here rather than left to `Validation`, so the refusal names the
    // algorithm and the reason instead of a generic "invalid algorithm".
    if header.alg != ACCEPTED_ALG {
        return Err(IdpError::InvalidToken(format!(
            "id token is signed with {:?}; only {ACCEPTED_ALG:?} is accepted",
            header.alg
        )));
    }
    if let Some(crit) = header.crit.as_ref().filter(|crit| !crit.is_empty()) {
        return Err(IdpError::InvalidToken(format!(
            "id token declares unsupported critical headers: {crit:?}"
        )));
    }
    if header.zip.is_some() {
        return Err(IdpError::InvalidToken(
            "id token is compressed; compressed payloads are not accepted".to_string(),
        ));
    }
    if header.cty.is_some() {
        return Err(IdpError::InvalidToken(
            "id token declares a content type; nested payloads are not accepted".to_string(),
        ));
    }
    if let Some(typ) = header.typ.as_deref() {
        let normalized = typ.trim().to_ascii_lowercase();
        if normalized != "jwt" && normalized != "application/jwt" {
            return Err(IdpError::InvalidToken(format!(
                "id token has unexpected typ {typ:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn header(value: Value) -> jsonwebtoken::Header {
        serde_json::from_value(value).expect("header deserializes")
    }

    fn jwk_of(kid: &str) -> Jwk {
        serde_json::from_value(json!({
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
            "n": "AQAB",
            "e": "AQAB"
        }))
        .expect("jwk deserializes")
    }

    /// A set publishing one `kid` twice must fail, not pick a key at random.
    #[test]
    fn a_key_published_twice_under_one_kid_is_refused() {
        let keys = vec![jwk_of("shared"), jwk_of("shared")];
        let error = unique_key(&keys, "shared").expect_err("a duplicate kid must be refused");
        let message = error.to_string();
        assert!(message.contains("ambiguous"), "{message}");
        assert!(message.contains("shared"), "{message}");
    }

    #[test]
    fn the_only_key_under_that_kid_is_returned() {
        let keys = vec![jwk_of("rotating"), jwk_of("current")];
        let found = unique_key(&keys, "current")
            .expect("lookup succeeds")
            .expect("key is present");
        assert_eq!(found.common.key_id.as_deref(), Some("current"));
    }

    /// An unknown kid means "refresh and retry", not "the set is malformed".
    #[test]
    fn an_unknown_kid_is_none_rather_than_an_error() {
        let keys = vec![jwk_of("current")];
        assert!(
            unique_key(&keys, "absent")
                .expect("lookup succeeds")
                .is_none()
        );
    }

    #[test]
    fn a_single_audience_naming_this_client_is_accepted() {
        assert!(audience_is_only(&json!("re0auth"), "re0auth"));
        assert!(audience_is_only(&json!(["re0auth"]), "re0auth"));
    }

    /// The gap this closes: `jsonwebtoken` only requires the sets to intersect,
    /// so an id token minted for another client but listing ours would pass.
    #[test]
    fn an_extra_audience_besides_this_client_is_rejected() {
        assert!(!audience_is_only(
            &json!(["re0auth", "some-other-client"]),
            "re0auth"
        ));
        assert!(!audience_is_only(&json!(["some-other-client"]), "re0auth"));
    }

    /// The documented boundary (`IDP-SETUP.md` §2, ADR-0047): only RS256.
    ///
    /// `Validation` would refuse another algorithm anyway, but with a message that
    /// names no cause. An ES256-signed id token is what an Apple-style provider
    /// sends, so the refusal is the first thing an operator hits.
    #[test]
    fn only_rs256_is_accepted() {
        for alg in ["ES256", "ES384", "HS256"] {
            let error = reject_unsupported_header(&header(json!({ "alg": alg })))
                .expect_err("another algorithm must be refused");
            let message = error.to_string();
            assert!(message.contains(alg), "{alg} must be named: {message}");
            assert!(message.contains("RS256"), "{message}");
        }
    }

    #[test]
    fn an_azp_naming_this_client_is_accepted() {
        assert!(azp_is_acceptable(Some("re0auth"), "re0auth"));
    }

    #[test]
    fn an_azp_naming_another_client_is_rejected() {
        assert!(!azp_is_acceptable(Some("someone-else"), "re0auth"));
        assert!(!azp_is_acceptable(Some(""), "re0auth"));
    }

    /// 单 aud 场景下 azp 可以缺席
    #[test]
    fn an_absent_azp_is_accepted() {
        assert!(azp_is_acceptable(None, "re0auth"));
    }

    #[test]
    fn malformed_audience_forms_are_rejected() {
        assert!(!audience_is_only(&json!(null), "re0auth"));
        assert!(!audience_is_only(&json!([]), "re0auth"));
        assert!(!audience_is_only(&json!([1, 2]), "re0auth"));
    }

    #[test]
    fn a_plain_jwt_header_is_accepted() {
        assert!(reject_unsupported_header(&header(json!({"alg": "RS256"}))).is_ok());
        assert!(reject_unsupported_header(&header(json!({"alg": "RS256", "typ": "JWT"}))).is_ok());
        assert!(
            reject_unsupported_header(&header(json!({"alg": "RS256", "typ": "application/jwt"})))
                .is_ok()
        );
    }

    /// RFC 7515 §4.1.6: a `crit` value the receiver does not understand must be
    /// refused. `jsonwebtoken` parses the field and ignores it.
    #[test]
    fn critical_headers_are_rejected() {
        let error = reject_unsupported_header(&header(json!({
            "alg": "RS256",
            "crit": ["exp"],
            "exp": 123
        })))
        .expect_err("crit must be refused");
        assert!(error.to_string().contains("critical"), "{error}");
    }

    #[test]
    fn a_foreign_typ_is_rejected() {
        let error = reject_unsupported_header(&header(json!({"alg": "RS256", "typ": "at+jwt"})))
            .expect_err("a foreign typ must be refused");
        assert!(error.to_string().contains("typ"), "{error}");
    }

    /// 嵌套 JWT 不属于本依赖方的用例
    #[test]
    fn a_nested_content_type_is_rejected() {
        for cty in ["JWT", "application/jwt"] {
            let error = reject_unsupported_header(&header(json!({"alg": "RS256", "cty": cty})))
                .expect_err("cty must be refused");
            assert!(error.to_string().contains("content type"), "{error}");
        }
    }

    #[test]
    fn a_compressed_payload_is_rejected() {
        let error = reject_unsupported_header(&header(json!({"alg": "RS256", "zip": "DEF"})))
            .expect_err("zip must be refused");
        assert!(error.to_string().contains("compressed"), "{error}");
    }

    fn status_error(status: u16) -> anyhow::Error {
        UpstreamStatus {
            status,
            retry_after_secs: None,
        }
        .into()
    }

    /// A refusal and an outage call for opposite responses, so they must not
    /// share a variant. `error_for_status` used to collapse both into a message,
    /// which made every expired authorization code look like a 503.
    #[test]
    fn a_four_xx_response_is_a_rejection_not_an_outage() {
        for status in [400, 401, 403, 429] {
            match transport_error(status_error(status)) {
                IdpError::Rejected { status: got, .. } => assert_eq!(got, status),
                other => panic!("{status} must be Rejected, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_five_xx_response_is_an_outage() {
        for status in [500, 502, 503] {
            assert!(
                matches!(
                    transport_error(status_error(status)),
                    IdpError::Unavailable(_)
                ),
                "{status} means the provider could not answer, not that it refused"
            );
        }
    }

    /// Transport failures never produced a status; they stay retryable.
    #[test]
    fn a_transport_failure_is_an_outage() {
        let error = anyhow::anyhow!("connection reset");
        assert!(matches!(transport_error(error), IdpError::Unavailable(_)));
    }
}
