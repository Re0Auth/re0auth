//! Wire types shared by the OAuth use cases and the HTTP layer.
use serde::{Deserialize, Serialize};

use re0auth_api::ports::MissingBinding;
use re0auth_api::{ClientId, Unix};

#[derive(Clone, Debug, Serialize, utoipa::ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    pub scope: String,
}

/// What a revocation request actually did.
///
/// RFC 7009 requires the HTTP response to stay 200 for unknown and non-owned
/// tokens, but the application layer still needs the distinction for audit and
/// metrics. Collapsing all three into `Ok(())` is what made the old endpoint
/// look successful while doing nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationOutcome {
    Revoked,
    Unknown,
    NotOwned,
}

#[derive(Clone, Debug, Serialize, utoipa::ToSchema)]
pub struct UserInfo {
    pub sub: String,
    /// OIDC Core §5.4: only the `profile` scope may disclose it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Serialize, utoipa::ToSchema)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: u32,
}

#[derive(Clone, Debug)]
pub struct AuthorizeRequest {
    pub client_id: ClientId,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub auth_time: Unix,
}

#[derive(Clone, Debug)]
pub enum AuthorizeOutcome {
    Redirect(String),
    Consent { request_id: String },
}

#[derive(Clone, Debug, Serialize, utoipa::ToSchema)]
pub struct PendingConsentView {
    pub request_id: String,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub expires_at: Unix,
    /// What the requested scopes need that the user has not connected yet.
    ///
    /// Advisory. The consent screen uses it to offer the missing step; the data
    /// plane re-checks the binding on every read regardless.
    #[schema(value_type = Vec<MissingBindingShape>)]
    pub missing_bindings: Vec<MissingBinding>,
}

/// A schema twin of `re0auth_api::ports::MissingBinding`.
///
/// The port type lives in the published `re0auth-api` crate, which must not
/// depend on utoipa, so the schema needs a local copy. The unit test below pins
/// the two to the same serialised shape.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct MissingBindingShape {
    pub(crate) upstream_id: String,
    pub(crate) scopes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ConsentDecision {
    Approve,
    Deny,
}

#[derive(Clone, Debug, Serialize, utoipa::ToSchema)]
pub struct ConsentOutcome {
    pub redirect_to: String,
}

/// RFC 7662 introspection response. Inactive tokens expose only `active`.
#[derive(Clone, Debug, Serialize, utoipa::ToSchema)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<Unix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<Unix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl IntrospectionResponse {
    #[must_use]
    pub fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            token_type: None,
            exp: None,
            iat: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
        }
    }
}
