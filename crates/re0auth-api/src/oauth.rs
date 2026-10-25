//! OAuth/OIDC wire claims and the token-signing port.

use serde::{Deserialize, Serialize};

use crate::{Re0Result, Unix};

pub const SUPPORTED_SCOPES: &[&str] = &[
    "openid",
    "profile",
    "phigros.stats.read",
    "phihub.save.read",
];
pub const ACCESS_TOKEN_USE: &str = "access";
pub const APPROVAL_TICKET_USE: &str = "approval_ticket";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub scope: String,
    pub exp: Unix,
    pub iat: Unix,
    pub jti: String,
    pub token_use: String,
}

/// INV-NOLOG-01: `nonce` is a replay-guard secret.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: Unix,
    pub iat: Unix,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl std::fmt::Debug for IdTokenClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdTokenClaims")
            .field("iss", &self.iss)
            .field("sub", &self.sub)
            .field("aud", &self.aud)
            .field("exp", &self.exp)
            .field("iat", &self.iat)
            .field("nonce", &self.nonce.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// INV-NOLOG-01: `user_code` is a one-time approval secret.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApprovalTicketClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub user_code: String,
    pub exp: Unix,
    pub iat: Unix,
    pub jti: String,
    pub token_use: String,
}

impl std::fmt::Debug for ApprovalTicketClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalTicketClaims")
            .field("iss", &self.iss)
            .field("sub", &self.sub)
            .field("aud", &self.aud)
            .field("user_code", &"<redacted>")
            .field("exp", &self.exp)
            .field("iat", &self.iat)
            .field("jti", &"<redacted>")
            .field("token_use", &self.token_use)
            .finish()
    }
}

/// The signing port. Implementations live in adapters.
pub trait TokenSigner: Send + Sync {
    fn sign_access(&self, claims: &AccessTokenClaims) -> Re0Result<String>;
    fn sign_id(&self, claims: &IdTokenClaims) -> Re0Result<String>;
    fn sign_approval_ticket(&self, claims: &ApprovalTicketClaims) -> Re0Result<String>;
    fn verify_access(&self, token: &str) -> Re0Result<AccessTokenClaims>;
    fn verify_approval_ticket(&self, token: &str) -> Re0Result<ApprovalTicketClaims>;
    fn jwks(&self) -> String;
}
