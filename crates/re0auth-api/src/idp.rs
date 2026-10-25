//! External identity-provider port.

use async_trait::async_trait;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdpIdentity {
    pub issuer: String,
    pub subject: String,
    pub display_name: String,
}

#[derive(Debug, Error)]
pub enum IdpError {
    #[error("identity provider unavailable: {0}")]
    Unavailable(String),
    #[error("identity provider protocol error: {0}")]
    Protocol(String),
    /// The provider answered, and refused.
    ///
    /// Separate from [`Self::Unavailable`] because the two demand opposite
    /// responses: an expired or reused authorization code is the client's own
    /// fault and retrying it verbatim will never work, while an unreachable
    /// provider is ours to retry. Collapsing them into one variant makes the
    /// caller either lie to the client or retry a doomed exchange.
    #[error("identity provider rejected the request with status {status}: {detail}")]
    Rejected { status: u16, detail: String },
    #[error("invalid id token: {0}")]
    InvalidToken(String),
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("issuer mismatch")]
    IssuerMismatch,
}

pub type IdpResult<T> = Result<T, IdpError>;

#[async_trait]
pub trait IdpClient: Send + Sync {
    fn authorization_url(&self, state: &str, nonce: &str, code_challenge: &str) -> String;
    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        nonce: &str,
    ) -> IdpResult<IdpIdentity>;
}
