//! Login transactions: what a sign-in round trip remembers.
//!
//! Split out of `ports.rs` to stay inside the per-file line budget.

use crate::ports::REDACTED;
use crate::{Unix, UserId};

/// What a login transaction is for (ADR-0050).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginPurpose {
    /// A plain sign-in: an unknown identity may create an account.
    Login,
    /// Adding an identity to an account that is already signed in. Never creates
    /// a user, and needs the initiating session to be the current one.
    Attach,
}

impl LoginPurpose {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Attach => "attach",
        }
    }

    /// Parses a stored value; an unknown one is `None` rather than a guess.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "login" => Some(Self::Login),
            "attach" => Some(Self::Attach),
            _ => None,
        }
    }
}

/// INV-NOLOG-01: `nonce` and `pkce_verifier` are secrets.
#[derive(Clone, Eq, PartialEq)]
pub struct LoginTransaction {
    pub state_hash: Vec<u8>,
    pub nonce: String,
    pub pkce_verifier: String,
    pub return_to: String,
    /// INV-IDP-01: the provider this login started against.
    ///
    /// The callback must not choose a provider from the query string: the code
    /// was issued by one specific IdP, and honouring a caller-supplied provider
    /// would let a request present a code to the wrong one. Bound at start,
    /// read back at callback.
    pub provider: String,
    /// Why this transaction exists.
    ///
    /// `Attach` means "add the identity that comes back to the account that
    /// started the flow"; the callback reads this back to decide whether a live
    /// session is required and whether a missing identity may create a user.
    /// Only `Login` may create one.
    pub purpose: LoginPurpose,
    /// The account that started an `Attach` flow; `None` for a plain login.
    pub initiator: Option<UserId>,
    pub created_at: Unix,
    pub expires_at: Unix,
    pub consumed_at: Option<Unix>,
}

impl std::fmt::Debug for LoginTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginTransaction")
            .field("state_hash", &REDACTED)
            .field("nonce", &REDACTED)
            .field("pkce_verifier", &REDACTED)
            .field("return_to", &self.return_to)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .finish()
    }
}
