//! PKCE (RFC 7636) helpers. Pure functions only.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

#[must_use]
pub fn challenge_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[must_use]
pub fn verify_s256(verifier: &str, challenge: &str) -> bool {
    challenge_s256(verifier) == challenge
}

/// SHA-256 of `value`, as the 32 raw bytes a state is stored under.
///
/// States are hashed before storage so a leaked database row cannot be replayed:
/// the row holds the digest, and only the browser holds the value that produces
/// it. Not the same thing as `challenge_s256`, which base64-encodes for the wire.
#[must_use]
pub fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_example_matches() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(challenge_s256(verifier), challenge);
        assert!(verify_s256(verifier, challenge));
        assert!(!verify_s256("wrong-verifier", challenge));
    }
}
