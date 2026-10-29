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

/// RFC 7636 §4.1 的 verifier 语法
#[must_use]
pub fn is_valid_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
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

    #[test]
    fn verifier_syntax_follows_rfc7636_length_bounds() {
        let shortest = "a".repeat(43);
        let longest = "a".repeat(128);
        assert!(is_valid_verifier(&shortest), "43 characters is the minimum");
        assert!(is_valid_verifier(&longest), "128 characters is the maximum");
        assert!(!is_valid_verifier(""), "an empty verifier is not valid");
        assert!(!is_valid_verifier(&"a".repeat(42)), "42 is one short");
        assert!(!is_valid_verifier(&"a".repeat(129)), "129 is one over");
    }

    #[test]
    fn verifier_syntax_rejects_reserved_characters() {
        let base = "a".repeat(43);
        for illegal in [' ', '/', '+', '=', '%', '\n', '#'] {
            let mut candidate = base.clone();
            candidate.pop();
            candidate.push(illegal);
            assert!(
                !is_valid_verifier(&candidate),
                "{illegal:?} must not appear in a verifier"
            );
        }
        assert!(is_valid_verifier(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        ));
    }
}
