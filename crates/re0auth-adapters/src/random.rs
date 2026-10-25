use re0auth_api::Random;

/// The OS entropy source, without a userspace CSPRNG in between.
///
/// `rand`'s `OsRng` was a one-line wrapper over `getrandom::getrandom`, so
/// calling `getrandom` directly produces the same machine code minus a call
/// frame. Asking the OS on every call is deliberate for a server that mints at
/// most a handful of secrets per request: the cost is one syscall, and there is
/// no process-wide PRNG state to leak or to fork.
pub struct OsRandom;

impl Random for OsRandom {
    fn bytes(&self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        // The port is infallible on purpose. If the OS entropy source fails
        // there is no safe degradation: continuing would mean issuing
        // predictable tokens, nonces and CSRF secrets. Failing loudly beats
        // minting guessable credentials.
        getrandom::fill(&mut bytes).expect("the OS entropy source failed");
        bytes
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn bytes_are_the_requested_length() {
        for len in [0, 1, 8, 16, 32, 64] {
            assert_eq!(OsRandom.bytes(len).len(), len);
        }
    }

    #[test]
    fn successive_draws_do_not_repeat() {
        // A length check alone would pass on a broken source that returns a
        // fixed buffer, so compare contents. 64 draws of 32 bytes collide by
        // chance with probability around 2^-200.
        let draws: Vec<Vec<u8>> = (0..64).map(|_| OsRandom.bytes(32)).collect();
        let unique: HashSet<&Vec<u8>> = draws.iter().collect();
        assert_eq!(unique.len(), draws.len(), "two draws were identical");
    }

    #[test]
    fn a_draw_is_not_all_zeroes() {
        // The classic failure of a misconfigured entropy source is a zero
        // buffer that looks like success.
        assert!(
            OsRandom.bytes(32).iter().any(|&byte| byte != 0),
            "32 bytes of zeroes means the entropy source is not working"
        );
    }
}
