#![forbid(unsafe_code)]

//! Pure domain rules. No I/O, no async, no system clock reads.

use re0auth_api::Unix;

pub mod device;
pub mod gateway;
pub mod pkce;
pub mod scope;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenUse {
    Access,
    Id,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ClaimError {
    MissingSubject,
    WrongTokenUse,
}

/// `id_token` must carry a non-empty `sub` (HR-01).
pub fn require_id_subject(use_: TokenUse, sub: Option<&str>) -> Result<(), ClaimError> {
    if use_ != TokenUse::Id {
        return Err(ClaimError::WrongTokenUse);
    }
    match sub {
        Some(s) if !s.is_empty() => Ok(()),
        _ => Err(ClaimError::MissingSubject),
    }
}

pub fn auth_code_ttl(_now: Unix) -> Unix {
    5 * 60
}

pub fn login_state_ttl(_now: Unix) -> Unix {
    10 * 60
}

pub fn pending_authorization_ttl(_now: Unix) -> Unix {
    10 * 60
}

pub fn approval_ticket_ttl(_now: Unix) -> Unix {
    5 * 60
}

pub fn access_token_ttl(_now: Unix) -> Unix {
    15 * 60
}

pub fn refresh_token_ttl(_now: Unix) -> Unix {
    30 * 24 * 60 * 60
}

pub fn session_idle_ttl(_now: Unix) -> Unix {
    30 * 60
}

pub fn session_absolute_ttl(_now: Unix) -> Unix {
    7 * 24 * 60 * 60
}

#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn id_tokens_accept_exactly_non_empty_subjects(subject in r"[\s\S]{0,32}") {
            prop_assert_eq!(
                require_id_subject(TokenUse::Id, Some(&subject)).is_ok(),
                !subject.is_empty(),
            );
        }

        #[test]
        fn non_id_tokens_are_rejected_regardless_of_the_subject(
            subject in proptest::option::of(r"[\s\S]{0,32}"),
        ) {
            prop_assert_eq!(
                require_id_subject(TokenUse::Access, subject.as_deref()),
                Err(ClaimError::WrongTokenUse),
            );
        }
    }

    #[test]
    fn id_tokens_without_a_subject_are_rejected() {
        assert_eq!(
            require_id_subject(TokenUse::Id, None),
            Err(ClaimError::MissingSubject)
        );
    }
}
