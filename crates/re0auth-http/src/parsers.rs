//! HTTP header and credential parsing.
//!
//! These functions handle caller-controlled bytes before the values reach a
//! service. The wire formats are delegated to audited crates (`headers` for
//! cookies and Basic credentials, `percent-encoding` for RFC 6749 §2.3.1), so
//! what remains here is the part no crate can decide for us: which malformed
//! inputs mean `invalid_client` and which simply mean "absent".
//!
//! Delegation is not a behaviour change by itself. Two library behaviours are
//! deliberately overridden below, each with a test:
//!
//! - `headers::Cookie` yields `Some("")` for an empty value; an empty session
//!   cookie must be treated as absent.
//! - `percent-encoding` passes malformed escapes (`%zz`, `%2`) straight
//!   through; a Basic credential must be well-formed, so these are rejected
//!   rather than accepted verbatim.
//!
//! `headers` also does not percent-decode Basic credentials at all, so that
//! step stays here.

use axum::http::{HeaderMap, header};
use headers::authorization::{Basic, Bearer};
use headers::{Authorization, Cookie, HeaderMapExt};
use percent_encoding::percent_decode_str;
use re0auth_api::ClientId;
use uuid::Uuid;

use crate::{ApiError, Shape, invalid_client_response, invalid_request};

pub(crate) fn session_cookie(headers: &HeaderMap, secure: bool) -> Option<String> {
    cookie_value(headers, super::cookies::session_cookie_name(secure))
}

pub(crate) fn csrf_cookie(headers: &HeaderMap, secure: bool) -> Option<String> {
    cookie_value(headers, super::cookies::csrf_cookie_name(secure))
}

pub(crate) fn csrf_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-csrf-token")?
        .to_str()
        .ok()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Reads one cookie through `headers`.
///
/// The empty-value check is ours: the crate reports `name=` as a present cookie
/// with an empty value, and an empty session is not a session. The value is
/// owned because `headers::Cookie` borrows the decoded map it built.
pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie: Cookie = headers.typed_get()?;
    cookie
        .get(name)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let authorization: Authorization<Bearer> = headers.typed_get()?;
    let token = authorization.0.token();
    (!token.is_empty()).then(|| token.to_string())
}

pub(crate) fn parse_client_id(value: Option<&str>) -> Result<ClientId, ApiError> {
    let value = value.ok_or_else(|| invalid_request("client_id is required", Shape::Rfc6749))?;
    Uuid::parse_str(value)
        .map(ClientId)
        .map_err(|_| invalid_request("client_id is not a UUID", Shape::Rfc6749))
}

/// Client credentials as presented on a token-shaped endpoint.
///
/// RFC 6749 §2.3.1 allows `client_secret_basic` and `client_secret_post`. The
/// two must not disagree: a request that names one client in `Authorization`
/// and another in the form body is a smuggling attempt, not a typo.
pub(crate) struct ClientCredentials {
    pub(crate) id: ClientId,
    pub(crate) secret: Option<String>,
}

pub(crate) fn client_credentials(
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> Result<ClientCredentials, ApiError> {
    let basic = parse_basic_credentials(headers)?;
    match basic {
        Some((basic_id, basic_secret)) => {
            // RFC 6749 §2.3: a client must not use more than one authentication
            // method per request. A body secret next to Basic is either a broken
            // client or a parser-differential attempt; neither is accepted.
            if form_client_secret.is_some_and(|secret| !secret.is_empty()) {
                return Err(invalid_request(
                    "use only one client authentication method",
                    Shape::Rfc6749,
                ));
            }
            if let Some(form_id) = form_client_id
                && form_id != basic_id
            {
                return Err(invalid_request(
                    "client_id in the body does not match the Basic credentials",
                    Shape::Rfc6749,
                ));
            }
            Ok(ClientCredentials {
                id: parse_client_id(Some(&basic_id))?,
                secret: Some(basic_secret),
            })
        }
        None => Ok(ClientCredentials {
            id: parse_client_id(form_client_id)?,
            secret: form_client_secret
                .filter(|value| !value.is_empty())
                .map(str::to_string),
        }),
    }
}

/// Decodes an `Authorization: Basic` header.
///
/// A missing header is `Ok(None)`. A header that is present but unusable is
/// `Err(invalid_client_response())`, because RFC 6749 §5.2 requires
/// `invalid_client` for failed client authentication — not `invalid_request`.
pub(crate) fn parse_basic_credentials(
    headers: &HeaderMap,
) -> Result<Option<(String, String)>, ApiError> {
    if headers.get(header::AUTHORIZATION).is_none() {
        return Ok(None);
    }
    let Some(auth): Option<Authorization<Basic>> = headers.typed_get() else {
        // Present but not a Basic credential: a Bearer header on the token
        // endpoints is a caller bug worth naming rather than ignoring.
        return Err(invalid_client_response());
    };
    let username = form_decode(auth.username())?;
    let password = form_decode(auth.password())?;
    Ok(Some((username, password)))
}

/// RFC 6749 §2.3.1: both halves are `application/x-www-form-urlencoded` before
/// base64, which means percent-escapes must be decoded.
///
/// `percent-encoding` deliberately leaves malformed escapes in place (`%zz`
/// decodes to `%zz`). Accepting that would let a credential containing a stray
/// `%` authenticate as a different secret, so a malformed escape is an error
/// here even though the crate tolerates it.
fn form_decode(value: &str) -> Result<String, ApiError> {
    if has_malformed_escape(value) {
        return Err(invalid_client_response());
    }
    percent_decode_str(value)
        .decode_utf8()
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| invalid_client_response())
}

/// True when a `%` is not followed by exactly two hex digits.
fn has_malformed_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(hex) = bytes.get(index + 1..index + 3) else {
                return true;
            };
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use re0auth_api::redirect_uri::{self, RedirectUriError};

    fn form_value() -> impl Strategy<Value = (String, String)> {
        proptest::collection::vec((any::<bool>(), 0x20u8..0x7f), 0..16).prop_map(|parts| {
            let mut raw = String::new();
            let mut decoded = String::new();
            for (force_percent, byte) in parts {
                let character = char::from(byte);
                let plain =
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_' | '~');
                if force_percent || !plain {
                    raw.push('%');
                    raw.push_str(&format!("{byte:02X}"));
                } else {
                    raw.push(character);
                }
                decoded.push(character);
            }
            (raw, decoded)
        })
    }

    proptest! {
        #[test]
        fn form_decode_round_trips_percent_encoded_ascii((raw, expected) in form_value()) {
            prop_assert_eq!(form_decode(&raw).ok(), Some(expected));
        }

        #[test]
        fn a_malformed_percent_escape_is_refused(
            prefix in "[a-z]{0,8}",
            bad in "[^0-9A-Fa-f]",
            suffix in "[a-z]{0,8}",
        ) {
            let raw = format!("{prefix}%{bad}{suffix}");
            prop_assert!(has_malformed_escape(&raw));
            prop_assert!(form_decode(&raw).is_err());
        }

        #[test]
        fn a_truncated_percent_escape_is_refused(prefix in "[a-z]{0,8}") {
            let raw = format!("{prefix}%A");
            prop_assert!(has_malformed_escape(&raw));
            prop_assert!(form_decode(&raw).is_err());
        }

        #[test]
        fn client_id_accepts_exactly_uuid_strings(value in "\\PC{0,50}") {
            let expected = Uuid::parse_str(&value).ok();
            match parse_client_id(Some(&value)) {
                Ok(id) => prop_assert_eq!(Some(id.0), expected),
                Err(_) => prop_assert!(expected.is_none()),
            }
        }

        #[test]
        fn a_non_empty_cookie_round_trips(value in "[A-Za-z0-9._~-]{1,40}") {
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, format!("session={value}").parse().unwrap());
            prop_assert_eq!(cookie_value(&headers, "session"), Some(value));
        }

        #[test]
        fn an_empty_cookie_is_absent(_seed in any::<u8>()) {
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, "session=".parse().unwrap());
            prop_assert_eq!(cookie_value(&headers, "session"), None);
        }

        #[test]
        fn https_redirects_without_a_fragment_are_accepted(
            host in "[a-z][a-z0-9-]{2,20}",
            path in "/[A-Za-z0-9._~/-]{0,40}",
            query in "[a-z0-9=&]{0,20}",
        ) {
            let suffix = if query.is_empty() { String::new() } else { format!("?{query}") };
            let value = format!("https://{host}.example{path}{suffix}");
            prop_assert_eq!(redirect_uri::validate(&value), Ok(()));
        }

        #[test]
        fn a_fragment_always_turns_an_accepted_redirect_into_fragment_error(
            host in "[a-z][a-z0-9-]{2,20}",
            path in "/[A-Za-z0-9._~/-]{0,40}",
            fragment in "[A-Za-z0-9._~-]{1,20}",
        ) {
            let value = format!("https://{host}.example{path}#{fragment}");
            prop_assert_eq!(
                redirect_uri::validate(&value),
                Err(RedirectUriError::Fragment)
            );
        }

        #[test]
        fn userinfo_always_turns_an_accepted_redirect_into_credentials_error(
            host in "[a-z][a-z0-9-]{2,20}",
            user in "[a-z]{1,12}",
            password in "[a-z]{1,12}",
        ) {
            let value = format!("https://{user}:{password}@{host}.example/callback");
            prop_assert_eq!(
                redirect_uri::validate(&value),
                Err(RedirectUriError::Credentials)
            );
        }

        #[test]
        fn plain_http_off_loopback_is_always_insecure(host in "[a-z][a-z0-9-]{2,20}") {
            let value = format!("http://{host}.example/callback");
            prop_assert_eq!(
                redirect_uri::validate(&value),
                Err(RedirectUriError::Insecure)
            );
        }

        #[test]
        fn an_accepted_redirect_never_carries_a_fragment_or_credentials(
            raw in "[\\PC]{0,80}",
        ) {
            if redirect_uri::validate(&raw).is_ok() {
                let url = url::Url::parse(&raw).expect("accepted implies parseable");
                prop_assert!(url.fragment().is_none());
                prop_assert!(url.username().is_empty());
                prop_assert!(url.password().is_none());
                prop_assert!(matches!(url.scheme(), "https" | "http"));
            }
        }
    }
}
