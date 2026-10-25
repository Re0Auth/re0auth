//! Request correlation (`API-SURFACE.md` §9).
//!
//! Kept out of `lib.rs` because that file is at its line budget and this is a
//! self-contained concern: it takes a request, attaches an id, and re-emits it.

use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

/// The correlation id for the current request, as a request extension.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

pub const REQUEST_ID_HEADER: HeaderName = header::HeaderName::from_static("x-request-id");

/// A caller-supplied id is echoed back so a client can correlate its own logs
/// with ours. It is validated rather than trusted: the value ends up in a
/// response header, and an unvalidated one lets a caller inject arbitrary bytes
/// into a place log collectors treat as data.
///
/// Invalid or missing ids are replaced, never rejected — failing a request
/// because a correlation header was malformed would turn a diagnostic aid into
/// an availability problem.
pub async fn layer(mut request: Request, next: Next) -> Response {
    let supplied = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| is_valid(value))
        .map(ToString::to_string);
    let request_id = supplied.unwrap_or_else(|| Uuid::now_v7().to_string());
    // Written back onto the request so every handler can read it from the same
    // `HeaderMap` it already takes. An extension would force each handler to
    // grow a second extractor for one string.
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        request.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));

    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

/// Reads the id the middleware attached. `None` only when a handler is called
/// directly, which tests do; a real request always has one.
#[must_use]
pub fn of(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
}

/// Accepts a bounded, printable token. Anything else is replaced rather than
/// echoed: CR/LF would let a caller inject headers.
fn is_valid(value: &str) -> bool {
    const MAX: usize = 128;
    !value.is_empty()
        && value.len() <= MAX
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_ids_are_accepted() {
        for id in [
            "abc",
            "req-123",
            "01J8ZK_9.abc:def",
            "a".repeat(128).as_str(),
        ] {
            assert!(is_valid(id), "{id} should be accepted");
        }
    }

    #[test]
    fn header_injection_attempts_are_rejected() {
        // A newline here would let a caller append their own headers.
        for id in [
            "abc\r\nX-Injected: 1",
            "abc\nX-Injected: 1",
            "abc def",
            "",
            "\u{4e2d}\u{6587}",
        ] {
            assert!(!is_valid(id), "{id:?} should be rejected");
        }
    }

    #[test]
    fn overlong_ids_are_rejected() {
        // Unbounded echo would let a caller inflate every response and every log
        // line; the cap is what keeps correlation cheap.
        assert!(!is_valid(&"a".repeat(129)));
    }
}
