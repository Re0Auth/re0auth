//! Where a flow may send the browser once it finishes.
//!
//! One reading of "a local path", shared by login and by binding. Both used to
//! have their own predicate, and the two disagreed: one rejected a `://` in the
//! query, the other rejected carriage returns. Neither rejected a tab, and a
//! browser strips tab and newlines *while parsing a URL* — so `/\t/host` was
//! accepted here and then resolved as `//host`, i.e. an open redirect.
//!
//! The raw string is checked for control characters before the URL parser ever
//! sees it, because the parser is exactly the layer that removes them.

use url::Url;

/// Longest destination we are willing to echo back into `Location`.
const MAX_LEN: usize = 2048;

/// A host that cannot resolve, used only as a base for relative references.
const BASE: &str = "http://re0auth.invalid";

/// Where a rejected destination lands. Always a page the user can act on.
pub const FALLBACK: &str = "/account";

/// Resolves a site-relative reference against [`BASE`].
///
/// `None` for anything that is not a path on this origin, so a caller that needs
/// the query string cannot be handed an absolute URL by accident.
#[must_use]
pub(crate) fn parse(raw: &str) -> Option<Url> {
    if raw.is_empty() || raw.len() > MAX_LEN || !raw.starts_with('/') {
        return None;
    }
    // A browser treats `\` as `/` in special schemes, so `/\/host` is `///host`.
    if raw.contains('\\') || raw.chars().any(char::is_control) {
        return None;
    }
    let url = Url::parse(BASE).ok()?.join(raw).ok()?;
    // `join` changes the host for `//host`; nothing else in a path can.
    if url.scheme() != "http" || url.host_str() != Some("re0auth.invalid") {
        return None;
    }
    if url.path().starts_with("//") {
        return None;
    }
    Some(url)
}

/// Whether `raw` may be used as a redirect target.
#[must_use]
pub fn is_safe(raw: &str) -> bool {
    parse(raw).is_some()
}

/// `raw` when it is safe, otherwise [`FALLBACK`].
#[must_use]
pub fn or_fallback(raw: &str) -> String {
    if is_safe(raw) {
        raw.to_string()
    } else {
        FALLBACK.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_paths_pass_through() {
        for good in [
            "/",
            "/account",
            "/account?tab=bindings",
            "/oauth/authorize?client_id=x&redirect_uri=https%3A%2F%2Fclient.example%2Fcb",
            // A `://` inside the query is not a redirect target of its own: the
            // browser resolves this against our origin, not against the query.
            "/path?next=https://evil.example",
        ] {
            assert!(is_safe(good), "{good:?} must be allowed");
            assert_eq!(or_fallback(good), good);
        }
    }

    #[test]
    fn absolute_and_protocol_relative_targets_are_rejected() {
        for bad in [
            "",
            "account",
            "//evil.example",
            "///evil.example",
            "https://evil.example/",
            "https:/evil.example",
            "javascript:alert(1)",
            "data:text/html,<script>",
        ] {
            assert!(!is_safe(bad), "{bad:?} must not become a redirect target");
            assert_eq!(or_fallback(bad), FALLBACK);
        }
    }

    /// The bypass this module exists for. A browser removes ASCII tab and
    /// newlines before parsing, so these each resolve as `//evil.example`.
    #[test]
    fn control_characters_cannot_hide_a_protocol_relative_url() {
        for bad in [
            "/\t/evil.example",
            "/\n/evil.example",
            "/\r/evil.example",
            "/\u{0}/evil.example",
            "/\u{1}/evil.example",
            "/\u{7f}/evil.example",
            "/a\tb",
        ] {
            assert!(
                !is_safe(bad),
                "{bad:?} must be rejected before the URL parser strips the control character"
            );
        }
    }

    /// Browsers treat `\` as `/` for http(s), so a backslash is a separator.
    #[test]
    fn backslashes_are_rejected() {
        for bad in ["/\\evil.example", "/\\/evil.example", "/a\\b"] {
            assert!(!is_safe(bad), "{bad:?} must not become a redirect target");
        }
    }

    #[test]
    fn overlong_destinations_are_rejected() {
        let long = format!("/{}", "a".repeat(MAX_LEN));
        assert!(!is_safe(&long));
    }

    #[test]
    fn the_query_survives_parsing() {
        let url = parse("/device?user_code=ABCD-EFGH").expect("parsed");
        assert_eq!(url.path(), "/device");
        assert_eq!(url.query(), Some("user_code=ABCD-EFGH"));
    }
}
