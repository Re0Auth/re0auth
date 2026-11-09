//! User-facing copy for the server-rendered pages.
//!
//! The catalog is the single source shared with the SPA. Unknown keys fall back
//! to the default locale and then to the key itself: a missing translation must
//! never take a page down.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use axum::http::HeaderMap;

const ZH: &str = include_str!("../../../locales/zh-CN.json");
const EN: &str = include_str!("../../../locales/en.json");
const DEFAULT: &str = "zh-CN";

fn catalogs() -> &'static BTreeMap<String, BTreeMap<String, String>> {
    static CATALOGS: OnceLock<BTreeMap<String, BTreeMap<String, String>>> = OnceLock::new();
    CATALOGS.get_or_init(|| {
        let mut catalogs = BTreeMap::new();
        for (locale, raw) in [("zh-CN", ZH), ("en", EN)] {
            let parsed = serde_json::from_str(raw).expect("locale catalog is valid JSON");
            catalogs.insert(locale.to_string(), parsed);
        }
        catalogs
    })
}

/// Resolve `?lang=` > `re0auth_lang` cookie > `Accept-Language` > `zh-CN`.
#[must_use]
pub(crate) fn resolve_locale(headers: &HeaderMap, query: Option<&str>) -> String {
    if let Some(query) = query {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            if key == "lang" {
                return normalize(&value);
            }
        }
    }
    if let Some(cookies) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
    {
        for cookie in cookies.split(';') {
            let mut parts = cookie.trim().splitn(2, '=');
            if parts.next() == Some("re0auth_lang")
                && let Some(value) = parts.next()
            {
                return normalize(value);
            }
        }
    }
    if let Some(accept) = headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok())
    {
        for candidate in accept.split(',') {
            let language = candidate.split(';').next().unwrap_or("").trim();
            if language.starts_with("en") {
                return "en".to_string();
            }
            if language.starts_with("zh") {
                return "zh-CN".to_string();
            }
        }
    }
    DEFAULT.to_string()
}

fn normalize(value: &str) -> String {
    let value = value.trim();
    if value.starts_with("en") {
        "en".to_string()
    } else {
        DEFAULT.to_string()
    }
}

/// Translate `key`. Never panics.
#[must_use]
pub(crate) fn t(locale: &str, key: &str) -> String {
    catalogs()
        .get(locale)
        .and_then(|catalog| catalog.get(key))
        .or_else(|| catalogs().get(DEFAULT).and_then(|catalog| catalog.get(key)))
        .cloned()
        .unwrap_or_else(|| key.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn catalogs_have_the_same_keys() {
        let catalogs = catalogs();
        let zh: BTreeSet<_> = catalogs["zh-CN"].keys().collect();
        let en: BTreeSet<_> = catalogs["en"].keys().collect();
        assert_eq!(zh, en);
    }

    #[test]
    fn missing_keys_fall_back_safely() {
        assert_eq!(t("en", "unknown-key"), "unknown-key");
        assert_eq!(t("xx", "device_approval_title"), "批准设备");
    }
}

tokio::task_local! {
    static LOCALE: String;
}

/// Resolve the locale for one request and expose it to the page renderer.
pub(crate) async fn layer(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let locale = resolve_locale(request.headers(), request.uri().query());
    LOCALE.scope(locale, next.run(request)).await
}

#[must_use]
pub(crate) fn current_locale() -> String {
    LOCALE
        .try_with(Clone::clone)
        .unwrap_or_else(|_| DEFAULT.to_string())
}
