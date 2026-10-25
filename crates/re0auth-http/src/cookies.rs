//! Cookie construction for the two browser lanes.
//!
//! Session cookies authenticate; the login-intent cookie only proves that the
//! callback belongs to the browser that started the login (INV-LOGIN-05). Both
//! are built here so no call site can forget `Path`, `SameSite` or `Secure`.

use axum::http::{HeaderMap, header};
use axum::response::Response;
use cookie::{Cookie, SameSite};
use re0auth_app::auth::CreatedSession;

use crate::parsers::cookie_value;

pub(crate) fn with_session_cookies(
    state: &crate::AppState,
    created: CreatedSession,
    mut response: Response,
) -> Response {
    let secure = state.auth.secure_cookies();
    let max_age = created
        .session
        .absolute_expires_at
        .saturating_sub(created.session.created_at);
    append_set_cookie(
        &mut response,
        session_set_cookie("re0auth_session", &created.cookie, max_age, secure, true),
    );
    append_set_cookie(
        &mut response,
        session_set_cookie("re0auth_csrf", &created.csrf_token, max_age, secure, false),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

pub(crate) fn clear_session_cookies(response: &mut Response) {
    append_set_cookie(
        response,
        session_set_cookie("re0auth_session", "", 0, false, true),
    );
    append_set_cookie(
        response,
        session_set_cookie("re0auth_csrf", "", 0, false, false),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
}

/// How long a login may take between the redirect and the callback.
const LOGIN_INTENT_TTL_SECS: i64 = 600;

const LOGIN_INTENT_COOKIE: &str = "re0auth_login";
const LOGIN_INTENT_COOKIE_HOST: &str = "__Host-re0auth_login";

/// `__Host-` pins the cookie to this origin: no `Domain`, `Path=/`, `Secure`.
///
/// The plain name is used only when the issuer is not https, where browsers
/// reject the prefix.
fn login_intent_name(secure: bool) -> &'static str {
    if secure {
        LOGIN_INTENT_COOKIE_HOST
    } else {
        LOGIN_INTENT_COOKIE
    }
}

pub(crate) fn login_intent_cookie(secure: bool, state: &str) -> Cookie<'static> {
    let mut cookie = Cookie::new(login_intent_name(secure).to_string(), state.to_string());
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_max_age(cookie::time::Duration::seconds(LOGIN_INTENT_TTL_SECS));
    cookie.set_secure(secure);
    cookie
}

/// INV-LOGIN-05: the callback must present the state this browser was issued.
pub(crate) fn login_intent_from(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, LOGIN_INTENT_COOKIE_HOST)
        .or_else(|| cookie_value(headers, LOGIN_INTENT_COOKIE))
}

/// Builds a session-family cookie.
///
/// Every attribute is set here rather than at the call site, so a cookie cannot
/// ship without `Path`, `SameSite` or an expiry. The value is written as-is: it
/// is a URL-safe base64 token that our own parser hashes, so percent-encoding it
/// would change the value the client sends back.
pub(crate) fn session_set_cookie(
    name: &str,
    value: &str,
    max_age: i64,
    secure: bool,
    http_only: bool,
) -> Cookie<'static> {
    let mut cookie = Cookie::new(name.to_string(), value.to_string());
    cookie.set_path("/");
    cookie.set_http_only(http_only);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_max_age(cookie::time::Duration::seconds(max_age));
    cookie.set_secure(secure);
    cookie
}

pub(crate) fn append_set_cookie(response: &mut Response, cookie: Cookie<'_>) {
    if let Ok(value) = header::HeaderValue::from_str(&cookie.to_string()) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}
