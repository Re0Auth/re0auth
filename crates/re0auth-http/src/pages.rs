//! Server-rendered pages and their error lane.
//!
//! These are the only HTML responses the Rust side produces: the device approval
//! form, its result and error pages, and the login failure page. Everything a
//! person reads comes from [`crate::copy`].

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use maud::{Markup, PreEscaped, html};
use re0auth_api::ports::RepoError;
use re0auth_app::auth::AuthError;

use crate::copy;
use crate::idp_status;

pub(crate) struct HtmlFailure(pub(crate) Box<Response>);

impl IntoResponse for HtmlFailure {
    fn into_response(self) -> Response {
        *self.0
    }
}

pub(crate) fn device_approval_page(
    ticket: &str,
    user_code: &str,
    client_id: &str,
    scopes: &[String],
) -> Response {
    let body = html! {
        main.card {
            h1 { (copy::DEVICE_APPROVAL_TITLE) }
            p.muted { (copy::DEVICE_CODE_LABEL) }
            p.code { (user_code) }
            p.muted { (copy::CLIENT_LABEL) }
            p.code { (client_id) }
            p.muted { (copy::SCOPES_LABEL) }
            ul { @for scope in scopes { li { (scope) } } }
            p.muted { (copy::DEVICE_APPROVAL_WARNING) }
            form method="post" action="/device/approve" {
                input type="hidden" name="ticket" value=(ticket);
                button type="submit" { (copy::APPROVE_BUTTON) }
            }
            form method="post" action="/device/deny" {
                input type="hidden" name="ticket" value=(ticket);
                button type="submit" class="secondary" { (copy::DENY_BUTTON) }
            }
        }
    };
    html_response(StatusCode::OK, copy::DEVICE_APPROVAL_TITLE, body)
}

pub(crate) fn device_result_page(approved: bool) -> Response {
    let (title, message) = if approved {
        (copy::DEVICE_APPROVED_TITLE, copy::DEVICE_APPROVED_MESSAGE)
    } else {
        (copy::DEVICE_DENIED_TITLE, copy::DEVICE_DENIED_MESSAGE)
    };
    let body = html! {
        main.card {
            h1 { (title) }
            p.muted { (message) }
        }
    };
    html_response(StatusCode::OK, title, body)
}

pub(crate) fn device_error_page(message: &str) -> Response {
    let body = html! {
        main.card {
            h1 { (copy::DEVICE_ERROR_HEADING) }
            p.muted { (message) }
        }
    };
    html_response(StatusCode::BAD_REQUEST, copy::DEVICE_ERROR_TITLE, body)
}

pub(crate) fn auth_error_html(error: AuthError) -> HtmlFailure {
    let message = error.to_string();
    let status = match &error {
        AuthError::IdpUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        AuthError::Idp(error) => idp_status(error),
        AuthError::UnknownIdentityProvider => StatusCode::NOT_FOUND,
        AuthError::IdentityProviderRequired => StatusCode::BAD_REQUEST,
        AuthError::LoginRequired => StatusCode::UNAUTHORIZED,
        AuthError::NotFound => StatusCode::NOT_FOUND,
        AuthError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        AuthError::Repo(RepoError::Busy) => StatusCode::SERVICE_UNAVAILABLE,
        AuthError::Repo(_) | AuthError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    let body = html! {
        main.card {
            h1 { (copy::AUTH_ERROR_TITLE) }
            p.muted { (message) }
        }
    };
    HtmlFailure(Box::new(html_response(
        status,
        copy::AUTH_ERROR_TITLE,
        body,
    )))
}

/// Wraps a page body in the one layout these Rust-rendered pages share.
///
/// `html!` escapes every interpolation, so a page cannot be built without
/// escaping by accident. The two `PreEscaped` uses are deliberate exceptions: the
/// doctype, and the stylesheet, which is a `const` rather than a value from a
/// request. maud escapes `& < > "`, which covers text and its own double-quoted
/// attributes; `'` needs no escaping in either context.
fn html_response(status: StatusCode, title: &str, body: Markup) -> Response {
    let document = html! {
        (PreEscaped("<!doctype html>"))
        html lang="zh-CN" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                style { (PreEscaped(PAGE_STYLE)) }
            }
            body { (body) }
        }
    };
    let mut response = (status, document.into_string()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    response.headers_mut().insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    response
}

const PAGE_STYLE: &str = "\
:root{color-scheme:light dark;--bg:#fff;--fg:#171717;--muted:#4d4d4d;--border:rgba(0,0,0,.08);--primary:#171717;--primary-fg:#fff}\
@media (prefers-color-scheme:dark){:root{--bg:#0a0a0a;--fg:#fafafa;--muted:#a1a1a1;--border:rgba(255,255,255,.12);--primary:#fafafa;--primary-fg:#171717}}\
*{box-sizing:border-box}body{margin:0;min-height:100dvh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:16px/1.5 ui-sans-serif,system-ui,'Noto Sans SC','Microsoft YaHei',sans-serif;padding:24px}\
.card{width:100%;max-width:440px;background:var(--bg);border-radius:8px;box-shadow:0 0 0 1px var(--border);padding:28px}\
h1{font-size:24px;line-height:1.2;margin:0 0 16px;letter-spacing:-.02em}.muted{color:var(--muted);margin:12px 0 4px}\
.code{font-family:ui-monospace,'Cascadia Code','JetBrains Mono',monospace;font-variant-numeric:tabular-nums;font-size:20px;margin:0 0 12px;word-break:break-all}\
ul{padding-left:20px;color:var(--muted)}form{margin-top:12px}button{width:100%;height:44px;border:0;border-radius:6px;background:var(--primary);color:var(--primary-fg);font:inherit;font-weight:500;cursor:pointer}\
button.secondary{background:transparent;color:var(--fg);box-shadow:0 0 0 1px var(--border)}\
button:focus-visible{outline:2px solid #0a72ef;outline-offset:2px}";
