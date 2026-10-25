//! Device verification and the one-time approval form.

use std::fmt::Write as _;
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Form, Query, State};
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Redirect, Response};
use qrcodegen::{QrCode, QrCodeEcc};
use re0auth_api::ports::ApprovalDecision;
use re0auth_app::auth::AuthError;
use serde::Deserialize;
use url::form_urlencoded;

use crate::AppState;
use crate::cookies::{append_set_cookie, login_intent_cookie};
use crate::copy;
use crate::pages::{HtmlFailure, auth_error_html, device_error_page, device_result_page};
use crate::request_id;

#[derive(Debug, Deserialize)]
pub(crate) struct DevicePageQuery {
    user_code: Option<String>,
    /// INV-IDP-01: the device verification page is where a user is sent to log
    /// in, so with several providers it must be able to carry the choice. The
    /// device flow itself never picks one — the user does, here.
    idp: Option<String>,
}

pub(crate) async fn device_start(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<DevicePageQuery>,
) -> Response {
    let Some(user_code) = query.user_code else {
        return device_error_page(copy::MISSING_USER_CODE);
    };
    // INV-RATE-01: per-code attempt counters are keyed on the derived address,
    // so an attacker behind a trusted proxy cannot split one identity across
    // many spoofed hops to widen its guessing budget.
    let client_ip = state.client_address(addr, &headers);
    if !state.auth.device_attempt_allowed(&client_ip) {
        return auth_error_html(AuthError::RateLimited).into_response();
    }
    match state
        .auth
        .device_code_attempt_locked(&client_ip, &user_code)
        .await
    {
        Ok(true) => return auth_error_html(AuthError::RateLimited).into_response(),
        Ok(false) => {}
        Err(error) => return auth_error_html(error).into_response(),
    }
    if let Err(error) = state.auth.device_info(&user_code).await {
        if let Err(record_error) = state
            .auth
            .record_device_code_miss(&client_ip, &user_code)
            .await
        {
            return auth_error_html(record_error).into_response();
        }
        state.auth.record_device_failure(&client_ip);
        return auth_error_html(error).into_response();
    }
    if let Err(error) = state
        .auth
        .clear_device_code_attempts(&client_ip, &user_code)
        .await
    {
        return auth_error_html(error).into_response();
    }
    state.auth.clear_device_attempts(&client_ip);
    let return_to = {
        let mut serializer = form_urlencoded::Serializer::new("/device?".to_string());
        serializer.append_pair("user_code", &user_code);
        serializer.finish()
    };
    match state
        .auth
        .start_login(&return_to, query.idp.as_deref())
        .await
    {
        Ok(start) => {
            let mut response = Redirect::to(&start.url).into_response();
            append_set_cookie(
                &mut response,
                login_intent_cookie(state.auth.secure_cookies(), &start.state),
            );
            response
        }
        Err(error) => auth_error_html(error).into_response(),
    }
}

pub(crate) async fn device_qr(
    State(state): State<AppState>,
    Query(query): Query<DevicePageQuery>,
) -> Result<Response, HtmlFailure> {
    let Some(user_code) = query.user_code else {
        return Ok(device_error_page(copy::MISSING_USER_CODE));
    };
    state
        .auth
        .device_info(&user_code)
        .await
        .map_err(auth_error_html)?;
    let uri = state.auth.device_verification_uri(&user_code);
    let svg = qr_svg(&uri).map_err(|_| auth_error_html(AuthError::Internal))?;
    let mut response = ([(header::CONTENT_TYPE, "image/svg+xml")], svg).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    Ok(response)
}

pub(crate) fn qr_svg(text: &str) -> Result<String, qrcodegen::DataTooLong> {
    let code = QrCode::encode_text(text, QrCodeEcc::Medium)?;
    let border = 4;
    let size = code.size() + border * 2;
    let mut path = String::new();
    for y in 0..code.size() {
        for x in 0..code.size() {
            if code.get_module(x, y) {
                let _ = write!(path, "M{} {}h1v1h-1z", x + border, y + border);
            }
        }
    }
    Ok(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" \
         shape-rendering=\"crispEdges\"><rect width=\"{size}\" height=\"{size}\" fill=\"#fff\"/>\
         <path d=\"{path}\" fill=\"#171717\"/></svg>"
    ))
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeviceDecisionForm {
    ticket: Option<String>,
}

pub(crate) async fn device_approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeviceDecisionForm>,
) -> Result<Response, HtmlFailure> {
    decide_device(&state, &headers, form, ApprovalDecision::Approve).await
}

pub(crate) async fn device_deny(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeviceDecisionForm>,
) -> Result<Response, HtmlFailure> {
    decide_device(&state, &headers, form, ApprovalDecision::Deny).await
}

async fn decide_device(
    state: &AppState,
    headers: &HeaderMap,
    form: DeviceDecisionForm,
    decision: ApprovalDecision,
) -> Result<Response, HtmlFailure> {
    let ticket = form
        .ticket
        .as_deref()
        .ok_or_else(|| auth_error_html(AuthError::InvalidTicket))?;
    state
        .auth
        .decide_device(ticket, decision, request_id::of(headers))
        .await
        .map_err(auth_error_html)?;
    Ok(device_result_page(matches!(
        decision,
        ApprovalDecision::Approve
    )))
}
