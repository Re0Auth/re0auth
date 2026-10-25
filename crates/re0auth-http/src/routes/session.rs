//! Browser session, login, and account routes.
//!
//! Everything here answers a session cookie or starts the IdP redirect. The
//! cookies themselves live in [`crate::cookies`]; the pages in [`crate::pages`].

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Json, Redirect, Response};
use re0auth_api::ClientId;
use re0auth_app::auth::{AuthError, LoginOutcome, SessionContext};
use serde::{Deserialize, Serialize};
use url::form_urlencoded;
use uuid::Uuid;

use crate::cookies::{
    append_set_cookie, clear_session_cookies, login_intent_cookie, login_intent_from,
    with_session_cookies,
};
use crate::pages::{HtmlFailure, auth_error_html, device_approval_page};
use crate::parsers::{csrf_cookie, csrf_header, session_cookie};
use crate::rate::charge_unauthenticated;
use crate::request_id;
use crate::{ApiError, AppState, Shape, auth_error, no_store};

#[derive(Debug, Deserialize)]
pub(crate) struct LoginQuery {
    return_to: Option<String>,
    /// INV-IDP-01: selects the provider at *start* only. The callback ignores it.
    idp: Option<String>,
}

pub(crate) async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
) -> Result<Response, HtmlFailure> {
    // INV-RATE-01: login is unauthenticated and writes a transaction per call.
    if let Err(error) = charge_unauthenticated(
        &state,
        &state.client_address(addr, &headers),
        Shape::Rfc6749,
    ) {
        // Keep the header: a browser that retries blindly is the failure mode the
        // limiter exists to avoid. The body stays the HTML error page.
        let retry_after = error.headers.get(header::RETRY_AFTER).cloned();
        let mut response = auth_error_html(AuthError::RateLimited).into_response();
        if let Some(value) = retry_after {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return Err(HtmlFailure(Box::new(response)));
    }
    let return_to = query.return_to.as_deref().unwrap_or("/");
    let start = state
        .auth
        .start_login(return_to, query.idp.as_deref())
        .await
        .map_err(auth_error_html)?;
    let mut response = Redirect::to(&start.url).into_response();
    append_set_cookie(
        &mut response,
        login_intent_cookie(state.auth.secure_cookies(), &start.state),
    );
    Ok(response)
}

#[derive(Debug, Deserialize)]
pub(crate) struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub(crate) async fn auth_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, HtmlFailure> {
    if query.error.is_some() {
        return Err(auth_error_html(AuthError::InvalidRequest(
            "identity provider rejected login",
        )));
    }
    let code = query
        .code
        .as_deref()
        .ok_or_else(|| auth_error_html(AuthError::InvalidRequest("code is required")))?;
    let state_param = query
        .state
        .as_deref()
        .ok_or_else(|| auth_error_html(AuthError::InvalidRequest("state is required")))?;

    // INV-LOGIN-05: the state must have been issued to this browser. A callback
    // URL captured in another browser would otherwise create a session for the
    // identity that completed the IdP login (login CSRF).
    if login_intent_from(&headers).as_deref() != Some(state_param) {
        return Err(auth_error_html(AuthError::StateInvalid));
    }

    match state
        .auth
        .complete_login(code, state_param)
        .await
        .map_err(auth_error_html)?
    {
        LoginOutcome::Session { created, return_to } => {
            let response = Redirect::to(&return_to).into_response();
            Ok(with_session_cookies(&state, created, response))
        }
        LoginOutcome::DeviceApproval {
            ticket,
            user_code,
            client_id,
            scopes,
        } => Ok(device_approval_page(
            &ticket,
            &user_code,
            client_id.0.to_string().as_str(),
            &scopes,
        )),
    }
}

/// The `/api/me` response body.
///
/// A struct rather than a `json!` literal: the SPA mirrors this shape in
/// `web/src/lib/api.ts`, and `api_contract` compares the two by serialising this
/// type. A hand-built object cannot be compared to anything, so the drift it
/// allowed was invisible.
#[derive(Debug, Serialize)]
pub struct MeView {
    pub user: MeUserView,
    pub csrf_token: String,
}

#[derive(Debug, Serialize)]
pub struct MeUserView {
    pub id: String,
    pub display_name: String,
}

pub(crate) async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    let csrf = csrf_cookie(&headers).ok_or_else(|| auth_error(AuthError::LoginRequired))?;
    if !state.auth.validate_csrf(&context.session, &csrf) {
        return Err(auth_error(AuthError::LoginRequired));
    }
    let view = MeView {
        user: MeUserView {
            id: context.user.id.0.to_string(),
            display_name: context.user.display_name,
        },
        csrf_token: csrf,
    };
    Ok(no_store(Json(view).into_response()))
}

pub(crate) async fn authorizations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    let views = state
        .auth
        .list_authorizations(context.user.id)
        .await
        .map_err(auth_error)?;
    Ok(no_store(Json(views).into_response()))
}

pub(crate) async fn revoke_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;
    let client_id = Uuid::parse_str(&client_id)
        .map(ClientId)
        .map_err(|_| auth_error(AuthError::InvalidRequest("invalid client id")))?;
    state
        .auth
        .revoke_authorization(context.user.id, client_id, request_id::of(&headers))
        .await
        .map_err(auth_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;
    let raw = session_cookie(&headers).ok_or_else(|| auth_error(AuthError::LoginRequired))?;
    state.auth.logout(&raw).await.map_err(auth_error)?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    clear_session_cookies(&mut response);
    Ok(response)
}

pub(crate) async fn logout_all(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;
    state
        .auth
        .logout_all(context.user.id)
        .await
        .map_err(auth_error)?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    clear_session_cookies(&mut response);
    Ok(response)
}

pub(crate) async fn session_context_from_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<SessionContext, ApiError> {
    let raw = session_cookie(headers).ok_or_else(|| auth_error(AuthError::LoginRequired))?;
    state.auth.session_context(&raw).await.map_err(auth_error)
}

/// Every state change is a POST guarded by a CSRF token (INV-HTTP-01,
/// INV-SESSION-01).
pub(crate) fn require_csrf(
    state: &AppState,
    context: &SessionContext,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    let token = csrf_header(headers).ok_or_else(|| auth_error(AuthError::Csrf))?;
    if state.auth.validate_csrf(&context.session, token) {
        Ok(())
    } else {
        Err(auth_error(AuthError::Csrf))
    }
}

pub(crate) fn login_redirect(original: &axum::http::Uri) -> Response {
    let return_to = original.path_and_query().map_or("/", |path| path.as_str());
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("return_to", return_to);
    Redirect::to(&format!("/login?{}", serializer.finish())).into_response()
}
