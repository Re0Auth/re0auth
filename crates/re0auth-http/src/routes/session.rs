//! Browser session, login, and account routes.
//!
//! Everything here answers a session cookie or starts the IdP redirect. The
//! cookies themselves live in [`crate::cookies`]; the pages in [`crate::pages`].

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Json, Redirect, Response};
use re0auth_api::{ClientId, IdentityId};
use re0auth_app::auth::{AuthError, LoginOutcome, ProviderView, SessionContext};
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
use crate::{ApiError, AppState, Shape, auth_error, no_store, problem_response};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct ProvidersResponse {
    providers: Vec<ProviderView>,
}

/// Public: the login page needs this before a session exists. It exposes only
/// selector ids and display labels, never client ids or secrets.
#[utoipa::path(
    get,
    path = "/api/auth/providers",
    tag = "auth",
    responses((status = 200, body = ProvidersResponse, description = "The providers the login page may offer."))
)]
pub(crate) async fn providers(State(state): State<AppState>) -> Json<ProvidersResponse> {
    Json(ProvidersResponse {
        providers: state.auth.providers(),
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginQuery {
    return_to: Option<String>,
    /// INV-IDP-01: selects the provider at *start* only. The callback ignores it.
    idp: Option<String>,
}

#[utoipa::path(
    get,
    path = "/auth/login",
    tag = "auth",
    params(
        ("return_to" = Option<String>, Query, description = "Where to land after login."),
        ("idp" = Option<String>, Query, description = "Selects the provider at start; the callback ignores it.")
    ),
    responses(
        (status = 302, description = "Redirect to the identity provider, or back to the selector."),
        (status = 429, description = "Rate limited; the Retry-After header is preserved.", body = crate::OAuthErrorBody, content_type = "application/json")
    )
)]
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
    // The default lands on the account page, not the home page: a finished
    // login that returns to a static landing shows no evidence it worked.
    let return_to = query
        .return_to
        .as_deref()
        .unwrap_or(re0auth_app::return_to::FALLBACK);
    let start = match state
        .auth
        .start_login(return_to, query.idp.as_deref())
        .await
    {
        Ok(start) => start,
        // Several providers: send the browser to the SPA selector instead of a
        // dead-end error page. The selector calls this route again with `idp`.
        Err(AuthError::IdentityProviderRequired) => {
            let mut serializer = form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("return_to", return_to);
            let location = format!("/login?{}", serializer.finish());
            return Ok(Redirect::to(&location).into_response());
        }
        Err(error) => return Err(auth_error_html(error)),
    };
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

#[utoipa::path(
    get,
    path = "/auth/callback",
    tag = "auth",
    params(
        ("code" = Option<String>, Query),
        ("state" = Option<String>, Query, description = "Must match the login intent cookie (login CSRF)."),
        ("error" = Option<String>, Query)
    ),
    responses(
        (status = 302, description = "Session created; sets the session cookies."),
        (status = 200, description = "Device approval page, when the login belonged to a device flow.", body = String, content_type = "text/html")
    )
)]
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
    if login_intent_from(&headers, state.auth.secure_cookies()).as_deref() != Some(state_param) {
        return Err(auth_error_html(AuthError::StateInvalid));
    }

    // The account already signed in, if any. An expired or revoked cookie is not
    // a session, so its error is discarded rather than shown: the user asked to
    // sign in, and the answer is about the identity, not the stale cookie.
    let current = match session_cookie(&headers, state.auth.secure_cookies()) {
        Some(raw) => state
            .auth
            .session_context(&raw)
            .await
            .ok()
            .map(|context| context.user.id),
        None => None,
    };

    match state
        .auth
        .complete_login(code, state_param, current)
        .await
        .map_err(auth_error_html)?
    {
        // A query flag rather than a flash cookie: the account page clears it from
        // the address bar on first render.
        LoginOutcome::IdentityAttached => {
            Ok(Redirect::to("/account?identity=attached").into_response())
        }
        LoginOutcome::Session { created, return_to } => {
            // 出口再验一次，不依赖写入时的把关
            let response =
                Redirect::to(&re0auth_app::return_to::or_fallback(&return_to)).into_response();
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
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MeView {
    pub user: MeUserView,
    pub csrf_token: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MeUserView {
    pub id: String,
    pub display_name: String,
    /// 仅供界面决定是否显示管理入口，鉴权仍由服务端判定
    pub role: &'static str,
}

#[utoipa::path(
    get,
    path = "/api/me",
    tag = "session",
    security(("session" = [])),
    responses(
        (status = 200, body = MeView, description = "The caller, plus the CSRF token to echo in X-CSRF-Token."),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json", description = "No session, or the CSRF check failed.")
    )
)]
pub(crate) async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    let csrf = csrf_cookie(&headers, state.auth.secure_cookies())
        .ok_or_else(|| auth_error(AuthError::LoginRequired))?;
    if !state.auth.validate_csrf(&context.session, &csrf) {
        return Err(auth_error(AuthError::LoginRequired));
    }
    let view = MeView {
        user: MeUserView {
            id: context.user.id.0.to_string(),
            display_name: context.user.display_name,
            role: context.user.role.as_str(),
        },
        csrf_token: csrf,
    };
    Ok(no_store(Json(view).into_response()))
}

#[utoipa::path(
    get,
    path = "/api/me/authorizations",
    tag = "session",
    security(("session" = [])),
    responses(
        (status = 200, body = Vec<re0auth_app::auth::AuthorizationView>),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
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

#[utoipa::path(
    delete,
    path = "/api/me/authorizations/{client_id}",
    tag = "session",
    security(("session" = [])),
    params(
        ("client_id" = String, Path, description = "The client whose consent is withdrawn."),
        ("X-CSRF-Token" = String, Header, description = "CSRF token from GET /api/me.")
    ),
    responses(
        (status = 204, description = "The consent is gone."),
        (status = 400, body = crate::ProblemBody, content_type = "application/problem+json", description = "The client id is not a UUID."),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
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

#[utoipa::path(
    post,
    path = "/api/logout",
    tag = "session",
    security(("session" = [])),
    params(("X-CSRF-Token" = String, Header, description = "CSRF token from GET /api/me.")),
    responses(
        (status = 204, description = "The session is gone and its cookies are cleared."),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
pub(crate) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;
    let secure = state.auth.secure_cookies();
    let raw =
        session_cookie(&headers, secure).ok_or_else(|| auth_error(AuthError::LoginRequired))?;
    state.auth.logout(&raw).await.map_err(auth_error)?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    clear_session_cookies(&mut response, secure);
    Ok(response)
}

#[utoipa::path(
    post,
    path = "/api/logout-all",
    tag = "session",
    security(("session" = [])),
    params(("X-CSRF-Token" = String, Header, description = "CSRF token from GET /api/me.")),
    responses(
        (status = 204, description = "Every session of the caller is revoked."),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
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
    clear_session_cookies(&mut response, state.auth.secure_cookies());
    Ok(response)
}

#[utoipa::path(
    delete,
    path = "/api/me",
    tag = "session",
    security(("session" = [])),
    params(("X-CSRF-Token" = String, Header, description = "CSRF token from GET /api/me.")),
    responses(
        (status = 204, description = "The account and every row that hangs off it are gone. Upstream credentials were revoked first."),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 409, body = crate::ProblemBody, content_type = "application/problem+json", description = "bindings_not_revocable: an upstream refused, so deleting now would leave a live credential behind.")
    )
)]
pub(crate) async fn delete_account(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;
    // F-6 cascade before the row goes: deleting locally first would leave a live
    // upstream credential with no local record to retry from. A refusal aborts the
    // deletion rather than papering over it.
    if let Some(binding) = state.binding.as_ref() {
        let summary = binding
            .cascade_revoke(context.user.id, request_id::of(&headers))
            .await
            .map_err(auth_error)?;
        if !summary.failed.is_empty() {
            return Err(problem_response(
                StatusCode::CONFLICT,
                "bindings_not_revocable",
                "some upstream credentials could not be revoked; retry before deleting the account",
            ));
        }
    } else if state
        .auth
        .has_revocable_bindings(context.user.id)
        .await
        .map_err(auth_error)?
    {
        // A missing binding service is not evidence that nothing is bound.
        return Err(problem_response(
            StatusCode::CONFLICT,
            "bindings_not_revocable",
            "upstream revocation is not configured; refusing to delete a live credential",
        ));
    }
    state
        .auth
        .delete_account(context.user.id, request_id::of(&headers))
        .await
        .map_err(auth_error)?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    clear_session_cookies(&mut response, state.auth.secure_cookies());
    Ok(response)
}

#[utoipa::path(
    delete,
    path = "/api/me/identities/{id}",
    tag = "session",
    security(("session" = [])),
    params(
        ("id" = String, Path, description = "The identity to detach."),
        ("X-CSRF-Token" = String, Header, description = "CSRF token from GET /api/me.")
    ),
    responses(
        (status = 204, description = "The login method is no longer attached."),
        (status = 400, body = crate::ProblemBody, content_type = "application/problem+json", description = "Not a UUID."),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 404, body = crate::ProblemBody, content_type = "application/problem+json", description = "No such identity on this account."),
        (status = 409, body = crate::ProblemBody, content_type = "application/problem+json", description = "last_identity: the account would become unreachable.")
    )
)]
pub(crate) async fn detach_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;
    let identity = Uuid::parse_str(&id)
        .map(IdentityId)
        .map_err(|_| auth_error(AuthError::InvalidRequest("invalid identity id")))?;
    state
        .auth
        .detach_identity(context.user.id, identity)
        .await
        .map_err(auth_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct AttachBody {
    /// Several providers need an explicit choice; one provider ignores this.
    #[serde(default)]
    idp: Option<String>,
}

/// One login method as the account page sees it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct IdentityView {
    pub id: String,
    /// The IdP issuer. Shown instead of the subject, which never leaves the server.
    pub issuer: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct AttachStartView {
    pub authorization_url: String,
}

#[utoipa::path(
    get,
    path = "/api/me/identities",
    tag = "session",
    security(("session" = [])),
    responses(
        (status = 200, body = Vec<IdentityView>, description = "Oldest first. The subject is not included."),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
pub(crate) async fn identities(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    let views: Vec<IdentityView> = state
        .auth
        .list_identities(context.user.id)
        .await
        .map_err(auth_error)?
        .into_iter()
        .map(|identity| IdentityView {
            id: identity.id.0.to_string(),
            issuer: identity.issuer,
        })
        .collect();
    Ok(no_store(Json(views).into_response()))
}

#[utoipa::path(
    post,
    path = "/api/me/identities/begin",
    tag = "session",
    security(("session" = [])),
    params(("X-CSRF-Token" = String, Header, description = "CSRF token from GET /api/me.")),
    request_body = AttachBody,
    responses(
        (status = 200, body = AttachStartView, description = "Where to send the browser to authorize the new login method."),
        (status = 400, body = crate::ProblemBody, content_type = "application/problem+json", description = "identity_provider_required when several providers exist and none was chosen."),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
pub(crate) async fn begin_identity_attach(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AttachBody>,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;
    let start = state
        .auth
        .start_attach(context.user.id, "/account", body.idp.as_deref())
        .await
        .map_err(auth_error)?;
    let mut response = Json(AttachStartView {
        authorization_url: start.url,
    })
    .into_response();
    append_set_cookie(
        &mut response,
        login_intent_cookie(state.auth.secure_cookies(), &start.state),
    );
    Ok(no_store(response))
}

pub(crate) async fn session_context_from_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<SessionContext, ApiError> {
    let raw = session_cookie(headers, state.auth.secure_cookies())
        .ok_or_else(|| auth_error(AuthError::LoginRequired))?;
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
