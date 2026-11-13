//! Routes that start and finish a binding flow.
//!
//! Kept apart from `lib.rs` for the same reason the storage repositories are:
//! the router file has a line budget, and adding a feature should not push it
//! over.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use re0auth_api::BindingId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use re0auth_app::auth::{AuthError, BindingRevocationSummary};
use re0auth_app::binding::BindingError;

use crate::authz::{SessionPrincipal, session_principal};
use crate::{
    ApiError, AppState, Shape, auth_error, invalid_request, no_store, problem_response, request_id,
    require_csrf,
};

/// The body of a binding start request.
///
/// A POST rather than a GET with a query string: starting a flow writes a
/// pending binding, so a link that any page can trigger is exactly the CSRF
/// this route used to be unable to defend while it answered 302.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct BeginBody {
    upstream: String,
    #[serde(default)]
    return_to: Option<String>,
}

/// Where the SPA should send the browser once the flow exists.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct BeginView {
    pub(crate) authorization_url: String,
}

/// The upstreams a user may start a flow for, as configured.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct BindableUpstreamsView {
    pub(crate) upstreams: Vec<BindableUpstreamView>,
}

/// One connectable upstream: `id` is the key, `display_name` is the label.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct BindableUpstreamView {
    pub(crate) id: String,
    pub(crate) display_name: String,
}

/// Creates a binding flow and returns where to send the browser.
///
/// Answers JSON rather than a redirect so the caller can keep the CSRF header:
/// a top-level navigation cannot carry it, and a cross-origin follow is opaque
/// to a script. The SPA reads the URL and navigates itself.
///
/// CSRF-checked like every other state-changing route: without it an attacker
/// could make a victim's browser start a binding flow the victim never asked
/// for, and the callback would then attach whatever account the attacker chose.
#[utoipa::path(
    post,
    path = "/api/me/bindings/begin",
    tag = "bindings",
    security(("session" = [])),
    params(("X-CSRF-Token" = String, Header, description = "CSRF token from GET /api/me.")),
    request_body = BeginBody,
    responses(
        (status = 200, body = BeginView, description = "Where to send the browser to authorize the upstream."),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 404, body = crate::ProblemBody, content_type = "application/problem+json", description = "Binding is not configured on this deployment.")
    )
)]
pub(crate) async fn begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BeginBody>,
) -> Result<Response, ApiError> {
    let SessionPrincipal(context) = session_principal(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;

    let Some(binding) = state.binding.as_ref() else {
        return Err(not_configured());
    };
    let upstream = body.upstream.trim();
    if upstream.is_empty() {
        return Err(invalid_request("upstream is required", Shape::Problem));
    }
    let return_to = body.return_to.as_deref().unwrap_or("/account");

    let started = binding
        .start(context.user.id, upstream, return_to)
        .await
        .map_err(binding_error)?;
    Ok(no_store(
        Json(BeginView {
            authorization_url: started.authorization_url,
        })
        .into_response(),
    ))
}

/// Lists the upstreams a user may bind.
///
/// Read-only, so no CSRF: the portal needs this to render a connect action at
/// all, because a `ConnectorRegistry` resolves by id and cannot enumerate.
#[utoipa::path(
    get,
    path = "/api/me/bindings/upstreams",
    tag = "bindings",
    security(("session" = [])),
    responses(
        (status = 200, body = BindableUpstreamsView, description = "Upstreams the deployment lets the caller bind."),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
pub(crate) async fn upstreams(
    State(state): State<AppState>,
    SessionPrincipal(_context): SessionPrincipal,
) -> Result<Response, ApiError> {
    let Some(binding) = state.binding.as_ref() else {
        return Err(not_configured());
    };
    Ok(no_store(
        Json(BindableUpstreamsView {
            upstreams: binding
                .bindable_upstreams()
                .iter()
                .map(|upstream| BindableUpstreamView {
                    id: upstream.id.clone(),
                    display_name: upstream.display_name.clone(),
                })
                .collect(),
        })
        .into_response(),
    ))
}

/// Redeems the upstream callback.
///
/// No CSRF check here, and that is deliberate: the request is a top-level
/// browser navigation from the upstream, which cannot carry our header. What
/// authenticates it is the one-shot state, which only the flow that started it
/// could produce — and the user comes from that flow, never from this request.
#[utoipa::path(
    get,
    path = "/api/me/bindings/callback",
    tag = "bindings",
    security(("session" = [])),
    params(
        ("state" = String, Query, description = "The one-shot state issued by /api/me/bindings/begin."),
        ("code" = String, Query, description = "The upstream authorization code.")
    ),
    responses(
        (status = 302, description = "The binding is stored; the browser returns to the account page."),
        (status = 400, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
pub(crate) async fn complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let Some(binding) = state.binding.as_ref() else {
        return Err(not_configured());
    };
    let (Some(state_value), Some(code)) = (query.get("state"), query.get("code")) else {
        return Err(invalid_request("missing state or code", Shape::Problem));
    };

    // INV-BIND-04: completing the flow is a session-bound operation, not a
    // capability carried by `state`. A leaked or forwarded authorization URL
    // must not let its starter claim an account the victim authorized.
    let SessionPrincipal(context) = session_principal(&state, &headers).await?;

    let done = binding
        .complete(context.user.id, state_value, code)
        .await
        .map_err(binding_error)?;
    Ok(no_store(
        Redirect::to(&re0auth_app::return_to::or_fallback(&done.return_to)).into_response(),
    ))
}

#[utoipa::path(
    get,
    path = "/api/me/bindings",
    tag = "bindings",
    security(("session" = [])),
    responses(
        (status = 200, body = Vec<re0auth_app::auth::BindingView>),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
pub(crate) async fn bindings(
    State(state): State<AppState>,
    SessionPrincipal(context): SessionPrincipal,
) -> Result<Response, ApiError> {
    let views = state
        .auth
        .list_bindings(context.user.id)
        .await
        .map_err(auth_error)?;
    Ok(no_store(Json(views).into_response()))
}

#[utoipa::path(
    delete,
    path = "/api/me/bindings/{id}",
    tag = "bindings",
    security(("session" = [])),
    params(
        ("id" = String, Path, description = "The binding to drop."),
        ("X-CSRF-Token" = String, Header, description = "CSRF token from GET /api/me.")
    ),
    responses(
        (status = 200, body = re0auth_app::auth::BindingRevocationSummary, description = "What was revoked; a binding the upstream refused to confirm stays in place and is listed in `failed`."),
        (status = 400, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 404, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
pub(crate) async fn revoke_binding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    SessionPrincipal(context): SessionPrincipal,
) -> Result<Response, ApiError> {
    require_csrf(&state, &context, &headers)?;
    let binding_id = Uuid::parse_str(&id)
        .map(BindingId)
        .map_err(|_| auth_error(AuthError::InvalidRequest("invalid binding id")))?;
    // F-6 for one row: ask the upstream first and keep the local row when it
    // will not confirm. Deleting first would destroy the only copy of a
    // credential that is still alive upstream, with no way to retry.
    let summary = match state.binding.as_ref() {
        Some(binding) => binding
            .cascade_revoke_one(
                context.user.id,
                binding_id,
                context.user.id,
                request_id::of(&headers),
            )
            .await
            .map_err(auth_error)?,
        // No binding service means no connector to notify; the local revoke is
        // the whole operation and cannot partially succeed.
        None => BindingRevocationSummary {
            revoked: state
                .auth
                .revoke_binding(context.user.id, binding_id, request_id::of(&headers))
                .await
                .map_err(auth_error)?,
            failed: Vec::new(),
        },
    };
    Ok(no_store(Json(summary).into_response()))
}

/// The binding killswitch: every binding the caller owns, in one transaction.
#[utoipa::path(
    delete,
    path = "/api/me/bindings",
    tag = "bindings",
    security(("session" = [])),
    params(("X-CSRF-Token" = String, Header, description = "CSRF token from GET /api/me.")),
    responses(
        (status = 200, body = re0auth_app::auth::BindingRevocationSummary, description = "What was revoked, and what the upstream refused to confirm."),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
pub(crate) async fn revoke_all_bindings(
    State(state): State<AppState>,
    headers: HeaderMap,
    SessionPrincipal(context): SessionPrincipal,
) -> Result<Response, ApiError> {
    require_csrf(&state, &context, &headers)?;
    // F-6: the killswitch asks the upstream first and keeps the local row when
    // the upstream will not confirm. Deleting first would destroy the only copy
    // of a credential that is still alive upstream, with no way to retry.
    let summary = match state.binding.as_ref() {
        Some(binding) => binding
            .cascade_revoke(context.user.id, request_id::of(&headers))
            .await
            .map_err(auth_error)?,
        // No binding service means no connector to notify; the local sweep is
        // the whole operation and cannot partially succeed.
        None => state
            .auth
            .revoke_all_bindings(context.user.id, request_id::of(&headers))
            .await
            .map_err(auth_error)?,
    };
    Ok(no_store(Json(summary).into_response()))
}

/// A connector that does not declare endpoints cannot bind, and saying so is
/// better than a redirect to an authorization page we could not redeem.
fn not_configured() -> ApiError {
    problem_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "binding is not configured for this deployment",
    )
}

fn binding_error(error: BindingError) -> ApiError {
    match error {
        BindingError::UnknownConnector => invalid_request("unknown connector", Shape::Problem),
        BindingError::FlowNotValid => invalid_request("binding flow is not valid", Shape::Problem),
        BindingError::UpstreamRejected(_) | BindingError::InsufficientScope => {
            invalid_request("the upstream refused the authorization", Shape::Problem)
        }
        BindingError::UpstreamUnavailable(_) | BindingError::Internal(_) => problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "the upstream could not be reached",
        ),
    }
}
