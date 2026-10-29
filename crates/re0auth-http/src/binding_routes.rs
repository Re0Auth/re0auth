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

use re0auth_app::auth::AuthError;
use re0auth_app::binding::BindingError;

use crate::{
    ApiError, AppState, Shape, auth_error, invalid_request, no_store, problem_response, request_id,
    require_csrf, session_context_from_headers,
};

/// The body of a binding start request.
///
/// A POST rather than a GET with a query string: starting a flow writes a
/// pending binding, so a link that any page can trigger is exactly the CSRF
/// this route used to be unable to defend while it answered 302.
#[derive(Debug, Deserialize)]
pub(crate) struct BeginBody {
    upstream: String,
    #[serde(default)]
    return_to: Option<String>,
}

/// Where the SPA should send the browser once the flow exists.
#[derive(Debug, Serialize)]
pub(crate) struct BeginView {
    pub(crate) authorization_url: String,
}

/// The upstreams a user may start a flow for, as configured.
#[derive(Debug, Serialize)]
pub(crate) struct BindableUpstreamsView {
    pub(crate) upstreams: Vec<String>,
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
pub(crate) async fn begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BeginBody>,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
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
pub(crate) async fn upstreams(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    session_context_from_headers(&state, &headers).await?;
    let Some(binding) = state.binding.as_ref() else {
        return Err(not_configured());
    };
    Ok(no_store(
        Json(BindableUpstreamsView {
            upstreams: binding.bindable_upstreams().to_vec(),
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
    let context = session_context_from_headers(&state, &headers).await?;

    let done = binding
        .complete(context.user.id, state_value, code)
        .await
        .map_err(binding_error)?;
    Ok(no_store(
        Redirect::to(&re0auth_app::return_to::or_fallback(&done.return_to)).into_response(),
    ))
}

pub(crate) async fn bindings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    let views = state
        .auth
        .list_bindings(context.user.id)
        .await
        .map_err(auth_error)?;
    Ok(no_store(Json(views).into_response()))
}

pub(crate) async fn revoke_binding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;
    let binding_id = Uuid::parse_str(&id)
        .map(BindingId)
        .map_err(|_| auth_error(AuthError::InvalidRequest("invalid binding id")))?;
    // Capture first: the local revoke deletes the credential in the same
    // transaction, so anything read afterwards is already gone.
    let pending = match state.binding.as_ref() {
        Some(binding) => {
            binding
                .prepare_revocation(context.user.id, Some(binding_id))
                .await
        }
        None => Vec::new(),
    };
    state
        .auth
        .revoke_binding(context.user.id, binding_id, request_id::of(&headers))
        .await
        .map_err(auth_error)?;
    // After the commit: the user's request already succeeded, and an upstream
    // that is down must not turn it into a failure.
    if let Some(binding) = state.binding.as_ref() {
        binding.notify_upstreams(pending).await;
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The binding killswitch: every binding the caller owns, in one transaction.
pub(crate) async fn revoke_all_bindings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;
    let pending = match state.binding.as_ref() {
        Some(binding) => binding.prepare_revocation(context.user.id, None).await,
        None => Vec::new(),
    };
    let summary = state
        .auth
        .revoke_all_bindings(context.user.id, request_id::of(&headers))
        .await
        .map_err(auth_error)?;
    // One call per upstream, after the single local transaction committed. A
    // failure here leaves the credential alive until it expires, which is the
    // documented cost of not holding a second copy just to revoke it later.
    if let Some(binding) = state.binding.as_ref() {
        binding.notify_upstreams(pending).await;
    }
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
