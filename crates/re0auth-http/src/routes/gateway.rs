//! Data-plane gateway routes.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use re0auth_api::rate::Lane;
use re0auth_app::gateway::GatewayRequest;
use re0auth_app::oauth::OAuthError;

use crate::parsers::bearer_token;
use crate::rate::charge;
use crate::request_id;
use crate::{ApiError, AppState, Shape, error_response, gateway_error, no_store, oauth_error};

/// Data-plane fetch: `GET /api/v1/upstreams/{connector}/{resource}`.
///
/// The caller identifies itself with a Re0Auth access token. The connector and
/// the resource name are resolved against the registry; the upstream subject and
/// the required scope both come from server-side state, never from the request.
pub(crate) async fn fetch_upstream(
    State(state): State<AppState>,
    Path((connector, resource)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    fetch(state, connector, resource, headers, false).await
}

/// Raw view: `GET /api/v1/raw/{connector}/{resource}`.
///
/// Same pipeline as `fetch_upstream`, plus INV-RAW-01's two gates. The response
/// body is identical; what differs is who may ask for it.
pub(crate) async fn fetch_raw(
    State(state): State<AppState>,
    Path((connector, resource)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    fetch(state, connector, resource, headers, true).await
}

async fn fetch(
    state: AppState,
    connector: String,
    resource: String,
    headers: HeaderMap,
    raw: bool,
) -> Result<Response, ApiError> {
    let Some(gateway) = state.gateway.clone() else {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "unknown_connector",
            "no connector is configured",
        ));
    };
    let token = bearer_token(&headers)
        .ok_or_else(|| oauth_error(OAuthError::InvalidToken, Shape::Problem))?;
    let (user_id, granted, client_id) = state
        .oauth
        .verify_gateway_token(token)
        .await
        .map_err(|error| oauth_error(error, Shape::Problem))?;
    // Authenticated lane, keyed by the client that owns the token. Keyed by IP
    // instead, one bot behind many addresses could bypass its budget, and a
    // shared address (a school, a carrier NAT) would punish unrelated callers.
    charge(&state, Lane::Authenticated, &client_id, Shape::Problem)?;
    // The user lane is charged as well: many bots may share one client id, so a
    // client ceiling alone would let them hammer one player without limit.
    // Checked after the client lane so a single abusive integration still hits
    // its own ceiling first.
    charge(
        &state,
        Lane::PerUser,
        &user_id.0.to_string(),
        Shape::Problem,
    )?;
    let connector_id = re0auth_app::gateway::connector_id_for_name(&connector);
    let scopes: Vec<String> = granted
        .split_ascii_whitespace()
        .map(ToString::to_string)
        .collect();
    let payload = gateway
        .fetch(GatewayRequest {
            user_id,
            client_id: &client_id,
            granted_scopes: &scopes,
            connector_id,
            resource: &resource,
            raw,
            correlation_id: request_id::of(&headers),
        })
        .await
        .map_err(gateway_error)?;
    // The broker already limits and labels the body; accept the label only if it
    // parses as a media type, otherwise fall back to octet-stream.
    let content_type = gateway_content_type(&payload.content_type);
    let mut response = Response::new(axum::body::Body::from(payload.body));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    Ok(no_store(response))
}

/// The `Content-Type` a gateway response carries.
///
/// The label came from an upstream, so it is parsed rather than copied: a
/// `contains('/')` test accepts `a/b; c=d,e` and anything else shaped like a
/// slash, and the value ends up in a response header.
pub(crate) fn gateway_content_type(raw: &str) -> header::HeaderValue {
    raw.parse::<mime::Mime>()
        .ok()
        .and_then(|value| header::HeaderValue::from_str(value.as_ref()).ok())
        .unwrap_or_else(|| header::HeaderValue::from_static("application/octet-stream"))
}
