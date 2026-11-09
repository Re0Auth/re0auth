//! Data-plane gateway routes.

use std::collections::HashMap;
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use re0auth_api::rate::Lane;
use re0auth_app::gateway::{GatewayRequest, Pagination};
use re0auth_app::oauth::OAuthError;

use crate::parsers::bearer_token;
use crate::rate::{charge, charge_unauthenticated};
use crate::request_id;
use crate::{
    ApiError, AppState, Shape, error_response, gateway_error, invalid_request, no_store,
    oauth_error,
};

/// Data-plane fetch: `GET /api/v1/upstreams/{connector}/{resource}`.
///
/// The caller identifies itself with a Re0Auth access token. The connector and
/// the resource name are resolved against the registry; the upstream subject and
/// the required scope both come from server-side state, never from the request.
#[utoipa::path(
    get,
    path = "/api/v1/upstreams/{connector}/{resource}",
    tag = "gateway",
    security(("bearer" = [])),
    params(
        ("connector" = String, Path, description = "The configured connector id."),
        ("resource" = String, Path, description = "A resource name declared in that connector's config."),
        ("limit" = Option<u32>, Query, description = "Page size for list resources: default 20, max 100."),
        ("cursor" = Option<String>, Query, description = "Opaque cursor taken from next_cursor.")
    ),
    responses(
        (status = 200, body = re0auth_app::gateway::Envelope<'static>, description = "The normalized envelope: upstream, endpoint, fetched_at, request_id, stability, data."),
        (status = 400, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 403, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 404, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 502, body = crate::ProblemBody, content_type = "application/problem+json", description = "upstream_contract_changed, or the upstream could not be reached.")
    )
)]
pub(crate) async fn fetch_upstream(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((connector, resource)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    charge_unauthenticated(
        &state,
        &state.client_address(addr, &headers),
        Shape::Problem,
    )?;
    fetch(state, connector, resource, headers, false, &params).await
}

/// Raw view: `GET /api/v1/raw/{connector}/{resource}`.
///
/// Same pipeline as `fetch_upstream`, plus INV-RAW-01's two gates. The response
/// body is identical; what differs is who may ask for it.
#[utoipa::path(
    get,
    path = "/api/v1/raw/{connector}/{resource}",
    tag = "gateway",
    security(("bearer" = [])),
    params(
        ("connector" = String, Path, description = "The configured connector id."),
        ("resource" = String, Path, description = "A resource name declared in that connector's config.")
    ),
    responses(
        (status = 200, description = "The upstream bytes unchanged, under the upstream's own Content-Type. No envelope.", body = String, content_type = "application/octet-stream"),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 403, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
pub(crate) async fn fetch_raw(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((connector, resource)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    charge_unauthenticated(
        &state,
        &state.client_address(addr, &headers),
        Shape::Problem,
    )?;
    fetch(state, connector, resource, headers, true, &params).await
}

/// `limit` 与 `cursor` 是网关自己的分页参数（ADR-0049），其余查询参数仍然原样
/// 透传给上游——透传模式下上游参数是调用方和上游之间的事。
fn pagination(params: &HashMap<String, String>) -> Result<Pagination, ApiError> {
    let limit = match params.get("limit") {
        None => None,
        Some(raw) => Some(
            raw.parse::<u32>()
                .map_err(|_| invalid_request("limit must be a number", Shape::Problem))?,
        ),
    };
    Ok(Pagination {
        limit,
        cursor: params.get("cursor").cloned(),
    })
}

async fn fetch(
    state: AppState,
    connector: String,
    resource: String,
    headers: HeaderMap,
    raw: bool,
    params: &HashMap<String, String>,
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
        .verify_gateway_token(&token)
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
            pagination: pagination(params)?,
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
    // Raw bodies carry the upstream's bytes; `nosniff` stops a browser from
    // treating them as active content on this origin.
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
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
