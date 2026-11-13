//! Data-plane gateway routes.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use crate::catalog::{self, Catalog};
use axum::Json;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use percent_encoding::percent_decode_str;
use re0auth_api::connector::AssetResponse;
use re0auth_api::rate::Lane;
use re0auth_app::gateway::{GatewayRequest, Pagination};

use crate::authz::{GatewayIdentity, gateway_identity};
use crate::parsers::has_malformed_escape;
use crate::rate::{charge, charge_unauthenticated};
use crate::request_id;
use crate::{ApiError, AppState, Shape, error_response, gateway_error, invalid_request, no_store};

async fn require_catalog_token(
    state: &AppState,
    addr: SocketAddr,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    gateway_identity(state, addr, headers).await?;
    Ok(())
}

/// `GET /api/v1/upstreams`: the deployment's resource catalog.
#[utoipa::path(
    get,
    path = "/api/v1/upstreams",
    tag = "gateway",
    security(("bearer" = [])),
    responses(
        (status = 200, body = Catalog, description = "Connectors and their configured resources."),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
pub(crate) async fn list_upstreams(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Catalog>, ApiError> {
    require_catalog_token(&state, addr, &headers).await?;
    Ok(Json(state.catalog.as_ref().clone()))
}

/// `GET /api/v1/upstreams/{connector}/{resource}/schema`: the declared data schema.
#[utoipa::path(
    get,
    path = "/api/v1/upstreams/{connector}/{resource}/schema",
    tag = "gateway",
    security(("bearer" = [])),
    params(
        ("connector" = String, Path, description = "The configured connector id."),
        ("resource" = String, Path, description = "A resource name declared in that connector's config.")
    ),
    responses(
        (status = 200, description = "A JSON Schema document for the resource's data field."),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 404, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
pub(crate) async fn resource_schema(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((connector, resource)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_catalog_token(&state, addr, &headers).await?;
    if !state.catalog.contains(&connector, &resource) {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "unknown_resource",
            "the resource is not configured",
        ));
    }
    let schema = catalog::schema_json(&connector, &resource).ok_or_else(|| {
        error_response(
            StatusCode::NOT_FOUND,
            "unknown_schema",
            "no schema is declared for this resource",
        )
    })?;
    Ok(Json(schema))
}

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
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let params = parse_query(raw.as_deref())?;
    let pagination = pagination(&params)?;
    fetch(
        state,
        addr,
        (connector, resource),
        headers,
        false,
        &params,
        pagination,
    )
    .await
}

/// Binary asset fetch: `GET /api/v1/assets/{connector}/{resource}`.
///
/// Uses the same token, scope, and rate-limit pipeline as normalized fetch. The
/// gateway validates the configured media types and coalesces the response body.
#[utoipa::path(
    get,
    path = "/api/v1/assets/{connector}/{resource}",
    tag = "gateway",
    security(("bearer" = [])),
    params(
        ("connector" = String, Path, description = "The configured connector id."),
        ("resource" = String, Path, description = "A binary resource name declared in that connector's config."),
        ("Accept" = String, Header, description = "Must allow one of the resource's configured image content types, or */*.")
    ),
    responses(
        (status = 200, body = String, content_type = "image/*", description = "The configured binary image, without a JSON envelope."),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 403, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 404, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 406, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 502, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
pub(crate) async fn fetch_asset(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((connector, resource)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let params = parse_query(raw.as_deref())?;
    let Some(gateway) = state.gateway.clone() else {
        charge_unauthenticated(
            &state,
            &state.client_address(addr, &headers),
            Shape::Problem,
        )?;
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "unknown_connector",
            "no connector is configured",
        ));
    };
    let GatewayIdentity {
        user_id,
        granted_scopes,
        client_id,
    } = gateway_identity(&state, addr, &headers).await?;
    charge(
        &state,
        Lane::PerUser,
        &user_id.0.to_string(),
        Shape::Problem,
    )?;
    let connector_id = re0auth_app::gateway::connector_id_for_name(&connector);
    let scopes: Vec<String> = granted_scopes
        .split_ascii_whitespace()
        .map(ToString::to_string)
        .collect();
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok());
    let asset = gateway
        .fetch_asset(
            GatewayRequest {
                user_id,
                client_id: &client_id,
                granted_scopes: &scopes,
                connector_id,
                resource: &resource,
                raw: false,
                correlation_id: request_id::of(&headers),
                params: &params,
                pagination: Pagination::default(),
            },
            accept,
        )
        .await
        .map_err(|error| match error {
            re0auth_app::gateway::GatewayError::UnknownResource => error_response(
                StatusCode::NOT_FOUND,
                "unknown_resource",
                "the resource is not a configured binary asset",
            ),
            other => gateway_error(other),
        })?;
    let (content_type, body) = match asset {
        AssetResponse::Buffered(payload) => (payload.content_type, Body::from(payload.body)),
        AssetResponse::Streaming(stream) => (stream.content_type, Body::from_stream(stream.body)),
    };
    let mut response = Response::new(body);
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, gateway_content_type(&content_type));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    Ok(no_store(response))
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
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let params = parse_query(raw.as_deref())?;
    let pagination = pagination(&params)?;
    fetch(
        state,
        addr,
        (connector, resource),
        headers,
        true,
        &params,
        pagination,
    )
    .await
}

/// Parses and bounds-checks the complete query string without dropping keys.
///
/// Repeated keys are kept as a list: a declared array consumes them, and a
/// scalar that appears twice is rejected once the resource's spec is known.
fn parse_query(raw: Option<&str>) -> Result<BTreeMap<String, Vec<String>>, ApiError> {
    let raw = raw.unwrap_or_default();
    if raw.len() > 4096 {
        return Err(invalid_request("query string is too long", Shape::Problem));
    }
    let mut params: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (pair_index, pair) in raw.split('&').filter(|pair| !pair.is_empty()).enumerate() {
        if pair_index >= 32 {
            return Err(invalid_request("too many query parameters", Shape::Problem));
        }
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode_query_component(raw_key)
            .ok_or_else(|| invalid_request("invalid query encoding", Shape::Problem))?;
        let value = decode_query_component(raw_value)
            .ok_or_else(|| invalid_request("invalid query encoding", Shape::Problem))?;
        if key.is_empty() {
            return Err(invalid_request(
                "empty query parameter name",
                Shape::Problem,
            ));
        }
        params.entry(key).or_default().push(value);
    }
    Ok(params)
}

fn decode_query_component(raw: &str) -> Option<String> {
    if has_malformed_escape(raw) {
        return None;
    }
    let form = raw.replace('+', " ");
    percent_decode_str(&form)
        .decode_utf8()
        .ok()
        .map(std::borrow::Cow::into_owned)
}

/// Reads a key that may appear once, rejecting repeats.
fn single_value<'a>(
    params: &'a BTreeMap<String, Vec<String>>,
    name: &str,
) -> Result<Option<&'a str>, ApiError> {
    match params.get(name).map(Vec::as_slice) {
        None => Ok(None),
        Some([value]) => Ok(Some(value.as_str())),
        Some(_) => Err(invalid_request("duplicate query parameter", Shape::Problem)),
    }
}

/// `limit` 与 `cursor` are parsed here but remain in the map so the gateway can
/// reject them on resources that do not support pagination.
fn pagination(params: &BTreeMap<String, Vec<String>>) -> Result<Pagination, ApiError> {
    let limit = match single_value(params, "limit")? {
        None => None,
        Some(raw) => Some(
            raw.parse::<u32>()
                .map_err(|_| invalid_request("limit must be a number", Shape::Problem))?,
        ),
    };
    Ok(Pagination {
        limit,
        cursor: single_value(params, "cursor")?.map(ToString::to_string),
    })
}

async fn fetch(
    state: AppState,
    addr: SocketAddr,
    (connector, resource): (String, String),
    headers: HeaderMap,
    raw: bool,
    params: &BTreeMap<String, Vec<String>>,
    pagination: Pagination,
) -> Result<Response, ApiError> {
    let Some(gateway) = state.gateway.clone() else {
        charge_unauthenticated(
            &state,
            &state.client_address(addr, &headers),
            Shape::Problem,
        )?;
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "unknown_connector",
            "no connector is configured",
        ));
    };
    let GatewayIdentity {
        user_id,
        granted_scopes,
        client_id,
    } = gateway_identity(&state, addr, &headers).await?;
    charge(
        &state,
        Lane::PerUser,
        &user_id.0.to_string(),
        Shape::Problem,
    )?;
    let connector_id = re0auth_app::gateway::connector_id_for_name(&connector);
    let scopes: Vec<String> = granted_scopes
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
            params,
            pagination,
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

#[cfg(test)]
mod query_tests {
    use super::*;

    #[test]
    fn every_declared_parameter_survives_query_parsing() {
        let params = parse_query(Some("song_id=s&rank=IN&limit=10&cursor=abc")).expect("query");
        assert_eq!(params["song_id"], ["s"]);
        assert_eq!(params["rank"], ["IN"]);
        assert_eq!(params.len(), 4);
        let page = pagination(&params).expect("pagination");
        assert_eq!(page.limit, Some(10));
        assert_eq!(page.cursor.as_deref(), Some("abc"));
    }

    #[test]
    fn path_query_values_decode_strictly_after_pair_splitting() {
        for (raw, expected) in [
            ("IN%2FOUT", "IN/OUT"),
            (
                "%E7%8B%82%E5%96%9C%E8%98%AD%E8%88%9E",
                "\u{72c2}\u{559c}\u{862d}\u{821e}",
            ),
            ("Ain%20Soph%20Aur", "Ain Soph Aur"),
            ("IN%2B", "IN+"),
            ("IN+", "IN "),
            ("C%23", "C#"),
            ("What%3F", "What?"),
            ("A%26B", "A&B"),
            ("A%25B", "A%B"),
        ] {
            let params = parse_query(Some(&format!("song={raw}"))).expect("valid query");
            assert_eq!(params["song"], [expected]);
        }
        for raw in ["song=%FF", "song=%ZZ", "song=%"] {
            assert!(parse_query(Some(raw)).is_err(), "{raw}");
        }
    }

    #[test]
    fn repeated_keys_are_kept_for_arrays_but_pagination_still_rejects_them() {
        let params = parse_query(Some("request=rks&request=scoreHistory")).expect("query");
        assert_eq!(params["request"], ["rks", "scoreHistory"]);
        assert!(parse_query(Some("=1")).is_err());
        assert!(parse_query(Some(&"a=1&".repeat(40))).is_err());
        assert!(pagination(&parse_query(Some("limit=abc")).expect("query")).is_err());
        assert!(pagination(&parse_query(Some("limit=1&limit=2")).expect("query")).is_err());
    }
}
