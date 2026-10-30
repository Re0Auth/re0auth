//! OAuth 2.0 / OIDC protocol endpoints.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Form, OriginalUri, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Json, Redirect, Response};
use re0auth_api::oauth::SUPPORTED_SCOPES;
use re0auth_app::auth::AuthError;
use re0auth_app::oauth::{
    AuthorizeOutcome, AuthorizeRequest, ConsentDecision, OAuthError, parse_scope,
};
use serde::Deserialize;
use serde_json::json;
use url::form_urlencoded;

use crate::parsers::{bearer_token, client_credentials, parse_client_id, session_cookie};
use crate::rate::charge_unauthenticated;
use crate::request_id;
use crate::routes::session::{login_redirect, require_csrf, session_context_from_headers};
use crate::{ApiError, AppState, Shape, auth_error, invalid_request, no_store, oauth_error};

pub(crate) async fn discovery(State(state): State<AppState>) -> impl IntoResponse {
    let issuer = state.oauth.issuer();
    (
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        Json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/oauth/authorize"),
            "token_endpoint": format!("{issuer}/oauth/token"),
            "userinfo_endpoint": format!("{issuer}/userinfo"),
            "jwks_uri": format!("{issuer}/jwks.json"),
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code"
            ],
            "device_authorization_endpoint": format!("{issuer}/oauth/device_authorization"),
            "revocation_endpoint": format!("{issuer}/oauth/revoke"),
            "revocation_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none"
            ],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none"
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": SUPPORTED_SCOPES,
        })),
    )
}

pub(crate) async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        state.oauth.jwks(),
    )
}

#[derive(Debug, Deserialize)]
pub(crate) struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    #[serde(rename = "state")]
    oauth_state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

pub(crate) async fn authorize(
    State(state): State<AppState>,
    Query(query): Query<AuthorizeQuery>,
    OriginalUri(original): OriginalUri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if query.response_type.as_deref() != Some("code") {
        return Err(invalid_request(
            "response_type must be code",
            Shape::Rfc6749,
        ));
    }
    if query.code_challenge_method.as_deref() != Some("S256") {
        return Err(invalid_request(
            "code_challenge_method must be S256",
            Shape::Rfc6749,
        ));
    }
    let client_id = parse_client_id(query.client_id.as_deref())?;
    let redirect_uri = query
        .redirect_uri
        .as_deref()
        .ok_or_else(|| invalid_request("redirect_uri is required", Shape::Rfc6749))?;
    let code_challenge = query
        .code_challenge
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_request("code_challenge is required", Shape::Rfc6749))?;
    let scopes = parse_scope(query.scope.as_deref().unwrap_or(""));
    if scopes.is_empty() {
        return Err(oauth_error(OAuthError::InvalidScope, Shape::Rfc6749));
    }

    let Some(raw_session) = session_cookie(&headers, state.auth.secure_cookies()) else {
        return Ok(login_redirect(&original));
    };
    let session = match state.auth.session_context(&raw_session).await {
        Ok(session) => session,
        Err(AuthError::LoginRequired) => return Ok(login_redirect(&original)),
        Err(error) => return Err(auth_error(error)),
    };

    let outcome = state
        .oauth
        .authorize(
            session.session.id,
            session.user.id,
            AuthorizeRequest {
                client_id,
                redirect_uri: redirect_uri.to_string(),
                scopes,
                state: query.oauth_state,
                code_challenge: code_challenge.to_string(),
                nonce: query.nonce,
            },
            request_id::of(&headers),
        )
        .await
        .map_err(|error| oauth_error(error, Shape::Rfc6749))?;

    match outcome {
        AuthorizeOutcome::Redirect(url) => Ok(Redirect::to(&url).into_response()),
        AuthorizeOutcome::Consent { request_id } => {
            let mut serializer = form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("request", &request_id);
            Ok(Redirect::to(&format!("/consent?{}", serializer.finish())).into_response())
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct PendingQuery {
    request: Option<String>,
}

pub(crate) async fn oauth_pending(
    State(state): State<AppState>,
    Query(query): Query<PendingQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    let request_id = query
        .request
        .as_deref()
        .ok_or_else(|| invalid_request("request is required", Shape::Problem))?;
    let view = state
        .oauth
        .pending(&context.session.id, &context.user.id, request_id)
        .await
        .map_err(|error| oauth_error(error, Shape::Problem))?;
    Ok(no_store(Json(view).into_response()))
}

#[derive(Debug, Deserialize)]
pub(crate) struct ConsentBody {
    request_id: String,
    decision: ConsentDecision,
}

pub(crate) async fn oauth_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ConsentBody>,
) -> Result<Response, ApiError> {
    let context = session_context_from_headers(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;
    let outcome = state
        .oauth
        .consent(
            &context.session.id,
            &context.user.id,
            &body.request_id,
            body.decision,
            request_id::of(&headers),
        )
        .await
        .map_err(|error| oauth_error(error, Shape::Problem))?;
    Ok(no_store(Json(outcome).into_response()))
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeviceAuthorizationForm {
    client_id: Option<String>,
    client_secret: Option<String>,
    scope: Option<String>,
}

pub(crate) async fn device_authorization(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<DeviceAuthorizationForm>,
) -> Result<Response, ApiError> {
    // INV-RATE-01: the rate-limit key is the derived client address, not the
    // peer, so a trusted proxy's view of the caller is honoured.
    charge_unauthenticated(
        &state,
        &state.client_address(addr, &headers),
        Shape::Rfc6749,
    )?;
    let credentials = client_credentials(
        &headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    )?;
    let scopes = parse_scope(form.scope.as_deref().unwrap_or(""));
    if scopes.is_empty() {
        return Err(oauth_error(OAuthError::InvalidScope, Shape::Rfc6749));
    }
    let response = state
        .oauth
        .device_authorization(credentials.id, credentials.secret.as_deref(), scopes)
        .await
        .map_err(|error| oauth_error(error, Shape::Rfc6749))?;
    Ok(no_store(Json(response).into_response()))
}

#[derive(Debug, Deserialize)]
pub(crate) struct TokenForm {
    grant_type: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    device_code: Option<String>,
}

pub(crate) async fn token(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Result<Response, ApiError> {
    // INV-RATE-01: an anonymous caller's bucket is keyed on its derived address.
    charge_unauthenticated(
        &state,
        &state.client_address(addr, &headers),
        Shape::Rfc6749,
    )?;
    let credentials = client_credentials(
        &headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    )?;
    let client_id = credentials.id;
    let secret = credentials.secret.as_deref();
    let response = match form.grant_type.as_deref() {
        Some("authorization_code") => {
            let code = form
                .code
                .as_deref()
                .ok_or_else(|| invalid_request("code is required", Shape::Rfc6749))?;
            let redirect_uri = form
                .redirect_uri
                .as_deref()
                .ok_or_else(|| invalid_request("redirect_uri is required", Shape::Rfc6749))?;
            let code_verifier = form
                .code_verifier
                .as_deref()
                .ok_or_else(|| invalid_request("code_verifier is required", Shape::Rfc6749))?;
            state
                .oauth
                .exchange_code(client_id, secret, code, redirect_uri, code_verifier)
                .await
                .map_err(|error| oauth_error(error, Shape::Rfc6749))?
        }
        Some("refresh_token") => {
            let refresh_token = form
                .refresh_token
                .as_deref()
                .ok_or_else(|| invalid_request("refresh_token is required", Shape::Rfc6749))?;
            state
                .oauth
                .refresh(client_id, secret, refresh_token, request_id::of(&headers))
                .await
                .map_err(|error| oauth_error(error, Shape::Rfc6749))?
        }
        Some("urn:ietf:params:oauth:grant-type:device_code") => {
            let device_code = form
                .device_code
                .as_deref()
                .ok_or_else(|| invalid_request("device_code is required", Shape::Rfc6749))?;
            state
                .oauth
                .exchange_device_code(client_id, secret, device_code, request_id::of(&headers))
                .await
                .map_err(|error| oauth_error(error, Shape::Rfc6749))?
        }
        Some(_) => return Err(invalid_request("unsupported grant_type", Shape::Rfc6749)),
        None => return Err(invalid_request("grant_type is required", Shape::Rfc6749)),
    };

    Ok(no_store(Json(response).into_response()))
}

pub(crate) async fn userinfo(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<re0auth_app::oauth::UserInfo>, ApiError> {
    // 验签是最贵的一步，必须先限流
    charge_unauthenticated(
        &state,
        &state.client_address(addr, &headers),
        Shape::Rfc6749,
    )?;
    let token = bearer_token(&headers)
        .ok_or_else(|| oauth_error(OAuthError::InvalidToken, Shape::Rfc6749))?;
    state
        .oauth
        .userinfo(token)
        .await
        .map(Json)
        .map_err(|error| oauth_error(error, Shape::Rfc6749))
}

#[derive(Debug, Deserialize)]
pub(crate) struct RevokeForm {
    token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

/// RFC 7009 revocation endpoint.
///
/// Answers `200` with an empty body whenever the request is well-formed, even if
/// the token is unknown or already revoked. Anything else would let a caller use
/// this endpoint as an oracle for whether a token exists. A malformed request
/// (missing `token`, bad `client_id`) still gets an error, because that is a
/// client bug rather than a probe.
pub(crate) async fn revoke(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<RevokeForm>,
) -> Result<Response, ApiError> {
    charge_unauthenticated(
        &state,
        &state.client_address(addr, &headers),
        Shape::Rfc6749,
    )?;
    let credentials = client_credentials(
        &headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    )?;
    let token = form
        .token
        .as_deref()
        .ok_or_else(|| invalid_request("token is required", Shape::Rfc6749))?;
    if token.is_empty() {
        return Err(invalid_request("token must not be empty", Shape::Rfc6749));
    }
    state
        .oauth
        .revoke_token(
            token,
            credentials.id,
            credentials.secret.as_deref(),
            request_id::of(&headers),
        )
        .await
        .map_err(|error| oauth_error(error, Shape::Rfc6749))?;
    Ok(no_store(StatusCode::OK.into_response()))
}
