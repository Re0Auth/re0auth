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
use serde::{Deserialize, Serialize};
use url::form_urlencoded;

use crate::parsers::{bearer_token, client_credentials, parse_client_id, session_cookie};
use crate::rate::charge_unauthenticated;
use crate::request_id;
use crate::routes::session::{login_redirect, require_csrf, session_context_from_headers};
use crate::{
    ApiError, AppState, Shape, auth_error, invalid_request, no_store, oauth_error,
    problem_response, unsupported_grant_type,
};

/// The OIDC discovery document.
///
/// A struct rather than a `json!` literal: the OpenAPI schema has to come from
/// the type that serialises the response, and a hand-built object has no type
/// to derive one from.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    device_authorization_endpoint: String,
    revocation_endpoint: String,
    revocation_endpoint_auth_methods_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    scopes_supported: Vec<String>,
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    tag = "protocol",
    responses((status = 200, body = DiscoveryDocument))
)]
pub(crate) async fn discovery(State(state): State<AppState>) -> impl IntoResponse {
    let issuer = state.oauth.issuer();
    let document = DiscoveryDocument {
        issuer: issuer.to_string(),
        authorization_endpoint: format!("{issuer}/oauth/authorize"),
        token_endpoint: format!("{issuer}/oauth/token"),
        userinfo_endpoint: format!("{issuer}/userinfo"),
        jwks_uri: format!("{issuer}/jwks.json"),
        response_types_supported: strings(&["code"]),
        grant_types_supported: strings(&[
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
        ]),
        device_authorization_endpoint: format!("{issuer}/oauth/device_authorization"),
        revocation_endpoint: format!("{issuer}/oauth/revoke"),
        revocation_endpoint_auth_methods_supported: strings(&[
            "client_secret_basic",
            "client_secret_post",
            "none",
        ]),
        code_challenge_methods_supported: strings(&["S256"]),
        token_endpoint_auth_methods_supported: strings(&[
            "client_secret_basic",
            "client_secret_post",
            "none",
        ]),
        subject_types_supported: strings(&["public"]),
        id_token_signing_alg_values_supported: strings(&["RS256"]),
        scopes_supported: strings(SUPPORTED_SCOPES),
    };
    (
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        Json(document),
    )
}

/// The JWK set, as the signer produced it.
///
/// The key entries are passed through verbatim: their fields belong to RFC 7517, and
/// re-deriving them here would be a second copy of that contract. The document
/// is parsed into this type rather than forwarded blind, so the response cannot
/// drift away from the shape the OpenAPI document promises.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct JwksDocument {
    keys: Vec<serde_json::Value>,
}

#[utoipa::path(
    get,
    path = "/jwks.json",
    tag = "protocol",
    responses((status = 200, body = JwksDocument))
)]
pub(crate) async fn jwks(State(state): State<AppState>) -> Result<Response, ApiError> {
    let raw = state.oauth.jwks();
    let document: JwksDocument = serde_json::from_str(&raw).map_err(|_| {
        problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the signing keys could not be read",
        )
    })?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        Json(document),
    )
        .into_response())
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

#[utoipa::path(
    get,
    path = "/oauth/authorize",
    tag = "protocol",
    security(("session" = [])),
    params(
        ("response_type" = String, Query, description = "Must be code."),
        ("client_id" = String, Query),
        ("redirect_uri" = String, Query, description = "Must match one of the client's registered URIs."),
        ("scope" = String, Query),
        ("state" = Option<String>, Query),
        ("code_challenge" = String, Query, description = "PKCE challenge; S256 only."),
        ("code_challenge_method" = String, Query, description = "Must be S256."),
        ("nonce" = Option<String>, Query)
    ),
    responses(
        (status = 302, description = "To the client's redirect_uri with a code, or to the consent screen."),
        (status = 400, body = crate::OAuthErrorBody, content_type = "application/json", description = "RFC 6749 flat error body.")
    )
)]
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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct PendingQuery {
    request: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/oauth/pending",
    tag = "protocol",
    params(("request" = String, Query, description = "The pending authorization request id.")),
    responses(
        (status = 200, body = re0auth_app::oauth::PendingConsentView),
        (status = 400, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct ConsentBody {
    request_id: String,
    decision: ConsentDecision,
}

#[utoipa::path(
    post,
    path = "/api/oauth/consent",
    tag = "protocol",
    params(("X-CSRF-Token" = String, Header, description = "CSRF token from GET /api/me.")),
    request_body = ConsentBody,
    responses(
        (status = 200, body = re0auth_app::oauth::ConsentOutcome),
        (status = 400, body = crate::ProblemBody, content_type = "application/problem+json"),
        (status = 401, body = crate::ProblemBody, content_type = "application/problem+json")
    )
)]
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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct DeviceAuthorizationForm {
    client_id: Option<String>,
    client_secret: Option<String>,
    scope: Option<String>,
}

#[utoipa::path(
    post,
    path = "/oauth/device_authorization",
    tag = "protocol",
    request_body(content = DeviceAuthorizationForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, body = re0auth_app::oauth::DeviceAuthorizationResponse),
        (status = 400, body = crate::OAuthErrorBody, content_type = "application/json"),
        (status = 429, body = crate::OAuthErrorBody, content_type = "application/json")
    )
)]
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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
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

#[utoipa::path(
    post,
    path = "/oauth/token",
    tag = "protocol",
    request_body(content = TokenForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, body = re0auth_app::oauth::TokenResponse),
        (status = 400, body = crate::OAuthErrorBody, content_type = "application/json"),
        (status = 401, body = crate::OAuthErrorBody, content_type = "application/json")
    )
)]
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
        Some(_) => return Err(unsupported_grant_type(Shape::Rfc6749)),
        None => return Err(invalid_request("grant_type is required", Shape::Rfc6749)),
    };

    Ok(no_store(Json(response).into_response()))
}

#[utoipa::path(
    get,
    path = "/userinfo",
    tag = "protocol",
    security(("bearer" = [])),
    responses(
        (status = 200, body = re0auth_app::oauth::UserInfo),
        (status = 401, body = crate::OAuthErrorBody, content_type = "application/json")
    )
)]
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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct RevokeForm {
    token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    /// RFC 7009：未知提示须忽略并扩大检索
    #[serde(rename = "token_type_hint")]
    _token_type_hint: Option<String>,
}

/// RFC 7009 revocation endpoint.
///
/// Answers `200` with an empty body whenever the request is well-formed, even if
/// the token is unknown or already revoked. Anything else would let a caller use
/// this endpoint as an oracle for whether a token exists. A malformed request
/// (missing `token`, bad `client_id`) still gets an error, because that is a
/// client bug rather than a probe.
#[utoipa::path(
    post,
    path = "/oauth/revoke",
    tag = "protocol",
    request_body(content = RevokeForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Always 200 for a well-formed request, even when the token was unknown: answering otherwise would make this endpoint an existence oracle."),
        (status = 400, body = crate::OAuthErrorBody, content_type = "application/json")
    )
)]
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
