//! The two error shapes this crate answers with, and the mapping from each
//! service error to them.
//!
//! Kept out of `lib.rs` because the router file has a line budget, and because
//! "which lane answers which shape" is one decision that deserves one home:
//! RFC 6749 §5.2 for the OAuth protocol endpoints, RFC 9457 problem details for
//! the gateway and session lanes.

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use re0auth_api::connector::UpstreamError;
use re0auth_api::idp::IdpError;
use re0auth_app::admin_service::AdminError;
use re0auth_app::auth::AuthError;
use re0auth_app::gateway::GatewayError;
use re0auth_app::oauth::OAuthError;
use serde_json::{Value, json};

use crate::limit_headers;

pub(crate) fn gateway_error(error: GatewayError) -> ApiError {
    let status = match &error {
        GatewayError::InsufficientScope => StatusCode::FORBIDDEN,
        GatewayError::BindingRequired | GatewayError::BindingNeedsReauth => StatusCode::FORBIDDEN,
        GatewayError::BindingInactive => StatusCode::FORBIDDEN,
        GatewayError::InvalidRequest(_) | GatewayError::InvalidResource(_) => {
            StatusCode::BAD_REQUEST
        }
        GatewayError::ConnectorNotFound | GatewayError::UnknownResource => StatusCode::NOT_FOUND,
        GatewayError::RawNotAllowed => StatusCode::FORBIDDEN,
        GatewayError::CircuitOpen { .. } => StatusCode::SERVICE_UNAVAILABLE,
        GatewayError::Upstream(UpstreamError::CredentialExpired) => StatusCode::UNAUTHORIZED,
        GatewayError::Upstream(UpstreamError::InsufficientScope) => StatusCode::FORBIDDEN,
        GatewayError::Upstream(UpstreamError::NotFound) => StatusCode::NOT_FOUND,
        // A rejected parameter is the caller's problem, not a gateway fault.
        GatewayError::Upstream(UpstreamError::Rejected) => StatusCode::BAD_REQUEST,
        GatewayError::Upstream(UpstreamError::RateLimited { .. }) => StatusCode::TOO_MANY_REQUESTS,
        // INV-RES-01: our own capacity, not the upstream's. 503 rather than 429
        // because no per-client quota was exceeded — retrying after the in-flight
        // work drains will succeed.
        GatewayError::Upstream(UpstreamError::Overloaded) => StatusCode::SERVICE_UNAVAILABLE,
        GatewayError::Upstream(_) | GatewayError::Internal => StatusCode::BAD_GATEWAY,
        // `GatewayError` is `#[non_exhaustive]`; unknown variants are server-side.
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    // A 503 or 429 without `Retry-After` leaves the client retrying blind, which
    // turns our own protection into the load source.
    let retry_after = match &error {
        GatewayError::CircuitOpen { retry_after_secs } => Some(*retry_after_secs),
        GatewayError::Upstream(UpstreamError::RateLimited { retry_after_secs }) => {
            retry_after_secs.map(|seconds| i64::try_from(seconds).unwrap_or(i64::MAX))
        }
        // No upstream signal exists for our own budget, so offer a short hint:
        // in-flight fetches are bounded by the 10s client timeout.
        GatewayError::Upstream(UpstreamError::Overloaded) => Some(1),
        _ => None,
    };
    let mut response = problem_response(status, error.code(), &error.to_string());
    if let Some(seconds) = retry_after {
        // Merge rather than replace. Assigning a fresh map here was safe while the
        // body was the flat shape, which carries no headers of its own; the problem
        // shape sets its content type in the map, so replacing it would drop the
        // content type on exactly the responses that most need a retry hint.
        for (name, value) in limit_headers::retry_after_only(seconds.max(1).unsigned_abs()) {
            if let Some(name) = name {
                response.headers.insert(name, value);
            }
        }
    }
    response
}

pub(crate) fn idp_status(error: &IdpError) -> StatusCode {
    match error {
        IdpError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        IdpError::Protocol(_) => StatusCode::BAD_GATEWAY,
        // The provider answered and refused. Reporting 401 here would tell the
        // browser to re-authenticate, which cannot help: the code the provider
        // just rejected is the one we sent. 400 says "this exchange is dead",
        // and the client restarts from authorization.
        IdpError::Rejected { status, .. } => {
            StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_REQUEST)
        }
        IdpError::InvalidToken(_) | IdpError::NonceMismatch | IdpError::IssuerMismatch => {
            StatusCode::BAD_REQUEST
        }
    }
}

/// The session / device / login lane, which answers RFC 9457 (see
/// [`problem_response`]). Only the OAuth protocol endpoints keep RFC 6749.
pub(crate) fn auth_error(error: AuthError) -> ApiError {
    match error {
        AuthError::LoginRequired => problem_response(
            StatusCode::UNAUTHORIZED,
            "login_required",
            "an active session is required",
        ),
        AuthError::IdpUnavailable => problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "idp_unavailable",
            "identity provider is not configured",
        ),
        AuthError::UnknownIdentityProvider => problem_response(
            StatusCode::NOT_FOUND,
            "unknown_identity_provider",
            "no identity provider is configured under that name",
        ),
        AuthError::IdentityProviderRequired => problem_response(
            StatusCode::BAD_REQUEST,
            "identity_provider_required",
            "several identity providers are configured; pass `idp` to choose one",
        ),
        AuthError::Idp(error) => problem_response(
            idp_status(&error),
            "idp_error",
            "identity provider request failed",
        ),
        AuthError::Csrf => problem_response(
            StatusCode::FORBIDDEN,
            "invalid_csrf",
            "csrf token is missing or invalid",
        ),
        AuthError::InvalidRequest(description) => {
            problem_response(StatusCode::BAD_REQUEST, "invalid_request", description)
        }
        AuthError::StateInvalid
        | AuthError::StateExpired
        | AuthError::StateConsumed
        | AuthError::InvalidTicket
        | AuthError::TicketExpired
        | AuthError::TicketConsumed
        | AuthError::DeviceUnavailable => problem_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "login or approval state is invalid",
        ),
        AuthError::NotFound => {
            problem_response(StatusCode::NOT_FOUND, "not_found", "resource not found")
        }
        AuthError::RateLimited => problem_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many attempts; retry later",
        ),
        AuthError::Repo(_) | AuthError::Internal => problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "internal error",
        ),
    }
}

/// The admin lane, which answers RFC 9457 like the session lane.
///
/// The codes are the contract's, not the enum's: `AdminError` carries prose for
/// the admin UI, while clients branch on these stable strings.
pub(crate) fn admin_error(error: AdminError) -> ApiError {
    match error {
        AdminError::NotFound => {
            problem_response(StatusCode::NOT_FOUND, "not_found", "resource not found")
        }
        AdminError::InvalidRequest(description) => {
            problem_response(StatusCode::BAD_REQUEST, "invalid_request", description)
        }
        AdminError::Conflict(description) => {
            problem_response(StatusCode::CONFLICT, "conflict", description)
        }
        AdminError::Repo(_) => problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "internal error",
        ),
    }
}

/// An authenticated session that is not an admin must be told apart from no
/// session at all: the first is a 403, the second a 401 (see §8.3 on 401 vs 403).
pub(crate) fn admin_required() -> ApiError {
    problem_response(
        StatusCode::FORBIDDEN,
        "forbidden",
        "an admin session is required",
    )
}

/// An error response.
///
/// A struct rather than a tuple so the header map can be boxed (inlining it
/// pushes every `Result<_, ApiError>` over clippy's large-error threshold) and
/// so `IntoResponse` can be implemented here once. `WWW-Authenticate` on
/// `invalid_client` is required by RFC 6749 §5.2.
#[derive(Debug)]
pub(crate) struct ApiError {
    pub(crate) status: StatusCode,
    /// Boxed: `HeaderMap` is large enough to push every handler's `Result` past
    /// clippy's `result_large_err` threshold.
    pub(crate) headers: Box<HeaderMap>,
    pub(crate) body: Json<Value>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, *self.headers, self.body).into_response()
    }
}

pub(crate) fn invalid_request(description: &'static str, shape: Shape) -> ApiError {
    shape.response(StatusCode::BAD_REQUEST, "invalid_request", description)
}

/// Renders an `OAuthError` in the shape the calling lane uses.
///
/// The shape travels with the call rather than with the error because the gateway
/// validates tokens too: a failure there is an `OAuthError` but reaches a gateway
/// client, which follows `API-SURFACE.md` §8.3 rather than RFC 6749.
///
/// Two arms stay flat regardless of `shape`: `invalid_client` (RFC 6749 §5.2
/// requires its `WWW-Authenticate`) and `slow_down` (RFC 8628 §3.5 defines the
/// extra `interval` member). Both are only reachable from the OAuth endpoints.
pub(crate) fn oauth_error(error: OAuthError, shape: Shape) -> ApiError {
    match error {
        OAuthError::InvalidRequest(description) => {
            shape.response(StatusCode::BAD_REQUEST, "invalid_request", description)
        }
        OAuthError::InvalidClient => invalid_client_response(),
        OAuthError::InvalidGrant(description) => {
            shape.response(StatusCode::BAD_REQUEST, "invalid_grant", description)
        }
        OAuthError::InvalidScope => shape.response(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "requested scope is not allowed",
        ),
        OAuthError::InvalidToken => {
            // RFC 6750 §3.1: a bearer-protected resource answers 401 with the
            // scheme it would have accepted. The gateway shares this arm, so the
            // header is added regardless of the body shape.
            let mut error = shape.response(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "access token is invalid",
            );
            error.headers.insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer error=\"invalid_token\""),
            );
            error
        }
        OAuthError::UnauthorizedClient => shape.response(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "client is not approved",
        ),
        OAuthError::LoginRequired => shape.response(
            StatusCode::UNAUTHORIZED,
            "login_required",
            "an active session is required",
        ),
        OAuthError::AuthorizationPending => shape.response(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            "the user has not approved the device yet",
        ),
        OAuthError::SlowDown { interval_secs } => ApiError {
            status: StatusCode::BAD_REQUEST,
            headers: Box::default(),
            body: Json(json!({
                "error": "slow_down",
                "error_description": "poll interval increased",
                "interval": interval_secs,
            })),
        },
        OAuthError::ExpiredToken => shape.response(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "the device code has expired",
        ),
        OAuthError::AccessDenied => shape.response(
            StatusCode::BAD_REQUEST,
            "access_denied",
            "the user denied the device authorization",
        ),
        OAuthError::ConsentNotFound => shape.response(
            StatusCode::NOT_FOUND,
            "consent_not_found",
            "consent request was not found for this session",
        ),
        OAuthError::ConsentExpired => shape.response(
            StatusCode::BAD_REQUEST,
            "consent_expired",
            "consent request has expired; restart authorization",
        ),
        OAuthError::ConsentUsed => shape.response(
            StatusCode::BAD_REQUEST,
            "consent_used",
            "consent request has already been used",
        ),
        OAuthError::Internal => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "internal error",
        ),
    }
}

/// Which error shape a lane answers with.
///
/// Not a detail of the error: the same refusal (a rate limit, an invalid token)
/// reaches an RFC 6749 client and a gateway client, and the two expect different
/// bodies. Making it explicit at the call site is what stops the shape from
/// depending on which helper happened to be used.
#[derive(Clone, Copy)]
pub(crate) enum Shape {
    /// RFC 6749 §5.2: `error` / `error_description`. OAuth protocol endpoints only.
    Rfc6749,
    /// RFC 9457 problem details. Gateway, session, admin.
    Problem,
}

impl Shape {
    pub(crate) fn response(self, status: StatusCode, code: &str, detail: &str) -> ApiError {
        match self {
            Self::Rfc6749 => error_response(status, code, detail),
            Self::Problem => problem_response(status, code, detail),
        }
    }
}

pub(crate) fn error_response(status: StatusCode, code: &str, description: &str) -> ApiError {
    ApiError {
        status,
        headers: Box::default(),
        body: Json(json!({
            "error": code,
            "error_description": description,
        })),
    }
}

/// RFC 9457 problem details, for the lanes that are not the OAuth protocol.
///
/// Two shapes coexist because the standards disagree: RFC 6749 §5.2 fixes
/// `error` / `error_description` for the token endpoint, while the gateway and
/// session lanes have no such constraint and can use the general format. Which one
/// applies is decided by the lane, not by the error code — the `token` and
/// `device_authorization` handlers answer RFC 6749 even for errors the gateway
/// shares a spelling with.
///
/// `type` is `about:blank`, which the spec allows when the problem is not further
/// specified. It is the honest value: we host no problem-type registry, so a URI
/// under our own domain would not resolve and would be a promise we cannot keep.
/// The identifier a client can actually branch on is `code`, which is the same
/// string the error tables are keyed on. For `about:blank` the spec points clients
/// at the HTTP status, so `title` is the canonical reason phrase and `detail`
/// carries our explanation.
pub(crate) fn problem_response(status: StatusCode, code: &str, detail: &str) -> ApiError {
    #[derive(serde::Serialize)]
    struct Problem<'a> {
        #[serde(rename = "type")]
        kind: &'static str,
        title: &'a str,
        status: u16,
        detail: &'a str,
        code: &'a str,
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    ApiError {
        status,
        headers: Box::new(headers),
        body: Json(
            serde_json::to_value(Problem {
                kind: "about:blank",
                title: status.canonical_reason().unwrap_or("Error"),
                status: status.as_u16(),
                detail,
                code,
            })
            .expect("a problem body is a struct of primitives"),
        ),
    }
}

/// RFC 6749 §5.2: a failed client authentication answers 401 and names the
/// scheme it would have accepted.
pub(crate) fn invalid_client_response() -> ApiError {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"token\""),
    );
    ApiError {
        status: StatusCode::UNAUTHORIZED,
        headers: Box::new(headers),
        body: Json(json!({
            "error": "invalid_client",
            "error_description": "client authentication failed",
        })),
    }
}
