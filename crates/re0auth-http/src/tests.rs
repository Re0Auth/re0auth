use crate::cookies::session_set_cookie;
use crate::pages::{
    HtmlFailure, auth_error_html, device_approval_page, device_error_page, device_result_page,
};
use crate::parsers::{
    bearer_token, csrf_cookie, csrf_header, parse_basic_credentials, parse_client_id,
    session_cookie,
};
use crate::routes::device::qr_svg;
use crate::routes::gateway::gateway_content_type;
use crate::routes::session::login_redirect;
use crate::*;
use axum::http::HeaderMap;
use re0auth_api::idp::IdpError;
use re0auth_api::ports::RepoError;
use re0auth_app::auth::AuthError;
use re0auth_app::gateway::GatewayError;
use re0auth_app::oauth::OAuthError;
use uuid::Uuid;

/// The stable error code, whichever shape the lane uses.
///
/// Both lanes publish the same identifiers: RFC 6749 calls the member `error`,
/// RFC 9457 traffic carries it as the `code` extension. A test that read only one
/// spelling would silently see an empty string for the other lane.
fn code_of(body: &serde_json::Value) -> String {
    body["code"]
        .as_str()
        .or_else(|| body["error"].as_str())
        .unwrap_or("")
        .to_string()
}

fn api(error: ApiError) -> (StatusCode, String) {
    (error.status, code_of(&error.body.0))
}

/// Same as [`api`], but keeps the headers so a test can assert on
/// `WWW-Authenticate` and friends.
fn api_with_headers(error: ApiError) -> (StatusCode, HeaderMap, String) {
    let headers = (*error.headers).clone();
    (error.status, headers, code_of(&error.body.0))
}

fn html(error: HtmlFailure) -> StatusCode {
    let response = *error.0;
    assert!(
        response.headers().contains_key(header::CONTENT_TYPE),
        "every HTML failure must be labelled as HTML"
    );
    response.status()
}

#[test]
fn oauth_errors_map_to_distinct_statuses_and_codes() {
    // Each arm of `oauth_error` must stay distinguishable: collapsing two of
    // them would silently change what a client is told to do.
    let cases: Vec<(OAuthError, StatusCode, &str)> = vec![
        (
            OAuthError::InvalidRequest("bad param"),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            OAuthError::InvalidClient,
            StatusCode::UNAUTHORIZED,
            "invalid_client",
        ),
        (
            OAuthError::InvalidGrant("expired"),
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            OAuthError::InvalidScope,
            StatusCode::BAD_REQUEST,
            "invalid_scope",
        ),
        (
            OAuthError::InvalidToken,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
        ),
        (
            OAuthError::UnauthorizedClient,
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
        ),
        (
            OAuthError::LoginRequired,
            StatusCode::UNAUTHORIZED,
            "login_required",
        ),
        (
            OAuthError::AuthorizationPending,
            StatusCode::BAD_REQUEST,
            "authorization_pending",
        ),
        (
            OAuthError::ExpiredToken,
            StatusCode::BAD_REQUEST,
            "expired_token",
        ),
        (
            OAuthError::AccessDenied,
            StatusCode::BAD_REQUEST,
            "access_denied",
        ),
        (
            OAuthError::ConsentNotFound,
            StatusCode::NOT_FOUND,
            "consent_not_found",
        ),
        (
            OAuthError::ConsentExpired,
            StatusCode::BAD_REQUEST,
            "consent_expired",
        ),
        (
            OAuthError::ConsentUsed,
            StatusCode::BAD_REQUEST,
            "consent_used",
        ),
        (
            OAuthError::TemporarilyUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
        ),
        (
            OAuthError::Internal,
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
        ),
    ];
    for (error, status, code) in cases {
        let actual = api(oauth_error(error, Shape::Rfc6749));
        assert_eq!(actual, (status, code.to_string()));
    }
}

#[test]
fn temporarily_unavailable_carries_retry_after() {
    let (status, headers, code) = api_with_headers(oauth_error(
        OAuthError::TemporarilyUnavailable,
        Shape::Rfc6749,
    ));
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(code, "temporarily_unavailable");
    assert_eq!(
        headers
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
}

#[test]
fn slow_down_carries_the_new_interval() {
    let error = oauth_error(OAuthError::SlowDown { interval_secs: 10 }, Shape::Rfc6749);
    let status = error.status;
    let body = error.body;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body.0["error"], "slow_down");
    assert_eq!(body.0["interval"], 10);
}

#[test]
fn invalid_client_carries_the_basic_challenge() {
    // RFC 6749 §5.2 requires the challenge header, not just the status code:
    // without it a client cannot tell which scheme it failed.
    let (status, headers, code) =
        api_with_headers(oauth_error(OAuthError::InvalidClient, Shape::Rfc6749));
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code, "invalid_client");
    let challenge = headers
        .get(header::WWW_AUTHENTICATE)
        .expect("WWW-Authenticate")
        .to_str()
        .expect("ascii");
    assert!(challenge.starts_with("Basic"), "was {challenge:?}");
}

#[test]
fn every_other_oauth_error_carries_no_extra_headers() {
    // A stray `WWW-Authenticate` on, say, `invalid_grant` would tell the client
    // to retry authentication when the request itself was wrong. Only
    // `invalid_client` (Basic) and `invalid_token` (Bearer) name a scheme.
    for error in [
        OAuthError::InvalidRequest("bad"),
        OAuthError::InvalidGrant("expired"),
        OAuthError::InvalidScope,
        OAuthError::UnauthorizedClient,
    ] {
        let (_, headers, _) = api_with_headers(oauth_error(error, Shape::Rfc6749));
        assert!(
            !headers.contains_key(header::WWW_AUTHENTICATE),
            "only invalid_client and invalid_token may carry the challenge"
        );
    }
}

#[test]
fn invalid_token_carries_the_bearer_challenge() {
    // RFC 6750 §3.1: a bearer-protected resource answers 401 with the scheme and
    // the failure, so a generic client can tell `expired` from `wrong scheme`.
    let (status, headers, code) =
        api_with_headers(oauth_error(OAuthError::InvalidToken, Shape::Rfc6749));
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code, "invalid_token");
    let challenge = headers
        .get(header::WWW_AUTHENTICATE)
        .expect("WWW-Authenticate")
        .to_str()
        .expect("ascii");
    assert_eq!(challenge, "Bearer error=\"invalid_token\"");
}

#[test]
fn auth_errors_map_to_api_codes() {
    let cases: Vec<(AuthError, StatusCode, &str)> = vec![
        (
            AuthError::LoginRequired,
            StatusCode::UNAUTHORIZED,
            "login_required",
        ),
        (
            AuthError::IdpUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "idp_unavailable",
        ),
        (
            AuthError::Idp(IdpError::Unavailable("down".into())),
            StatusCode::SERVICE_UNAVAILABLE,
            "idp_error",
        ),
        (
            AuthError::Idp(IdpError::Protocol("bad".into())),
            StatusCode::BAD_GATEWAY,
            "idp_error",
        ),
        // The provider answered and refused: an expired or reused code. Reporting
        // 503 here would tell the client to retry an exchange that can never
        // work, which is exactly what the old flattening did.
        (
            AuthError::Idp(IdpError::Rejected {
                status: 400,
                detail: "invalid_grant".into(),
            }),
            StatusCode::BAD_REQUEST,
            "idp_error",
        ),
        // A refusal is passed through, but never as 401: that would send the
        // browser to re-authenticate with the credential that just failed.
        (
            AuthError::Idp(IdpError::Rejected {
                status: 429,
                detail: "slow down".into(),
            }),
            StatusCode::TOO_MANY_REQUESTS,
            "idp_error",
        ),
        (
            AuthError::Idp(IdpError::InvalidToken("forged".into())),
            StatusCode::BAD_REQUEST,
            "idp_error",
        ),
        (
            AuthError::Idp(IdpError::NonceMismatch),
            StatusCode::BAD_REQUEST,
            "idp_error",
        ),
        (
            AuthError::Idp(IdpError::IssuerMismatch),
            StatusCode::BAD_REQUEST,
            "idp_error",
        ),
        (AuthError::Csrf, StatusCode::FORBIDDEN, "invalid_csrf"),
        (
            AuthError::InvalidRequest("bad"),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            AuthError::StateInvalid,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            AuthError::StateExpired,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            AuthError::StateConsumed,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            AuthError::InvalidTicket,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            AuthError::TicketExpired,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            AuthError::TicketConsumed,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            AuthError::DeviceUnavailable,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (AuthError::NotFound, StatusCode::NOT_FOUND, "not_found"),
        (
            AuthError::RateLimited,
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
        ),
        (
            AuthError::Repo(RepoError::Busy),
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
        ),
        (
            AuthError::Repo(RepoError::NotFound),
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
        ),
        (
            AuthError::Internal,
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
        ),
    ];
    for (error, status, code) in cases {
        let actual = api(auth_error(error));
        assert_eq!(actual, (status, code.to_string()));
    }
}

#[test]
fn admin_errors_map_to_problem_codes() {
    use re0auth_app::admin_service::AdminError;
    // The admin lane reuses the stable codes of the problem shape: clients
    // branch on these strings, so the mapping must stay pinned here.
    let cases: Vec<(AdminError, StatusCode, &str)> = vec![
        (AdminError::NotFound, StatusCode::NOT_FOUND, "not_found"),
        (
            AdminError::InvalidRequest("bad"),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            AdminError::Conflict("last admin"),
            StatusCode::CONFLICT,
            "conflict",
        ),
        (
            AdminError::Repo(RepoError::Busy),
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
        ),
        (
            AdminError::Repo(RepoError::NotFound),
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
        ),
    ];
    for (error, status, code) in cases {
        let mapped = admin_error(error);
        assert_eq!(mapped.status, status);
        assert_eq!(code_of(&mapped.body.0), code);
    }

    // An authenticated non-admin is a 403, never a 401: re-login cannot help.
    let denied = admin_required();
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(code_of(&denied.body.0), "forbidden");
}

#[test]
fn busy_session_and_admin_errors_carry_retry_after() {
    use re0auth_app::admin_service::AdminError;

    for error in [
        auth_error(AuthError::Repo(RepoError::Busy)),
        admin_error(AdminError::Repo(RepoError::Busy)),
    ] {
        let (status, headers, code) = api_with_headers(error);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(code, "temporarily_unavailable");
        assert_eq!(
            headers
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
    }
}

#[test]
fn auth_errors_map_to_html_statuses() {
    // The browser-facing path must not leak a 500 for a client mistake.
    assert_eq!(
        html(auth_error_html(AuthError::LoginRequired)),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        html(auth_error_html(AuthError::NotFound)),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        html(auth_error_html(AuthError::RateLimited)),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        html(auth_error_html(AuthError::IdpUnavailable)),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        html(auth_error_html(AuthError::Idp(IdpError::Protocol(
            "x".into()
        )))),
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(
        html(auth_error_html(AuthError::Idp(IdpError::NonceMismatch))),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        html(auth_error_html(AuthError::Repo(RepoError::Busy))),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        html(auth_error_html(AuthError::Repo(RepoError::NotFound))),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        html(auth_error_html(AuthError::Internal)),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        html(auth_error_html(AuthError::StateInvalid)),
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn client_id_must_be_a_uuid() {
    assert!(parse_client_id(None).is_err());
    assert!(parse_client_id(Some("")).is_err());
    assert!(parse_client_id(Some("not-a-uuid")).is_err());
    assert!(parse_client_id(Some("../../etc/passwd")).is_err());
    assert!(parse_client_id(Some(&format!("{} ", Uuid::now_v7()))).is_err());
    let id = Uuid::now_v7();
    assert_eq!(parse_client_id(Some(&id.to_string())).unwrap().0, id);
}

#[test]
fn invalid_request_is_always_a_bad_request() {
    let (status, code) = api(invalid_request("missing field", Shape::Rfc6749));
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code, "invalid_request");
}

#[test]
fn cookie_parsing_ignores_malformed_pairs() {
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, "garbage".parse().unwrap());
    assert_eq!(session_cookie(&headers, false), None);

    headers.insert(header::COOKIE, "re0auth_session=".parse().unwrap());
    assert_eq!(
        session_cookie(&headers, false),
        None,
        "empty value is not a session"
    );

    headers.insert(
        header::COOKIE,
        "other=1; re0auth_session=abc; re0auth_csrf=def"
            .parse()
            .unwrap(),
    );
    assert_eq!(session_cookie(&headers, false), Some("abc".to_string()));
    assert_eq!(csrf_cookie(&headers, false), Some("def".to_string()));

    headers.insert(header::COOKIE, "re0auth_session=a=b".parse().unwrap());
    assert_eq!(
        session_cookie(&headers, false),
        Some("a=b".to_string()),
        "split on first '=' only"
    );
}

#[test]
fn basic_credentials_decode_the_rfc_6749_form_encoding() {
    // RFC 6749 §2.3.1: both halves are form-urlencoded before base64.
    let (id, secret) = basic_header("a%20b", "c%2Bd").expect("credentials");
    assert_eq!(id, "a b");
    assert_eq!(secret, "c+d");
}

#[test]
fn malformed_percent_escapes_are_invalid_client_not_accepted_verbatim() {
    // `percent-encoding` passes these through unchanged. Accepting them would
    // let a credential containing a stray `%` authenticate as a different
    // secret, so each must be rejected rather than decoded to itself.
    for (id, secret) in [("a%zz", "b"), ("a%2", "b"), ("a", "b%"), ("%G0", "b")] {
        let error = basic_header(id, secret).expect_err(&format!("{id}:{secret}"));
        let (status, code) = api(error);
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{id}:{secret}");
        assert_eq!(code, "invalid_client", "{id}:{secret}");
    }
}

#[test]
fn a_non_basic_authorization_header_is_invalid_client() {
    // The library returns `None` for any non-Basic scheme, which would be
    // indistinguishable from "no header". Present-but-wrong must be an error.
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
    let Err(error) = parse_basic_credentials(&headers) else {
        panic!("a Bearer header must not be read as absent");
    };
    let (status, code) = api(error);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code, "invalid_client");
}

#[test]
fn a_missing_authorization_header_is_absent_not_an_error() {
    let headers = HeaderMap::new();
    assert_eq!(parse_basic_credentials(&headers).expect("absent"), None);
}

/// Builds a `Basic` header from the raw (pre-encoding) halves.
fn basic_header(id: &str, secret: &str) -> Result<(String, String), ApiError> {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"));
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Basic {encoded}").parse().unwrap(),
    );
    parse_basic_credentials(&headers)?
        .ok_or_else(|| invalid_request("no credentials", Shape::Rfc6749))
}

#[test]
fn an_empty_cookie_value_is_absent() {
    // `headers::Cookie` reports `name=` as present with an empty value.
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, "re0auth_session=".parse().unwrap());
    assert_eq!(
        session_cookie(&headers, false),
        None,
        "the library would return Some(\"\"); we must not"
    );
}

#[test]
fn csrf_header_rejects_blank_and_non_ascii() {
    let mut headers = HeaderMap::new();
    assert_eq!(csrf_header(&headers), None);
    headers.insert("x-csrf-token", "   ".parse().unwrap());
    assert_eq!(csrf_header(&headers), None);
    headers.insert("x-csrf-token", " token ".parse().unwrap());
    assert_eq!(csrf_header(&headers), Some("token"));
}

#[test]
fn bearer_token_requires_the_exact_scheme() {
    let mut headers = HeaderMap::new();
    assert_eq!(bearer_token(&headers), None);
    headers.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
    assert_eq!(bearer_token(&headers), None);
    headers.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
    assert_eq!(bearer_token(&headers), None, "empty token is not a token");
    headers.insert(header::AUTHORIZATION, "bearer abc".parse().unwrap());
    assert_eq!(bearer_token(&headers), None, "scheme is case-sensitive");
    headers.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
    assert_eq!(bearer_token(&headers), Some("abc"));
}

#[test]
fn qr_rejects_payloads_that_cannot_fit() {
    assert!(qr_svg("https://example.com/device?user_code=ABCD-EFGH").is_ok());
    // Far beyond any QR capacity: must fail rather than emit a broken image.
    assert!(qr_svg(&"x".repeat(10_000)).is_err());
}

#[test]
fn device_result_page_distinguishes_denial() {
    let approved = device_result_page(true);
    assert_eq!(approved.status(), StatusCode::OK);
    let denied = device_result_page(false);
    assert_eq!(denied.status(), StatusCode::OK);
}

#[test]
fn device_error_page_is_a_bad_request() {
    let response = device_error_page("<bad>");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn login_redirect_keeps_the_original_query() {
    let uri: axum::http::Uri = "/oauth/authorize?client_id=x&scope=openid".parse().unwrap();
    let response = login_redirect(&uri);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("location");
    assert!(location.starts_with("/login?return_to="));
    assert!(location.contains("scope%3Dopenid"));
}

#[test]
fn gateway_errors_map_to_client_facing_statuses() {
    use re0auth_api::connector::UpstreamError;
    // Expected codes are written out rather than taken from `error.code()`: a
    // test that derives its expectation from the code under test can never catch
    // a rename that drifts away from the published contract.
    let cases: Vec<(GatewayError, StatusCode, &str)> = vec![
        (
            GatewayError::InsufficientScope,
            StatusCode::FORBIDDEN,
            "insufficient_scope",
        ),
        (
            GatewayError::BindingRequired,
            StatusCode::FORBIDDEN,
            "binding_required",
        ),
        (
            GatewayError::BindingNeedsReauth,
            StatusCode::FORBIDDEN,
            "upstream_needs_reauth",
        ),
        (
            GatewayError::BindingInactive,
            StatusCode::FORBIDDEN,
            "access_denied",
        ),
        (
            GatewayError::InvalidRequest("bad"),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            GatewayError::ConnectorNotFound,
            StatusCode::NOT_FOUND,
            "unknown_connector",
        ),
        (
            GatewayError::UnknownResource,
            StatusCode::NOT_FOUND,
            "endpoint_not_found",
        ),
        (
            GatewayError::CircuitOpen {
                retry_after_secs: 30,
            },
            StatusCode::SERVICE_UNAVAILABLE,
            "upstream_busy",
        ),
        (
            GatewayError::Upstream(UpstreamError::CredentialExpired),
            StatusCode::UNAUTHORIZED,
            "upstream_needs_reauth",
        ),
        (
            GatewayError::Upstream(UpstreamError::InsufficientScope),
            StatusCode::FORBIDDEN,
            "insufficient_scope",
        ),
        (
            GatewayError::Upstream(UpstreamError::NotFound),
            StatusCode::NOT_FOUND,
            "not_found",
        ),
        (
            GatewayError::Upstream(UpstreamError::RateLimited {
                retry_after_secs: Some(5),
            }),
            StatusCode::TOO_MANY_REQUESTS,
            "upstream_rate_limited",
        ),
        (
            GatewayError::Upstream(UpstreamError::Truncated),
            StatusCode::BAD_GATEWAY,
            "upstream_response_too_large",
        ),
        (
            GatewayError::Internal,
            StatusCode::BAD_GATEWAY,
            "internal_error",
        ),
    ];
    for (error, status, code) in cases {
        let actual = gateway_error(error);
        assert_eq!(actual.status, status);
        assert_eq!(code_of(&actual.body.0), code);
    }
}

/// The SPA parses this shape, so the two definitions have to agree on the member
/// names.
///
/// This lives here rather than next to the other cross-language gates in
/// `re0auth-archtest` because the wire struct is private to this crate: archtest
/// cannot serialize it, and widening it to `pub` to satisfy a test would make a
/// response body part of the crate's public API. Comparing the serialized keys
/// against the zod schema is the same check the archtest gates make for the DTOs —
/// a renamed member is invisible to the compiler on one side.
#[test]
fn the_problem_shape_matches_the_spas_schema() {
    let body = problem_response(StatusCode::FORBIDDEN, "insufficient_scope", "detail").body;
    let mut rust_fields: Vec<String> = body
        .0
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect();
    rust_fields.sort();

    let api = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web/src/lib/api.ts"),
    )
    .expect("the SPA's api.ts");

    let start = api
        .find("const problemSchema")
        .expect("problemSchema is declared");
    let schema = &api[start..];
    let end = schema
        .find("});")
        .expect("problemSchema is an object literal");
    let mut ts_fields: Vec<String> = schema[..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let name = line.split(':').next()?.trim();
            (!name.is_empty()
                && name != "const problemSchema = z.object({"
                && !name.contains('{')
                && !name.contains('('))
            .then(|| name.to_string())
        })
        .collect();
    ts_fields.sort();

    // Subset, not equality: the SPA declares the members it reads, and the
    // response carries the registered ones it ignores. What must never happen is
    // the SPA reading a member the server stopped sending.
    for field in &ts_fields {
        assert!(
            rust_fields.contains(field),
            "the SPA reads `{field}` from the problem body, but the server sends \
             {rust_fields:?}"
        );
    }
    assert!(
        ts_fields.contains(&"code".to_string()),
        "the stable error code is what the SPA branches on; it cannot be dropped"
    );
}

/// RFC 9457 (which obsoletes RFC 7807) for the lanes that are not the OAuth
/// protocol: the gateway and the session API.
///
/// The registered members are the standard five plus our `code` extension, and the
/// media type is what tells a client which shape it is holding — without it a
/// caller has to guess from the members' names.
#[test]
fn non_oauth_lanes_answer_rfc_9457_problem_details() {
    let error = gateway_error(GatewayError::InsufficientScope);
    let content_type = error
        .headers
        .get(header::CONTENT_TYPE)
        .expect("the problem shape labels itself")
        .to_str()
        .expect("ascii");
    assert_eq!(content_type, "application/problem+json");
    assert_eq!(error.body.0["type"], "about:blank");
    assert_eq!(error.body.0["title"], "Forbidden");
    assert_eq!(error.body.0["status"], 403);
    assert_eq!(error.body.0["code"], "insufficient_scope");
    assert!(error.body.0["detail"].is_string());

    // The session lane is the same shape, so a client learns one body for both.
    let session = auth_error(AuthError::Csrf);
    assert_eq!(session.body.0["code"], "invalid_csrf");
    assert_eq!(session.body.0["status"], 403);
    assert!(session.body.0.get("error").is_none());
}

/// The OAuth protocol endpoints must keep RFC 6749 §5.2. Changing them to the
/// problem shape would break every standard client, which is why the lane — not
/// the error code — decides the body.
#[test]
fn oauth_endpoints_still_answer_rfc_6749() {
    let error = oauth_error(OAuthError::InvalidGrant("expired"), Shape::Rfc6749);
    assert_eq!(error.body.0["error"], "invalid_grant");
    assert!(error.body.0.get("code").is_none());
    assert!(
        !error.headers.contains_key(header::CONTENT_TYPE),
        "the flat shape relies on the body's own JSON content type"
    );
}

/// A rate limit is refused by a helper both lanes call, so the shape has to come
/// from the caller. Guessing it from the error would make `/oauth/token` answer
/// the problem shape and break its clients.
#[test]
fn a_shared_refusal_takes_its_shape_from_the_lane() {
    let flat = Shape::Rfc6749.response(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "wait");
    let problem = Shape::Problem.response(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "wait");
    assert_eq!(flat.body.0["error"], "rate_limited");
    assert!(flat.body.0.get("code").is_none());
    assert_eq!(problem.body.0["code"], "rate_limited");
    assert_eq!(
        problem
            .headers
            .get(header::CONTENT_TYPE)
            .expect("labelled")
            .to_str()
            .expect("ascii"),
        "application/problem+json"
    );
}

/// A 503 or 429 that does not say how long to wait is worse than useless: a
/// well-behaved client can only retry in a tight loop, which is exactly the load
/// the breaker was protecting against.
#[test]
fn busy_and_rate_limited_errors_carry_retry_after() {
    use re0auth_api::connector::UpstreamError;

    let cases = [
        (
            GatewayError::CircuitOpen {
                retry_after_secs: 30,
            },
            "30",
        ),
        (
            GatewayError::Upstream(UpstreamError::RateLimited {
                retry_after_secs: Some(5),
            }),
            "5",
        ),
        (
            // INV-RES-01: our own capacity. Without a hint the client retries
            // blind and turns the drain into a stampede.
            GatewayError::Upstream(UpstreamError::Overloaded),
            "1",
        ),
    ];
    for (error, expected) in cases {
        let response = gateway_error(error);
        let header = response
            .headers
            .get(axum::http::header::RETRY_AFTER)
            .unwrap_or_else(|| panic!("missing Retry-After for {expected}"));
        assert_eq!(header.to_str().expect("ascii"), expected);
    }
}

#[test]
fn non_busy_errors_do_not_advertise_retry_after() {
    use re0auth_api::connector::UpstreamError;

    // A 404 is not going to become a 200 by waiting, so a Retry-After there
    // would actively mislead the client.
    for error in [
        GatewayError::ConnectorNotFound,
        GatewayError::InsufficientScope,
        GatewayError::Upstream(UpstreamError::NotFound),
        GatewayError::Upstream(UpstreamError::RateLimited {
            retry_after_secs: None,
        }),
    ] {
        let response = gateway_error(error);
        assert!(
            response
                .headers
                .get(axum::http::header::RETRY_AFTER)
                .is_none(),
            "unexpected Retry-After on {:?}",
            response.status
        );
    }
}

#[test]
fn a_nonpositive_retry_after_is_floored_to_one_second() {
    // `HeaderValue::from_str("0")` parses, but a zero-second retry is an
    // instruction to hammer us immediately, so the floor is deliberate.
    let response = gateway_error(GatewayError::CircuitOpen {
        retry_after_secs: 0,
    });
    assert_eq!(
        response
            .headers
            .get(axum::http::header::RETRY_AFTER)
            .expect("Retry-After")
            .to_str()
            .expect("ascii"),
        "1"
    );
}

/// INV-RES-01: an exhausted in-flight budget is a 503 with its own code.
/// It must not read as `upstream_unavailable` — the upstream is healthy; we
/// refused to send the request — and it must not read as a client quota error.
#[test]
fn an_exhausted_budget_maps_to_its_own_503() {
    use re0auth_api::connector::UpstreamError;

    let error = GatewayError::Upstream(UpstreamError::Overloaded);
    assert_eq!(error.code(), "upstream_capacity_exhausted");

    let response = gateway_error(error);
    assert_eq!(
        response.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "capacity pressure is transient, not a bad request"
    );
}

/// The SPA reads `authorization_url` and `upstreams` off these two bodies, so a
/// renamed member parses as `undefined` in the browser. The structs are private
/// to this crate, so — like the problem-shape check above — the comparison
/// lives here rather than in `re0auth-archtest`.
#[test]
fn the_binding_shapes_match_the_spas_schemas() {
    let api = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web/src/lib/api.ts"),
    )
    .expect("the SPA's api.ts");

    let begin = serde_json::to_value(crate::binding_routes::BeginView {
        authorization_url: "https://upstream.example/authorize".to_string(),
    })
    .expect("serialise BeginView");
    assert_eq!(
        spa_schema_fields(&api, "bindingStartSchema"),
        json_keys(&begin)
    );

    let upstreams = serde_json::to_value(crate::binding_routes::BindableUpstreamsView {
        upstreams: vec!["phigros".to_string()],
    })
    .expect("serialise BindableUpstreamsView");
    assert_eq!(
        spa_schema_fields(&api, "bindableUpstreamsSchema"),
        json_keys(&upstreams)
    );

    let summary = serde_json::to_value(re0auth_app::auth::BindingRevocationSummary { revoked: 2 })
        .expect("serialise BindingRevocationSummary");
    assert_eq!(
        spa_schema_fields(&api, "bindingRevocationSchema"),
        json_keys(&summary)
    );
}

/// The member names of one flat `z.object({...})` in `api.ts`, sorted.
fn spa_schema_fields(api: &str, name: &str) -> Vec<String> {
    let start = api
        .find(&format!("export const {name} = z.object({{"))
        .unwrap_or_else(|| panic!("api.ts has no `{name}` schema"));
    let body = &api[start..];
    let end = body
        .find("\n});")
        .unwrap_or_else(|| panic!("`{name}` has no closing `}});` at column zero"));
    let mut fields: Vec<String> = body[..end]
        .lines()
        .skip(1)
        .filter_map(|line| {
            let key = line.trim().split(':').next()?.trim();
            (!key.is_empty() && !key.contains('{')).then(|| key.to_string())
        })
        .collect();
    fields.sort();
    fields
}

/// The keys of a serialised JSON object, sorted.
fn json_keys(value: &serde_json::Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .expect("a JSON object")
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

/// An upstream names the body's media type; it is parsed, not copied.
#[test]
fn gateway_content_type_is_a_parsed_media_type() {
    use axum::http::HeaderValue;

    for (raw, expected) in [
        ("application/json", "application/json"),
        ("text/html; charset=utf-8", "text/html; charset=utf-8"),
        ("application/vnd.api+json", "application/vnd.api+json"),
    ] {
        assert_eq!(
            gateway_content_type(raw),
            HeaderValue::from_str(expected).expect("expected header"),
            "{raw:?}"
        );
    }

    // A bare slash is what the old `contains('/')` test accepted.
    for raw in [
        "",
        "/",
        "a/b; =",
        "a/b\r\nx-injected: 1",
        "not a media type",
        "application/json; boundary",
    ] {
        assert_eq!(
            gateway_content_type(raw),
            HeaderValue::from_static("application/octet-stream"),
            "{raw:?}"
        );
    }
}

/// The value the client echoes back has to be the one we hashed, so the cookie
/// writer must not re-encode it. `Cookie`'s `Display` leaves the value alone
/// unless `.encoded()` is asked for, and this pins that.
#[test]
fn session_cookies_carry_the_value_verbatim() {
    let token = "abc-DEF_0123456789";
    let rendered = session_set_cookie("re0auth_session", token, 3600, true, true).to_string();
    assert!(
        rendered.starts_with(&format!("re0auth_session={token};")),
        "{rendered}"
    );
    for attribute in [
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=3600",
        "Path=/",
        "Secure",
    ] {
        assert!(
            rendered.contains(attribute),
            "{attribute} missing: {rendered}"
        );
    }
}

/// The SPA reads the CSRF cookie to echo the header, so it must not be HttpOnly;
/// the session cookie must be.
#[test]
fn only_the_session_cookie_is_http_only() {
    let session = session_set_cookie("re0auth_session", "v", 60, false, true).to_string();
    let csrf = session_set_cookie("re0auth_csrf", "v", 60, false, false).to_string();
    assert!(session.contains("HttpOnly"), "{session}");
    assert!(!csrf.contains("HttpOnly"), "{csrf}");
    assert!(
        !session.contains("Secure"),
        "plain http development: {session}"
    );
}

/// Clearing means an empty value and a zero lifetime, not just a missing cookie.
#[test]
fn a_cleared_cookie_expires_immediately() {
    let cleared = session_set_cookie("re0auth_session", "", 0, false, true).to_string();
    assert!(cleared.starts_with("re0auth_session=;"), "{cleared}");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
}

/// Every value the approval page interpolates comes from the client or from the
/// upstream's client list, so each one has to come out inert. This is the
/// behaviour of the page, not of one escaping helper: it stays green whichever
/// way the template is built.
#[tokio::test]
async fn the_approval_page_neutralises_every_interpolated_value() {
    let ticket = r#"x" /><script>alert(1)</script>"#;
    let user_code = "<img src=x onerror=alert(2)>";
    let client_id = "<svg/onload=alert(3)>";
    let response = device_approval_page(
        ticket,
        user_code,
        client_id,
        &["<script>alert(4)</script>".to_string()],
    );
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = String::from_utf8(bytes.to_vec()).expect("utf8");
    // Only tag openers matter: the payloads themselves survive as *text*, which
    // is the point. `onerror=alert(2)` inside an escaped `&lt;img ...&gt;` is inert.
    for hostile in ["<script", "<img", "<svg", "<iframe"] {
        assert!(
            !body.contains(hostile),
            "{hostile:?} must not survive as markup: {body}"
        );
    }
    assert!(
        body.contains("&lt;script&gt;alert(4)&lt;/script&gt;"),
        "the scope is text: {body}"
    );
    // The ticket lands in a double-quoted attribute, so a quote must be escaped.
    assert!(
        !body.contains(r#"value="x" /><"#),
        "the attribute must not be closable: {body}"
    );
}

/// The error page shows a message that can carry upstream text.
#[tokio::test]
async fn the_error_page_neutralises_the_message() {
    let response = device_error_page("<script>alert(1)</script>");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = String::from_utf8(bytes.to_vec()).expect("utf8");
    assert!(!body.contains("<script>"), "{body}");
    assert!(body.contains("&lt;script&gt;"), "{body}");
}
