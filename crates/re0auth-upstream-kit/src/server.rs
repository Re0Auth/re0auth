use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{DefaultBodyLimit, Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::conformance::check_discovery;
use crate::discovery::Discovery;

pub const MAX_BODY_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountInfo {
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct ResourceError(pub String);

#[async_trait]
pub trait ResourceHandler: Send + Sync {
    async fn fetch(&self, subject: &str) -> Result<Value, ResourceError>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CascadeRevocationRequest {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: Option<String>,
}

#[async_trait]
pub trait CascadeRevoker: Send + Sync {
    async fn revoke(&self, request: CascadeRevocationRequest) -> Result<(), ResourceError>;
}

pub type BearerAuthenticator = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;
pub type ClientAuthenticator = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;
pub type AccountLookup = Arc<dyn Fn(&str) -> Option<AccountInfo> + Send + Sync>;

#[derive(Clone)]
pub struct Hooks {
    pub bearer: BearerAuthenticator,
    pub client: ClientAuthenticator,
    pub account: AccountLookup,
    pub resources: HashMap<String, Arc<dyn ResourceHandler>>,
    pub cascade: Option<Arc<dyn CascadeRevoker>>,
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("missing resource handler: {0}")]
    MissingResource(String),
    #[error("discovery failed conformance: {0}")]
    Conformance(String),
}

#[derive(Clone)]
struct AppState {
    discovery: Discovery,
    hooks: Hooks,
}

pub struct Server {
    state: AppState,
}

impl Server {
    pub fn new(discovery: Discovery, hooks: Hooks) -> Result<Self, ServerError> {
        let report = check_discovery(&discovery);
        if !report.passed() {
            let failures = report
                .failures()
                .map(|check| format!("{}: {}", check.name, check.detail))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(ServerError::Conformance(failures));
        }

        for resource in &discovery.resources {
            if !hooks.resources.contains_key(&resource.name) {
                return Err(ServerError::MissingResource(resource.name.clone()));
            }
        }

        let mut discovery = discovery;
        if hooks.cascade.is_none() {
            discovery.oauth.cascade_revocation_endpoint = None;
        } else if discovery.oauth.cascade_revocation_endpoint.is_none() {
            let base = discovery.oauth.issuer.trim_end_matches('/');
            discovery.oauth.cascade_revocation_endpoint =
                Some(format!("{base}/oauth/cascade_revocation"));
        }

        Ok(Self {
            state: AppState { discovery, hooks },
        })
    }

    pub fn discovery(&self) -> &Discovery {
        &self.state.discovery
    }

    pub fn router(&self) -> Router {
        let state = self.state.clone();
        let has_cascade = state.hooks.cascade.is_some();
        let mut router = Router::new()
            .route("/.well-known/re0auth-upstream", get(discovery_handler))
            .route(
                "/.well-known/oauth-authorization-server",
                get(oauth_handler),
            )
            .route("/account", get(account_handler))
            .route("/resources/{name}", get(resource_handler));
        if has_cascade {
            router = router.route("/oauth/cascade_revocation", post(cascade_handler));
        }
        router
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
            .with_state(state)
    }
}

async fn discovery_handler(State(state): State<AppState>) -> Response {
    let mut response = Json(state.discovery).into_response();
    set_header(&mut response, header::CACHE_CONTROL, "public, max-age=300");
    response
}

async fn oauth_handler(State(state): State<AppState>) -> Response {
    let mut response = Json(state.discovery.oauth).into_response();
    set_header(&mut response, header::CACHE_CONTROL, "public, max-age=300");
    response
}

async fn account_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(subject) = bearer_subject(&state.hooks, &headers) else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "missing or invalid bearer token",
        );
    };
    let Some(info) = (state.hooks.account)(&subject) else {
        return oauth_error(StatusCode::NOT_FOUND, "not_found", "account not found");
    };
    let mut response = Json(info).into_response();
    set_header(&mut response, header::CACHE_CONTROL, "no-store");
    response
}

async fn resource_handler(
    State(state): State<AppState>,
    AxumPath(name): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let Some(subject) = bearer_subject(&state.hooks, &headers) else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "missing or invalid bearer token",
        );
    };
    let Some(handler) = state.hooks.resources.get(&name) else {
        return oauth_error(StatusCode::NOT_FOUND, "not_found", "unknown resource");
    };
    match handler.fetch(&subject).await {
        Ok(value) => {
            let mut response = Json(value).into_response();
            set_header(&mut response, header::CACHE_CONTROL, "no-store");
            response
        }
        Err(err) => oauth_error(StatusCode::BAD_GATEWAY, "upstream_error", &err.to_string()),
    }
}

async fn cascade_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<CascadeRevocationRequest>,
) -> Response {
    let Some((client_id, client_secret)) = basic_client(&headers) else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication required",
        );
    };
    if !(state.hooks.client)(&client_id, &client_secret) {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client");
    }
    let Some(revoker) = state.hooks.cascade.as_ref() else {
        return oauth_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "cascade revocation not implemented",
        );
    };
    match revoker.revoke(request).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(err) => oauth_error(StatusCode::BAD_GATEWAY, "upstream_error", &err.to_string()),
    }
}

fn bearer_subject(hooks: &Hooks, headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    (hooks.bearer)(token)
}

fn basic_client(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

fn set_header(response: &mut Response, name: header::HeaderName, value: &'static str) {
    response
        .headers_mut()
        .insert(name, value.parse().expect("static header value"));
}

fn oauth_error(status: StatusCode, code: &str, description: &str) -> Response {
    (
        status,
        Json(json!({"error": code, "error_description": description})),
    )
        .into_response()
}
