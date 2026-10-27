#![forbid(unsafe_code)]

//! HTTP layer. Parses and renders; it does not implement business rules.

mod admin;
mod binding_routes;
mod client_address;
mod cookies;
mod copy;
mod error;
mod limit_headers;
mod pages;
mod parsers;
mod rate;
mod request_id;
mod routes;
mod static_assets;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware;
use axum::response::Response;
use axum::routing::{delete, get, patch, post};
use re0auth_app::admin_service::AdminService;
use re0auth_app::auth::AuthService;
use re0auth_app::gateway::GatewayService;
use re0auth_app::oauth::OAuthService;
use routes::device::{device_approve, device_deny, device_qr, device_start};
use routes::gateway::{fetch_raw, fetch_upstream};
use routes::oauth::{
    authorize, device_authorization, discovery, jwks, oauth_consent, oauth_pending, revoke, token,
    userinfo,
};
use routes::session::{
    auth_callback, authorizations, login, logout, logout_all, me, providers, revoke_authorization,
};

pub use routes::session::{MeUserView, MeView};
pub(crate) use routes::session::{require_csrf, session_context_from_headers};

pub(crate) use error::*;

/// INV-RES-02 default. Callers override it from `limits.inbound_body_bytes`.
const DEFAULT_INBOUND_BODY_BYTES: usize = 1024 * 1024;

pub use client_address::ProxyRange;
/// The correlation id for the current request, as a request extension.
pub use request_id::RequestId;
pub use static_assets::is_reserved_path;

#[derive(Clone)]
pub struct AppState {
    pub oauth: Arc<OAuthService>,
    pub auth: Arc<AuthService>,
    /// Absent when no connector is configured; identity flows never read it.
    pub gateway: Option<Arc<GatewayService>>,
    /// Starts and completes binding flows. Absent when no connector declares an
    /// authorization endpoint, in which case the routes answer 404 rather than
    /// pretending binding is available.
    pub binding: Option<Arc<re0auth_app::binding::BindingService>>,
    /// The administration surface. Absent in embedded uses and tests that only
    /// exercise the identity flows; its routes answer 404 rather than pretending
    /// an admin exists.
    pub admin: Option<Arc<AdminService>>,
    /// INV-RATE-01: never `Option`. An unconfigured budget means "no limit",
    /// which is a limiter (`Unlimited`), not a missing one — otherwise every
    /// call site needs an `if let` and one of them will forget.
    pub rate: Arc<dyn re0auth_api::rate::RateLimiter>,
    /// INV-RES-02: request bodies are capped before extraction. This is part of
    /// the state rather than a constant because `limits.inbound_body_bytes` is a
    /// documented knob; a constant made that knob silently inert.
    pub inbound_body_bytes: usize,
    /// INV-RATE-01: peers allowed to speak for the client via `X-Forwarded-For`.
    /// Empty means "never trust the header", which is the correct default for a
    /// directly exposed instance.
    pub trusted_proxies: Vec<client_address::ProxyRange>,
}

impl AppState {
    #[must_use]
    pub fn new(oauth: OAuthService, auth: AuthService) -> Self {
        Self {
            oauth: Arc::new(oauth),
            auth: Arc::new(auth),
            gateway: None,
            binding: None,
            admin: None,
            rate: Arc::new(re0auth_api::rate::Unlimited),
            inbound_body_bytes: DEFAULT_INBOUND_BODY_BYTES,
            trusted_proxies: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_gateway(mut self, gateway: Arc<GatewayService>) -> Self {
        self.gateway = Some(gateway);
        self
    }

    #[must_use]
    pub fn with_binding(mut self, binding: Arc<re0auth_app::binding::BindingService>) -> Self {
        self.binding = Some(binding);
        self
    }

    #[must_use]
    pub fn with_admin(mut self, admin: Arc<AdminService>) -> Self {
        self.admin = Some(admin);
        self
    }

    #[must_use]
    pub fn with_rate_limiter(mut self, rate: Arc<dyn re0auth_api::rate::RateLimiter>) -> Self {
        self.rate = rate;
        self
    }

    #[must_use]
    pub fn with_inbound_body_bytes(mut self, bytes: usize) -> Self {
        self.inbound_body_bytes = bytes;
        self
    }

    #[must_use]
    pub fn with_trusted_proxies(mut self, proxies: Vec<client_address::ProxyRange>) -> Self {
        self.trusted_proxies = proxies;
        self
    }

    /// INV-RATE-01: the one place a request's address is derived.
    fn client_address(&self, peer: SocketAddr, headers: &HeaderMap) -> String {
        client_address::resolve(peer.ip(), headers, &self.trusted_proxies)
    }
}

pub fn router(state: AppState) -> Router {
    let inbound_body_bytes = state.inbound_body_bytes;
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        // INV-READY-01: readiness means "can serve requests", not "process is
        // up". The probe touches storage so an orchestrator stops routing to an
        // instance whose database is gone.
        .route("/readyz", get(readyz))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks.json", get(jwks))
        .route("/api/auth/providers", get(providers))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(auth_callback))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/device_authorization", post(device_authorization))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        .route("/userinfo", get(userinfo))
        .route("/api/oauth/pending", get(oauth_pending))
        .route("/api/oauth/consent", post(oauth_consent))
        .route("/api/me", get(me))
        .route("/api/me/authorizations", get(authorizations))
        .route(
            "/api/me/bindings",
            get(binding_routes::bindings).delete(binding_routes::revoke_all_bindings),
        )
        // Static segments before the `{id}` route: axum matches in registration
        // order, so `/{id}` first would swallow `begin` and `callback`.
        .route("/api/me/bindings/begin", post(binding_routes::begin))
        .route("/api/me/bindings/callback", get(binding_routes::complete))
        .route("/api/me/bindings/upstreams", get(binding_routes::upstreams))
        .route(
            "/api/me/bindings/{id}",
            delete(binding_routes::revoke_binding),
        )
        .route(
            "/api/me/authorizations/{client_id}",
            delete(revoke_authorization),
        )
        .route("/api/logout", post(logout))
        .route("/api/logout-all", post(logout_all))
        .route("/device/start", get(device_start))
        .route("/device/qr.svg", get(device_qr))
        .route("/device/approve", post(device_approve))
        .route("/device/deny", post(device_deny))
        .route(
            "/api/v1/upstreams/{connector}/{resource}",
            get(fetch_upstream),
        )
        .route("/api/v1/raw/{connector}/{resource}", get(fetch_raw))
        // Admin API (B1). The action sub-resource is registered before the
        // `{id}` route so `rotate-secret` cannot be read as an id.
        .route(
            "/api/admin/clients",
            get(admin::list_clients).post(admin::create_client),
        )
        .route(
            "/api/admin/clients/{id}/rotate-secret",
            post(admin::rotate_client_secret),
        )
        .route(
            "/api/admin/clients/{id}",
            get(admin::get_client).patch(admin::update_client),
        )
        .route("/api/admin/users", get(admin::list_users))
        .route("/api/admin/users/{id}", patch(admin::update_user))
        .route("/api/admin/connectors", get(admin::list_connectors))
        .route("/api/admin/connectors/{id}", get(admin::get_connector))
        .route("/api/admin/bindings", get(admin::list_bindings))
        .route("/api/admin/bindings/{id}", delete(admin::revoke_binding))
        .route("/api/admin/audit", get(admin::list_audit))
        .fallback(static_assets::serve)
        // INV-RES-02: reject oversized bodies before any extractor buffers them.
        // axum's own 2 MiB default is not the configured value, so leaving this
        // out made `limits.inbound_body_bytes` a knob that changed nothing.
        .layer(DefaultBodyLimit::max(inbound_body_bytes))
        .layer(middleware::from_fn(request_id::layer))
        .with_state(state)
}

async fn readyz(State(state): State<AppState>) -> (StatusCode, &'static str) {
    match state.oauth.check_storage().await {
        Ok(()) => (StatusCode::OK, "ready"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "storage unavailable"),
    }
}

fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
mod tests;
