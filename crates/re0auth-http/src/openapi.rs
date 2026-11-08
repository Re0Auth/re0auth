//! The OpenAPI document.
//!
//! Derived by `utoipa` from the handlers' own attributes, never written by hand:
//! a path that existed only here would be a second copy of the router.
//! `the_openapi_document_matches_the_router` (archtest) compares this document
//! with `re0auth_http::router()`, so a route added without a declaration fails
//! the build instead of drifting.

use utoipa::OpenApi;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, Http, HttpAuthScheme, SecurityScheme};

use crate::routes::{device, gateway, oauth, session};
use crate::{admin, binding_routes};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Re0Auth",
        version = env!("CARGO_PKG_VERSION"),
        description = "OAuth 2.0 authorization server plus the music-data gateway it fronts. Two error shapes coexist: the OAuth protocol lanes answer the RFC 6749 flat form, everything else answers RFC 9457 problem details whose stable identifier is code."
    ),
    paths(
        crate::healthz,
        crate::readyz,
        session::providers,
        session::login,
        session::auth_callback,
        session::me,
        session::authorizations,
        session::revoke_authorization,
        session::logout,
        session::logout_all,
        binding_routes::begin,
        binding_routes::upstreams,
        binding_routes::complete,
        binding_routes::bindings,
        binding_routes::revoke_binding,
        binding_routes::revoke_all_bindings,
        oauth::discovery,
        oauth::jwks,
        oauth::authorize,
        oauth::oauth_pending,
        oauth::oauth_consent,
        oauth::device_authorization,
        oauth::token,
        oauth::userinfo,
        oauth::revoke,
        device::device_start,
        device::device_qr,
        device::device_approve,
        device::device_deny,
        gateway::fetch_upstream,
        gateway::fetch_raw,
        admin::list_clients,
        admin::create_client,
        admin::get_client,
        admin::update_client,
        admin::rotate_client_secret,
        admin::list_users,
        admin::update_user,
        admin::list_connectors,
        admin::get_connector,
        admin::list_bindings,
        admin::revoke_binding,
        admin::killswitch,
        admin::list_audit,
    ),
    components(schemas(
        crate::ProblemBody,
        crate::OAuthErrorBody,
        session::ProvidersResponse,
        session::MeView,
        session::MeUserView,
        binding_routes::BeginBody,
        binding_routes::BeginView,
        binding_routes::BindableUpstreamsView,
        oauth::ConsentBody,
        oauth::DiscoveryDocument,
        oauth::JwksDocument,
        oauth::DeviceAuthorizationForm,
        oauth::TokenForm,
        oauth::RevokeForm,
        device::DeviceDecisionForm,
        admin::CreateClientBody,
        admin::UpdateClientBody,
        admin::UpdateUserBody,
        admin::KillswitchBody,
        re0auth_app::auth::ProviderView,
        re0auth_app::auth::AuthorizationView,
        re0auth_app::auth::BindingView,
        re0auth_app::auth::BindingRevocationSummary,
        re0auth_app::auth::FailedRevocation,
        re0auth_app::oauth::PendingConsentView,
        re0auth_app::oauth::ConsentOutcome,
        re0auth_app::oauth::TokenResponse,
        re0auth_app::oauth::UserInfo,
        re0auth_app::oauth::DeviceAuthorizationResponse,
        re0auth_app::admin_service::AdminClientView,
        re0auth_app::admin_service::AdminUserView,
        re0auth_app::admin_service::AdminResourceView,
        re0auth_app::admin_service::AdminConnectorView,
        re0auth_app::admin_service::AdminBindingView,
        re0auth_app::admin_service::AdminAuditView,
        re0auth_app::admin_service::CreatedClientView,
        re0auth_app::admin_service::RotatedSecretView,
        re0auth_app::gateway::Envelope,
        re0auth_app::gateway::PageBody,
    ))
)]
pub struct ApiDoc;

/// The document, built from the same declarations the router serves.
///
/// The two security schemes are added here rather than declared per operation
/// twice: `session` is the browser cookie, `bearer` is the gateway token. The
/// cookie is named `re0auth_session`; a deployment with secure cookies serves
/// the same cookie under the `__Host-` prefix, which browsers treat as a
/// different name, so the scheme documents the unprefixed one.
#[must_use]
pub fn document() -> utoipa::openapi::OpenApi {
    let mut document = ApiDoc::openapi();
    let components = document.components.get_or_insert_with(Default::default);
    components.add_security_scheme(
        "session",
        SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new("re0auth_session"))),
    );
    components.add_security_scheme(
        "bearer",
        SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
    );
    document
}

/// The document as it is committed: pretty JSON, path order preserved by the
/// `preserve_path_order` feature so a regenerated file diffs cleanly.
#[must_use]
pub fn render() -> String {
    let mut text = serde_json::to_string_pretty(&document()).expect("the document serialises");
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    fn committed_path() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("openapi.json")
    }

    /// The document must serialise: a spec that cannot be written is not a spec.
    #[test]
    fn the_document_serialises_with_its_paths() {
        let json = serde_json::to_value(super::document()).expect("the document serialises");
        let paths = json
            .get("paths")
            .and_then(|value| value.as_object())
            .expect("paths is an object");
        assert!(paths.contains_key("/api/me"), "the spec kept GET /api/me");
        assert!(
            json.get("components")
                .and_then(|value| value.get("schemas"))
                .and_then(|value| value.as_object())
                .is_some_and(|schemas| !schemas.is_empty()),
            "the spec carries component schemas"
        );
    }

    /// Every operation declares at least one response. An operation with none is
    /// a placeholder that tells a consumer nothing about what comes back.
    #[test]
    fn every_operation_declares_a_response() {
        let json = serde_json::to_value(super::document()).expect("the document serialises");
        let paths = json["paths"].as_object().expect("paths is an object");
        let mut bare = Vec::new();
        for (path, item) in paths {
            for (method, operation) in item.as_object().expect("a path item is an object") {
                let responses = operation
                    .get("responses")
                    .and_then(|value| value.as_object());
                if responses.is_none_or(|responses| responses.is_empty()) {
                    bare.push(format!("{} {}", method.to_uppercase(), path));
                }
            }
        }
        assert!(bare.is_empty(), "operations without responses: {bare:?}");
    }

    /// A committed spec that no longer matches the code is the same class of
    /// defect as a stale appendix: it reads as truth and is not. Regenerating is
    /// one command, and the failure message names it.
    #[test]
    fn the_committed_spec_matches_the_code() {
        let path = committed_path();
        let rendered = super::render();
        if std::env::var_os("UPDATE_OPENAPI").is_some() {
            std::fs::write(&path, &rendered).expect("write openapi.json");
            return;
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "cannot read {}: {error}. Regenerate with: \
                 UPDATE_OPENAPI=1 cargo test -p re0auth-http --lib openapi",
                path.display()
            )
        });
        if committed != rendered {
            let first = committed
                .lines()
                .zip(rendered.lines())
                .enumerate()
                .find(|(_, (a, b))| a != b)
                .map(|(index, (a, b))| (index + 1, a.to_string(), b.to_string()));
            panic!(
                "openapi.json is stale: the committed copy differs from the code.\n\
                 first difference at line {}\n  committed: {}\n  generated: {}\n\
                 Regenerate with: UPDATE_OPENAPI=1 cargo test -p re0auth-http --lib openapi",
                first.as_ref().map_or(0, |(line, _, _)| *line),
                first.as_ref().map_or("<none>", |(_, a, _)| a.as_str()),
                first.as_ref().map_or("<none>", |(_, _, b)| b.as_str()),
            );
        }
    }
}
