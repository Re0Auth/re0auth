//! The admin API: `/api/admin/*` (B1).
//!
//! Every route requires a session whose user has `role=admin`; every write also
//! checks CSRF. Connectors are deliberately read-only: configuration is the
//! source of truth (ADR-0015/0032), so a write route here would only teach
//! clients that runtime edits stick when they do not.
//!
//! Kept out of `lib.rs` for the usual reason: the router file has a line
//! budget, and the twelve routes deserve one home that describes them together.

use std::collections::HashMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use uuid::Uuid;

use re0auth_api::audit::{AuditAction, AuditTier};
use re0auth_api::ports::{AuditFilter, BindingQuery, BindingStatus, ClientStatus, UserRole};
use re0auth_api::{AuditId, BindingId, ClientId, ConnectorId, UserId};
use re0auth_app::admin_service::{AdminService, ClientPatch, NewClientInput, Page};
use re0auth_app::auth::SessionContext;

use crate::{
    ApiError, AppState, Shape, admin_error, admin_required, invalid_request, no_store,
    problem_response, request_id, require_csrf, session_context_from_headers,
};

type Params = HashMap<String, String>;

/// The service, or the 404 a deployment without it answers.
///
/// `None` is a deliberate state, not a bug: an embedded instance or a test may
/// run the identity surface and never expose administration.
fn service(state: &AppState) -> Result<&AdminService, ApiError> {
    state.admin.as_deref().ok_or_else(|| {
        problem_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "the admin API is not configured",
        )
    })
}

/// Resolves the session and enforces `role=admin`.
///
/// 401 (no session) and 403 (not an admin) stay distinct: collapsing them would
/// tell a logged-in non-admin to log in again, which cannot change the outcome.
async fn admin_session(state: &AppState, headers: &HeaderMap) -> Result<SessionContext, ApiError> {
    let context = session_context_from_headers(state, headers).await?;
    if context.user.role != UserRole::Admin {
        return Err(admin_required());
    }
    Ok(context)
}

fn limit(params: &Params) -> Result<Option<u32>, ApiError> {
    match params.get("limit") {
        None => Ok(None),
        Some(raw) => raw
            .parse()
            .map(Some)
            .map_err(|_| invalid_request("limit must be a number", Shape::Problem)),
    }
}

/// A UUID query parameter, wrapped into its domain id type.
///
/// Parsed by hand rather than via a typed `Query<T>`: a serde rejection would
/// answer axum's plain-text 400, and this lane owes the client a problem body
/// with a stable `code` (API-SURFACE.md §5.1).
fn uuid_param<T>(
    params: &Params,
    key: &str,
    message: &'static str,
    wrap: impl FnOnce(Uuid) -> T,
) -> Result<Option<T>, ApiError> {
    match params.get(key) {
        None => Ok(None),
        Some(raw) => Uuid::parse_str(raw)
            .map(|id| Some(wrap(id)))
            .map_err(|_| invalid_request(message, Shape::Problem)),
    }
}

fn path_id<T>(
    raw: &str,
    message: &'static str,
    wrap: impl FnOnce(Uuid) -> T,
) -> Result<T, ApiError> {
    Uuid::parse_str(raw)
        .map(wrap)
        .map_err(|_| invalid_request(message, Shape::Problem))
}

fn unix_param(params: &Params, key: &str) -> Result<Option<i64>, ApiError> {
    match params.get(key) {
        None => Ok(None),
        Some(raw) => raw
            .parse()
            .map(Some)
            .map_err(|_| invalid_request("time filters must be Unix seconds", Shape::Problem)),
    }
}

fn client_status(raw: &str) -> Result<ClientStatus, ApiError> {
    Ok(match raw {
        "pending" => ClientStatus::Pending,
        "approved" => ClientStatus::Approved,
        "suspended" => ClientStatus::Suspended,
        "revoked" => ClientStatus::Revoked,
        _ => {
            return Err(invalid_request(
                "status must be pending, approved, suspended or revoked",
                Shape::Problem,
            ));
        }
    })
}

fn user_role(raw: &str) -> Result<UserRole, ApiError> {
    Ok(match raw {
        "admin" => UserRole::Admin,
        "user" => UserRole::User,
        _ => {
            return Err(invalid_request(
                "role must be admin or user",
                Shape::Problem,
            ));
        }
    })
}

fn binding_status(raw: &str) -> Result<BindingStatus, ApiError> {
    Ok(match raw {
        "pending" => BindingStatus::Pending,
        "active" => BindingStatus::Active,
        "needs_reauth" => BindingStatus::NeedsReauth,
        "revoked" => BindingStatus::Revoked,
        "expired" => BindingStatus::Expired,
        _ => return Err(invalid_request("unknown binding status", Shape::Problem)),
    })
}

fn json_body<T>(body: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    body.map(|Json(value)| value)
        .map_err(|_| invalid_request("invalid JSON body", Shape::Problem))
}

/// 入库前的唯一关口
fn check_redirect_uris(values: &[String]) -> Result<(), ApiError> {
    for value in values {
        re0auth_api::redirect_uri::validate(value)
            .map_err(|error| invalid_request(error.description(), Shape::Problem))?;
    }
    Ok(())
}

// ---- Clients -------------------------------------------------------------

pub(crate) async fn list_clients(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<Params>,
) -> Result<Response, ApiError> {
    admin_session(&state, &headers).await?;
    let page = service(&state)?
        .list_clients(
            uuid_param(&params, "cursor", "cursor must be a UUID", ClientId)?,
            limit(&params)?,
        )
        .await
        .map_err(admin_error)?;
    Ok(no_store(Json(page).into_response()))
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateClientBody {
    name: String,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    allowed_scopes: Vec<String>,
    #[serde(default)]
    confidential: bool,
    #[serde(default)]
    raw_access: bool,
    #[serde(default)]
    status: Option<String>,
}

pub(crate) async fn create_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<CreateClientBody>, JsonRejection>,
) -> Result<Response, ApiError> {
    let context = admin_session(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;
    let body = json_body(body)?;
    // A new client is not usable until an admin approves it. Defaulting to
    // approved would turn the create route into a silent privilege grant.
    let status = match body.status.as_deref() {
        None => ClientStatus::Pending,
        Some(raw) => client_status(raw)?,
    };
    check_redirect_uris(&body.redirect_uris)?;
    let created = service(&state)?
        .create_client(
            context.user.id,
            request_id::of(&headers),
            NewClientInput {
                name: body.name,
                redirect_uris: body.redirect_uris,
                allowed_scopes: body.allowed_scopes,
                raw_access: body.raw_access,
                confidential: body.confidential,
                status,
            },
        )
        .await
        .map_err(admin_error)?;
    let location = format!("/api/admin/clients/{}", created.id);
    let mut response = Json(created).into_response();
    *response.status_mut() = StatusCode::CREATED;
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&location).expect("a UUID is a valid header value"),
    );
    Ok(no_store(response))
}

pub(crate) async fn get_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    admin_session(&state, &headers).await?;
    let id = path_id(&id, "client id must be a UUID", ClientId)?;
    let view = service(&state)?
        .get_client(&id)
        .await
        .map_err(admin_error)?;
    Ok(no_store(Json(view).into_response()))
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdateClientBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    allowed_scopes: Option<Vec<String>>,
    #[serde(default)]
    raw_access: Option<bool>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    expected_updated_at: Option<i64>,
}

pub(crate) async fn update_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<Json<UpdateClientBody>, JsonRejection>,
) -> Result<Response, ApiError> {
    let context = admin_session(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;
    let body = json_body(body)?;
    let id = path_id(&id, "client id must be a UUID", ClientId)?;
    let status = match body.status.as_deref() {
        None => None,
        Some(raw) => Some(client_status(raw)?),
    };
    if let Some(uris) = &body.redirect_uris {
        check_redirect_uris(uris)?;
    }
    let view = service(&state)?
        .update_client(
            context.user.id,
            &id,
            ClientPatch {
                name: body.name,
                redirect_uris: body.redirect_uris,
                allowed_scopes: body.allowed_scopes,
                raw_access: body.raw_access,
                status,
                expected_updated_at: body.expected_updated_at,
            },
            request_id::of(&headers),
        )
        .await
        .map_err(admin_error)?;
    Ok(no_store(Json(view).into_response()))
}

pub(crate) async fn rotate_client_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let context = admin_session(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;
    let id = path_id(&id, "client id must be a UUID", ClientId)?;
    let rotated = service(&state)?
        .rotate_client_secret(context.user.id, &id, request_id::of(&headers))
        .await
        .map_err(admin_error)?;
    Ok(no_store(Json(rotated).into_response()))
}

// ---- Users ---------------------------------------------------------------

pub(crate) async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<Params>,
) -> Result<Response, ApiError> {
    admin_session(&state, &headers).await?;
    let page = service(&state)?
        .list_users(
            uuid_param(&params, "cursor", "cursor must be a UUID", UserId)?,
            limit(&params)?,
        )
        .await
        .map_err(admin_error)?;
    Ok(no_store(Json(page).into_response()))
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdateUserBody {
    role: String,
}

pub(crate) async fn update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<Json<UpdateUserBody>, JsonRejection>,
) -> Result<Response, ApiError> {
    let context = admin_session(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;
    let body = json_body(body)?;
    let target = path_id(&id, "user id must be a UUID", UserId)?;
    let role = user_role(&body.role)?;
    let view = service(&state)?
        .set_user_role(context.user.id, target, role, request_id::of(&headers))
        .await
        .map_err(admin_error)?;
    Ok(no_store(Json(view).into_response()))
}

// ---- Connectors (read-only) ----------------------------------------------

pub(crate) async fn list_connectors(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    admin_session(&state, &headers).await?;
    let items = service(&state)?
        .list_connectors()
        .await
        .map_err(admin_error)?;
    // The registry is small and not cursor-paged; the envelope stays uniform so
    // a client parses one list shape everywhere.
    let page = Page {
        items,
        next_cursor: None,
    };
    Ok(no_store(Json(page).into_response()))
}

pub(crate) async fn get_connector(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    admin_session(&state, &headers).await?;
    let id = path_id(&id, "connector id must be a UUID", ConnectorId)?;
    let view = service(&state)?
        .get_connector(&id)
        .await
        .map_err(admin_error)?;
    Ok(no_store(Json(view).into_response()))
}

// ---- Bindings ------------------------------------------------------------

pub(crate) async fn list_bindings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<Params>,
) -> Result<Response, ApiError> {
    admin_session(&state, &headers).await?;
    let query = BindingQuery {
        user: uuid_param(&params, "user", "user filter must be a UUID", UserId)?,
        upstream: params.get("connector").cloned(),
        status: match params.get("status") {
            None => None,
            Some(raw) => Some(binding_status(raw)?),
        },
    };
    let page = service(&state)?
        .list_bindings(
            uuid_param(&params, "cursor", "cursor must be a UUID", BindingId)?,
            query,
            limit(&params)?,
        )
        .await
        .map_err(admin_error)?;
    Ok(no_store(Json(page).into_response()))
}

/// The admin killswitch: revokes any binding, and the fact names the admin.
pub(crate) async fn revoke_binding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let context = admin_session(&state, &headers).await?;
    require_csrf(&state, &context, &headers)?;
    let id = path_id(&id, "binding id must be a UUID", BindingId)?;
    service(&state)?
        .revoke_binding(context.user.id, id, request_id::of(&headers))
        .await
        .map_err(admin_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---- Audit ---------------------------------------------------------------

pub(crate) async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<Params>,
) -> Result<Response, ApiError> {
    admin_session(&state, &headers).await?;
    let filter = AuditFilter {
        actor: uuid_param(&params, "actor", "actor filter must be a UUID", UserId)?,
        client: uuid_param(&params, "client", "client filter must be a UUID", ClientId)?,
        action: match params.get("action") {
            None => None,
            Some(raw) => Some(
                AuditAction::parse(raw)
                    .ok_or_else(|| invalid_request("unknown audit action", Shape::Problem))?,
            ),
        },
        tier: match params.get("tier") {
            None => None,
            Some(raw) => Some(
                AuditTier::parse(raw)
                    .ok_or_else(|| invalid_request("unknown audit tier", Shape::Problem))?,
            ),
        },
        from: unix_param(&params, "from")?,
        to: unix_param(&params, "to")?,
    };
    let page = service(&state)?
        .list_audit(
            filter,
            uuid_param(&params, "cursor", "cursor must be a UUID", AuditId)?,
            limit(&params)?,
        )
        .await
        .map_err(admin_error)?;
    Ok(no_store(Json(page).into_response()))
}
