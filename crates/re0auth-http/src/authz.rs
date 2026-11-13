use std::net::SocketAddr;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use re0auth_api::ports::UserRole;
use re0auth_api::rate::Lane;
use re0auth_app::auth::SessionContext;
use re0auth_app::oauth::OAuthError;

use crate::parsers::bearer_token;
use crate::rate::{charge, charge_unauthenticated};
use crate::{ApiError, AppState, Shape, admin_required, oauth_error, session_context_from_headers};

pub(crate) struct SessionPrincipal(pub SessionContext);
pub(crate) struct AdminPrincipal(pub SessionContext);

impl<S> FromRequestParts<S> for SessionPrincipal
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        session_principal(&AppState::from_ref(state), &parts.headers).await
    }
}

impl<S> FromRequestParts<S> for AdminPrincipal
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let SessionPrincipal(context) =
            session_principal(&AppState::from_ref(state), &parts.headers).await?;
        if context.user.role != UserRole::Admin {
            return Err(admin_required());
        }
        Ok(AdminPrincipal(context))
    }
}

pub(crate) async fn session_principal(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<SessionPrincipal, ApiError> {
    session_context_from_headers(state, headers)
        .await
        .map(SessionPrincipal)
}

pub(crate) struct GatewayIdentity {
    pub(crate) user_id: re0auth_api::UserId,
    pub(crate) granted_scopes: String,
    pub(crate) client_id: String,
}

pub(crate) async fn gateway_identity(
    state: &AppState,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<GatewayIdentity, ApiError> {
    charge_unauthenticated(state, &state.client_address(peer, headers), Shape::Problem)?;
    let token = bearer_token(headers)
        .ok_or_else(|| oauth_error(OAuthError::InvalidToken, Shape::Problem))?;
    let (user_id, granted_scopes, client_id) = state
        .oauth
        .verify_gateway_token(&token)
        .await
        .map_err(|error| oauth_error(error, Shape::Problem))?;
    charge(state, Lane::Authenticated, &client_id, Shape::Problem)?;
    Ok(GatewayIdentity {
        user_id,
        granted_scopes,
        client_id,
    })
}
