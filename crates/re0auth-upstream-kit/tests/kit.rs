use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use serde_json::{Value, json};
use tower::ServiceExt;

use re0auth_upstream_kit::conformance::check_discovery;
use re0auth_upstream_kit::{
    AccountInfo, CascadeRevocationRequest, CascadeRevoker, Config, Hooks, RawSpec, Resource,
    ResourceError, ResourceHandler, Server, TokenClass, new_discovery,
};

fn config() -> Config {
    Config {
        game: "phigros".to_string(),
        source: "phi-backend".to_string(),
        display_name: "Phi Backend".to_string(),
        issuer: "https://api.example.com".to_string(),
        token_class: TokenClass::Revocable,
        resources: vec![Resource {
            name: "stats".to_string(),
            schema: "re0auth.phigros.stats/1".to_string(),
            scope: "phigros.stats.read".to_string(),
        }],
        raw: Some(RawSpec {
            base: "https://api.example.com/raw".to_string(),
            openapi: None,
        }),
        contact: Some("security@example.com".to_string()),
    }
}

struct Stats;

#[async_trait]
impl ResourceHandler for Stats {
    async fn fetch(&self, subject: &str) -> Result<Value, ResourceError> {
        Ok(json!({"subject": subject, "score": 42}))
    }
}

struct Revoker;

#[async_trait]
impl CascadeRevoker for Revoker {
    async fn revoke(&self, request: CascadeRevocationRequest) -> Result<(), ResourceError> {
        if request.token.is_empty() {
            Err(ResourceError("empty token".to_string()))
        } else {
            Ok(())
        }
    }
}

fn hooks(with_cascade: bool) -> Hooks {
    let mut resources: HashMap<String, Arc<dyn ResourceHandler>> = HashMap::new();
    resources.insert("stats".to_string(), Arc::new(Stats));
    Hooks {
        bearer: Arc::new(|token: &str| {
            if token == "good" {
                Some("subject-1".to_string())
            } else {
                None
            }
        }),
        client: Arc::new(|id: &str, secret: &str| id == "client" && secret == "secret"),
        account: Arc::new(|subject: &str| {
            Some(AccountInfo {
                subject: subject.to_string(),
                display_name: Some("Player".to_string()),
            })
        }),
        resources,
        cascade: if with_cascade {
            Some(Arc::new(Revoker))
        } else {
            None
        },
    }
}

#[test]
fn discovery_has_expected_shape() {
    let discovery = new_discovery(config()).expect("valid discovery");
    assert_eq!(discovery.re0auth_upstream_version, 1);
    assert!(
        discovery
            .scopes_supported
            .iter()
            .any(|scope| scope == "account.read")
    );
    assert!(
        discovery
            .scopes_supported
            .iter()
            .any(|scope| scope == "phigros.stats.read")
    );
    assert_eq!(
        discovery.oauth.authorization_endpoint,
        "https://api.example.com/oauth/authorize"
    );
    assert!(check_discovery(&discovery).passed());
}

#[test]
fn invalid_scope_is_rejected() {
    let mut cfg = config();
    cfg.resources[0].scope = "Phigros.stats.read".to_string();
    assert!(new_discovery(cfg).is_err());
}

#[test]
fn missing_account_scope_is_reported() {
    let mut discovery = new_discovery(config()).expect("valid discovery");
    discovery
        .scopes_supported
        .retain(|scope| scope != "account.read");
    assert!(!check_discovery(&discovery).passed());
}

#[tokio::test]
async fn discovery_and_account_routes() {
    let discovery = new_discovery(config()).expect("valid discovery");
    let server = Server::new(discovery, hooks(false)).expect("server");
    let router = server.router();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/re0auth-upstream")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let document: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(document["re0auth_upstream_version"].as_u64(), Some(1));

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/account")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/account")
                .header(header::AUTHORIZATION, "Bearer good")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let document: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(document["subject"], "subject-1");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/resources/stats")
                .header(header::AUTHORIZATION, "Bearer good")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let document: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(document["score"], 42);
}

#[tokio::test]
async fn cascade_route_requires_client_auth() {
    let discovery = new_discovery(config()).expect("valid discovery");
    let server = Server::new(discovery, hooks(true)).expect("server");
    let router = server.router();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/cascade_revocation")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("token=abc"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let encoded = base64::engine::general_purpose::STANDARD.encode("client:secret");
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/cascade_revocation")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, format!("Basic {encoded}"))
                .body(Body::from("token=abc"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn cascade_route_is_absent_without_hook() {
    let discovery = new_discovery(config()).expect("valid discovery");
    let server = Server::new(discovery, hooks(false)).expect("server");
    assert!(
        server
            .discovery()
            .oauth
            .cascade_revocation_endpoint
            .is_none()
    );

    let response = server
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/cascade_revocation")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("token=abc"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
