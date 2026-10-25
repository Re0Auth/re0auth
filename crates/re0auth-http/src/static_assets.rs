use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../web/build/"]
struct WebAssets;

const INDEX: &str = "index.html";

pub async fn serve(request: Request<Body>) -> Response {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let path = request.uri().path();
    if is_reserved_path(path) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let head = request.method() == Method::HEAD;
    let asset_path = path.trim_start_matches('/');

    if asset_path.is_empty() || path.ends_with('/') {
        return index_response(head);
    }

    if let Some(file) = WebAssets::get(asset_path) {
        return asset_response(asset_path, file, head);
    }

    // A missing asset must not turn into the SPA shell: that would hide a
    // broken JS/CSS URL behind a 200 HTML response.
    if asset_path.starts_with("_app/")
        || asset_path
            .rsplit('/')
            .next()
            .is_some_and(|s| s.contains('.'))
    {
        return StatusCode::NOT_FOUND.into_response();
    }

    index_response(head)
}

/// Whether `path` belongs to a namespace the single-page app must not answer.
///
/// The router is the source of truth for what exists; this list only decides what
/// the *fallback* must refuse, so that an unknown path under `/api/` is a 404
/// rather than the SPA shell with a 200. `every_route_is_reserved_by_the_fallback`
/// keeps the two from drifting apart.
#[must_use]
pub fn is_reserved_path(path: &str) -> bool {
    let exact = matches!(
        path,
        "/api"
            | "/auth"
            | "/oauth"
            | "/userinfo"
            | "/jwks.json"
            | "/.well-known"
            | "/healthz"
            | "/readyz"
            | "/device/start"
            | "/device/approve"
            | "/device/deny"
    );

    exact
        || path.starts_with("/api/")
        || path.starts_with("/auth/")
        || path.starts_with("/oauth/")
        || path.starts_with("/.well-known/")
        || (path.starts_with("/device/") && path != "/device/")
}

fn index_response(head: bool) -> Response {
    match WebAssets::get(INDEX) {
        Some(file) => asset_response(INDEX, file, head),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn asset_response(path: &str, file: rust_embed::EmbeddedFile, head: bool) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let cache = if path == INDEX {
        "no-store"
    } else if path.starts_with("_app/immutable/") {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=3600"
    };
    let len = file.data.len();
    let body = if head {
        Body::empty()
    } else {
        Body::from(file.data.into_owned())
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime.to_string())
        .header(header::CONTENT_LENGTH, len.to_string())
        .header(header::CACHE_CONTROL, cache)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    if path == INDEX {
        builder = builder
            .header(header::X_FRAME_OPTIONS, "DENY")
            .header(header::REFERRER_POLICY, "no-referrer");
    }

    builder
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    fn request(method: Method, path: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .expect("test request")
    }

    async fn body_text(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("read body");
        String::from_utf8(bytes.to_vec()).expect("utf8 body")
    }

    #[tokio::test]
    async fn spa_paths_return_the_shell() {
        for path in [
            "/", "/login", "/consent", "/device", "/device/", "/account", "/about",
        ] {
            let response = serve(request(Method::GET, path)).await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert!(body_text(response).await.contains("_app/immutable"));
        }
    }

    #[tokio::test]
    async fn api_and_device_subpaths_do_not_fall_back() {
        for path in [
            "/api/does-not-exist",
            "/auth/does-not-exist",
            "/oauth/does-not-exist",
            "/device/start",
            "/device/approve",
            "/device/does-not-exist",
            "/healthz",
        ] {
            let response = serve(request(Method::GET, path)).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[tokio::test]
    async fn missing_assets_are_not_html() {
        let response = serve(request(Method::GET, "/_app/missing.js")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = serve(request(Method::GET, "/missing.css")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn immutable_assets_are_served_with_cache_headers() {
        let path = WebAssets::iter()
            .find(|p| p.starts_with("_app/immutable/"))
            .expect("web build has immutable assets");
        let response = serve(request(Method::GET, &format!("/{path}"))).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable"
        );
    }

    #[tokio::test]
    async fn head_has_headers_but_no_body() {
        let response = serve(request(Method::HEAD, "/login")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::CONTENT_LENGTH).is_some());
        assert!(body_text(response).await.is_empty());
    }

    #[tokio::test]
    async fn non_read_methods_are_rejected() {
        let response = serve(request(Method::POST, "/login")).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
