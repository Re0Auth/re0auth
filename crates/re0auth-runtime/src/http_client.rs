//! Guarded outbound HTTP client.
//!
//! All outbound traffic (IdP discovery/JWKS/token, upstream fetch, webhooks)
//! must go through this module (HR-05, INV-OUT-01). No other module may
//! construct a `reqwest::Client` directly.
//!
//! The guard resolves the host once, classifies every returned address, and
//! pins the connection to a vetted IP (INV-SSRF-01, §6.9). Redirects are off.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use serde::de::DeserializeOwned;
use tokio::net::lookup_host;
use url::Url;

use crate::outbound::{OutboundDenied, OutboundPolicy, check_addresses, check_scheme};
use crate::tls::{TlsConfig, TrustSummary};

/// A response body the guard has agreed to carry.
///
/// Deliberately neutral: the guard knows bytes and a content type, not what the
/// data plane intends to do with them. `re0auth-connectors` turns this into its
/// own `UpstreamPayload`, which keeps the connector types out of infrastructure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawResponse {
    pub content_type: String,
    pub body: Vec<u8>,
}

/// Upper bound from §6.9; keeps a hostile upstream from exhausting memory.
// INV-RES-01: one upstream response is capped at 4 MiB, raw included.
const DEFAULT_MAX_BODY: usize = 4 * 1024 * 1024;

/// The longest an upstream `Retry-After` is allowed to hold us.
///
/// The header is untrusted input, and it is mirrored to our own callers as
/// guidance. Without a ceiling a source could ask for a day, and a client that
/// believed us would wait a day.
const MAX_RETRY_AFTER_SECS: u64 = 3600;

/// A non-success upstream status, carried as data rather than as message text.
///
/// Classification used to string-match the error message. That works only by
/// accident: any transport error whose text happens to contain "401" would be
/// read as an auth failure. A typed value cannot be misread, and it is what lets
/// `map_transport_error` classify 400 as business instead of internal.
#[derive(Debug)]
pub struct UpstreamStatus {
    pub status: u16,
    /// How long the upstream asked us to wait, when it said so in seconds.
    ///
    /// `Retry-After` also has an HTTP-date form. A rate limiter answering 429
    /// sends the numeric one, and reading dates would mean another dependency for
    /// a form nothing we talk to uses — so a date is left as "no hint", which is
    /// what the field already means.
    pub retry_after_secs: Option<u64>,
}

impl std::fmt::Display for UpstreamStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "upstream returned {}", self.status)
    }
}

impl std::error::Error for UpstreamStatus {}

/// The response body exceeded the cap.
///
/// Same reason as [`UpstreamStatus`]: `Truncated` is an internal fault and must
/// not be confused with a body that merely happened to mention a number.
#[derive(Debug)]
pub struct UpstreamTooLarge {
    pub limit: usize,
}

impl std::fmt::Display for UpstreamTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "upstream response exceeds {} bytes", self.limit)
    }
}

impl std::error::Error for UpstreamTooLarge {}

/// The only outbound HTTP client. Every call resolves, vets and
/// pins the connection to a vetted IP (INV-SSRF-01, §6.9). Redirects are off.
/// Nothing else may construct a default client (INV-OUT-01).
#[derive(Clone, Debug)]
pub struct GuardedClient {
    config: Arc<rustls::ClientConfig>,
    policy: OutboundPolicy,
    allow_http: bool,
    max_body: usize,
    trust: TrustSummary,
    /// One client per host, keyed with the IP it is pinned to.
    ///
    /// A fresh `reqwest::Client` per request is cheap to build (measured at
    /// 1.95 µs) but it also throws away the connection pool, which means a
    /// full TCP + TLS handshake on every upstream call. Keeping the client
    /// alive is what makes keep-alive possible at all.
    ///
    /// The entry stores the pinned address so a host that moves is followed:
    /// the cached client is only reused while it points at the address the
    /// guard just vetted. Rebuilding on change costs one handshake, which is
    /// what an unpinned client would pay anyway.
    clients: Arc<Mutex<HashMap<String, PinnedClient>>>,
}

#[derive(Debug)]
struct PinnedClient {
    pinned: SocketAddr,
    client: reqwest::Client,
}

/// Outbound identity sent with every request.
///
/// GitHub's API answers 403 to a request without one, and `reqwest` sends none
/// by default. Set on the client rather than at each call site: there are enough
/// request methods that one would eventually be missed.
fn user_agent() -> String {
    format!("re0auth/{}", env!("CARGO_PKG_VERSION"))
}

/// Returns the cached client only when it is still pinned to the address the
/// caller just vetted. A host that moved must rebuild, or the guard would keep
/// using a connection to an address it no longer vouches for.
// INV-OUT-02: a cached client never outlives the address it was pinned to.
fn cached_client(
    clients: &HashMap<String, PinnedClient>,
    host: &str,
    pinned: SocketAddr,
) -> Option<reqwest::Client> {
    clients
        .get(host)
        .filter(|entry| entry.pinned == pinned)
        .map(|entry| entry.client.clone())
}

impl GuardedClient {
    pub fn new() -> anyhow::Result<Self> {
        Self::with_policy(OutboundPolicy::PublicOnly, false)
    }

    pub fn with_policy(policy: OutboundPolicy, allow_http: bool) -> anyhow::Result<Self> {
        Self::with_tls(policy, allow_http, TlsConfig::default())
    }

    /// Builds the trust store once; every request reuses it.
    pub fn with_tls(
        policy: OutboundPolicy,
        allow_http: bool,
        tls: TlsConfig,
    ) -> anyhow::Result<Self> {
        let (config, trust) = tls.build()?;
        Ok(Self {
            config: Arc::new(config),
            policy,
            allow_http,
            max_body: DEFAULT_MAX_BODY,
            trust,
            clients: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    #[must_use]
    pub fn trust(&self) -> TrustSummary {
        self.trust
    }

    /// Resolves, vets, then pins the chosen address so DNS cannot be rebound
    /// between the check and the connection.
    pub async fn vet(&self, raw: &str) -> Result<(Url, SocketAddr), OutboundDenied> {
        let url = Url::parse(raw).map_err(|_| OutboundDenied::Scheme("malformed"))?;
        check_scheme(url.scheme(), self.allow_http)?;
        let host = url.host_str().ok_or(OutboundDenied::NoAddress)?;
        let port = url
            .port_or_known_default()
            .ok_or(OutboundDenied::NoAddress)?;

        let addresses: Vec<IpAddr> = if let Ok(literal) = host.parse::<IpAddr>() {
            vec![literal]
        } else {
            let resolved = lookup_host((host, port))
                .await
                .map_err(|_| OutboundDenied::NoAddress)?;
            resolved.map(|socket| socket.ip()).collect()
        };

        let pinned = check_addresses(&addresses, self.policy)?;
        Ok((url, SocketAddr::new(pinned, port)))
    }

    /// Pins the request to the vetted address while keeping `Host` and SNI.
    /// The injected `ClientConfig` is what makes "never read the system trust
    /// store" true at runtime, not just in the dependency graph.
    ///
    /// The client is cached per host and reused only while it still points at
    /// the address just vetted, so pool reuse never outlives a DNS move.
    fn client_for(&self, url: &Url, pinned: SocketAddr) -> anyhow::Result<reqwest::Client> {
        let host = url.host_str().context("vetted URL lost its host")?;

        let mut clients = self
            .clients
            .lock()
            .map_err(|_| anyhow::anyhow!("outbound client cache is poisoned"))?;

        if let Some(client) = cached_client(&clients, host, pinned) {
            return Ok(client);
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            // 系统代理会让 DNS 钉住失效，必须显式关掉
            .no_proxy()
            // 缺 User-Agent 会被上游拒绝，如 GitHub API 回 403
            .user_agent(user_agent())
            .use_preconfigured_tls(self.config.as_ref().clone())
            .resolve(host, pinned)
            .build()
            .context("build pinned HTTP client")?;

        clients.insert(
            host.to_string(),
            PinnedClient {
                pinned,
                client: client.clone(),
            },
        );
        Ok(client)
    }

    pub async fn get_json<T: DeserializeOwned>(&self, url: &str) -> anyhow::Result<T> {
        let (url, pinned) = self
            .vet(url)
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        let client = self.client_for(&url, pinned)?;
        let response = ensure_success(
            client
                .get(url)
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await?,
        )?;
        self.read_json(response).await
    }

    /// GET with a bearer token, preserving the upstream status code so the
    /// caller can classify 401/403/404/429 instead of flattening them.
    ///
    /// Status mapping is deliberate: `401` and `403` are business outcomes
    /// (INV-GW-01/02), so they must survive as distinct errors.
    pub async fn get_with_bearer(
        &self,
        url: &str,
        token: &str,
        max_body: usize,
    ) -> anyhow::Result<RawResponse> {
        let (url, pinned) = self
            .vet(url)
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        let client = self.client_for(&url, pinned)?;
        let response = client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .bearer_auth(token)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Err(status_error(&response).into());
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        let limit = max_body.min(self.max_body);
        let body = read_limited(response, limit).await?;

        Ok(RawResponse { content_type, body })
    }

    /// POSTs a JSON body, optionally bearer-authenticated, preserving the
    /// upstream status code the way [`Self::get_with_bearer`] does.
    ///
    /// This is the data-plane POST counterpart: the body is built by the
    /// connector from its own template (ADR-0046), never from a request. The
    /// credential may travel in the body instead of the header, so `token` is an
    /// `Option` — passing `None` is how a resource says "credential is a field".
    pub async fn post_json_raw(
        &self,
        url: &str,
        token: Option<&str>,
        body: &serde_json::Value,
        max_body: usize,
    ) -> anyhow::Result<RawResponse> {
        let (url, pinned) = self
            .vet(url)
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        let client = self.client_for(&url, pinned)?;
        let mut request = client
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(body);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await?;

        let status = response.status();
        if !status.is_success() {
            return Err(status_error(&response).into());
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        let limit = max_body.min(self.max_body);
        let body = read_limited(response, limit).await?;

        Ok(RawResponse { content_type, body })
    }

    pub async fn post_form_json<T: DeserializeOwned>(
        &self,
        url: &str,
        form: &[(&str, &str)],
    ) -> anyhow::Result<T> {
        let (url, pinned) = self
            .vet(url)
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        let client = self.client_for(&url, pinned)?;
        let response = ensure_success(
            client
                .post(url)
                .header(reqwest::header::ACCEPT, "application/json")
                .form(form)
                .send()
                .await?,
        )?;
        self.read_json(response).await
    }

    /// POSTs a form whose values are built at runtime.
    ///
    /// Exists because a token request carries a client secret, and that secret is
    /// not a `&str` that outlives the call in a form a `&[(&str, &str)]` can
    /// borrow. Everything else — vetting, pinning, the size cap — is the same
    /// path as [`Self::post_form_json`].
    pub async fn post_form<T: DeserializeOwned>(
        &self,
        url: &str,
        form: &[(&str, String)],
    ) -> anyhow::Result<T> {
        let (url, pinned) = self
            .vet(url)
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        let client = self.client_for(&url, pinned)?;
        let pairs: Vec<(&str, &str)> = form
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect();
        let response = ensure_success(
            client
                .post(url)
                .header(reqwest::header::ACCEPT, "application/json")
                .form(&pairs)
                .send()
                .await?,
        )?;
        self.read_json(response).await
    }

    async fn read_json<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> anyhow::Result<T> {
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .map(|value| value.to_str().unwrap_or_default().to_string());
        let bytes = read_limited(response, self.max_body).await?;
        if let Some(value) = content_type
            && !is_json_media_type(&value)
        {
            return Err(anyhow::anyhow!(
                "upstream answered with content type {value:?}, expected JSON"
            ));
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// POSTs a form and returns the body as text.
    ///
    /// Some OAuth2 providers (GitHub unless asked otherwise, QQ always) answer
    /// the token endpoint with `application/x-www-form-urlencoded` or with a
    /// JSONP wrapper. Parsing them is the caller's job; what must not happen is
    /// sending `Accept: application/json` and then guessing at a body the server
    /// never agreed to produce.
    pub async fn post_form_text(
        &self,
        url: &str,
        form: &[(&str, &str)],
        accept: &str,
    ) -> anyhow::Result<String> {
        let (url, pinned) = self
            .vet(url)
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        let client = self.client_for(&url, pinned)?;
        let response = ensure_success(
            client
                .post(url)
                .header(reqwest::header::ACCEPT, accept)
                .form(form)
                .send()
                .await?,
        )?;
        self.read_text(response).await
    }

    /// 返回原始响应，状态码不判错
    pub async fn execute(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> anyhow::Result<http::Response<Vec<u8>>> {
        let raw = request.uri().to_string();
        let (url, pinned) = self
            .vet(&raw)
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        let client = self.client_for(&url, pinned)?;

        let mut builder = client.request(request.method().clone(), url);
        for (name, value) in request.headers() {
            builder = builder.header(name, value);
        }
        if !request.body().is_empty() {
            builder = builder.body(request.body().clone());
        }
        let response = builder.send().await?;

        let status = response.status();
        let headers = response.headers().clone();
        let body = read_limited(response, self.max_body).await?;

        let mut out = http::Response::builder().status(status);
        for (name, value) in headers.iter() {
            out = out.header(name, value);
        }
        out.body(body)
            .map_err(|error| anyhow::anyhow!("building outbound response: {error}"))
    }

    /// GETs `url` with an `Accept` header and returns the body as text.
    pub async fn get_text(&self, url: &str, accept: &str) -> anyhow::Result<String> {
        let (url, pinned) = self
            .vet(url)
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        let client = self.client_for(&url, pinned)?;
        let response = ensure_success(
            client
                .get(url)
                .header(reqwest::header::ACCEPT, accept)
                .send()
                .await?,
        )?;
        self.read_text(response).await
    }

    /// GETs `url` as JSON, authenticated with a bearer token.
    ///
    /// This is the plain userinfo read, not an upstream data-plane fetch: the
    /// caller wants a typed document, and a non-2xx is a protocol failure rather
    /// than a business outcome to classify.
    pub async fn get_json_with_bearer<T: DeserializeOwned>(
        &self,
        url: &str,
        token: &str,
    ) -> anyhow::Result<T> {
        let (url, pinned) = self
            .vet(url)
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        let client = self.client_for(&url, pinned)?;
        let response = ensure_success(
            client
                .get(url)
                .header(reqwest::header::ACCEPT, "application/json")
                .bearer_auth(token)
                .send()
                .await?,
        )?;
        self.read_json(response).await
    }

    async fn read_text(&self, response: reqwest::Response) -> anyhow::Result<String> {
        let bytes = read_limited(response, self.max_body).await?;
        String::from_utf8(bytes)
            .map_err(|error| anyhow::anyhow!("upstream response is not UTF-8: {error}"))
    }
}

/// Reads a body chunk by chunk, aborting as soon as it passes `limit`.
///
/// The guard's whole purpose is to bound what a hostile peer can make us hold.
/// Buffering first and checking the length afterwards defeats that: the peak
/// allocation is whatever the peer chose to send, not the limit. Every response
/// read therefore goes through here, and the check happens before the bytes are
/// kept rather than after they are all in memory.
/// 只认 JSON 媒体类型，缺头时放行
fn is_json_media_type(value: &str) -> bool {
    let essence = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    essence == "application/json" || essence.ends_with("+json")
}

async fn read_limited(mut response: reqwest::Response, limit: usize) -> anyhow::Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > limit {
            // Oversized responses are internal faults, never silent truncation.
            return Err(UpstreamTooLarge { limit }.into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Turns a non-success response into [`UpstreamStatus`], keeping the code.
///
/// `error_for_status` throws the status away: the resulting `reqwest::Error`
/// exposes a URL and a message, so a caller can only re-read the number out of
/// the text or give up and call everything "unavailable". An expired
/// authorization code answered with `400 invalid_grant` then reaches the user as
/// `503 idp_unavailable` — the client is told to retry a request that will never
/// succeed, because the fault was theirs.
fn ensure_success(response: reqwest::Response) -> anyhow::Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    Err(status_error(&response).into())
}

/// Turns a non-success response into the error every caller classifies on.
///
/// One constructor rather than one per call site: the fields have to stay in sync
/// across the paths that read a response, and a site that forgot `Retry-After`
/// would be a 429 that silently loses its hint.
fn status_error(response: &reqwest::Response) -> UpstreamStatus {
    UpstreamStatus {
        status: response.status().as_u16(),
        retry_after_secs: retry_after_secs(response),
    }
}

/// Reads `Retry-After` as a delay in seconds, capped.
///
/// A value that is not a bare number — including the HTTP-date form — is read as
/// "no hint" rather than guessed at, so a malformed header cannot become a delay
/// nobody asked for.
fn retry_after_secs(response: &reqwest::Response) -> Option<u64> {
    let raw = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?;
    let seconds = raw.trim().parse::<u64>().ok()?;
    Some(seconds.min(MAX_RETRY_AFTER_SECS))
}

/// Shared handle used by adapters that hold the guard behind a trait object.
pub type SharedGuard = Arc<GuardedClient>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_json_media_types_are_accepted() {
        assert!(is_json_media_type("application/json"));
        assert!(is_json_media_type("application/json; charset=utf-8"));
        assert!(is_json_media_type("Application/JSON"));
        assert!(is_json_media_type("application/jwk-set+json"));
        assert!(!is_json_media_type("text/html"));
        assert!(!is_json_media_type("application/x-www-form-urlencoded"));
        assert!(!is_json_media_type(""));
    }

    /// Serves a chunked body that never terminates, over plain TCP.
    ///
    /// The terminating zero-length chunk is never sent, and the socket is held
    /// open. A streaming reader hits the limit and returns; a reader that waits
    /// for the whole body waits forever. That is what separates the two, which a
    /// finite body cannot: both reject it, only the peak allocation differs.
    ///
    /// A plain thread rather than a runtime task: INV-SPAWN-01 allows exactly one
    /// spawn in the tree and it names the scheduler. Test-only exceptions would
    /// weaken a gate that exists precisely to have no exceptions.
    fn serve_endless() -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            let (socket, _) = listener.accept().expect("accept");
            // Read the request head first. Answering before the request is on the
            // wire makes hyper see a response it never asked for.
            let mut reader = BufReader::new(socket.try_clone().expect("clone"));
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).expect("read") == 0 || line == "\r\n" {
                    break;
                }
            }
            let mut socket = socket;
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n",
                )
                .expect("head");
            // 1 KiB chunks, forever. The client is expected to stop us.
            for _ in 0..64 {
                if socket.write_all(b"400\r\n").is_err() || socket.write_all(&[b'x'; 1024]).is_err()
                {
                    return;
                }
                if socket.write_all(b"\r\n").is_err() {
                    return;
                }
            }
            // Hold the connection open instead of sending the last chunk.
            std::thread::sleep(std::time::Duration::from_secs(30));
        });
        format!("http://{addr}/")
    }

    fn serve_once(body: Vec<u8>) -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            let (socket, _) = listener.accept().expect("accept");
            // Read the request head first. Answering before the request is on the
            // wire makes hyper see a response it never asked for.
            let mut reader = BufReader::new(socket.try_clone().expect("clone"));
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).expect("read") == 0 || line == "\r\n" {
                    break;
                }
            }
            let mut socket = socket;
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                body.len()
            );
            socket.write_all(head.as_bytes()).expect("head");
            socket.write_all(&body).expect("body");
            socket.flush().expect("flush");
        });
        format!("http://{addr}/")
    }

    /// The peer sends forever; the reader must not wait for the end of the body.
    #[tokio::test]
    async fn an_endless_body_is_refused_before_it_is_read_to_the_end() {
        let url = serve_endless();
        let response = plain_get(&url).await;
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_limited(response, 1024),
        )
        .await
        .expect("the reader waited for a body that never ends; it is buffering, not streaming");

        let error = outcome.expect_err("oversized");
        let oversized = error
            .downcast_ref::<UpstreamTooLarge>()
            .expect("typed as UpstreamTooLarge, not a generic transport error");
        assert_eq!(oversized.limit, 1024);
    }

    #[tokio::test]
    async fn a_body_exactly_at_the_limit_is_accepted() {
        let url = serve_once(vec![b'x'; 1024]);
        let response = plain_get(&url).await;
        let body = read_limited(response, 1024).await.expect("at the limit");
        assert_eq!(body.len(), 1024, "a body exactly at the cap is not over it");
    }

    /// Serves one empty response with the given status line and extra headers.
    fn serve_status(status: &str, headers: &str) -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (status, headers) = (status.to_string(), headers.to_string());
        std::thread::spawn(move || {
            let (socket, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(socket.try_clone().expect("clone"));
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).expect("read") == 0 || line == "\r\n" {
                    break;
                }
            }
            let mut socket = socket;
            socket
                .write_all(
                    format!("HTTP/1.1 {status}\r\n{headers}content-length: 0\r\n\r\n").as_bytes(),
                )
                .expect("head");
            socket.flush().expect("flush");
        });
        format!("http://{addr}/")
    }

    /// The upstream's own hint has to reach the classifier, or the caller retries
    /// blind against a source that just asked for room.
    #[tokio::test]
    async fn an_upstream_retry_after_is_read_as_seconds() {
        let url = serve_status("429 Too Many Requests", "retry-after: 42\r\n");
        let error = status_error(&plain_get(&url).await);
        assert_eq!(error.status, 429);
        assert_eq!(error.retry_after_secs, Some(42));
    }

    /// The header is untrusted input that we mirror to our own callers, so it
    /// cannot be allowed to hold anyone for a day.
    #[tokio::test]
    async fn an_upstream_retry_after_is_capped() {
        let url = serve_status("429 Too Many Requests", "retry-after: 999999\r\n");
        assert_eq!(
            status_error(&plain_get(&url).await).retry_after_secs,
            Some(MAX_RETRY_AFTER_SECS)
        );
    }

    /// The HTTP-date form is read as no hint rather than guessed at, so a header
    /// we cannot read becomes the old behaviour instead of a wrong delay.
    #[tokio::test]
    async fn an_unreadable_retry_after_is_no_hint() {
        let url = serve_status(
            "429 Too Many Requests",
            "retry-after: Wed, 21 Oct 2026 07:28:00 GMT\r\n",
        );
        assert_eq!(status_error(&plain_get(&url).await).retry_after_secs, None);
    }

    /// Serves one request, capturing its body and answering a small JSON object.
    /// Returns the URL and a slot holding the received body.
    fn serve_capture() -> (String, Arc<Mutex<Option<String>>>) {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let captured = Arc::new(Mutex::new(None));
        let sink = captured.clone();
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(socket.try_clone().expect("clone"));
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).expect("read") == 0 || line == "\r\n" {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(rest) = lower.strip_prefix("content-length:") {
                    content_length = rest.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).expect("body");
            *sink.lock().expect("lock") = Some(String::from_utf8_lossy(&body).to_string());
            let response = b"{\"ok\":true}";
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                response.len()
            );
            socket.write_all(head.as_bytes()).expect("head");
            socket.write_all(response).expect("body");
            socket.flush().expect("flush");
        });
        (format!("http://{addr}/read"), captured)
    }

    /// A server-generated POST body must reach the upstream through the same
    /// guard a GET uses — the data-plane counterpart ADR-0046 adds.
    #[tokio::test]
    async fn a_post_body_reaches_the_upstream_through_the_guard() {
        let (url, captured) = serve_capture();
        let client =
            GuardedClient::with_policy(OutboundPolicy::AllowLoopback, true).expect("client");
        let body = serde_json::json!({ "api_user_id": "player-1", "token": "secret" });
        let response = client
            .post_json_raw(&url, None, &body, 1024)
            .await
            .expect("post");
        assert_eq!(response.body, b"{\"ok\":true}");

        let sent = captured
            .lock()
            .expect("lock")
            .clone()
            .expect("body captured");
        assert!(
            sent.contains("\"api_user_id\":\"player-1\""),
            "got {sent:?}"
        );
        assert!(sent.contains("\"token\":\"secret\""), "got {sent:?}");
    }

    /// Plain client for the loopback test server.
    ///
    /// Built with an explicit provider, like `TlsConfig::build` does. `reqwest::get`
    /// would install nothing and panic; installing a process-wide default would
    /// quietly become a production dependency on global mutable state.
    async fn plain_get(url: &str) -> reqwest::Response {
        let (config, _) = TlsConfig::mozilla_only().build().expect("tls");
        reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .build()
            .expect("client")
            .get(url)
            .send()
            .await
            .expect("response")
    }

    #[tokio::test]
    async fn rejects_plain_http_by_default() {
        let client = GuardedClient::new().expect("client");
        let error = client.vet("http://example.com/x").await.expect_err("http");
        assert_eq!(error, OutboundDenied::Scheme("http"));
    }

    #[tokio::test]
    async fn rejects_non_http_schemes() {
        let client = GuardedClient::new().expect("client");
        for raw in [
            "file:///etc/passwd",
            "ftp://example.com/x",
            "data:text/plain,x",
        ] {
            assert!(client.vet(raw).await.is_err(), "{raw} must be rejected");
        }
    }

    #[tokio::test]
    async fn rejects_literal_private_and_loopback_targets() {
        let client = GuardedClient::new().expect("client");
        for raw in [
            "https://127.0.0.1/x",
            "https://10.0.0.1/x",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/x",
            "https://[::ffff:169.254.169.254]/x",
        ] {
            assert!(client.vet(raw).await.is_err(), "{raw} must be rejected");
        }
    }

    #[tokio::test]
    async fn accepts_a_public_literal_without_dns() {
        let client = GuardedClient::new().expect("client");
        let (url, pinned) = client.vet("https://203.0.113.10/x").await.expect("public");
        assert_eq!(url.host_str(), Some("203.0.113.10"));
        assert_eq!(pinned.ip(), "203.0.113.10".parse::<IpAddr>().expect("ip"));
        assert_eq!(pinned.port(), 443);
    }

    #[tokio::test]
    async fn private_net_switch_still_blocks_metadata() {
        let client =
            GuardedClient::with_policy(OutboundPolicy::AllowPrivateNet, true).expect("client");
        assert!(client.vet("http://10.0.0.1/x").await.is_ok());
        assert!(client.vet("https://169.254.169.254/x").await.is_err());
        assert!(client.vet("https://127.0.0.1/x").await.is_err());
    }

    fn cached_hosts(client: &GuardedClient) -> usize {
        client.clients.lock().expect("cache lock").len()
    }

    fn cached_pin(client: &GuardedClient, host: &str) -> Option<SocketAddr> {
        client
            .clients
            .lock()
            .expect("cache lock")
            .get(host)
            .map(|entry| entry.pinned)
    }

    fn cache_with(host: &str, pinned: SocketAddr) -> HashMap<String, PinnedClient> {
        let (config, _) = TlsConfig::mozilla_only().build().expect("tls");
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .build()
            .expect("client");
        let mut clients = HashMap::new();
        clients.insert(host.to_string(), PinnedClient { pinned, client });
        clients
    }

    #[test]
    fn a_host_pinned_to_the_same_address_returns_the_cached_client() {
        let pinned: SocketAddr = "203.0.113.9:443".parse().expect("addr");
        let clients = cache_with("upstream.example", pinned);

        assert!(
            cached_client(&clients, "upstream.example", pinned).is_some(),
            "the cached client must be returned, otherwise every request pays \
             a new TCP and TLS handshake"
        );
    }

    #[test]
    fn a_host_that_moved_is_not_served_from_stale_cache() {
        let old: SocketAddr = "203.0.113.9:443".parse().expect("addr");
        let moved: SocketAddr = "203.0.113.77:443".parse().expect("addr");
        let clients = cache_with("upstream.example", old);

        assert!(
            cached_client(&clients, "upstream.example", moved).is_none(),
            "a client pinned to the old address must not be reused after the \
             guard vetted a different one"
        );
    }

    #[test]
    fn an_unknown_host_has_no_cached_client() {
        let pinned: SocketAddr = "203.0.113.9:443".parse().expect("addr");
        let clients = cache_with("upstream.example", pinned);

        assert!(
            cached_client(&clients, "other.example", pinned).is_none(),
            "entries are per host; one host must not serve another"
        );
    }

    #[test]
    fn a_host_that_moves_is_followed_instead_of_reusing_the_old_pin() {
        let client = GuardedClient::new().expect("client");
        let url = Url::parse("https://upstream.example/v1/x").expect("url");
        let first: SocketAddr = "203.0.113.9:443".parse().expect("addr");
        let moved: SocketAddr = "203.0.113.77:443".parse().expect("addr");

        client.client_for(&url, first).expect("first");
        client.client_for(&url, moved).expect("moved");

        assert_eq!(
            cached_pin(&client, "upstream.example"),
            Some(moved),
            "the cache must rebuild when the vetted address changes, or the \
             guard would keep talking to an address it no longer vouches for"
        );
    }

    #[test]
    fn the_client_cache_is_bounded_by_the_number_of_hosts() {
        let client = GuardedClient::new().expect("client");
        for host in ["a.example", "b.example"] {
            let url = Url::parse(&format!("https://{host}/v1/x")).expect("url");
            let pinned: SocketAddr = "203.0.113.9:443".parse().expect("addr");
            client.client_for(&url, pinned).expect("client");
        }
        assert_eq!(
            cached_hosts(&client),
            2,
            "entries are per host, so the cache cannot grow with request count"
        );
    }

    /// Serves one response and reports the request headers it received.
    fn serve_capture_headers() -> (String, Arc<Mutex<Option<String>>>) {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let captured = Arc::new(Mutex::new(None));
        let sink = captured.clone();
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(socket.try_clone().expect("clone"));
            let mut head = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).expect("read") == 0 || line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            *sink.lock().expect("lock") = Some(head);
            let response = b"{}";
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                        response.len()
                    )
                    .as_bytes(),
                )
                .expect("head");
            socket.write_all(response).expect("body");
            socket.flush().expect("flush");
        });
        (format!("http://{addr}/user"), captured)
    }

    /// GitHub's API answers 403 to a request without a User-Agent, and `reqwest`
    /// sends none by default. The header is set once on the client, so this test
    /// is what keeps a new request method from silently dropping it.
    #[tokio::test]
    async fn every_outbound_request_carries_a_user_agent() {
        let (url, captured) = serve_capture_headers();
        let client =
            GuardedClient::with_policy(OutboundPolicy::AllowLoopback, true).expect("client");
        client
            .get_json_with_bearer::<serde_json::Value>(&url, "token")
            .await
            .expect("get");

        let head = captured.lock().expect("lock").clone().expect("head");
        let lower = head.to_ascii_lowercase();
        let line = lower
            .lines()
            .find(|line| line.starts_with("user-agent:"))
            .unwrap_or_else(|| panic!("no user-agent in {head:?}"));
        assert!(
            line.trim() != "user-agent:",
            "user-agent must be non-empty, got {line:?}"
        );
        assert!(
            line.contains("re0auth/"),
            "user-agent must name this client, got {line:?}"
        );
    }
}
