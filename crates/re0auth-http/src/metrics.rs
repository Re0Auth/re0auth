//! Prometheus metrics and exposition.

use std::collections::HashSet;
use std::sync::Mutex;

use axum::extract::{ConnectInfo, MatchedPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use prometheus::{
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts, Registry,
    TextEncoder,
};

use crate::AppState;

const BUCKETS: [f64; 6] = [0.005, 0.025, 0.1, 0.5, 1.0, 5.0];
const MAX_GATEWAY_SERIES: usize = 1024;

pub struct Metrics {
    registry: Registry,
    http_requests: IntCounterVec,
    http_duration: HistogramVec,
    gateway_requests: IntCounterVec,
    circuit_open: GaugeVec,
    rate_limit_denied: IntCounterVec,
    oauth_token_issued: IntCounterVec,
    refresh_rotations: IntCounter,
    gateway_series: Mutex<HashSet<(String, String)>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    #[must_use]
    pub fn new() -> Self {
        let registry = Registry::new();
        let http_requests = IntCounterVec::new(
            Opts::new(
                "http_requests_total",
                "HTTP requests by route, method, and status.",
            ),
            &["route", "method", "status"],
        )
        .expect("valid http counter");
        let http_duration = HistogramVec::new(
            HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration in seconds.",
            )
            .buckets(BUCKETS.to_vec()),
            &["route", "method"],
        )
        .expect("valid http histogram");
        let gateway_requests = IntCounterVec::new(
            Opts::new(
                "gateway_requests_total",
                "Gateway requests by connector, resource, and status.",
            ),
            &["connector", "resource", "status"],
        )
        .expect("valid gateway counter");
        let circuit_open = GaugeVec::new(
            Opts::new(
                "circuit_breaker_open",
                "Whether a connector circuit is open.",
            ),
            &["connector"],
        )
        .expect("valid circuit gauge");
        let rate_limit_denied = IntCounterVec::new(
            Opts::new("rate_limit_denied_total", "Rate-limit denials by lane."),
            &["lane"],
        )
        .expect("valid rate-limit counter");
        let oauth_token_issued = IntCounterVec::new(
            Opts::new("oauth_token_issued_total", "Tokens issued by grant type."),
            &["grant_type"],
        )
        .expect("valid token counter");
        let refresh_rotations = IntCounter::new(
            "refresh_rotations_total",
            "Refresh-token rotations performed.",
        )
        .expect("valid refresh counter");

        for metric in [
            Box::new(http_requests.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(http_duration.clone()),
            Box::new(gateway_requests.clone()),
            Box::new(circuit_open.clone()),
            Box::new(rate_limit_denied.clone()),
            Box::new(oauth_token_issued.clone()),
            Box::new(refresh_rotations.clone()),
        ] {
            registry.register(metric).expect("unique metric");
        }

        Self {
            registry,
            http_requests,
            http_duration,
            gateway_requests,
            circuit_open,
            rate_limit_denied,
            oauth_token_issued,
            refresh_rotations,
            gateway_series: Mutex::new(HashSet::new()),
        }
    }

    pub(crate) fn inc(&self, name: &str, labels: &[(&str, &str)]) {
        match name {
            "http_requests_total" => self
                .http_requests
                .with_label_values(&[
                    label(labels, "route"),
                    label(labels, "method"),
                    label(labels, "status"),
                ])
                .inc(),
            "gateway_requests_total" => self
                .gateway_requests
                .with_label_values(&[
                    label(labels, "connector"),
                    label(labels, "resource"),
                    label(labels, "status"),
                ])
                .inc(),
            "rate_limit_denied_total" => self
                .rate_limit_denied
                .with_label_values(&[label(labels, "lane")])
                .inc(),
            "oauth_token_issued_total" => self
                .oauth_token_issued
                .with_label_values(&[label(labels, "grant_type")])
                .inc(),
            "refresh_rotations_total" => self.refresh_rotations.inc(),
            _ => {}
        }
    }

    pub(crate) fn observe(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        if name == "http_request_duration_seconds" {
            self.http_duration
                .with_label_values(&[label(labels, "route"), label(labels, "method")])
                .observe(value);
        }
    }

    pub(crate) fn gauge(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        if name == "circuit_breaker_open" {
            self.circuit_open
                .with_label_values(&[label(labels, "connector")])
                .set(value);
        }
    }

    /// Keeps the gateway labels bounded even when the path is caller-controlled.
    pub(crate) fn gateway_pair(&self, connector: &str, resource: &str) -> (String, String) {
        let mut seen = self
            .gateway_series
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let pair = (connector.to_string(), resource.to_string());
        if seen.len() >= MAX_GATEWAY_SERIES && !seen.contains(&pair) {
            return ("other".to_string(), "other".to_string());
        }
        seen.insert(pair.clone());
        pair
    }

    #[must_use]
    pub fn render(&self) -> String {
        let mut output = Vec::new();
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut output)
            .expect("encode metrics");
        String::from_utf8(output).expect("metrics are UTF-8")
    }
}

fn label<'a>(labels: &'a [(&str, &str)], key: &str) -> &'a str {
    labels
        .iter()
        .find_map(|(name, value)| (*name == key).then_some(*value))
        .unwrap_or("")
}

pub(crate) async fn layer(
    State(state): State<AppState>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_string();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let started = std::time::Instant::now();
    let response = next.run(request).await;
    let status = response.status().as_u16().to_string();
    if route != "/metrics" {
        state.metrics.inc(
            "http_requests_total",
            &[("route", &route), ("method", &method), ("status", &status)],
        );
        state.metrics.observe(
            "http_request_duration_seconds",
            started.elapsed().as_secs_f64(),
            &[("route", &route), ("method", &method)],
        );
    }
    if route != "unknown"
        && let Some((connector, resource)) = gateway_path_labels(&path)
    {
        let (connector, resource) = state.metrics.gateway_pair(connector, resource);
        state.metrics.inc(
            "gateway_requests_total",
            &[
                ("connector", &connector),
                ("resource", &resource),
                ("status", &status),
            ],
        );
        if response.status() == StatusCode::SERVICE_UNAVAILABLE {
            state
                .metrics
                .gauge("circuit_breaker_open", 1.0, &[("connector", &connector)]);
        }
    }
    response
}

fn gateway_path_labels(path: &str) -> Option<(&str, &str)> {
    let mut parts = path.trim_start_matches('/').split('/');
    if parts.next()? != "api" || parts.next()? != "v1" {
        return None;
    }
    let kind = parts.next()?;
    if kind != "upstreams" && kind != "raw" {
        return None;
    }
    Some((parts.next()?, parts.next()?))
}

#[utoipa::path(
    get,
    path = "/metrics",
    tag = "ops",
    responses(
        (status = 200, description = "Prometheus text exposition.", body = String, content_type = "text/plain; version=0.0.4"),
        (status = 403, description = "Metrics are enabled but the caller is neither loopback nor an admin."),
        (status = 404, description = "Metrics are disabled.")
    )
)]
pub(crate) async fn endpoint(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !state.metrics_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    // A same-host reverse proxy makes every request arrive from loopback, so
    // the peer address alone cannot separate "direct local scrape" from "public
    // request through the proxy". Forwarding headers are the discriminator: a
    // proxied call always needs an admin session.
    let proxied = headers.contains_key("x-forwarded-for") || headers.contains_key("forwarded");
    if (!addr.ip().is_loopback() || proxied)
        && crate::admin::admin_session(&state, &headers).await.is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    (
        [
            (
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        state.metrics.render(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_text_format(text: &str) {
        for line in text
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let (sample, value) = line.rsplit_once(' ').expect("sample and value");
            assert!(value.parse::<f64>().is_ok(), "bad value in {line:?}");
            let mut depth = 0_i32;
            let mut quoted = false;
            for character in sample.chars() {
                match character {
                    '"' => quoted = !quoted,
                    '{' if !quoted => depth += 1,
                    '}' if !quoted => depth -= 1,
                    _ => {}
                }
                assert!(depth >= 0, "unbalanced braces in {line:?}");
            }
            assert_eq!(depth, 0, "unbalanced braces in {line:?}");
        }
    }

    #[test]
    fn histogram_bucket_lines_close_their_labels() {
        let metrics = Metrics::new();
        metrics.observe(
            "http_request_duration_seconds",
            0.01,
            &[("route", "/oauth/token"), ("method", "POST")],
        );
        let rendered = metrics.render();
        assert_text_format(&rendered);
        let buckets = rendered
            .lines()
            .filter(|line| line.starts_with("http_request_duration_seconds_bucket"))
            .collect::<Vec<_>>();
        assert!(!buckets.is_empty());
        for line in buckets {
            assert!(line.contains('}'), "{line}");
        }
    }

    #[test]
    fn gateway_series_are_bounded() {
        let metrics = Metrics::new();
        for index in 0..=MAX_GATEWAY_SERIES {
            let _ = metrics.gateway_pair(&format!("connector-{index}"), "resource");
        }
        assert_eq!(
            metrics.gateway_pair("overflow", "resource"),
            ("other".to_string(), "other".to_string())
        );
    }
}
