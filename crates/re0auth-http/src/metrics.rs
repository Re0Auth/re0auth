//! Minimal Prometheus registry and exposition.
//!
//! No external recorder: the registry is bounded by the routes and label
//! values the server itself defines, and the text format is small enough that
//! a dependency would only add a second lifecycle to test.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::time::Instant;

use axum::extract::{ConnectInfo, MatchedPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::AppState;

const BUCKETS: [f64; 6] = [0.005, 0.025, 0.1, 0.5, 1.0, 5.0];

#[derive(Default)]
struct Histogram {
    buckets: [u64; BUCKETS.len()],
    count: u64,
    sum: f64,
}

#[derive(Default)]
pub struct Metrics {
    counters: Mutex<BTreeMap<String, u64>>,
    histograms: Mutex<BTreeMap<String, Histogram>>,
    gauges: Mutex<BTreeMap<String, f64>>,
}

impl Metrics {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn inc(&self, name: &str, labels: &[(&str, &str)]) {
        let key = sample_key(name, labels);
        *self
            .counters
            .lock()
            .expect("metrics counters")
            .entry(key)
            .or_default() += 1;
    }

    pub(crate) fn observe(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        let key = sample_key(name, labels);
        let mut histograms = self.histograms.lock().expect("metrics histograms");
        let histogram = histograms.entry(key).or_default();
        histogram.count += 1;
        histogram.sum += value;
        for (index, bucket) in BUCKETS.iter().enumerate() {
            if value <= *bucket {
                histogram.buckets[index] += 1;
            }
        }
    }

    pub(crate) fn gauge(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        let key = sample_key(name, labels);
        self.gauges
            .lock()
            .expect("metrics gauges")
            .insert(key, value);
    }

    #[must_use]
    pub fn render(&self) -> String {
        let mut output = String::new();
        let counters = self.counters.lock().expect("metrics counters");
        let mut counter_groups: BTreeMap<String, Vec<(String, u64)>> = BTreeMap::new();
        for (key, value) in counters.iter() {
            let name = key.split('{').next().unwrap_or(key).to_string();
            let labels = key.strip_prefix(&name).unwrap_or("").to_string();
            counter_groups
                .entry(name)
                .or_default()
                .push((labels, *value));
        }
        for (name, samples) in counter_groups {
            let _ = writeln!(output, "# TYPE {name} counter");
            for (labels, value) in samples {
                let _ = writeln!(output, "{name}{labels} {value}");
            }
        }
        drop(counters);

        let histograms = self.histograms.lock().expect("metrics histograms");
        let mut histogram_groups: BTreeMap<String, Vec<(String, HistogramValue)>> = BTreeMap::new();
        for (key, value) in histograms.iter() {
            let name = key.split('{').next().unwrap_or(key).to_string();
            let labels = key.strip_prefix(&name).unwrap_or("").to_string();
            histogram_groups
                .entry(name)
                .or_default()
                .push((labels, HistogramValue::from(value)));
        }
        for (name, samples) in histogram_groups {
            let _ = writeln!(output, "# TYPE {name} histogram");
            for (labels, value) in samples {
                for (index, bucket) in BUCKETS.iter().enumerate() {
                    let bucket_labels = insert_label(&labels, "le", &bucket.to_string());
                    let _ = writeln!(
                        output,
                        "{}_bucket{bucket_labels} {}",
                        name, value.buckets[index]
                    );
                }
                let inf = insert_label(&labels, "le", "+Inf");
                let _ = writeln!(output, "{}_bucket{inf} {}", name, value.count);
                let _ = writeln!(output, "{}_sum{labels} {}", name, value.sum);
                let _ = writeln!(output, "{}_count{labels} {}", name, value.count);
            }
        }
        drop(histograms);

        let gauges = self.gauges.lock().expect("metrics gauges");
        let mut gauge_groups: BTreeMap<String, Vec<(String, f64)>> = BTreeMap::new();
        for (key, value) in gauges.iter() {
            let name = key.split('{').next().unwrap_or(key).to_string();
            let labels = key.strip_prefix(&name).unwrap_or("").to_string();
            gauge_groups.entry(name).or_default().push((labels, *value));
        }
        for (name, samples) in gauge_groups {
            let _ = writeln!(output, "# TYPE {name} gauge");
            for (labels, value) in samples {
                let _ = writeln!(output, "{name}{labels} {value}");
            }
        }
        output
    }
}

struct HistogramValue {
    buckets: [u64; BUCKETS.len()],
    count: u64,
    sum: f64,
}

impl From<&Histogram> for HistogramValue {
    fn from(value: &Histogram) -> Self {
        Self {
            buckets: value.buckets,
            count: value.count,
            sum: value.sum,
        }
    }
}

fn sample_key(name: &str, labels: &[(&str, &str)]) -> String {
    let mut labels = labels.to_vec();
    labels.sort_by_key(|(key, _)| *key);
    let rendered = labels
        .iter()
        .map(|(key, value)| format!("{key}=\"{}\"", escape(value)))
        .collect::<Vec<_>>()
        .join(",");
    if rendered.is_empty() {
        name.to_string()
    } else {
        format!("{name}{{{rendered}}}")
    }
}

fn insert_label(labels: &str, key: &str, value: &str) -> String {
    if labels.is_empty() {
        format!("{{{key}=\"{}\"}}", escape(value))
    } else {
        format!(
            "{},{key}=\"{}\"",
            labels.trim_end_matches('}'),
            escape(value)
        )
        .replace("}}", "}")
    }
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
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
    let started = Instant::now();
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
    if let Some((connector, resource)) = gateway_labels(&path) {
        state.metrics.inc(
            "gateway_requests_total",
            &[
                ("connector", connector),
                ("resource", resource),
                ("status", &status),
            ],
        );
        if response.status() == StatusCode::SERVICE_UNAVAILABLE {
            state
                .metrics
                .gauge("circuit_breaker_open", 1.0, &[("connector", connector)]);
        }
    }
    response
}

fn gateway_labels(path: &str) -> Option<(&str, &str)> {
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
    if !addr.ip().is_loopback() && crate::admin::admin_session(&state, &headers).await.is_err() {
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
