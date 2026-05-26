// SPDX-License-Identifier: Apache-2.0
//! IICP provider node — registration, heartbeats, and task serving.
//!
//! Implements:
//! - `GET  /iicp/health`   — liveness / capacity (always 200)
//! - `GET  /metrics`       — Prometheus text (503 if `metrics` feature absent)
//! - `POST /v1/task`       — task handler with concurrency gate (IICP-E021),
//!   nonce replay protection (IICP-E011), and W3C traceparent propagation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::errors::{IicpError, Result};

const DEFAULT_DIRECTORY: &str = "https://iicp.network/api";
const HEARTBEAT_INTERVAL_SECS: u64 = 30;
const NONCE_TTL_SECS: u64 = 300;

/// Configuration for an IICP provider node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub node_id: String,
    pub endpoint: String,
    pub intent: String,
    pub model: Option<String>,
    pub region: Option<String>,
    pub capabilities: Vec<String>,
    pub directory_url: String,
    pub timeout_ms: u64,
    /// Maximum concurrent tasks; excess requests receive 429 IICP-E021.
    pub max_concurrent: usize,
    /// Tokens-per-minute capacity declared to directory (`limits.tokens_per_min`).
    pub tokens_per_min: u32,
    /// Per-request token cap declared on the capability object (`capabilities[].max_tokens`).
    pub max_tokens: u32,
    /// Optional native IICP binary endpoint (spec/iicp-dir.md v0.7.0).
    /// Scheme MUST be `iicp://` (plaintext) or `iicpsec://` (TLS).
    /// Default IICP port is 9484 (ADR-040). When set, the directory persists it
    /// and clients SHOULD prefer it over `endpoint` for task CALLs.
    pub transport_endpoint: Option<String>,
}

impl NodeConfig {
    pub fn new(
        node_id: impl Into<String>,
        endpoint: impl Into<String>,
        intent: impl Into<String>,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            endpoint: endpoint.into(),
            intent: intent.into(),
            model: None,
            region: None,
            capabilities: vec![],
            directory_url: DEFAULT_DIRECTORY.into(),
            timeout_ms: 5_000,
            max_concurrent: 4,
            tokens_per_min: 10_000,
            max_tokens: 8_192,
            transport_endpoint: None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TaskRequest {
    pub task_id: String,
    pub intent: String,
    pub payload: Value,
    pub constraints: Option<Value>,
    pub auth: Option<Value>,
    pub nonce: Option<String>,
    /// Injected server-side from the W3C `traceparent` header — not from the JSON body.
    #[serde(skip_deserializing)]
    pub _trace: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct TaskResponse {
    pub task_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

pub type TaskHandlerFn = Arc<
    dyn Fn(
            TaskRequest,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value>> + Send>>
        + Send
        + Sync,
>;

struct AppState {
    handler: TaskHandlerFn,
    node_id: String,
    region: String,
    intent: String,
    model: String,
    active_jobs: Arc<AtomicUsize>,
    max_concurrent: usize,
    nonce_cache: Arc<Mutex<HashMap<String, Instant>>>,
}

// ── GET /iicp/health ─────────────────────────────────────────────────────────

async fn health_endpoint(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let active = state.active_jobs.load(Ordering::Relaxed);
    Json(json!({
        "status": "ok",
        "node_id": state.node_id,
        "region": state.region,
        "load": (active as f64 / state.max_concurrent.max(1) as f64),
        "active_jobs": active,
        "max_concurrent": state.max_concurrent,
        "available": active < state.max_concurrent,
        "model": state.model,
        "intent": state.intent,
    }))
}

// ── GET /metrics ─────────────────────────────────────────────────────────────

async fn metrics_endpoint() -> Response {
    #[cfg(feature = "metrics")]
    {
        use prometheus::{Encoder, TextEncoder};
        let encoder = TextEncoder::new();
        let mf = prometheus::gather();
        let mut buf = Vec::new();
        if encoder.encode(&mf, &mut buf).is_ok() {
            return (
                StatusCode::OK,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; version=0.0.4",
                )],
                buf,
            )
                .into_response();
        }
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "metrics feature not enabled",
    )
        .into_response()
}

// ── POST /v1/task ─────────────────────────────────────────────────────────────

async fn task_endpoint(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut req): Json<TaskRequest>,
) -> Response {
    // Concurrency gate — IICP-E021
    let prev = state.active_jobs.fetch_add(1, Ordering::Relaxed);
    if prev >= state.max_concurrent {
        state.active_jobs.fetch_sub(1, Ordering::Relaxed);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", "2"), ("Content-Type", "application/json")],
            Json(json!({
                "error": {
                    "code": "IICP-E021",
                    "message": "capacity_exceeded",
                    "retry_after_ms": 2000,
                }
            })),
        )
            .into_response();
    }

    // Nonce replay protection — IICP-E011
    if let Some(ref nonce) = req.nonce {
        let mut cache = state.nonce_cache.lock().await;
        cache.retain(|_, inserted_at| inserted_at.elapsed().as_secs() < NONCE_TTL_SECS);
        if cache.contains_key(nonce) {
            state.active_jobs.fetch_sub(1, Ordering::Relaxed);
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": { "code": "IICP-E011", "message": "replay_detected" }
                })),
            )
                .into_response();
        }
        cache.insert(nonce.clone(), Instant::now());
    }

    // W3C traceparent propagation
    if let Some(tp) = headers.get("traceparent").and_then(|v| v.to_str().ok()) {
        req._trace = Some(json!({ "traceparent": tp }));
    }

    let task_id = req.task_id.clone();
    let result = (state.handler)(req).await;
    state.active_jobs.fetch_sub(1, Ordering::Relaxed);

    match result {
        Ok(value) => Json(TaskResponse {
            task_id,
            status: "completed".into(),
            result: Some(value),
            error: None,
        })
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(TaskResponse {
                task_id,
                status: "error".into(),
                result: None,
                error: Some(json!({ "message": e.to_string() })),
            }),
        )
            .into_response(),
    }
}

// ── IicpNode ──────────────────────────────────────────────────────────────────

/// IICP provider node — handles registration, heartbeats, and task serving.
pub struct IicpNode {
    cfg: NodeConfig,
    http: Client,
}

impl IicpNode {
    pub fn new(cfg: NodeConfig) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms + 2_000))
            .use_rustls_tls()
            .build()
            .expect("failed to build HTTP client");
        Self { cfg, http }
    }

    /// Register with the directory and return the assigned `node_token`.
    ///
    /// Payload conforms to spec/iicp-dir.md §3.1 REGISTER plus the v0.7.0
    /// dual-endpoint extension (`transport_endpoint`). Pre-iter-1413
    /// builds sent a non-spec flat-`intent` shape that the production
    /// directory rejects with 422; fixed here.
    pub async fn register(&self) -> Result<String> {
        // Build the spec-compliant capability object. Legacy
        // `capabilities: Vec<String>` is folded into the models array.
        let mut models: Vec<String> = match &self.cfg.model {
            Some(m) => vec![m.clone()],
            None => Vec::new(),
        };
        for cap in &self.cfg.capabilities {
            if !models.contains(cap) {
                models.push(cap.clone());
            }
        }
        let region = self
            .cfg
            .region
            .clone()
            .unwrap_or_else(|| "eu-central".to_string());

        let mut payload = json!({
            "endpoint": self.cfg.endpoint,
            "region": region,
            "capabilities": [{
                "intent": self.cfg.intent,
                "models": models,
                "max_tokens": self.cfg.max_tokens,
            }],
            "limits": {
                "max_concurrent": self.cfg.max_concurrent,
                "tokens_per_min": self.cfg.tokens_per_min,
            },
        });
        if !self.cfg.node_id.is_empty() {
            payload["node_id"] = json!(self.cfg.node_id);
        }
        // spec v0.7.0 — native IICP binary endpoint
        if let Some(t) = &self.cfg.transport_endpoint {
            payload["transport_endpoint"] = json!(t);
        }

        let resp = self
            .http
            .post(format!(
                "{}/v1/register",
                self.cfg.directory_url.trim_end_matches('/')
            ))
            .json(&payload)
            .send()
            .await
            .map_err(|e| IicpError::Node(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(IicpError::Node(format!(
                "register failed: {}",
                resp.status()
            )));
        }
        let data: Value = resp
            .json()
            .await
            .map_err(|e| IicpError::Node(e.to_string()))?;
        let token = data["node_token"]
            .as_str()
            .or_else(|| data["token"].as_str())
            .ok_or_else(|| IicpError::Node(format!("no node_token in response: {data}")))?;
        Ok(token.to_string())
    }

    /// Send a single heartbeat to the directory.
    pub async fn heartbeat(&self, node_token: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!(
                "{}/api/v1/heartbeat",
                self.cfg.directory_url.trim_end_matches('/')
            ))
            .json(&json!({
                "node_id": self.cfg.node_id,
                "node_token": node_token,
                "status": "available",
            }))
            .send()
            .await
            .map_err(|e| IicpError::Node(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(IicpError::Node(format!(
                "heartbeat failed: {}",
                resp.status()
            )));
        }
        Ok(())
    }

    /// Start the task server (blocks until cancelled).
    ///
    /// Serves `POST /v1/task`, `GET /iicp/health`, `GET /metrics`.
    /// Starts a background heartbeat loop when `node_token` is provided.
    pub async fn serve<F, Fut>(
        &self,
        handler: F,
        addr: &str,
        node_token: Option<String>,
    ) -> Result<()>
    where
        F: Fn(TaskRequest) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Value>> + Send + 'static,
    {
        let handler: TaskHandlerFn = Arc::new(move |req| Box::pin(handler(req)));
        let active_jobs = Arc::new(AtomicUsize::new(0));
        let nonce_cache = Arc::new(Mutex::new(HashMap::new()));

        let state = Arc::new(AppState {
            handler,
            node_id: self.cfg.node_id.clone(),
            region: self.cfg.region.clone().unwrap_or_else(|| "unknown".into()),
            intent: self.cfg.intent.clone(),
            model: self.cfg.model.clone().unwrap_or_default(),
            active_jobs,
            max_concurrent: self.cfg.max_concurrent,
            nonce_cache,
        });

        let app = Router::new()
            .route("/v1/task", post(task_endpoint))
            .route("/iicp/health", get(health_endpoint))
            .route("/metrics", get(metrics_endpoint))
            .with_state(state);

        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| IicpError::Node(format!("invalid addr: {e}")))?;
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| IicpError::Node(e.to_string()))?;

        tracing::info!("IICP node {} listening on {}", self.cfg.node_id, addr);

        if let Some(token) = node_token {
            let node_id = self.cfg.node_id.clone();
            let dir = self.cfg.directory_url.clone();
            let http = self.http.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(HEARTBEAT_INTERVAL_SECS)).await;
                    if let Err(e) = http
                        .post(format!("{}/api/v1/heartbeat", dir.trim_end_matches('/')))
                        .json(&json!({
                            "node_id": &node_id,
                            "node_token": &token,
                            "status": "available",
                        }))
                        .send()
                        .await
                    {
                        tracing::warn!("heartbeat failed: {e}");
                    }
                }
            });
        }

        axum::serve(listener, app)
            .await
            .map_err(|e| IicpError::Node(e.to_string()))
    }
}
