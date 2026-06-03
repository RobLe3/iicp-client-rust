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
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::errors::{IicpError, Result};

const DEFAULT_DIRECTORY: &str = "https://iicp.network/api";
const HEARTBEAT_INTERVAL_SECS: u64 = 30;
const NONCE_TTL_SECS: u64 = 300;

/// #404 — re-register: POST the register payload and return the fresh `node_token`.
/// Extracted from the heartbeat loop's re-register arm so the self-heal behaviour
/// is unit-testable (the 30s interval loop itself is not).
async fn reregister(http: &Client, url: &str, payload: &serde_json::Value) -> Option<String> {
    let resp = http.post(url).json(payload).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let data = resp.json::<serde_json::Value>().await.ok()?;
    data["node_token"]
        .as_str()
        .or_else(|| data["token"].as_str())
        .map(String::from)
}

/// #409 — classify a backend model name to the IICP intent it serves.
/// Embedding models (name contains "embed") advertise the embedding intent;
/// every other model advertises the node's configured/default intent (chat).
/// Conservative by design: we only split out embeddings, which is the verified
/// real case (e.g. an LM Studio backend serving a chat model + `*-embed-*`).
fn intent_for_model(model: &str, default_intent: &str) -> String {
    if model.to_lowercase().contains("embed") {
        "urn:iicp:intent:llm:embedding:v1".to_string()
    } else {
        default_intent.to_string()
    }
}

/// #408 / ADR-046 (B1/#414 — audio-in added) — input modalities a backend model
/// accepts. Vision-language models (name contains `vl`/`vision`/`llava`) accept
/// images; `omni` models accept image and audio; audio models (`audio`/`voxtral`)
/// accept audio; everything else is text-only. Conservative name-pattern detection.
/// Each is a modality of chat, not a separate intent (ADR-046). The directory + spec
/// accept text/image/audio/video in `input_modalities` (v0.10.0).
fn modalities_for_model(model: &str) -> Vec<&'static str> {
    let m = model.to_lowercase();
    let has_image = m.contains("-vl-")
        || m.ends_with("-vl")
        || m.contains("vision")
        || m.contains("llava")
        || m.contains("omni");
    let has_audio = m.contains("audio") || m.contains("voxtral") || m.contains("omni");
    let mut mods = vec!["text"];
    if has_image {
        mods.push("image");
    }
    if has_audio {
        mods.push("audio");
    }
    mods
}

/// #409 + #408 — group detected backend models into one capability object per
/// (intent, input_modalities), so a single node advertises every intent its
/// backend can serve (chat + embedding) AND distinguishes text-only vs
/// image-capable (vision) chat. The directory accepts a multi-element
/// `capabilities` array; clients pick the per-(intent,modality) model from
/// discover. Back-compatible: a single text chat model yields the same single
/// `["text"]` capability as before. Order: first-seen group leads (configured
/// model — typically chat/text — first).
fn build_capabilities(models: &[String], default_intent: &str, max_tokens: u32) -> Vec<Value> {
    if models.is_empty() {
        return vec![json!({
            "intent": default_intent, "models": [], "max_tokens": max_tokens,
            "input_modalities": ["text"],
        })];
    }
    // Group key = "intent\0modalities" to keep (intent, modality) groups distinct + ordered.
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, (String, Vec<&'static str>, Vec<String>)> = HashMap::new();
    for m in models {
        let intent = intent_for_model(m, default_intent);
        let modalities = modalities_for_model(m);
        let key = format!("{intent}\u{0}{}", modalities.join(","));
        let entry = groups.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            (intent.clone(), modalities.clone(), Vec::new())
        });
        if !entry.2.contains(m) {
            entry.2.push(m.clone());
        }
    }
    order
        .into_iter()
        .map(|key| {
            let (intent, modalities, models) = groups.remove(&key).expect("key from order");
            json!({
                "intent": intent,
                "models": models,
                "max_tokens": max_tokens,
                "input_modalities": modalities,
            })
        })
        .collect()
}

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
    /// #331 Phase A.1 / ADR-041 — NAT-traversal observability fields surfaced
    /// to the directory in the register payload. Populated by
    /// [`IicpNode::apply_nat_profile`] when an operator runs detect_nat at
    /// startup, OR set manually if the operator already knows their topology.
    ///
    /// `transport_method` is one of `direct` / `upnp_mapped` / `stun_hole_punch`
    /// / `turn_relay` / `external_tunnel` / `unknown`.
    pub transport_method: Option<String>,
    /// One of `full_cone` / `restricted_cone` / `port_restricted` / `symmetric`
    /// / `unknown` (observability only).
    pub nat_type: Option<String>,
    /// Forward-compat slot for ADR-041 transport_candidates[] + relay_endpoint.
    pub transport_metadata: Option<serde_json::Value>,
    /// ADR-043 §9 — 8-category exposure_mode, computed by `qualify_service` and set
    /// in `apply_nat_profile`. Surfaced to the directory `nodes.exposure_mode` column (#344).
    pub exposure_mode: Option<String>,
    /// S.12 §2.1 CIP policy block surfaced to the directory register payload.
    /// When `None`, register() falls back to the module-level
    /// [`crate::cip_policy::get_cip_policy`] — operators can configure once
    /// and have it apply to all nodes that don't override.
    pub cip_policy: Option<std::sync::Arc<crate::cip_policy::CooperativeInferencePolicy>>,
    /// ADR-019 declarative pricing block. When `None`, the SDK does not
    /// advertise pricing and the directory defaults to a 1.0 multiplier.
    pub pricing: Option<crate::pricing::PricingConfig>,
    /// Operator-provisioned HMAC key for ADR-019 pricing signatures. When
    /// empty, the SDK captures the directory-issued key from the register
    /// response and uses it for subsequent signing.
    pub node_hmac_key: String,
    /// Phase 3+ availability windows (ADR-006). Local-time "HH:MM" windows that
    /// shape the effective capacity advertised to the directory and gated at
    /// serve time. Empty → always full capacity. See [`crate::availability`].
    pub availability_windows: Vec<crate::availability::Window>,
    /// ADR-010 task_id idempotency. `false` by default to preserve the pre-0.6
    /// contract (a task_id may be resubmitted). When `true`, a duplicate task_id
    /// within the 5-minute window is rejected with IICP-E010.
    pub enable_idempotency: bool,
    /// Phase 2 mesh (ADR-009/022). When `true`, serve() gossips peers and exposes
    /// POST /v1/peers. Default false.
    pub enable_mesh: bool,
    /// When `true`, serve() exposes POST /v1/relay to forward tasks to peers learned
    /// via gossip (ADR-022). Requires `enable_mesh`. Default false.
    pub relay_capable: bool,
    /// Port for the RelayAcceptServer (R1 relay-as-last-resort, #341).
    /// Workers behind CGNAT connect here outbound and send RELAY_BIND. Default 9485.
    pub relay_accept_port: u16,
    /// R2: when set, this node acts as a relay WORKER — connects outbound to the
    /// specified relay endpoint. Format: "host:port" (e.g. "relay.example.com:9485").
    pub relay_worker_endpoint: Option<String>,
    /// Directory for persistent log files (`<node_id>.log` + `events.jsonl`).
    /// `None` disables file logging (stderr only). Overridden by `IICP_LOG_DIR`.
    pub log_dir: Option<std::path::PathBuf>,
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
            transport_method: None,
            nat_type: None,
            transport_metadata: None,
            exposure_mode: None,
            cip_policy: None,
            pricing: None,
            node_hmac_key: String::new(),
            availability_windows: Vec::new(),
            enable_idempotency: false,
            enable_mesh: false,
            relay_capable: false,
            relay_accept_port: 9485,
            relay_worker_endpoint: None,
            log_dir: None,
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
    /// Incremental task success/failure counters reset on each heartbeat.
    tasks_success: Arc<AtomicUsize>,
    tasks_failed: Arc<AtomicUsize>,
    max_concurrent: usize,
    availability: Arc<crate::availability::AvailabilityEvaluator>,
    /// #403 — CIP per-task admission policy (tool-execution gate).
    cip_policy: Arc<crate::cip_policy::CooperativeInferencePolicy>,
    idempotency: Arc<crate::idempotency::IdempotencyGuard>,
    enable_idempotency: bool,
    peer_manager: Arc<crate::peer_manager::PeerManager>,
    http: reqwest::Client,
    nonce_cache: Arc<Mutex<HashMap<String, Instant>>>,
    /// #343 — shared pinhole state for /iicp/health surface.
    pinhole_uid: Arc<std::sync::RwLock<Option<u32>>>,
    pinhole_lease_seconds: Arc<std::sync::RwLock<u32>>,
    /// R1 relay-as-last-resort (#341): sessions from workers binding outbound.
    #[cfg(feature = "iicp-tcp")]
    relay_sessions: Arc<crate::relay_session::RelaySessionRegistry>,
}

// ── GET /iicp/health ─────────────────────────────────────────────────────────

async fn health_endpoint(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let active = state.active_jobs.load(Ordering::Relaxed);
    let uid = state.pinhole_uid.read().ok().and_then(|g| *g);
    let lease = state
        .pinhole_lease_seconds
        .read()
        .map(|g| *g)
        .unwrap_or(3600);
    let pinhole_state = if let Some(uid) = uid {
        json!({ "active": true, "unique_id": uid, "lease_seconds": lease })
    } else {
        json!({ "active": false })
    };
    let eff_max = state
        .availability
        .effective_max_concurrent(state.max_concurrent);
    Json(json!({
        "status": "ok",
        "node_id": state.node_id,
        "region": state.region,
        "load": (active as f64 / state.max_concurrent.max(1) as f64),
        "active_jobs": active,
        "max_concurrent": state.max_concurrent,
        "effective_max_concurrent": eff_max,
        "available": active < eff_max,
        "model": state.model,
        "intent": state.intent,
        "pinhole_state": pinhole_state,
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

// ── POST /v1/peers (ADR-009 gossip exchange) ──────────────────────────────────

async fn peers_endpoint(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let sig = headers
        .get("x-iicp-signature")
        .and_then(|v| v.to_str().ok());
    if !state.peer_manager.verify_exchange(&body, sig) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":{"code":"IICP-E012","message":"invalid_signature"}})),
        )
            .into_response();
    }
    if let Ok(parsed) = serde_json::from_slice::<Value>(&body) {
        if let Some(arr) = parsed.get("known_peers").and_then(Value::as_array) {
            let dicts: Vec<Value> = arr.iter().filter(|p| p.is_object()).cloned().collect();
            state.peer_manager.merge_peers(&dicts);
        }
    }
    let peers: Vec<Value> = state
        .peer_manager
        .get_peers()
        .iter()
        .map(|p| {
            json!({
                "node_id": p.node_id,
                "endpoint": p.endpoint,
                "region": p.region,
                "last_seen": p.last_seen,
            })
        })
        .collect();
    Json(json!({ "peers": peers })).into_response()
}

// ── POST /v1/relay (ADR-022 mesh relay) ───────────────────────────────────────

async fn relay_endpoint(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<Value>,
) -> Response {
    let target_id = payload
        .get("target_node_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let task = payload.get("task");
    if target_id.is_empty() || task.is_none() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                json!({"error":{"code":"IICP-E000","message":"target_node_id and task required"}}),
            ),
        )
            .into_response();
    }
    let task_val = task.expect("checked above").clone();

    // R1: check relay session registry first (CGNAT workers with no inbound endpoint)
    #[cfg(feature = "iicp-tcp")]
    if let Some(session) = state.relay_sessions.get(target_id) {
        match session.forward_task(&task_val, 120).await {
            Ok(result) => {
                let task_id = task_val
                    .get("task_id")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                return Json(json!({
                    "task_id": task_id,
                    "status": "completed",
                    "result": result
                }))
                .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error":{"code":"IICP-E031","message":format!("relay session forward failed: {e}")}})),
                )
                    .into_response();
            }
        }
    }

    // Fall back to HTTP forwarding for routable peers (ADR-022)
    let target = match state.peer_manager.relay_target(target_id) {
        Some(t) => t,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error":{"code":"IICP-E030","message":"target not in peer list and not a bound relay worker"}})),
            )
                .into_response();
        }
    };
    let url = format!("{}/v1/task", target.endpoint.trim_end_matches('/'));
    match state
        .http
        .post(&url)
        .timeout(Duration::from_secs(120))
        .json(&task_val)
        .send()
        .await
    {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
            let bytes = resp.bytes().await.unwrap_or_default();
            (status, bytes).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error":{"code":"IICP-E031","message":format!("relay failed: {e}")}})),
        )
            .into_response(),
    }
}

// ── POST /v1/task ─────────────────────────────────────────────────────────────

/// Try to claim a concurrency slot. On `true` the caller owns one increment of
/// `active_jobs` and MUST `fetch_sub` it on every exit path. realtime/interactive
/// wait briefly for a slot; other tiers fail fast so the proxy sees back-pressure
/// immediately (ADR-006; see [`crate::scheduler`]).
async fn admit(state: &AppState, qos: &str) -> bool {
    // Effective cap folds in availability windows (ADR-006): a reduced/closed
    // window lowers capacity below max_concurrent.
    let cap = state
        .availability
        .effective_max_concurrent(state.max_concurrent);
    let prev = state.active_jobs.fetch_add(1, Ordering::Relaxed);
    if prev < cap {
        return true;
    }
    state.active_jobs.fetch_sub(1, Ordering::Relaxed);
    if !crate::scheduler::is_queue_eligible(qos) {
        return false;
    }
    let deadline = Instant::now() + crate::scheduler::QUEUE_WAIT;
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let cap = state
            .availability
            .effective_max_concurrent(state.max_concurrent);
        let prev = state.active_jobs.fetch_add(1, Ordering::Relaxed);
        if prev < cap {
            return true;
        }
        state.active_jobs.fetch_sub(1, Ordering::Relaxed);
    }
    false
}

async fn task_endpoint(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut req): Json<TaskRequest>,
) -> Response {
    // #403 — CIP per-task admission gate (parity with the adapter cip_gate):
    // reject tool-execution-domain intents unless the operator opted in via
    // cip_policy.allow_tool_execution. Checked before the QoS slot so a denied
    // task doesn't consume capacity.
    if !state.cip_policy.permits_intent(&req.intent) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": {
                    "code": "tool_execution_denied",
                    "message": "Tool-execution intents are not permitted by this node's CIP policy",
                }
            })),
        )
            .into_response();
    }

    // QoS-aware admission — IICP-E021
    let qos = req
        .constraints
        .as_ref()
        .and_then(|c| c.get("qos_class"))
        .and_then(|v| v.as_str())
        .unwrap_or("best_effort")
        .to_string();
    if !admit(&state, &qos).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", "2"), ("Content-Type", "application/json")],
            Json(json!({
                "error": {
                    "code": "IICP-E021",
                    "message": "capacity_exceeded",
                    "qos_class": qos,
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

    // Idempotency — duplicate task_id within the retry window (ADR-010). Opt-in
    // (NodeConfig.enable_idempotency) to preserve the pre-0.6 contract.
    if state.enable_idempotency && !state.idempotency.check_and_register(&req.task_id) {
        state.active_jobs.fetch_sub(1, Ordering::Relaxed);
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": { "code": "IICP-E010", "message": "duplicate_task" }
            })),
        )
            .into_response();
    }

    // W3C traceparent propagation
    if let Some(tp) = headers.get("traceparent").and_then(|v| v.to_str().ok()) {
        req._trace = Some(json!({ "traceparent": tp }));
    }

    let task_id = req.task_id.clone();
    // ADR-014 TRACE-02 — iicp.task.execute span via `tracing` crate.
    // `tracing-opentelemetry` bridge propagates this to an OTLP collector when
    // OTEL_EXPORTER_OTLP_ENDPOINT is set and the operator configures the bridge
    // at startup (e.g. via opentelemetry-otlp + tracing-opentelemetry).
    let result = {
        let span = tracing::info_span!(
            "iicp.task.execute",
            "iicp.task_id" = %task_id,
            "iicp.intent" = %req.intent,
        );
        let _guard = span.enter();
        (state.handler)(req).await
    };
    state.active_jobs.fetch_sub(1, Ordering::Relaxed);

    match result {
        Ok(value) => {
            state.tasks_success.fetch_add(1, Ordering::Relaxed);
            Json(TaskResponse {
                task_id,
                status: "completed".into(),
                result: Some(value),
                error: None,
            })
            .into_response()
        }
        Err(e) => {
            state.tasks_failed.fetch_add(1, Ordering::Relaxed);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TaskResponse {
                    task_id,
                    status: "error".into(),
                    result: None,
                    error: Some(json!({ "message": e.to_string() })),
                }),
            )
                .into_response()
        }
    }
}

// ── IicpNode ──────────────────────────────────────────────────────────────────

/// IICP provider node — handles registration, heartbeats, and task serving.
pub struct IicpNode {
    cfg: NodeConfig,
    http: Client,
    /// ADR-019 HMAC key used for signing pricing declarations. Initialized
    /// from `cfg.node_hmac_key`; populated from the directory's response on
    /// first register() so subsequent re-registrations sign with the
    /// directory-issued key.
    runtime_hmac_key: std::sync::RwLock<String>,
    /// BUG-5: token stashed by register() so deregister()/heartbeat don't need it re-passed.
    /// Arc so the background heartbeat task can update it after a re-registration (#399).
    runtime_token: Arc<std::sync::RwLock<String>>,
    /// #343 — UPnP IPv6 pinhole UID captured by `apply_nat_profile`, revoked
    /// on shutdown via [`Self::revoke_pinhole`]. Only read under the `nat`
    /// feature; allowed dead_code so non-nat builds compile cleanly.
    #[allow(dead_code)]
    pinhole_uid: std::sync::RwLock<Option<u32>>,
    #[allow(dead_code)]
    pinhole_lease_seconds: std::sync::RwLock<u32>,
    /// ADR-047 Part A (#411) — latest liveness nonce from the heartbeat response,
    /// answered (HMAC) on the next beat. None until the first response.
    liveness_challenge: std::sync::RwLock<Option<String>>,
}

impl IicpNode {
    pub fn new(cfg: NodeConfig) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms + 2_000))
            .use_rustls_tls()
            .build()
            .expect("failed to build HTTP client");
        let runtime_hmac_key = std::sync::RwLock::new(cfg.node_hmac_key.clone());
        Self {
            cfg,
            http,
            runtime_hmac_key,
            runtime_token: Arc::new(std::sync::RwLock::new(String::new())),
            pinhole_uid: std::sync::RwLock::new(None),
            pinhole_lease_seconds: std::sync::RwLock::new(3600),
            liveness_challenge: std::sync::RwLock::new(None),
        }
    }

    /// Current HMAC key in use for ADR-019 pricing signatures (empty if
    /// unregistered AND no operator-provisioned key).
    pub fn node_hmac_key(&self) -> String {
        self.runtime_hmac_key.read().expect("poisoned").clone()
    }

    /// Borrow this node's configuration. Useful for callers (e.g.
    /// [`crate::conformance::run_conformance_checks`]) that need to inspect
    /// `directory_url`, `endpoint`, or `node_id` without owning the config.
    pub fn cfg(&self) -> &NodeConfig {
        &self.cfg
    }

    /// Set the relay-worker endpoint after construction. Used by the CLI when a
    /// relay is auto-elected post-NAT-detection (tier ≥ 3): `serve()` reads
    /// `self.cfg.relay_worker_endpoint` to start the outbound relay session.
    pub fn set_relay_worker_endpoint(&mut self, endpoint: String) {
        self.cfg.relay_worker_endpoint = Some(endpoint);
    }

    /// Populate `endpoint`, `transport_endpoint`, and the NAT observability
    /// fields from a `NatProfile` produced by [`crate::nat_detection::detect_nat`].
    ///
    /// Operators typically call this right after `detect_nat()` and before
    /// `register()` so the directory receives the discovered public endpoint
    /// + transport_method/nat_type/transport_metadata in the same payload.
    ///
    /// Defensive: tier-4 (unreachable) profiles do NOT overwrite a manually-
    /// set endpoint, and `transport_method == "unreachable"` is filtered out
    /// before register.
    #[cfg(feature = "nat")]
    pub fn apply_nat_profile(&mut self, profile: &crate::nat_detection::NatProfile) {
        if profile.is_reachable() {
            if let Some(pub_ep) = &profile.public_endpoint {
                self.cfg.endpoint = pub_ep.clone();
            }
        }
        if let Some(tep) = &profile.transport_endpoint {
            self.cfg.transport_endpoint = Some(tep.clone());
        }
        let tm = match profile.transport_method {
            crate::nat_detection::TransportMethod::Direct => Some("direct"),
            crate::nat_detection::TransportMethod::UpnpMapped => Some("upnp_mapped"),
            crate::nat_detection::TransportMethod::StunHolePunch => Some("stun_hole_punch"),
            crate::nat_detection::TransportMethod::TurnRelay => Some("turn_relay"),
            crate::nat_detection::TransportMethod::ExternalTunnel => Some("external_tunnel"),
            crate::nat_detection::TransportMethod::Unreachable => None,
        };
        if let Some(name) = tm {
            self.cfg.transport_method = Some(name.into());
        }
        if self.cfg.nat_type.is_none() {
            self.cfg.nat_type = Some("unknown".into());
        }
        let tail: Vec<&str> = profile
            .detection_log
            .iter()
            .rev()
            .take(1)
            .map(|s| s.as_str())
            .collect();
        self.cfg.transport_metadata = Some(serde_json::json!({
            "tier": profile.tier,
            "detection_log_tail": tail,
        }));
        // ADR-043 §9 (#344) — derive the canonical 8-category exposure_mode and
        // advertise it so the directory can store nodes.exposure_mode for routing.
        self.cfg.exposure_mode = Some(
            crate::qualify::qualify_service(profile)
                .exposure_mode
                .to_string(),
        );
        // #343 — capture the IPv6 firewall pinhole UID and lease so we can renew and revoke.
        if let Some(v6) = &profile.ipv6 {
            if v6.pinhole_active {
                if let Some(uid) = v6.pinhole_unique_id {
                    if let Ok(mut slot) = self.pinhole_uid.write() {
                        *slot = Some(uid);
                    }
                }
                if let Some(lease) = v6.pinhole_lease_seconds {
                    if let Ok(mut slot) = self.pinhole_lease_seconds.write() {
                        *slot = lease;
                    }
                }
            }
        }
    }

    /// #343 — close the UPnP IPv6 firewall pinhole if one is tracked. Best-effort.
    #[cfg(feature = "nat")]
    pub async fn revoke_pinhole(&self) -> bool {
        let uid = match self.pinhole_uid.write() {
            Ok(mut slot) => slot.take(),
            Err(_) => None,
        };
        match uid {
            Some(uid) => crate::nat_detection::delete_ipv6_pinhole(uid).await,
            None => false,
        }
    }

    /// Tell the directory this node is going away.
    ///
    /// Mirrors `iicp_client.IicpNode.deregister` (Python iter-1471) and
    /// `IicpNode.deregister` (TS iter-1474). Best-effort: shutdown paths
    /// swallow failures so a flaky directory connection doesn't block exit.
    /// Deregister from the directory. `node_token` defaults to the token stashed by
    /// `register()` (BUG-5) when `None` — pass `Some(token)` to override.
    pub async fn deregister(&self, node_token: Option<&str>) -> Result<()> {
        let stashed = self.runtime_token.read().expect("poisoned").clone();
        let token = node_token.map(str::to_string).unwrap_or(stashed);
        if token.is_empty() {
            return Err(crate::errors::IicpError::Node(
                "deregister() requires a node_token (none stashed — call register() first)".into(),
            ));
        }
        let url = format!(
            "{}/v1/register",
            self.cfg.directory_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&token)
            .json(&serde_json::json!({"node_id": self.cfg.node_id}))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() && status.as_u16() != 404 {
            return Err(crate::errors::IicpError::Node(format!(
                "Deregister failed: {status}"
            )));
        }
        Ok(())
    }

    /// Register with the directory and return the assigned `node_token`.
    ///
    /// Payload conforms to spec/iicp-dir.md §3.1 REGISTER plus the v0.7.0
    /// dual-endpoint extension (`transport_endpoint`). Pre-iter-1413
    /// builds sent a non-spec flat-`intent` shape that the production
    /// directory rejects with 422; fixed here.
    /// Build the spec-compliant REGISTER payload (iicp-dir §3.1 + v0.7.0
    /// dual-endpoint). Extracted so the background heartbeat task can re-POST
    /// the same payload to recover after the directory drops the node (#399).
    fn build_register_payload(&self) -> Value {
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
            // #409 — advertise one capability object per intent the backend can
            // serve (e.g. chat + embedding from one Ollama/LM Studio backend),
            // classified from the detected model set, instead of a single intent.
            "capabilities": build_capabilities(&models, &self.cfg.intent, self.cfg.max_tokens),
            "limits": {
                "max_concurrent": self.cfg.max_concurrent,
                "tokens_per_min": self.cfg.tokens_per_min,
            },
        });
        if !self.cfg.node_id.is_empty() {
            payload["node_id"] = json!(self.cfg.node_id);
        }
        if let Some(t) = &self.cfg.transport_endpoint {
            payload["transport_endpoint"] = json!(t);
        }
        if let Some(m) = &self.cfg.transport_method {
            payload["transport_method"] = json!(m);
        }
        if let Some(n) = &self.cfg.nat_type {
            payload["nat_type"] = json!(n);
        }
        if let Some(md) = &self.cfg.transport_metadata {
            payload["transport_metadata"] = md.clone();
        }
        if let Some(e) = &self.cfg.exposure_mode {
            payload["exposure_mode"] = json!(e);
        }
        payload["sdk_language"] = json!("rust");
        payload["sdk_version"] = json!(env!("CARGO_PKG_VERSION"));
        let policy_arc = self
            .cfg
            .cip_policy
            .clone()
            .unwrap_or_else(crate::cip_policy::get_cip_policy);
        if let Some(block) = policy_arc.as_register_policy_block() {
            payload["policy"] = block;
        }
        if let Some(pricing) = &self.cfg.pricing {
            let hmac_key = self.runtime_hmac_key.read().expect("poisoned").clone();
            payload["pricing"] = crate::pricing::build_pricing_block(pricing, &hmac_key);
        }
        if !self.cfg.node_hmac_key.is_empty() {
            payload["node_hmac_key"] = json!(self.cfg.node_hmac_key);
        }
        payload
    }

    pub async fn register(&self) -> Result<String> {
        let payload = self.build_register_payload();

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
        // BUG-5: stash the token so deregister()/heartbeat don't need it re-passed.
        *self.runtime_token.write().expect("poisoned") = token.to_string();
        // ADR-019: capture directory-issued HMAC key for subsequent signing.
        // Operator-provisioned key (cfg.node_hmac_key) wins — we only set the
        // runtime key from the response when the operator hasn't set one.
        if self.cfg.node_hmac_key.is_empty() {
            if let Some(dir_key) = data["node_hmac_key"].as_str() {
                if !dir_key.is_empty() {
                    let mut guard = self.runtime_hmac_key.write().expect("poisoned");
                    *guard = dir_key.to_string();
                }
            }
        }
        Ok(token.to_string())
    }

    /// Send a single heartbeat to the directory.
    pub async fn heartbeat(&self, node_token: &str) -> Result<()> {
        let mut body = json!({
            "node_id": self.cfg.node_id,
            "node_token": node_token,
            "status": "available",
            // Live capacity after availability shaping (ADR-006).
            "max_concurrent": crate::availability::AvailabilityEvaluator::new(
                self.cfg.availability_windows.clone(),
            )
            .effective_max_concurrent(self.cfg.max_concurrent),
        });
        // ADR-047 Part A (#411) — answer the directory's liveness challenge from the
        // previous beat: HMAC the nonce with node_hmac_key (proves key control with
        // no dial-back; works for CGNAT/IPv6). No-op until both nonce + key exist.
        let hmac_key = self.node_hmac_key();
        let stored = self.liveness_challenge.read().expect("poisoned").clone();
        if let Some(ch) = &stored {
            if !hmac_key.is_empty() {
                body["challenge_response"] =
                    json!(crate::pricing::sign_body(ch.as_bytes(), &hmac_key));
            }
        }

        let resp = self
            .http
            // /v1/heartbeat — default directory_url already ends in /api;
            // the prior /api/v1/heartbeat path doubled the prefix and 404'd,
            // so last_seen never updated and nodes vanished from /v1/stats.
            .post(format!(
                "{}/v1/heartbeat",
                self.cfg.directory_url.trim_end_matches('/')
            ))
            // NodeTokenAuth middleware requires Bearer auth; the body
            // token is retained for back-compat with older directory builds.
            .bearer_auth(node_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| IicpError::Node(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(IicpError::Node(format!(
                "heartbeat failed: {}",
                resp.status()
            )));
        }
        // Capture the fresh nonce to answer on the next beat (ADR-047 Part A).
        if let Ok(data) = resp.json::<Value>().await {
            if let Some(ch) = data["challenge"].as_str() {
                *self.liveness_challenge.write().expect("poisoned") = Some(ch.to_string());
            }
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
        // Clone before handler is potentially moved into the relay worker closure (iicp-tcp only).
        #[cfg(feature = "iicp-tcp")]
        let handler_for_relay = Arc::clone(&handler);
        // Extract bind host before `addr` is shadowed by SocketAddr (iicp-tcp only).
        #[cfg(feature = "iicp-tcp")]
        let bind_host: String = addr.split(':').next().unwrap_or("0.0.0.0").to_string();
        let active_jobs = Arc::new(AtomicUsize::new(0));
        let nonce_cache = Arc::new(Mutex::new(HashMap::new()));
        // #343 — shared pinhole state: pass to AppState (health endpoint) and renewal task.
        let shared_pinhole_uid: Arc<std::sync::RwLock<Option<u32>>> = Arc::new(
            std::sync::RwLock::new(self.pinhole_uid.read().ok().and_then(|g| *g)),
        );
        let shared_pinhole_lease: Arc<std::sync::RwLock<u32>> = Arc::new(std::sync::RwLock::new(
            self.pinhole_lease_seconds
                .read()
                .map(|g| *g)
                .unwrap_or(3600),
        ));

        let tasks_success = Arc::new(AtomicUsize::new(0));
        let tasks_failed = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(AppState {
            handler,
            node_id: self.cfg.node_id.clone(),
            region: self.cfg.region.clone().unwrap_or_else(|| "unknown".into()),
            intent: self.cfg.intent.clone(),
            model: self.cfg.model.clone().unwrap_or_default(),
            active_jobs,
            tasks_success: Arc::clone(&tasks_success),
            tasks_failed: Arc::clone(&tasks_failed),
            max_concurrent: self.cfg.max_concurrent,
            availability: Arc::new(crate::availability::AvailabilityEvaluator::new(
                self.cfg.availability_windows.clone(),
            )),
            // #403 — resolve the CIP admission policy (cfg override or module default).
            cip_policy: self
                .cfg
                .cip_policy
                .clone()
                .unwrap_or_else(crate::cip_policy::get_cip_policy),
            idempotency: Arc::new(crate::idempotency::IdempotencyGuard::default()),
            enable_idempotency: self.cfg.enable_idempotency,
            peer_manager: Arc::new(crate::peer_manager::PeerManager::with_opts(
                self.cfg.directory_url.clone(),
                self.cfg.node_hmac_key.clone(),
                crate::peer_manager::PeerManagerOpts {
                    relay_capable: self.cfg.relay_capable,
                    relay_accept_port: self.cfg.relay_accept_port,
                },
            )),
            http: self.http.clone(),
            nonce_cache,
            pinhole_uid: Arc::clone(&shared_pinhole_uid),
            pinhole_lease_seconds: Arc::clone(&shared_pinhole_lease),
            #[cfg(feature = "iicp-tcp")]
            relay_sessions: Arc::new(crate::relay_session::RelaySessionRegistry::new()),
        });

        // Capture the availability handle before `state` is moved into the router,
        // so the heartbeat loop below can report effective capacity.
        let hb_availability = Arc::clone(&state.availability);
        // Phase 2 mesh: bootstrap + gossip when enabled (before `state` is moved).
        if self.cfg.enable_mesh {
            let pm = Arc::clone(&state.peer_manager);
            let node_id = self.cfg.node_id.clone();
            let own_endpoint = self.cfg.endpoint.clone();
            tokio::spawn(async move {
                pm.start(&node_id, &own_endpoint).await;
                let interval = pm.gossip_interval();
                loop {
                    tokio::time::sleep(interval).await;
                    pm.gossip_round().await;
                }
            });
        }

        let mut app = Router::new()
            .route("/v1/task", post(task_endpoint))
            .route("/iicp/health", get(health_endpoint))
            .route("/metrics", get(metrics_endpoint));
        if self.cfg.enable_mesh {
            app = app.route("/v1/peers", post(peers_endpoint));
        }
        if self.cfg.relay_capable {
            app = app.route("/v1/relay", post(relay_endpoint));
        }
        // R1: capture relay_sessions Arc before state is moved into the router.
        #[cfg(feature = "iicp-tcp")]
        let relay_sessions_arc = Arc::clone(&state.relay_sessions);
        let app = app.with_state(state);

        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| IicpError::Node(format!("invalid addr: {e}")))?;

        // For IPv6 addresses (including the default :: host), create a dual-stack socket
        // so the same listener accepts both IPv4 and IPv6 connections. Linux defaults to
        // IPV6_V6ONLY=1 which would silently reject IPv4; setting it to false here gives
        // macOS-equivalent behaviour on all platforms.
        let listener = if addr.is_ipv6() {
            let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))
                .map_err(|e| IicpError::Node(format!("socket create: {e}")))?;
            socket
                .set_only_v6(false)
                .map_err(|e| IicpError::Node(format!("set_only_v6: {e}")))?;
            socket
                .set_reuse_address(true)
                .map_err(|e| IicpError::Node(format!("set_reuse_address: {e}")))?;
            socket
                .bind(&addr.into())
                .map_err(|e| IicpError::Node(format!("bind {addr}: {e}")))?;
            socket
                .listen(1024)
                .map_err(|e| IicpError::Node(format!("listen: {e}")))?;
            let std_listener: std::net::TcpListener = socket.into();
            std_listener
                .set_nonblocking(true)
                .map_err(|e| IicpError::Node(e.to_string()))?;
            TcpListener::from_std(std_listener).map_err(|e| IicpError::Node(e.to_string()))?
        } else {
            TcpListener::bind(addr)
                .await
                .map_err(|e| IicpError::Node(e.to_string()))?
        };

        tracing::info!("IICP node {} listening on {}", self.cfg.node_id, addr);

        if let Some(token) = node_token {
            let node_id = self.cfg.node_id.clone();
            let dir = self.cfg.directory_url.clone();
            let http = self.http.clone();
            let avail = Arc::clone(&hb_availability);
            let max_c = self.cfg.max_concurrent;
            // Optional file logger shared with the heartbeat background task.
            let hb_log: Option<Arc<crate::node_log::NodeLog>> =
                self.cfg.log_dir.as_deref().and_then(|d| {
                    crate::node_log::NodeLog::open(d, &node_id)
                        .map(Arc::new)
                        .ok()
                });
            let hb_node_id = node_id.clone();
            let hb_tasks_success = Arc::clone(&tasks_success);
            let hb_tasks_failed = Arc::clone(&tasks_failed);
            // #399 — re-registration recovery: capture the register payload + the
            // shared runtime token so the loop can re-register and update the token
            // if the directory drops the node (deregister/TTL-expiry/restart).
            let hb_register_payload = self.build_register_payload();
            let hb_token_arc = Arc::clone(&self.runtime_token);
            let hb_register_url = format!("{}/v1/register", dir.trim_end_matches('/'));
            tokio::spawn(async move {
                let mut token = token;
                let mut seq: u64 = 0;
                loop {
                    tokio::time::sleep(Duration::from_secs(HEARTBEAT_INTERVAL_SECS)).await;
                    seq += 1;
                    // Drain incremental task counters so the directory receives
                    // the delta since the last heartbeat (ReputationService::upsert
                    // expects incremental, not cumulative counts).
                    let ok = hb_tasks_success.swap(0, Ordering::Relaxed);
                    let fail = hb_tasks_failed.swap(0, Ordering::Relaxed);
                    match http
                        // /v1/heartbeat — see heartbeat() above for the doubled-prefix
                        // history. Same fix applied here in the background loop.
                        .post(format!("{}/v1/heartbeat", dir.trim_end_matches('/')))
                        .bearer_auth(&token)
                        .json(&json!({
                            "node_id": &node_id,
                            "node_token": &token,
                            "status": "available",
                            // Live capacity after availability shaping (ADR-006).
                            "max_concurrent": avail.effective_max_concurrent(max_c),
                            // Task outcome metrics — only sent when non-zero to
                            // avoid moving reputation on idle periods.
                            "metrics": if ok > 0 || fail > 0 {
                                json!({"tasks_success": ok, "tasks_failed": fail})
                            } else {
                                json!({})
                            },
                        }))
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status().is_success() => {
                            if let Some(ref log) = hb_log {
                                log.write("heartbeat_ok", &hb_node_id, &format!("seq={seq}"));
                            }
                        }
                        // #399 — directory no longer knows this node (it was
                        // deregistered on a prior shutdown, TTL-expired after a
                        // heartbeat gap, or the directory restarted). Re-register
                        // and resume with the fresh token instead of heartbeating
                        // into the void forever.
                        Ok(resp) if matches!(resp.status().as_u16(), 401 | 404 | 410) => {
                            let code = resp.status().as_u16();
                            tracing::warn!(
                                "heartbeat rejected ({code}) — node unknown to directory; re-registering"
                            );
                            match reregister(&http, &hb_register_url, &hb_register_payload).await {
                                Some(t) => {
                                    token = t;
                                    if let Ok(mut g) = hb_token_arc.write() {
                                        *g = token.clone();
                                    }
                                    if let Some(ref log) = hb_log {
                                        log.write(
                                            "reregister_ok",
                                            &hb_node_id,
                                            &format!("seq={seq} after_status={code}"),
                                        );
                                    }
                                }
                                None => {
                                    tracing::warn!("re-registration failed (after status {code})");
                                    if let Some(ref log) = hb_log {
                                        log.write(
                                            "reregister_fail",
                                            &hb_node_id,
                                            &format!("seq={seq} after_status={code}"),
                                        );
                                    }
                                }
                            }
                        }
                        Ok(resp) => {
                            if let Some(ref log) = hb_log {
                                log.write(
                                    "heartbeat_fail",
                                    &hb_node_id,
                                    &format!("seq={seq} status={}", resp.status().as_u16()),
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!("heartbeat failed: {e}");
                            if let Some(ref log) = hb_log {
                                log.write(
                                    "heartbeat_fail",
                                    &hb_node_id,
                                    &format!("seq={seq} error={e}"),
                                );
                            }
                        }
                    }
                }
            });
        }

        // #343 — pinhole renewal task: extends the UPnP IPv6 firewall pinhole at lease/2.
        #[cfg(feature = "nat")]
        {
            let uid_arc = Arc::clone(&shared_pinhole_uid);
            let lease_arc = Arc::clone(&shared_pinhole_lease);
            tokio::spawn(async move {
                loop {
                    let (_uid, lease) = {
                        let u = uid_arc.read().ok().and_then(|g| *g);
                        let l = lease_arc.read().map(|g| *g).unwrap_or(3600);
                        (u, l)
                    };
                    let delay = Duration::from_secs(u64::from((lease / 2).max(60)));
                    tokio::time::sleep(delay).await;
                    let uid = match uid_arc.read().ok().and_then(|g| *g) {
                        Some(u) => u,
                        None => return,
                    };
                    let ok = crate::nat_detection::renew_ipv6_pinhole(uid, lease).await;
                    if ok {
                        tracing::debug!("UPnP IPv6 pinhole uid={uid} renewed (lease={lease}s)");
                    } else {
                        tracing::warn!("UPnP IPv6 pinhole uid={uid} renewal failed — will retry");
                    }
                }
            });
        }

        // R1: start RelayAcceptServer when relay-capable (#341)
        #[cfg(feature = "iicp-tcp")]
        if self.cfg.relay_capable {
            let relay_reg = relay_sessions_arc;
            let relay_host_str = bind_host.clone();
            let relay_port = self.cfg.relay_accept_port;
            tokio::spawn(async move {
                let srv = Arc::new(crate::relay_session::RelayAcceptServer::new(
                    (*relay_reg).clone(),
                    relay_host_str,
                    relay_port,
                ));
                if let Err(e) = srv.serve().await {
                    tracing::warn!("Relay accept server error: {e}");
                }
            });
        }

        // R2: start relay worker client if relay_worker_endpoint is configured (#341)
        #[cfg(feature = "iicp-tcp")]
        if let Some(ref ep) = self.cfg.relay_worker_endpoint {
            let ep = ep.clone();
            let node_id = self.cfg.node_id.clone();
            let intent = self.cfg.intent.clone();
            let models = self.cfg.model.clone().map(|m| vec![m]).unwrap_or_default();
            let handler_fn: crate::relay_worker_client::RelayHandlerFn =
                Arc::new(move |task: Value| {
                    let h = Arc::clone(&handler_for_relay);
                    Box::pin(async move {
                        let req = crate::node::TaskRequest {
                            task_id: task
                                .get("task_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            intent: task
                                .get("intent")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            payload: task.get("payload").cloned().unwrap_or(Value::Null),
                            constraints: task.get("constraints").cloned(),
                            auth: task.get("auth").cloned(),
                            nonce: None,
                            _trace: None,
                        };
                        h(req)
                            .await
                            .unwrap_or_else(|e| json!({"error": e.to_string()}))
                    })
                });
            let (rhost, rport) = {
                if let Some(pos) = ep.rfind(':') {
                    let port = ep[pos + 1..].parse::<u16>().unwrap_or(9485);
                    (ep[..pos].to_string(), port)
                } else {
                    (ep.clone(), 9485u16)
                }
            };
            // on_bind: re-register with the relay's public endpoint so the node
            // appears ACTIVE in directory + stats (#358).
            let http_client = self.http.clone();
            let dir_url = self.cfg.directory_url.clone();
            let on_bind_cb: crate::relay_worker_client::OnBindFn = Arc::new(
                move |rh: String, rp: u16, _wid: String| {
                    let http = http_client.clone();
                    let dir = dir_url.clone();
                    Box::pin(async move {
                        // A full re-register would require the IicpNode reference here,
                        // which isn't available. For v0.7.0 we log the bind event.
                        // The node operator should use the cli bin which has the full
                        // context to re-register. Full wiring tracked in #341 R2.
                        tracing::info!(
                            "Relay worker bound to relay {}:{} — update directory registration to use relay endpoint",
                            rh, rp,
                        );
                        let _ = (http, dir); // suppress unused warnings
                    })
                },
            );
            tokio::spawn(async move {
                let rwc = Arc::new(
                    crate::relay_worker_client::RelayWorkerClient::new(
                        node_id, intent, rhost, rport, handler_fn, models,
                    )
                    .with_on_bind(on_bind_cb),
                );
                rwc.run().await;
            });
        }

        axum::serve(listener, app)
            .await
            .map_err(|e| IicpError::Node(e.to_string()))
    }
}

#[cfg(test)]
mod capability_tests {
    use super::build_capabilities;

    const CHAT: &str = "urn:iicp:intent:llm:chat:v1";
    const EMBED: &str = "urn:iicp:intent:llm:embedding:v1";

    // #409 — a backend serving a chat model AND an embedding model advertises
    // BOTH intents (the verified LM Studio case). Fails on the old single-cap code.
    #[test]
    fn chat_plus_embedding_models_advertise_two_intents() {
        let models = vec![
            "qwen2.5-coder-14b-instruct".to_string(),
            "text-embedding-nomic-embed-text-v1.5".to_string(),
        ];
        let caps = build_capabilities(&models, CHAT, 4096);
        assert_eq!(caps.len(), 2, "should advertise chat + embedding");
        // chat first (configured model leads), embedding second
        assert_eq!(caps[0]["intent"], CHAT);
        assert_eq!(
            caps[0]["models"],
            serde_json::json!(["qwen2.5-coder-14b-instruct"])
        );
        assert_eq!(caps[1]["intent"], EMBED);
        assert_eq!(
            caps[1]["models"],
            serde_json::json!(["text-embedding-nomic-embed-text-v1.5"])
        );
    }

    // Back-compat: a chat-only model set yields exactly one text capability.
    #[test]
    fn chat_only_yields_single_capability() {
        let caps = build_capabilities(&["qwen2.5:0.5b".to_string()], CHAT, 4096);
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0]["intent"], CHAT);
        assert_eq!(caps[0]["models"], serde_json::json!(["qwen2.5:0.5b"]));
        assert_eq!(caps[0]["input_modalities"], serde_json::json!(["text"]));
    }

    // #408/ADR-046 — a vision model advertises a chat capability with image input,
    // SEPARATE from the text-only chat capability. Fails without modality grouping.
    #[test]
    fn vision_model_advertises_image_modality_chat_capability() {
        let models = vec![
            "qwen2.5-coder-14b".to_string(),
            "qwen/qwen3-vl-8b".to_string(),
        ];
        let caps = build_capabilities(&models, CHAT, 4096);
        assert_eq!(
            caps.len(),
            2,
            "text-chat and vision-chat are distinct capabilities"
        );
        assert_eq!(caps[0]["intent"], CHAT);
        assert_eq!(caps[0]["input_modalities"], serde_json::json!(["text"]));
        assert_eq!(caps[0]["models"], serde_json::json!(["qwen2.5-coder-14b"]));
        assert_eq!(caps[1]["intent"], CHAT);
        assert_eq!(
            caps[1]["input_modalities"],
            serde_json::json!(["text", "image"])
        );
        assert_eq!(caps[1]["models"], serde_json::json!(["qwen/qwen3-vl-8b"]));
    }

    // B1/#414 — an audio-in chat model advertises a chat capability with audio input,
    // SEPARATE from the text-only chat capability. Mirrors the vision (image) case.
    #[test]
    fn audio_model_advertises_audio_modality_chat_capability() {
        let models = vec!["qwen2.5:0.5b".to_string(), "qwen2-audio-7b".to_string()];
        let caps = build_capabilities(&models, CHAT, 4096);
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0]["input_modalities"], serde_json::json!(["text"]));
        assert_eq!(caps[1]["intent"], CHAT);
        assert_eq!(
            caps[1]["input_modalities"],
            serde_json::json!(["text", "audio"])
        );
        assert_eq!(caps[1]["models"], serde_json::json!(["qwen2-audio-7b"]));
    }

    // B1 — an "omni" model accepts both image and audio in chat.
    #[test]
    fn omni_model_advertises_image_and_audio_modalities() {
        let caps = build_capabilities(&["qwen2.5-omni-7b".to_string()], CHAT, 4096);
        assert_eq!(caps.len(), 1);
        assert_eq!(
            caps[0]["input_modalities"],
            serde_json::json!(["text", "image", "audio"])
        );
    }

    // No models → single default-intent capability with empty models (unchanged).
    #[test]
    fn empty_models_yields_default_intent_capability() {
        let caps = build_capabilities(&[], CHAT, 1024);
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0]["intent"], CHAT);
        assert_eq!(caps[0]["models"], serde_json::json!([]));
    }
}

#[cfg(test)]
mod reregister_tests {
    use super::reregister;
    use serde_json::json;

    // #404 — the re-register seam used by the self-healing heartbeat loop:
    // POST the register payload, return the fresh node_token.
    #[tokio::test]
    async fn reregister_returns_fresh_token() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/v1/register")
            .with_status(201)
            .with_body(json!({"node_token": "recovered-xyz"}).to_string())
            .create_async()
            .await;
        let http = reqwest::Client::new();
        let payload = json!({"endpoint": "https://x", "region": "r"});
        let url = format!("{}/v1/register", server.url());
        let tok = reregister(&http, &url, &payload).await;
        assert_eq!(tok, Some("recovered-xyz".to_string()));
        m.assert_async().await;
    }

    #[tokio::test]
    async fn reregister_none_on_failure() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/v1/register")
            .with_status(500)
            .create_async()
            .await;
        let http = reqwest::Client::new();
        let url = format!("{}/v1/register", server.url());
        let tok = reregister(&http, &url, &json!({})).await;
        assert_eq!(tok, None);
    }
}
