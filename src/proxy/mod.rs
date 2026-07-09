// SPDX-License-Identifier: Apache-2.0
//! iicp-node proxy (ADR-050) — local OpenAI/Ollama/Anthropic-compat gateway.
//!
//! A loopback HTTP server (axum) that translates external chat-API requests into IICP
//! mesh calls via [`IicpClient`] and back. It does NOT register with the directory
//! (consumer gateway). Mirrors the Python `iicp_client.proxy` and the TS gateway per
//! `project/proxy-unification-contract.md`; verified against the shared golden fixtures.
//!
//! v1 covers the non-CIP fixtures. The CIP affordability / no-eligible-workers gates
//! (402 IICP-E036 / 503 IICP-E022) require porting the proxy CIP dispatch and are
//! tracked under the conformance issue (#482).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{header, StatusCode},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

use std::sync::LazyLock;

use crate::client::IicpClient;
use crate::errors::IicpError;
use crate::types::{TaskRequest, TaskResponse};

pub mod cip;
use cip::{cip_config_from_env, compute_cip_envelope, CipConfig, CipError};

const INTENT: &str = "urn:iicp:intent:llm:chat:v1";
/// The proxy self-identifies as `iicp-proxy` on every response (Server header).
const SERVER_ID: &str = "iicp-proxy";
const OLLAMA_VERSION: &str = "0.1.0";
/// CIP consumer config (env IICP_PROXY_CIP_*); enabled defaults OFF (§2.2 ¶1).
static CIP_CONFIG: LazyLock<CipConfig> = LazyLock::new(cip_config_from_env);

/// Dispatch error surfaced to the gateway — an IICP error or a CIP gating error.
pub enum ProxyDispatchError {
    Iicp(IicpError),
    Cip(CipError),
}

/// Mockable IICP task surface — a boxed future avoids an `async-trait` dependency.
pub trait ProxyBackend: Send + Sync {
    fn submit(
        &self,
        intent: String,
        payload: Value,
    ) -> Pin<Box<dyn Future<Output = Result<TaskResponse, ProxyDispatchError>> + Send + '_>>;

    /// Discover nodes for CIP eligibility (used only when CIP is enabled). Default: none.
    fn discover(&self, _intent: String) -> Pin<Box<dyn Future<Output = Vec<Value>> + Send + '_>> {
        Box::pin(async { Vec::new() })
    }
}

impl ProxyBackend for IicpClient {
    fn submit(
        &self,
        intent: String,
        payload: Value,
    ) -> Pin<Box<dyn Future<Output = Result<TaskResponse, ProxyDispatchError>> + Send + '_>> {
        Box::pin(async move {
            self.submit(TaskRequest {
                task_id: String::new(),
                intent,
                payload,
                constraints: None,
                auth: None,
                // Proxy gateway has no registered node identity — self-query
                // neutrality (#488) does not apply to anonymous consumers.
                source_node_id: None,
                routing_policy: None,
            })
            .await
            .map_err(ProxyDispatchError::Iicp)
        })
    }

    fn discover(&self, intent: String) -> Pin<Box<dyn Future<Output = Vec<Value>> + Send + '_>> {
        Box::pin(async move {
            match self.discover(&intent, None, None).await {
                Ok(list) => list
                    .nodes
                    .into_iter()
                    .map(|n| {
                        serde_json::json!({
                            "node_id": n.node_id,
                            "allow_remote_inference": n.cip_policy.map(|c| c.allow_remote_inference).unwrap_or(false),
                            "reputation_score": n.score,
                        })
                    })
                    .collect(),
                Err(_) => Vec::new(),
            }
        })
    }
}

type Backend = Arc<dyn ProxyBackend>;

// ── translators (mirror the Python/TS gateways) ──────────────────────────────

fn first_message(resp: &TaskResponse) -> (String, String) {
    let result = resp.result.clone().unwrap_or_else(|| json!({}));
    let choices = result
        .get("choices")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    let msg = choices
        .first()
        .and_then(|c| c.get("message"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let role = msg
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("assistant")
        .to_string();
    let content = msg
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    (role, content)
}

fn usage_of(resp: &TaskResponse) -> Value {
    resp.result
        .as_ref()
        .and_then(|r| r.get("usage"))
        .cloned()
        .unwrap_or_else(|| json!({}))
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn to_openai(resp: &TaskResponse, model: &str) -> Value {
    let (role, content) = first_message(resp);
    json!({
        "id": "chatcmpl-iicp", "object": "chat.completion",
        "created": chrono::Utc::now().timestamp(), "model": model,
        "choices": [{"index": 0, "message": {"role": role, "content": content}, "finish_reason": "stop"}],
        "usage": usage_of(resp),
    })
}

fn to_ollama(resp: &TaskResponse, model: &str) -> Value {
    let (role, content) = first_message(resp);
    json!({"model": model, "created_at": now_iso(), "message": {"role": role, "content": content}, "done": true, "done_reason": "stop"})
}

fn to_ollama_generate(resp: &TaskResponse, model: &str) -> Value {
    let (_role, content) = first_message(resp);
    json!({"model": model, "created_at": now_iso(), "response": content, "done": true, "done_reason": "stop"})
}

fn to_anthropic(resp: &TaskResponse, model: &str) -> Value {
    let (_role, content) = first_message(resp);
    json!({
        "id": "msg_iicp", "type": "message", "role": "assistant", "model": model,
        "content": [{"type": "text", "text": content}], "stop_reason": "end_turn", "usage": usage_of(resp),
    })
}

// ── error bodies (per-surface) ───────────────────────────────────────────────
fn openai_err(code: &str, message: &str) -> Value {
    json!({"error": {"code": code, "message": message}})
}
fn ollama_err(code: &str, message: &str) -> Value {
    json!({"error": format!("{code}: {message}")})
}
fn anthropic_err(code: &str, message: &str) -> Value {
    json!({"type": "error", "error": {"type": "api_error", "message": format!("{code}: {message}")}})
}

// ── HTTP helpers (every response carries Server: iicp-proxy) ──────────────────
fn build(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::SERVER, SERVER_ID)
        .body(Body::from(body))
        .unwrap()
}
fn json_response(status: StatusCode, body: Value) -> Response {
    build(
        status,
        "application/json",
        serde_json::to_vec(&body).unwrap_or_default(),
    )
}

fn ai_generated(mut response: Response) -> Response {
    response.headers_mut().insert(
        "x-iicp-generated-by-ai",
        header::HeaderValue::from_static("true"),
    );
    response
}

// ── dispatch ─────────────────────────────────────────────────────────────────
enum Outcome {
    Ok(TaskResponse),
    Err(StatusCode, String),
}

fn extras(body: &Value) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    for k in ["temperature", "max_tokens", "cip", "billing", "qos"] {
        if let Some(v) = body.get(k) {
            m.insert(k.to_string(), v.clone());
        }
    }
    m
}

fn cip_outcome(err: &CipError) -> Outcome {
    match err {
        CipError::InsufficientCredits(c) => Outcome::Err(StatusCode::PAYMENT_REQUIRED, c.clone()),
        CipError::NoEligibleWorkers(c) => Outcome::Err(StatusCode::SERVICE_UNAVAILABLE, c.clone()),
    }
}

async fn run_task(b: &Backend, messages: Value, model: &str, body: &Value) -> Outcome {
    let mut payload = json!({"messages": messages, "model": model});
    if let Some(obj) = payload.as_object_mut() {
        obj.extend(extras(body));
    }
    // CIP consumer gating (§2.2) — only when enabled; surfaces 402 (E036) / 503 (E022),
    // else returns an envelope to attach. Pure consumer → Gate-4 local-first is skipped.
    if CIP_CONFIG.enabled {
        let nodes = b.discover(INTENT.to_string()).await;
        let balance = body
            .get("billing")
            .and_then(|x| x.get("consumer_balance"))
            .and_then(|v| v.as_f64());
        let qos = body.get("qos").and_then(|q| q.as_str());
        match compute_cip_envelope(&nodes, body, &CIP_CONFIG, "cip-task", qos, balance) {
            Err(e) => return cip_outcome(&e),
            Ok(Some(env)) => {
                if let (Some(obj), Some(eo)) = (payload.as_object_mut(), env.as_object()) {
                    obj.insert("cip".to_string(), Value::Object(eo.clone()));
                }
            }
            Ok(None) => {}
        }
    }
    match b.submit(INTENT.to_string(), payload).await {
        Ok(resp) if resp.status == "success" || resp.status == "completed" => Outcome::Ok(resp),
        Ok(resp) => {
            let code = resp
                .error
                .as_ref()
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_str())
                .unwrap_or("proxy_error")
                .to_string();
            Outcome::Err(StatusCode::BAD_GATEWAY, code)
        }
        Err(ProxyDispatchError::Cip(e)) => cip_outcome(&e),
        Err(ProxyDispatchError::Iicp(IicpError::NoNodes { .. })) => {
            Outcome::Err(StatusCode::BAD_GATEWAY, "IICP-E033".to_string())
        }
        Err(ProxyDispatchError::Iicp(e)) => {
            // SDK-internal failures map to 502 with their code; truly unexpected → 500.
            let code = format!("{e}");
            if code.starts_with("SDK-") || code.starts_with("IICP-") {
                Outcome::Err(
                    StatusCode::BAD_GATEWAY,
                    code.split(':').next().unwrap_or("proxy_error").to_string(),
                )
            } else {
                Outcome::Err(StatusCode::INTERNAL_SERVER_ERROR, "proxy_error".to_string())
            }
        }
    }
}

fn model_of(body: &Value) -> String {
    body.get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("iicp")
        .to_string()
}
fn messages_of(body: &Value) -> Value {
    body.get("messages").cloned().unwrap_or_else(|| json!([]))
}
fn err_msg(status: StatusCode) -> &'static str {
    if status == StatusCode::BAD_GATEWAY {
        "Upstream error"
    } else {
        "Internal proxy error"
    }
}

// ── handlers ─────────────────────────────────────────────────────────────────

async fn openai_chat(State(b): State<Backend>, Json(body): Json<Value>) -> Response {
    let model = model_of(&body);
    match run_task(&b, messages_of(&body), &model, &body).await {
        Outcome::Ok(resp) => ai_generated(json_response(StatusCode::OK, to_openai(&resp, &model))),
        Outcome::Err(s, code) => json_response(s, openai_err(&code, err_msg(s))),
    }
}

async fn ollama_chat(State(b): State<Backend>, Json(body): Json<Value>) -> Response {
    let model = model_of(&body);
    let stream = body
        .get("stream")
        .is_none_or(|v| v.as_bool().unwrap_or(true)); // default true
    match run_task(&b, messages_of(&body), &model, &body).await {
        Outcome::Ok(resp) => {
            let payload = to_ollama(&resp, &model);
            if stream {
                ai_generated(build(
                    StatusCode::OK,
                    "application/x-ndjson",
                    format!("{}\n", payload).into_bytes(),
                ))
            } else {
                ai_generated(json_response(StatusCode::OK, payload))
            }
        }
        Outcome::Err(s, code) => json_response(s, ollama_err(&code, err_msg(s))),
    }
}

async fn ollama_generate(State(b): State<Backend>, Json(body): Json<Value>) -> Response {
    let model = model_of(&body);
    let stream = body
        .get("stream")
        .is_none_or(|v| v.as_bool().unwrap_or(true));
    let prompt = body
        .get("prompt")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let messages = json!([{"role": "user", "content": prompt}]);
    match run_task(&b, messages, &model, &body).await {
        Outcome::Ok(resp) => {
            let payload = to_ollama_generate(&resp, &model);
            if stream {
                ai_generated(build(
                    StatusCode::OK,
                    "application/x-ndjson",
                    format!("{}\n", payload).into_bytes(),
                ))
            } else {
                ai_generated(json_response(StatusCode::OK, payload))
            }
        }
        Outcome::Err(s, code) => json_response(s, ollama_err(&code, err_msg(s))),
    }
}

async fn anthropic_messages(State(b): State<Backend>, Json(body): Json<Value>) -> Response {
    let model = model_of(&body);
    let stream = body
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false); // default false
    match run_task(&b, messages_of(&body), &model, &body).await {
        Outcome::Ok(resp) => {
            let msg = to_anthropic(&resp, &model);
            if stream {
                let (_r, text) = first_message(&resp);
                let ev = |t: &str, d: Value| {
                    format!(
                        "event: {t}\ndata: {}\n\n",
                        json!({"type": t})
                            .as_object()
                            .map(|m| {
                                let mut m = m.clone();
                                if let Some(o) = d.as_object() {
                                    m.extend(o.clone());
                                }
                                Value::Object(m)
                            })
                            .unwrap()
                    )
                };
                let mut sse = String::new();
                sse.push_str(&ev("message_start", json!({"message": msg})));
                sse.push_str(&ev(
                    "content_block_start",
                    json!({"index": 0, "content_block": {"type": "text", "text": ""}}),
                ));
                sse.push_str(&ev(
                    "content_block_delta",
                    json!({"index": 0, "delta": {"type": "text_delta", "text": text}}),
                ));
                sse.push_str(&ev("content_block_stop", json!({"index": 0})));
                sse.push_str(&ev(
                    "message_delta",
                    json!({"delta": {"stop_reason": "end_turn"}}),
                ));
                sse.push_str(&ev("message_stop", json!({})));
                ai_generated(build(StatusCode::OK, "text/event-stream", sse.into_bytes()))
            } else {
                ai_generated(json_response(StatusCode::OK, msg))
            }
        }
        Outcome::Err(s, code) => json_response(s, anthropic_err(&code, err_msg(s))),
    }
}

async fn ollama_version() -> Response {
    json_response(StatusCode::OK, json!({"version": OLLAMA_VERSION}))
}
async fn ollama_tags() -> Response {
    json_response(
        StatusCode::OK,
        json!({"models": [{"name": "iicp", "model": "iicp", "modified_at": "", "size": 0, "digest": ""}]}),
    )
}
async fn anthropic_models() -> Response {
    json_response(
        StatusCode::OK,
        json!({"object": "list", "data": [{"id": "iicp", "object": "model", "created": 1700000000, "owned_by": "iicp"}]}),
    )
}
async fn status() -> Response {
    json_response(StatusCode::OK, json!({"status": "ok", "role": "proxy"}))
}
async fn metrics() -> Response {
    build(
        StatusCode::OK,
        "text/plain; version=0.0.4",
        b"# iicp-proxy metrics\n".to_vec(),
    )
}

/// Build the gateway router. `backend` is injectable for tests.
pub fn proxy_router(backend: Backend) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(openai_chat))
        .route("/api/chat", post(ollama_chat))
        .route("/api/generate", post(ollama_generate))
        .route("/api/tags", get(ollama_tags))
        .route("/api/version", get(ollama_version))
        .route("/v1/messages", post(anthropic_messages))
        .route("/v1/models", get(anthropic_models))
        .route("/status", get(status))
        .route("/metrics", get(metrics))
        .with_state(backend)
}

/// Proxy server config (CLI flags / env map to this).
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    pub directory_url: Option<String>,
    pub region: Option<String>,
}

/// CLI entry: build a real `IicpClient` gateway and serve (loopback by default).
pub async fn run_proxy(cfg: ProxyConfig) -> std::io::Result<()> {
    let mut client_cfg = crate::types::ClientConfig::default();
    if let Some(d) = cfg.directory_url {
        client_cfg.directory_url = d;
    }
    client_cfg.region = cfg.region;
    let client = IicpClient::new(client_cfg).map_err(|e| std::io::Error::other(format!("{e}")))?;
    let backend: Backend = Arc::new(client);
    let app = proxy_router(backend);
    let addr = format!("{}:{}", cfg.host, cfg.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("iicp-node proxy → http://{addr} (OpenAI/Ollama/Anthropic compat; no directory registration)");
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mock {
        kind: String,
        value: Value,
    }
    impl ProxyBackend for Mock {
        fn submit(
            &self,
            _intent: String,
            _payload: Value,
        ) -> Pin<Box<dyn Future<Output = Result<TaskResponse, ProxyDispatchError>> + Send + '_>>
        {
            let kind = self.kind.clone();
            let mut value = self.value.clone();
            Box::pin(async move {
                match kind.as_str() {
                    "iicp_response" => {
                        // Fixtures omit task_id (required field) — inject one before deserialize.
                        if value.get("task_id").is_none() {
                            value["task_id"] = json!("t-mock");
                        }
                        Ok(serde_json::from_value::<TaskResponse>(value).unwrap())
                    }
                    "raise" => {
                        // value e.g. "CIPInsufficientCredits:IICP-E036" — simulate the CIP
                        // gate raising; the gateway maps it to 402/503.
                        let v = value.as_str().unwrap_or("");
                        let (name, code) = v.split_once(':').unwrap_or((v, ""));
                        let code = code.to_string();
                        Err(ProxyDispatchError::Cip(match name {
                            "CIPInsufficientCredits" => CipError::InsufficientCredits(code),
                            _ => CipError::NoEligibleWorkers(code),
                        }))
                    }
                    _ => Err(ProxyDispatchError::Iicp(IicpError::NoNodes {
                        intent: INTENT.to_string(),
                    })),
                }
            })
        }
    }

    fn nav(v: &Value, path: &str) -> Value {
        let mut cur = v.clone();
        for seg in path.split('.') {
            cur = if let Ok(idx) = seg.parse::<usize>() {
                cur.get(idx).cloned().unwrap_or(Value::Null)
            } else {
                cur.get(seg).cloned().unwrap_or(Value::Null)
            };
        }
        cur
    }

    #[tokio::test]
    async fn golden_fixtures_parity() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/proxy_fixtures.json"
        ));
        let fixtures: Value = serde_json::from_str(raw).unwrap();
        // All 18 fixtures run — CIP gating (402/503) is ported (cip.rs); the "raise" mock
        // drives the 4 CIP cases through the gateway's error mapping.

        for case in fixtures["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let m = &case["mock"];
            let backend: Backend = Arc::new(Mock {
                kind: m["kind"].as_str().unwrap_or("none").to_string(),
                value: m.get("value").cloned().unwrap_or_else(|| json!({})),
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let app = proxy_router(backend);
            let handle = tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });

            let req = &case["request"];
            let url = format!("http://127.0.0.1:{port}{}", req["path"].as_str().unwrap());
            let client = reqwest::Client::new();
            let rb = if req["method"] == "POST" {
                client
                    .post(&url)
                    .json(req.get("body").unwrap_or(&json!({})))
            } else {
                client.get(&url)
            };
            let resp = rb.send().await.unwrap();
            let status = resp.status().as_u16() as u64;
            let server = resp
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let ctype = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let generated_by_ai = resp
                .headers()
                .get("x-iicp-generated-by-ai")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let text = resp.text().await.unwrap();
            handle.abort();

            let exp = &case["expect"];
            assert_eq!(status, exp["status"].as_u64().unwrap(), "status for {name}");
            assert_eq!(server, "iicp-proxy", "Server header for {name}");
            if status == 200 && req["method"] == "POST" {
                assert_eq!(
                    generated_by_ai.as_deref(),
                    Some("true"),
                    "AI header for {name}"
                );
            }
            if let Some(ct) = exp.get("content_type").and_then(|v| v.as_str()) {
                assert!(ctype.starts_with(ct), "content-type {ctype} for {name}");
            }
            if let Some(bp) = exp.get("body_path").and_then(|v| v.as_object()) {
                let body: Value = serde_json::from_str(&text).unwrap();
                for (p, want) in bp {
                    assert_eq!(&nav(&body, p), want, "{name} body_path {p}");
                }
            }
            if let Some(bp) = exp.get("body_prefix").and_then(|v| v.as_object()) {
                let body: Value = serde_json::from_str(&text).unwrap();
                for (p, want) in bp {
                    let got = nav(&body, p);
                    assert!(
                        got.as_str()
                            .unwrap_or("")
                            .starts_with(want.as_str().unwrap_or("")),
                        "{name} body_prefix {p}: {got}"
                    );
                }
            }
            if let Some(np) = exp.get("ndjson_last_path").and_then(|v| v.as_object()) {
                let last = text.trim().lines().last().unwrap();
                let body: Value = serde_json::from_str(last).unwrap();
                for (p, want) in np {
                    assert_eq!(&nav(&body, p), want, "{name} ndjson {p}");
                }
            }
            if let Some(se) = exp.get("sse_event_types").and_then(|v| v.as_array()) {
                let types: Vec<String> = text
                    .lines()
                    .filter_map(|l| l.strip_prefix("event: ").map(|s| s.to_string()))
                    .collect();
                let want: Vec<String> =
                    se.iter().map(|v| v.as_str().unwrap().to_string()).collect();
                assert_eq!(types, want, "{name} sse events");
            }
        }
    }
}
