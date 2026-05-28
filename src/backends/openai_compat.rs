// SPDX-License-Identifier: Apache-2.0
//! OpenAI-compatible backend helper (Ollama / vLLM / LM Studio / OpenAI / ...).
//!
//! Rust port of iicp-client-python `backends/openai_compat.py` (iter-1423)
//! and iicp-client-typescript `backends/openai_compat.ts` (iter-1424).
//! Final Tier 1 port of #340 — closes Tier 1 across all 3 hybrid SDKs.
//!
//! Returns a closure suitable for [`IicpTcpServer::with_handler`] or any
//! HTTP task handler expecting `(task: serde_json::Value) -> serde_json::Value`.
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use iicp_client::backends::openai_compat::openai_compat_handler;
//! use iicp_client::iicp_tcp::IicpTcpServer;
//!
//! let handler = openai_compat_handler(OpenAiCompatOptions {
//!     base_url: "http://localhost:11434/v1".into(),
//!     model: Some("qwen2.5:0.5b".into()),
//!     ..Default::default()
//! });
//! let server = IicpTcpServer::new("0.0.0.0", 9484)
//!     .with_handler(handler);
//! server.serve_forever().await?;
//! ```

#[cfg(feature = "iicp-tcp")]
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

/// Configuration for [`openai_compat_handler`].
#[derive(Debug, Clone)]
pub struct OpenAiCompatOptions {
    /// Provider HTTP root (no trailing slash needed). Default: Ollama
    /// `http://localhost:11434/v1`.
    pub base_url: String,
    /// Default model name. If [`None`], the task payload MUST include `model`.
    pub model: Option<String>,
    /// Bearer token for the provider. Empty for local Ollama / vLLM.
    pub api_key: Option<String>,
    /// Per-request HTTP timeout.
    pub timeout: Duration,
}

impl Default for OpenAiCompatOptions {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:11434/v1".into(),
            model: None,
            api_key: None,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Map IICP intent URN → OpenAI-compatible HTTP path.
fn intent_to_path(intent: &str) -> Option<&'static str> {
    match intent {
        "urn:iicp:intent:llm:chat:v1" => Some("/chat/completions"),
        "urn:iicp:intent:llm:completion:v1" => Some("/completions"),
        "urn:iicp:intent:llm:embedding:v1" => Some("/embeddings"),
        _ => None,
    }
}

/// All supported intent URNs (for error messages).
pub const SUPPORTED_INTENTS: &[&str] = &[
    "urn:iicp:intent:llm:chat:v1",
    "urn:iicp:intent:llm:completion:v1",
    "urn:iicp:intent:llm:embedding:v1",
];

/// Build a task handler closure that proxies CALLs to an OpenAI-compatible
/// HTTP server. Returns an `Arc<dyn Fn>` matching the [`TcpTaskHandler`]
/// shape used by `IicpTcpServer`.
///
/// The closure inspects the incoming task's `intent` field to pick the path
/// and forwards `payload` as the JSON body. Returned `serde_json::Value`
/// is either `{"result": <upstream JSON>}` on success or
/// `{"error_code": int, "error_message": str}` on failure.
#[cfg(feature = "iicp-tcp")]
pub fn openai_compat_handler(opts: OpenAiCompatOptions) -> crate::iicp_tcp::TcpTaskHandler {
    build_handler("openai_compat", opts)
}

/// Shared handler builder used by every engine module (openai_compat / vllm /
/// llamacpp). `engine` is the label that appears in error messages.
#[cfg(feature = "iicp-tcp")]
pub(crate) fn build_handler(
    engine: &'static str,
    opts: OpenAiCompatOptions,
) -> crate::iicp_tcp::TcpTaskHandler {
    let opts = Arc::new(opts);
    Arc::new(move |task| {
        let opts = Arc::clone(&opts);
        Box::pin(async move { handle_task(engine, opts, task).await })
    })
}

/// Stand-alone async function form. Useful for HTTP-only deployments that
/// don't enable the `iicp-tcp` feature but still want to plug this handler
/// into their own task pipeline.
pub async fn invoke(opts: &OpenAiCompatOptions, intent: &str, payload: &Value) -> Value {
    invoke_with_engine("openai_compat", opts, intent, payload).await
}

/// Engine-labelled variant of [`invoke`], shared by the vllm / llamacpp modules.
pub(crate) async fn invoke_with_engine(
    engine: &'static str,
    opts: &OpenAiCompatOptions,
    intent: &str,
    payload: &Value,
) -> Value {
    let task = Task {
        task_id: String::new(),
        intent: intent.to_string(),
        payload: payload.clone(),
    };
    handle_task_inner(engine, opts.clone(), task).await
}

/// Lightweight task struct used by [`invoke`]. Kept private (the iicp_tcp
/// `TcpTask` is the public shape; this is just a glue type for HTTP callers).
struct Task {
    task_id: String,
    intent: String,
    payload: Value,
}

#[cfg(feature = "iicp-tcp")]
async fn handle_task(
    engine: &'static str,
    opts: Arc<OpenAiCompatOptions>,
    task: crate::iicp_tcp::TcpTask,
) -> Value {
    handle_task_inner(
        engine,
        (*opts).clone(),
        Task {
            task_id: task.task_id,
            intent: task.intent,
            payload: task.payload,
        },
    )
    .await
}

async fn handle_task_inner(engine: &'static str, opts: OpenAiCompatOptions, task: Task) -> Value {
    let _ = task.task_id;
    let intent = task.intent;
    let payload = task.payload;

    let path = match intent_to_path(&intent) {
        Some(p) => p,
        None => {
            return json!({
                "error_code": 400,
                "error_message": format!(
                    "{}: unsupported intent {:?}; supported: {:?}",
                    engine, intent, SUPPORTED_INTENTS
                ),
            });
        }
    };

    let mut body = match payload {
        Value::Object(o) => o,
        Value::Null => serde_json::Map::new(),
        other => {
            return json!({
                "error_code": 400,
                "error_message": format!(
                    "{}: task.payload must be a JSON object, got {}",
                    engine,
                    type_name(&other)
                ),
            });
        }
    };

    // Inject factory-default model when the task payload didn't set one.
    if !body.contains_key("model") {
        if let Some(m) = &opts.model {
            body.insert("model".into(), json!(m));
        }
    }
    if body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        return json!({
            "error_code": 400,
            "error_message": format!(
                "{}: no model — either pass `model` to the backend options \
                 or include `model` in the task payload",
                engine
            ),
        });
    }

    let base = opts.base_url.trim_end_matches('/');
    let url = format!("{base}{path}");

    let mut req = match reqwest::Client::builder().timeout(opts.timeout).build() {
        Ok(c) => c.post(&url).json(&Value::Object(body)),
        Err(e) => {
            return json!({
                "error_code": 500,
                "error_message": format!("{engine}: client build failed: {e}"),
            });
        }
    };
    if let Some(key) = &opts.api_key {
        if !key.is_empty() {
            req = req.bearer_auth(key);
        }
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) if e.is_timeout() => {
            return json!({"error_code": 408, "error_message": format!("{engine}: backend timed out")});
        }
        Err(e) => {
            return json!({
                "error_code": 502,
                "error_message": format!("{engine}: HTTP transport error: {e}"),
            });
        }
    };

    let status = resp.status().as_u16();
    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let truncated: String = text.chars().take(512).collect();
        return json!({
            "error_code": status,
            "error_message": format!("{engine}: upstream {status}: {truncated}"),
        });
    }

    match resp.json::<Value>().await {
        Ok(data) => json!({"result": data}),
        Err(e) => json!({
            "error_code": 502,
            "error_message": format!("{engine}: upstream returned non-JSON: {e}"),
        }),
    }
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
