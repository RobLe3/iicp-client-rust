// SPDX-License-Identifier: Apache-2.0
//! Drop-in backend handlers for iicp-client.
//!
//! Each helper returns a closure suitable for use as the task handler in
//! `IicpNode::serve()` or as the `TcpTaskHandler` for `IicpTcpServer`.
//!
//! - [`openai_compat`] — drives Ollama, LM Studio, or any OpenAI-compatible
//!   HTTP server.
//! - [`vllm`] — vLLM OpenAI server (default port 8000).
//! - [`llamacpp`] — llama.cpp `llama-server` (default port 8080).
//! - [`anthropic`] — native Anthropic Messages API (`POST /v1/messages`) for
//!   first-class Claude. Translates the IICP chat task ↔ Messages API so a
//!   Claude-backed node looks identical to an Ollama/vLLM node to clients.
//!
//! Use [`invoke_backend`] to dispatch by engine name (e.g. from a CLI
//! `--backend-type` flag). Valid names are listed in [`BACKEND_TYPES`].

pub mod anthropic;
pub mod llamacpp;
pub mod meshllm;
pub mod openai_compat;
pub mod vllm;

use serde_json::Value;

use crate::service_lifecycle::BackendCancellationRegistry;
use openai_compat::OpenAiCompatOptions;

/// Selectable backend engine names (mirrors the Python/TS `BACKEND_TYPES`).
pub const BACKEND_TYPES: &[&str] = &["openai_compat", "vllm", "llamacpp", "meshllm", "anthropic"];

/// Dispatch a stand-alone (HTTP-style) invocation to the named engine.
///
/// Returns `Err` with the offending name when `backend_type` is unknown so the
/// caller can surface a clear CLI error. Each engine shares the OpenAI dialect;
/// the only difference is the label in error messages and the per-engine default
/// port the caller may have applied to `opts.base_url`.
pub async fn invoke_backend(
    backend_type: &str,
    opts: &OpenAiCompatOptions,
    intent: &str,
    payload: &Value,
) -> Result<Value, String> {
    match backend_type {
        "openai_compat" => Ok(openai_compat::invoke(opts, intent, payload).await),
        "vllm" => Ok(vllm::invoke(opts, intent, payload).await),
        "llamacpp" => Ok(llamacpp::invoke(opts, intent, payload).await),
        "meshllm" => Ok(meshllm::invoke(opts, intent, payload).await),
        "anthropic" => Ok(anthropic::invoke(opts, intent, payload).await),
        other => Err(format!(
            "unknown backend_type {other:?}; choose one of {BACKEND_TYPES:?}"
        )),
    }
}

/// Opt-in lifecycle bridge for a backend invocation.
///
/// Aborting the HTTP future proves only that the transport request was
/// cancelled. It does not claim that the model runtime stopped execution.
pub async fn invoke_backend_with_cancellation(
    task_id: &str,
    registry: &BackendCancellationRegistry,
    backend_type: &str,
    opts: &OpenAiCompatOptions,
    intent: &str,
    payload: &Value,
) -> Result<Value, String> {
    let backend_type_owned = backend_type.to_owned();
    let opts_owned = opts.clone();
    let intent_owned = intent.to_owned();
    let payload_owned = payload.clone();
    let handle = tokio::spawn(async move {
        invoke_backend(
            &backend_type_owned,
            &opts_owned,
            &intent_owned,
            &payload_owned,
        )
        .await
    });
    let abort = handle.abort_handle();
    registry.register(task_id, move || {
        abort.abort();
        true
    });
    let result = match handle.await {
        Ok(result) => result,
        Err(error) if error.is_cancelled() => {
            registry
                .report(task_id, "transport_aborted")
                .expect("known cancellation evidence");
            Ok(serde_json::json!({
                "error_code": 499,
                "error_message": "backend request cancelled"
            }))
        }
        Err(error) => Err(format!("backend task join error: {error}")),
    };
    registry.complete(task_id);
    result
}
