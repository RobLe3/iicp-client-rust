// SPDX-License-Identifier: Apache-2.0
//! llama.cpp backend handler.
//!
//! The `llama-server` binary exposes an OpenAI-compatible `/v1/*` API, so this is a thin
//! wrapper over the shared core in [`super::openai_compat`] with llama.cpp's default port
//! (8080). Kept as a dedicated module so operators can select `backend_type=llamacpp`
//! explicitly. Port of iicp-adapter `backends/llamacpp.py` (parity Block B, #340).

use std::time::Duration;

use serde_json::Value;

use super::openai_compat::{invoke_with_engine, OpenAiCompatOptions};

const ENGINE: &str = "llamacpp";

/// Default options for a local llama.cpp `llama-server` (port 8080).
pub fn default_options() -> OpenAiCompatOptions {
    OpenAiCompatOptions {
        base_url: "http://localhost:8080/v1".into(),
        model: None,
        api_key: None,
        timeout: Duration::from_secs(30),
    }
}

/// Build a task handler closure proxying CALLs to a llama.cpp `llama-server`.
#[cfg(feature = "iicp-tcp")]
pub fn llamacpp_handler(opts: OpenAiCompatOptions) -> crate::iicp_tcp::TcpTaskHandler {
    super::openai_compat::build_handler(ENGINE, opts)
}

/// Stand-alone async invocation form (HTTP-only deployments).
pub async fn invoke(opts: &OpenAiCompatOptions, intent: &str, payload: &Value) -> Value {
    invoke_with_engine(ENGINE, opts, intent, payload).await
}
