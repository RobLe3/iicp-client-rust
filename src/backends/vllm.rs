// SPDX-License-Identifier: Apache-2.0
//! vLLM backend handler.
//!
//! vLLM's OpenAI server (`python -m vllm.entrypoints.openai.api_server`) speaks the
//! standard `/v1/*` dialect, so this is a thin wrapper over the shared core in
//! [`super::openai_compat`] with vLLM's default port (8000). Kept as a dedicated module
//! so operators can select `backend_type=vllm` explicitly. Port of iicp-adapter
//! `backends/vllm.py` (parity Block B, #340).

use std::time::Duration;

use serde_json::Value;

use super::openai_compat::{invoke_with_engine, OpenAiCompatOptions};

const ENGINE: &str = "vllm";

/// Default options for a local vLLM server (port 8000).
pub fn default_options() -> OpenAiCompatOptions {
    OpenAiCompatOptions {
        base_url: "http://localhost:8000/v1".into(),
        model: None,
        api_key: None,
        timeout: Duration::from_secs(30),
    }
}

/// Build a task handler closure proxying CALLs to a vLLM OpenAI server.
#[cfg(feature = "iicp-tcp")]
pub fn vllm_handler(opts: OpenAiCompatOptions) -> crate::iicp_tcp::TcpTaskHandler {
    super::openai_compat::build_handler(ENGINE, opts)
}

/// Stand-alone async invocation form (HTTP-only deployments).
pub async fn invoke(opts: &OpenAiCompatOptions, intent: &str, payload: &Value) -> Value {
    invoke_with_engine(ENGINE, opts, intent, payload).await
}
