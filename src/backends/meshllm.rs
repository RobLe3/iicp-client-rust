// SPDX-License-Identifier: Apache-2.0
//! MeshLLM local OpenAI-compatible backend.
//!
//! IICP uses MeshLLM only through its local `http://localhost:9337/v1` HTTP
//! interface. Its distributed topology and control plane remain outside IICP.
//! The stable profile intentionally accepts `llm:chat:v1` only.

use std::time::Duration;

use serde_json::{json, Value};

use super::openai_compat::{invoke_with_engine, OpenAiCompatOptions};

const ENGINE: &str = "meshllm";
const CHAT_INTENT: &str = "urn:iicp:intent:llm:chat:v1";

/// Default options for a local MeshLLM gateway.
pub fn default_options() -> OpenAiCompatOptions {
    OpenAiCompatOptions {
        base_url: "http://localhost:9337/v1".into(),
        model: None,
        api_key: None,
        timeout: Duration::from_secs(30),
    }
}

/// Stand-alone invocation form for the stable MeshLLM chat profile.
pub async fn invoke(opts: &OpenAiCompatOptions, intent: &str, payload: &Value) -> Value {
    if intent != CHAT_INTENT {
        return json!({
            "error_code": 400,
            "error_message": "MeshLLM stable backend supports llm:chat:v1 only"
        });
    }
    invoke_with_engine(ENGINE, opts, intent, payload).await
}
