// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

/// Client configuration (SDK-04: timeout_ms enforced at construction time).
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub directory_url: String,
    /// Maximum request timeout in milliseconds. Must be ≤ 120 000 (SDK-04).
    pub timeout_ms: u64,
    pub region: Option<String>,
    pub node_token: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            directory_url: "https://iicp.network/api".into(),
            timeout_ms: 30_000,
            region: None,
            node_token: None,
        }
    }
}

/// Options for `discover()` calls.
#[derive(Debug, Default, Clone)]
pub struct DiscoverOptions {
    pub region: Option<String>,
    pub model: Option<String>,
    pub min_reputation: Option<f64>,
    pub limit: Option<u32>,
}

/// A single IICP node returned by `/v1/discover`.
#[derive(Debug, Clone, Deserialize)]
pub struct Node {
    pub node_id: String,
    pub endpoint: String,
    pub score: f64,
    pub available: bool,
    pub region: String,
    pub models: Option<Vec<String>>,
    pub cip_policy: Option<CipPolicy>,
}

/// CIP policy block from the discover response.
#[derive(Debug, Clone, Deserialize)]
pub struct CipPolicy {
    pub allow_remote_inference: bool,
}

/// Response from `/v1/discover`.
#[derive(Debug, Clone, Deserialize)]
pub struct NodeList {
    pub nodes: Vec<Node>,
    pub count: u32,
}

/// IICP task request body.
#[derive(Debug, Clone, Serialize)]
pub struct TaskRequest {
    pub task_id: String,
    pub intent: String,
    pub payload: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<TaskConstraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<TaskAuth>,
}

/// Constraints block for a task request.
#[derive(Debug, Clone, Serialize)]
pub struct TaskConstraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Auth block for a task request.
#[derive(Debug, Clone, Serialize)]
pub struct TaskAuth {
    pub token: String,
}

/// Response from `POST /v1/task`.
#[derive(Debug, Clone, Deserialize)]
pub struct TaskResponse {
    pub task_id: String,
    pub status: String,
    pub result: Option<serde_json::Value>,
    pub metrics: Option<TaskMetrics>,
}

/// Task execution metrics.
#[derive(Debug, Clone, Deserialize)]
pub struct TaskMetrics {
    pub latency_ms: Option<f64>,
    pub tokens_used: Option<u32>,
}

/// A single chat message (role + content).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// Options for `chat()` calls.
#[derive(Debug, Default, Clone)]
pub struct ChatOptions {
    pub model: Option<String>,
    pub max_tokens: Option<u32>,
    pub timeout_ms: Option<u64>,
}

/// OpenAI-compatible chat completion response.
#[derive(Debug, Clone, Deserialize)]
pub struct ChatResponse {
    pub choices: Vec<ChatChoice>,
    pub usage: Option<ChatUsage>,
}

/// A single choice in a chat response.
#[derive(Debug, Clone, Deserialize)]
pub struct ChatChoice {
    pub message: ChatMessage,
    pub finish_reason: Option<String>,
}

/// Token usage from a chat completion.
#[derive(Debug, Clone, Deserialize)]
pub struct ChatUsage {
    pub total_tokens: Option<u32>,
    pub prompt_tokens: Option<u32>,
    pub completion_tokens: Option<u32>,
}
