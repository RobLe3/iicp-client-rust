// SPDX-License-Identifier: Apache-2.0
// Rust SDK client — deferred until Python/TypeScript SDKs are stable.
// Scaffolding only; not yet functional.
// See: https://github.com/RobLe3/iicp-client-rust

use crate::errors::{IicpError, Result};
use crate::http::HttpClient;
use crate::types::*;

const INTENT_RE: &str = r"^urn:iicp:intent:[a-z0-9_:/-]+$";
const MAX_TIMEOUT_MS: u64 = 120_000;

/// IICP client — discover → select → submit (ADR-016 §1).
pub struct IicpClient {
    config: ClientConfig,
    http: HttpClient,
}

impl IicpClient {
    /// Construct a client from config. Enforces SDK-04 (timeout_ms ≤ 120 000).
    pub fn new(config: ClientConfig) -> Result<Self> {
        if config.timeout_ms > MAX_TIMEOUT_MS {
            return Err(IicpError::TimeoutTooLarge(config.timeout_ms));
        }
        let http = HttpClient::new(config.timeout_ms, config.node_token.clone())?;
        Ok(Self { config, http })
    }

    /// Discover nodes for *intent* (SDK-01).
    pub async fn discover(&self, intent: &str, opts: Option<DiscoverOptions>) -> Result<NodeList> {
        self.validate_intent(intent)?;
        let opts = opts.unwrap_or_default();
        let mut url = format!(
            "{}/v1/discover?intent={}",
            self.config.directory_url, intent
        );
        if let Some(region) = opts.region.as_ref().or(self.config.region.as_ref()) {
            url.push_str(&format!("&region={}", region));
        }
        if let Some(model) = &opts.model {
            url.push_str(&format!("&model={}", model));
        }
        if let Some(rep) = opts.min_reputation {
            url.push_str(&format!("&min_reputation={}", rep));
        }
        url.push_str(&format!("&limit={}", opts.limit.unwrap_or(10)));
        self.http.get_json(&url).await
    }

    /// Submit an arbitrary task to a node (SDK-02: auto-generates task_id).
    pub async fn submit(&self, node: &Node, mut request: TaskRequest) -> Result<TaskResponse> {
        if request.task_id.is_empty() {
            request.task_id = uuid::Uuid::new_v4().to_string();
        }
        self.http
            .post_json(&format!("{}/v1/task", node.endpoint), &request, None)
            .await
    }

    /// High-level chat helper — builds an LLM chat task and submits it.
    pub async fn chat(
        &self,
        node: &Node,
        messages: Vec<ChatMessage>,
        opts: Option<ChatOptions>,
    ) -> Result<ChatResponse> {
        let opts = opts.unwrap_or_default();
        let request = TaskRequest {
            task_id: uuid::Uuid::new_v4().to_string(),
            intent: "urn:iicp:intent:llm:chat:v1".into(),
            payload: serde_json::json!({
                "model": opts.model.as_deref().unwrap_or(""),
                "messages": messages,
            }),
            constraints: Some(TaskConstraints {
                timeout_ms: opts.timeout_ms,
                max_tokens: opts.max_tokens,
                model: opts.model,
            }),
            auth: None,
        };
        let task_resp = self.submit(node, request).await?;
        let result = task_resp.result.ok_or_else(|| IicpError::Protocol {
            code: "no_result".into(),
            message: "Node returned task without a result".into(),
            status: 200,
        })?;
        Ok(serde_json::from_value(result)?)
    }

    fn validate_intent(&self, intent: &str) -> Result<()> {
        let re = regex::Regex::new(INTENT_RE).expect("valid regex");
        if !re.is_match(intent) {
            return Err(IicpError::InvalidIntent(intent.into()));
        }
        Ok(())
    }
}
