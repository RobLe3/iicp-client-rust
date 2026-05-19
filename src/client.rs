// SPDX-License-Identifier: Apache-2.0
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;

use crate::errors::{IicpError, Result};
use crate::http::HttpClient;
use crate::types::*;

// Compiled once at first use — avoid per-call allocation (fix: rust#3).
static INTENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^urn:iicp:intent:[a-z0-9_:/-]+$").unwrap());

const MAX_TIMEOUT_MS: u64 = 120_000;
const MAX_RETRIES: u32 = 3;

/// IICP client — discover → select → submit (ADR-016 §1).
pub struct IicpClient {
    config: ClientConfig,
    http: HttpClient,
}

impl IicpClient {
    /// Construct a client. Enforces SDK-04 (timeout_ms ≤ 120 000).
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
            "{}/api/v1/discover?intent={}",
            self.config.directory_url, intent
        );
        if let Some(region) = opts.region.as_ref().or(self.config.region.as_ref()) {
            url.push_str(&format!("&region={region}"));
        }
        if let Some(model) = &opts.model {
            url.push_str(&format!("&model={model}"));
        }
        if let Some(rep) = opts.min_reputation {
            url.push_str(&format!("&min_reputation={rep}"));
        }
        url.push_str(&format!("&limit={}", opts.limit.unwrap_or(10)));
        self.http.get_json(&url).await
    }

    /// Discover → select best node → submit task (SDK-01/02).
    /// Retries up to MAX_RETRIES on transient errors (SDK-05).
    pub async fn submit(&self, mut request: TaskRequest) -> Result<TaskResponse> {
        self.validate_intent(&request.intent)?;
        if request.task_id.is_empty() {
            request.task_id = uuid::Uuid::new_v4().to_string();
        }

        let nodes = self.discover(&request.intent, None).await?;
        let node = nodes
            .nodes
            .into_iter()
            .find(|n| n.available)
            .ok_or_else(|| IicpError::NoNodes { intent: request.intent.clone() })?;

        let mut last_err: Option<IicpError> = None;
        for attempt in 0..MAX_RETRIES {
            match self
                .http
                .post_json(&format!("{}/v1/task", node.endpoint), &request, None)
                .await
            {
                Ok(resp) => return Ok(resp),
                Err(e) if e.is_transient() && attempt < MAX_RETRIES - 1 => {
                    tokio::time::sleep(Duration::from_millis(200 * 2u64.pow(attempt))).await;
                    last_err = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap())
    }

    /// Discover → select best LLM node → submit chat task (SDK-02).
    pub async fn chat(
        &self,
        messages: Vec<ChatMessage>,
        opts: Option<ChatOptions>,
    ) -> Result<ChatResponse> {
        let opts = opts.unwrap_or_default();
        let request = TaskRequest {
            task_id: uuid::Uuid::new_v4().to_string(),
            intent: "urn:iicp:intent:llm:chat:v1".into(),
            payload: serde_json::json!({
                "messages": messages,
                "model": opts.model.as_deref().unwrap_or(""),
            }),
            constraints: Some(TaskConstraints {
                timeout_ms: opts.timeout_ms,
                max_tokens: opts.max_tokens,
                model: opts.model,
            }),
            auth: None,
        };
        let task_resp = self.submit(request).await?;
        let result = task_resp.result.ok_or_else(|| IicpError::Protocol {
            code: "no_result".into(),
            message: "Node returned task without a result payload".into(),
            status: 200,
        })?;
        Ok(serde_json::from_value(result)?)
    }

    fn validate_intent(&self, intent: &str) -> Result<()> {
        if !INTENT_RE.is_match(intent) {
            return Err(IicpError::InvalidIntent(intent.into()));
        }
        Ok(())
    }
}
