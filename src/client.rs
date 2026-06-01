// SPDX-License-Identifier: Apache-2.0
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;

use crate::errors::{IicpError, Result};
use crate::http::{make_traceparent, HttpClient};
use crate::types::*;

// Compiled once at first use — avoid per-call allocation (fix: rust#3).
static INTENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^urn:iicp:intent:[a-z0-9_:/-]+$").unwrap());

const MAX_TIMEOUT_MS: u64 = 120_000;
const MAX_RETRIES: u32 = 3;

/// SSRF guard: return true only if url is safe to use as a node endpoint (#388).
fn is_ssrf_safe(url: &str) -> bool {
    let lower = url.to_lowercase();
    let rest = if let Some(s) = lower.strip_prefix("https://") {
        s
    } else if let Some(s) = lower.strip_prefix("http://") {
        s
    } else {
        return false;
    };

    // Extract host — handles IPv6 [addr]:port and plain host:port/path
    let host = if rest.starts_with('[') {
        rest.split(']').next().map(|s| s.trim_start_matches('[')).unwrap_or("")
    } else {
        rest.split('/').next().unwrap_or("").split(':').next().unwrap_or("")
    };

    if host.is_empty() {
        return false;
    }
    if matches!(host, "localhost" | "0.0.0.0" | "::1" | "::") {
        return false;
    }
    const BLOCKED_SUFFIXES: &[&str] = &[".local", ".internal", ".lan", ".test", ".invalid", ".localhost"];
    if BLOCKED_SUFFIXES.iter().any(|s| host.ends_with(s)) {
        return false;
    }
    // Bare hostname (no dot and no colon = Docker service name; IPv6 has colons)
    if !host.contains('.') && !host.contains(':') {
        return false;
    }
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        match addr {
            std::net::IpAddr::V4(v4) => {
                if v4.is_loopback() || v4.is_private() || v4.is_link_local()
                    || v4.is_broadcast() || v4.is_unspecified()
                {
                    return false;
                }
                let o = v4.octets();
                if o[0] == 100 && (64..=127).contains(&o[1]) {
                    return false; // CGNAT 100.64/10
                }
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_multicast() || v6.is_unspecified() {
                    return false;
                }
            }
        }
    }
    true
}

/// Reject model/region strings containing query-separator or newline characters (#388 §FINDING-4-5).
fn is_safe_query_param(s: &str) -> bool {
    !s.contains(['&', '=', '\n', '\r', '\0'])
}

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

    /// Discover nodes for *intent* (SDK-01). Accepts an optional traceparent for propagation.
    pub async fn discover(
        &self,
        intent: &str,
        opts: Option<DiscoverOptions>,
        traceparent: Option<&str>,
    ) -> Result<NodeList> {
        self.validate_intent(intent)?;
        let opts = opts.unwrap_or_default();
        let mut url = format!(
            "{}/api/v1/discover?intent={}",
            self.config.directory_url, intent
        );
        if let Some(region) = opts.region.as_ref().or(self.config.region.as_ref()) {
            if is_safe_query_param(region) {
                url.push_str(&format!("&region={region}"));
            }
        }
        if let Some(model) = &opts.model {
            if is_safe_query_param(model) {
                url.push_str(&format!("&model={model}"));
            }
        }
        if let Some(rep) = opts.min_reputation {
            url.push_str(&format!("&min_reputation={rep}"));
        }
        url.push_str(&format!("&limit={}", opts.limit.unwrap_or(10)));
        self.http.get_json(&url, traceparent).await
    }

    /// Discover → select best node → submit task (SDK-01/02).
    /// Retries up to MAX_RETRIES on transient errors (SDK-05).
    /// Generates one W3C traceparent shared across discover + POST (SDK-06).
    pub async fn submit(&self, mut request: TaskRequest) -> Result<TaskResponse> {
        self.validate_intent(&request.intent)?;
        if request.task_id.is_empty() {
            request.task_id = uuid::Uuid::new_v4().to_string();
        }

        let tp = make_traceparent(); // SDK-06: shared across discover + node POST
        let nodes = self.discover(&request.intent, None, Some(&tp)).await?;
        let node = nodes
            .nodes
            .into_iter()
            .filter(|n| {
                if !is_ssrf_safe(&n.endpoint) {
                    eprintln!(
                        "[iicp-client] SSRF guard: skipping node {} — endpoint {} is not publicly routable",
                        &n.node_id[..n.node_id.len().min(8)],
                        n.endpoint
                    );
                    false
                } else {
                    true
                }
            })
            .find(|n| n.available)
            .ok_or_else(|| IicpError::NoNodes {
                intent: request.intent.clone(),
            })?;

        let mut last_err: Option<IicpError> = None;
        for attempt in 0..MAX_RETRIES {
            match self
                .http
                .post_json(
                    &format!("{}/v1/task", node.endpoint),
                    &request,
                    None,
                    Some(&tp),
                )
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
        let mut payload = serde_json::json!({ "messages": messages });
        if let Some(ref model) = opts.model {
            payload["model"] = serde_json::Value::String(model.clone());
        }
        if let Some(temp) = opts.temperature {
            payload["temperature"] = serde_json::json!(temp);
        }
        let request = TaskRequest {
            task_id: uuid::Uuid::new_v4().to_string(),
            intent: "urn:iicp:intent:llm:chat:v1".into(),
            payload,
            constraints: Some(TaskConstraints {
                timeout_ms: opts.timeout_ms,
                max_tokens: opts.max_tokens,
                model: opts.model,
            }),
            auth: None,
        };
        let task_resp = self.submit(request).await?;
        let node_id = task_resp.metrics.as_ref().and_then(|m| m.node_id.clone());
        let task_id = task_resp.task_id.clone();
        let result = task_resp.result.ok_or_else(|| IicpError::Protocol {
            code: "no_result".into(),
            message: "Node returned task without a result payload".into(),
            status: 200,
        })?;
        let mut resp: ChatResponse = serde_json::from_value(result)?;
        resp.task_id = task_id;
        resp.node_id = node_id;
        Ok(resp)
    }

    fn validate_intent(&self, intent: &str) -> Result<()> {
        if !INTENT_RE.is_match(intent) {
            return Err(IicpError::InvalidIntent(intent.into()));
        }
        Ok(())
    }
}
