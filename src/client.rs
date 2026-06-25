// SPDX-License-Identifier: Apache-2.0
use std::sync::LazyLock;
use std::time::Duration;

use rand::Rng;
use regex::Regex;

use crate::confidentiality::encrypt_payload;
use crate::consumer_token::{acquire_consumer_token, ConsumerTokenCache};
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
        rest.split(']')
            .next()
            .map(|s| s.trim_start_matches('['))
            .unwrap_or("")
    } else {
        rest.split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
    };

    if host.is_empty() {
        return false;
    }
    // Dev/test escape hatch (default OFF): allow loopback/private node endpoints so a
    // node + proxy can run on one host (local mesh) and for E2E tests. NEVER enable in
    // production — it re-opens the SSRF surface this guard exists to close.
    if matches!(
        std::env::var("IICP_PROXY_ALLOW_LOOPBACK_NODES")
            .as_deref()
            .map(str::trim),
        Ok("1") | Ok("true") | Ok("yes")
    ) {
        return true;
    }
    if matches!(host, "localhost" | "0.0.0.0" | "::1" | "::") {
        return false;
    }
    const BLOCKED_SUFFIXES: &[&str] = &[
        ".local",
        ".internal",
        ".lan",
        ".test",
        ".invalid",
        ".localhost",
    ];
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
                if v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
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

fn is_browser_usable_endpoint(url: &str) -> bool {
    let lower = url.to_lowercase();
    if lower.starts_with("https://") {
        return true;
    }
    if !lower.starts_with("http://") {
        return false;
    }

    let host = if let Some(rest) = lower.strip_prefix("http://") {
        if rest.starts_with('[') {
            rest.split(']')
                .next()
                .map(|s| s.trim_start_matches('['))
                .unwrap_or("")
        } else {
            rest.split('/')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("")
        }
    } else {
        ""
    };

    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Reject model/region strings containing query-separator or newline characters (#388 §FINDING-4-5).
fn is_safe_query_param(s: &str) -> bool {
    !s.contains(['&', '=', '\n', '\r', '\0'])
}

/// IICP client — discover → select → submit (ADR-016 §1).
pub struct IicpClient {
    config: ClientConfig,
    http: HttpClient,
    /// Phase 2 (#496): in-process consumer token cache.
    ct_cache: ConsumerTokenCache,
}

impl IicpClient {
    /// Construct a client. Enforces SDK-04 (timeout_ms ≤ 120 000).
    pub fn new(config: ClientConfig) -> Result<Self> {
        if config.timeout_ms > MAX_TIMEOUT_MS {
            return Err(IicpError::TimeoutTooLarge(config.timeout_ms));
        }
        let http = HttpClient::new(config.timeout_ms, config.node_token.clone())?;
        Ok(Self {
            config,
            http,
            ct_cache: ConsumerTokenCache::new(),
        })
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
        let base = self.config.directory_url.trim_end_matches('/');
        let mut url = format!("{base}/v1/discover?intent={intent}");
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
        let mut list: NodeList = self.http.get_json(&url, traceparent).await?;
        if opts.browser_usable_only.unwrap_or(false) {
            list.nodes.retain(|n| {
                n.browser_usable
                    .unwrap_or_else(|| is_browser_usable_endpoint(&n.endpoint))
            });
            list.count = list.nodes.len() as u32;
        }

        Ok(list)
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
        // Filter to safe, available nodes before candidate selection.
        let safe_nodes: Vec<_> = nodes
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
            .filter(|n| n.available)
            .collect();

        let candidates: Vec<_> = {
            let mut rng = rand::thread_rng();
            let max_retries = MAX_RETRIES as usize;
            if self.config.routing_strategy == "deterministic" || safe_nodes.len() <= 1 {
                safe_nodes.into_iter().take(max_retries).collect()
            } else if self.config.routing_strategy == "softmax_top_k" {
                let top_k = self.config.routing_top_k.max(1).min(safe_nodes.len());
                let pool = &safe_nodes[..top_k];
                let max_score = pool
                    .iter()
                    .map(|n| n.score)
                    .fold(f64::NEG_INFINITY, f64::max);
                let tau = self.config.routing_softmax_tau.max(0.001);
                let weights: Vec<f64> = pool
                    .iter()
                    .map(|n| ((n.score - max_score) / tau).exp())
                    .collect();
                let total: f64 = weights.iter().sum();
                let mut r = rng.gen::<f64>() * total;
                let mut chosen = pool[0].clone();
                for (node, weight) in pool.iter().zip(weights.iter()) {
                    r -= weight;
                    if r <= 0.0 {
                        chosen = node.clone();
                        break;
                    }
                }
                let mut c = vec![chosen.clone()];
                c.extend(
                    safe_nodes
                        .iter()
                        .take(max_retries)
                        .filter(|n| n.node_id != chosen.node_id)
                        .take(max_retries - 1)
                        .cloned(),
                );
                c
            } else if rng.gen::<f64>() < self.config.routing_epsilon {
                let explore_idx = rng.gen_range(0..safe_nodes.len());
                let explore_node = safe_nodes[explore_idx].clone();
                let mut c = vec![explore_node.clone()];
                c.extend(
                    safe_nodes
                        .iter()
                        .take(max_retries)
                        .filter(|n| n.node_id != explore_node.node_id)
                        .take(max_retries - 1)
                        .cloned(),
                );
                c
            } else {
                safe_nodes.into_iter().take(max_retries).collect()
            }
        };

        if candidates.is_empty() {
            return Err(IicpError::NoNodes {
                intent: request.intent.clone(),
            });
        }

        let mut last_err: Option<IicpError> = None;

        'nodes: for node in &candidates {
            // Phase 2 (#496): acquire directory-issued consumer token when caller has identity.
            let consumer_token: Option<String> = if let Some(ref tok) = self.config.node_token {
                acquire_consumer_token(
                    &self.ct_cache,
                    self.http.inner(),
                    &self.config.directory_url,
                    tok,
                    &node.node_id,
                    &request.intent,
                    5.0,
                )
                .await
            } else {
                None
            };

            // IICP-CX S.16: encryption is MANDATORY (privacy-first #360) — no opt-out.
            // Always encrypt when the node advertises a cx_public_key. During the migration
            // window (#532) a node with no key yet gets a loud warning + plaintext; fail-closed
            // at P0b once the mesh is key-ready. use_confidentiality no longer gates this.
            let body: serde_json::Value = if let Some(ref cx_key) = node.cx_public_key {
                let iicp_conf =
                    encrypt_payload(&request.payload, cx_key, &request.task_id, &request.intent)?;
                let mut body = serde_json::to_value(&request)?;
                if let Some(obj) = body.as_object_mut() {
                    obj.remove("payload");
                    obj.insert("iicp_conf".to_string(), serde_json::to_value(iicp_conf)?);
                }
                body
            } else {
                eprintln!(
                    "[iicp-cx] node {} advertises no encryption key — sending UNENCRYPTED \
                     (transitional; will be refused once the mesh is key-ready).",
                    node.node_id
                );
                serde_json::to_value(&request)?
            };

            for attempt in 0..MAX_RETRIES {
                match self
                    .http
                    .post_json_ct(
                        &format!("{}/v1/task", node.endpoint),
                        &body,
                        None,
                        consumer_token.as_deref(),
                        Some(&tp),
                    )
                    .await
                {
                    Ok(resp) => return Ok(resp),
                    Err(e) => {
                        last_err = Some(e);
                        let err = last_err.as_ref().unwrap();
                        if !err.is_transient() {
                            return Err(last_err.unwrap()); // hard failure, don't retry
                        }
                        // Network/connection error → try next node immediately
                        if matches!(err, IicpError::Http(_)) {
                            continue 'nodes;
                        }
                        // Server 5xx → retry same node with backoff
                        if attempt < MAX_RETRIES - 1 {
                            tokio::time::sleep(Duration::from_millis(200 * 2u64.pow(attempt)))
                                .await;
                        }
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| IicpError::NoNodes {
            intent: request.intent.clone(),
        }))
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
            source_node_id: None,
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
