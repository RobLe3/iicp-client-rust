// SPDX-License-Identifier: Apache-2.0
use std::sync::LazyLock;
use std::time::Duration;

use rand::Rng;
use regex::Regex;

use crate::confidentiality::{decrypt_response, encrypt_payload_with_context};
use crate::consumer_token::{acquire_consumer_token, ConsumerTokenCache};
use crate::dispatch_ticket::{policy_manifest_binding_matches, verify_dispatch_route_ticket};
use crate::errors::{IicpError, Result};
use crate::http::{make_traceparent, HttpClient};
use crate::policy::ensure_intent_allowed;
use crate::request_projection::project_route_options;
use crate::routing_policy::{
    filter_nodes_for_routing_policy, resolved_policy, routing_policy_refusal_message,
    ROUTING_POLICY_REFUSAL_CODE,
};
use crate::selection::weighted_v1_index;
use crate::types::*;

// Compiled once at first use — avoid per-call allocation (fix: rust#3).
static INTENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^urn:iicp:intent:[a-z0-9_:/-]+$").unwrap());

const MAX_TIMEOUT_MS: u64 = 120_000;
const MAX_RETRIES: u32 = 3;

enum TicketRouteError {
    LegacyRequired,
    Iicp(IicpError),
}

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

fn cx_plaintext_fallback_allowed() -> bool {
    std::env::var("IICP_CX_ALLOW_PLAINTEXT")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn node_short_id(node_id: &str) -> &str {
    &node_id[..node_id.len().min(8)]
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
    dispatch_ticket_key: std::sync::Mutex<Option<String>>,
}

impl IicpClient {
    /// Construct a client. Enforces SDK-04 (timeout_ms ≤ 120 000).
    pub fn new(config: ClientConfig) -> Result<Self> {
        if config.timeout_ms > MAX_TIMEOUT_MS {
            return Err(IicpError::TimeoutTooLarge(config.timeout_ms));
        }
        if !matches!(
            config.route_discovery_mode.as_str(),
            "auto" | "ticketed" | "legacy"
        ) {
            return Err(IicpError::Node(
                "route_discovery_mode must be auto, ticketed, or legacy".into(),
            ));
        }
        if !matches!(
            config.consumer_auth_mode.as_str(),
            "optional" | "required" | "disabled"
        ) {
            return Err(IicpError::PolicyRefused {
                code: "SDK-AUTH-MODE".into(),
                message: "consumer_auth_mode must be optional, required, or disabled".into(),
            });
        }
        let http = HttpClient::new(config.timeout_ms, config.node_token.clone())?;
        Ok(Self {
            config,
            http,
            ct_cache: ConsumerTokenCache::new(),
            dispatch_ticket_key: std::sync::Mutex::new(None),
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
        if let Some(qos) = &opts.qos {
            if is_safe_query_param(qos) {
                url.push_str(&format!("&qos={qos}"));
            }
        }
        if let Some(rep) = opts.min_reputation {
            url.push_str(&format!("&min_reputation={rep}"));
        }
        if let Some(profile) = &opts.profile_request {
            if is_safe_query_param(&profile.profile_id)
                && is_safe_query_param(&profile.profile_version)
                && profile.profile_fixture_sha256.len() == 64
                && profile
                    .profile_fixture_sha256
                    .chars()
                    .all(|c| c.is_ascii_hexdigit())
            {
                url.push_str(&format!(
                    "&profile_id={}&profile_version={}&profile_fixture_sha256={}&profile_required={}",
                    profile.profile_id,
                    profile.profile_version,
                    profile.profile_fixture_sha256,
                    profile.required,
                ));
            } else {
                return Err(IicpError::PolicyRefused {
                    code: "unsupported_pre_normative_profile".into(),
                    message: "invalid pre-normative profile request".into(),
                });
            }
        }
        url.push_str(&format!("&limit={}", opts.limit.unwrap_or(10)));
        let mut list: NodeList = self.http.get_json(&url, traceparent).await?;
        if opts.profile_request.as_ref().is_some_and(|p| p.required)
            && !matches!(list.profile_negotiation.as_ref(), Some(n) if n.status.as_deref() == Some("compatible") && n.dispatch_allowed == Some(true))
        {
            return Err(IicpError::PolicyRefused {
                code: "unsupported_pre_normative_profile".into(),
                message: "required pre-normative profile is not supported by the directory".into(),
            });
        }
        if opts.browser_usable_only.unwrap_or(false) {
            list.nodes.retain(|n| {
                n.browser_usable
                    .unwrap_or_else(|| is_browser_usable_endpoint(&n.endpoint))
            });
            list.count = list.nodes.len() as u32;
        }

        Ok(list)
    }

    async fn ticketed_candidates(
        &self,
        intent: &str,
        opts: &DiscoverOptions,
        traceparent: &str,
    ) -> std::result::Result<Vec<Node>, TicketRouteError> {
        let base = self.config.directory_url.trim_end_matches('/');
        let url = format!("{base}/v1/dispatch/ticket");
        let mut request = serde_json::json!({
            "intent": intent,
            "limit": opts.limit.unwrap_or(10).min(50),
        });
        if let Some(region) = opts.region.as_ref().or(self.config.region.as_ref()) {
            request["region"] = serde_json::Value::String(region.clone());
        }
        if let Some(model) = &opts.model {
            request["model"] = serde_json::Value::String(model.clone());
        }
        if let Some(qos) = &opts.qos {
            request["qos"] = serde_json::Value::String(qos.clone());
        }
        if let Some(reputation) = opts.min_reputation {
            request["min_reputation"] = serde_json::json!(reputation);
        }

        let mut excluded: Vec<String> = Vec::new();
        let mut candidates = Vec::new();
        for _ in 0..MAX_RETRIES {
            request["exclude_node_id_prefixes"] = serde_json::json!(excluded);
            let response = self
                .http
                .inner()
                .post(&url)
                .header("traceparent", traceparent)
                .json(&request)
                .send()
                .await
                .map_err(|e| TicketRouteError::Iicp(IicpError::Http(e)))?;
            let status = response.status().as_u16();
            if matches!(status, 405 | 501) {
                return Err(TicketRouteError::LegacyRequired);
            }
            let body: serde_json::Value = response
                .json()
                .await
                .map_err(|e| TicketRouteError::Iicp(IicpError::Http(e)))?;
            let error_code = body["error"]["code"].as_str();

            if status == 201 {
                let node_id = body["node_id"].as_str().unwrap_or("");
                // Never hold a std::sync::MutexGuard across an await. Besides
                // blocking parallel dispatches, that makes the proxy feature's
                // boxed request future non-Send. Fetch outside the lock, then
                // cache the first usable key once the response arrives.
                let key_missing = self.dispatch_ticket_key.lock().unwrap().is_none();
                if key_missing {
                    let key_url = format!("{base}/v1/directory-key");
                    if let Ok(key_response) = self.http.inner().get(key_url).send().await {
                        if key_response.status().is_success() {
                            if let Ok(key_body) = key_response.json::<serde_json::Value>().await {
                                if let Some(key) = key_body["public_key"].as_str() {
                                    let mut cached = self.dispatch_ticket_key.lock().unwrap();
                                    if cached.is_none() {
                                        *cached = Some(key.to_owned());
                                    }
                                }
                            }
                        }
                    }
                }
                let directory_key = self.dispatch_ticket_key.lock().unwrap().clone();
                let issuer = base.strip_suffix("/api").unwrap_or(base);
                let claims = body["ticket"].as_str().and_then(|ticket| {
                    directory_key.as_deref().and_then(|key| {
                        verify_dispatch_route_ticket(
                            ticket,
                            key,
                            issuer,
                            node_id,
                            intent,
                            chrono::Utc::now().timestamp(),
                        )
                    })
                });
                if claims.is_none() {
                    return Err(TicketRouteError::Iicp(IicpError::Protocol {
                        code: "IICP-DISPATCH-TICKET-UNVERIFIED".into(),
                        message: "Directory returned an unverifiable dispatch ticket".into(),
                        status,
                    }));
                }
                let mut route = body["route"].clone();
                if !policy_manifest_binding_matches(claims.as_ref().unwrap(), &route) {
                    return Err(TicketRouteError::Iicp(IicpError::Protocol {
                        code: "IICP-POLICY-MANIFEST-BINDING-MISMATCH".into(),
                        message: "Directory ticket does not match the route policy manifest".into(),
                        status,
                    }));
                }
                if let Some(obj) = route.as_object_mut() {
                    obj.insert("node_id".into(), body["node_id"].clone());
                }
                let mut node: Node = serde_json::from_value(route)
                    .map_err(|e| TicketRouteError::Iicp(IicpError::Serde(e)))?;
                node.dispatch_ticket_id_prefix =
                    body["ticket_id_prefix"].as_str().map(str::to_owned);
                excluded.push(node_short_id(&node.node_id).to_string());
                candidates.push(node);
                continue;
            }
            if status == 404 && error_code == Some("no_route_available") {
                break;
            }
            if status == 404 {
                return Err(TicketRouteError::LegacyRequired);
            }
            if status == 503 && error_code == Some("not_configured") {
                return Err(TicketRouteError::LegacyRequired);
            }
            return Err(TicketRouteError::Iicp(IicpError::Protocol {
                code: format!("IICP-DISPATCH-TICKET-{status}"),
                message: format!(
                    "Ticketed dispatch refused ({})",
                    error_code.unwrap_or("unknown")
                ),
                status,
            }));
        }
        Ok(candidates)
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
        let discover_options = project_route_options(&request, &self.config);
        let nodes = if self.config.route_discovery_mode == "legacy"
            || self.config.profile_request.is_some()
        {
            self.discover(&request.intent, Some(discover_options.clone()), Some(&tp))
                .await?
        } else {
            match self
                .ticketed_candidates(&request.intent, &discover_options, &tp)
                .await
            {
                Ok(nodes) => NodeList {
                    count: nodes.len() as u32,
                    nodes,
                    profile_negotiation: None,
                },
                Err(TicketRouteError::LegacyRequired)
                    if self.config.route_discovery_mode == "auto" =>
                {
                    self.discover(&request.intent, Some(discover_options.clone()), Some(&tp))
                        .await?
                }
                Err(TicketRouteError::LegacyRequired) => {
                    return Err(IicpError::Protocol {
                        code: "IICP-DISPATCH-TICKET-UNAVAILABLE".into(),
                        message: "Directory does not support ticketed dispatch".into(),
                        status: 501,
                    });
                }
                Err(TicketRouteError::Iicp(err)) => return Err(err),
            }
        };
        // Filter to safe, available and confidentiality-capable nodes before candidate
        // selection. A keyless provider must never receive plaintext by default; the
        // temporary escape hatch is intentionally explicit and noisy for controlled
        // transition/debugging only.
        let profile_negotiation = nodes.profile_negotiation.clone();
        let pre_policy_nodes: Vec<_> = nodes
            .nodes
            .into_iter()
            .filter(|n| {
                if !is_ssrf_safe(&n.endpoint) {
                    eprintln!(
                        "[iicp-client] SSRF guard: skipping node {} — endpoint {} is not publicly routable",
                        &n.node_id[..n.node_id.len().min(8)],
                        n.endpoint
                    );
                    return false;
                }
                if !n.available {
                    return false;
                }
                true
            })
            .collect();

        let request_policy = request
            .routing_policy
            .as_ref()
            .unwrap_or(&self.config.routing_policy);
        let effective_policy = resolved_policy(Some(request_policy));
        let allow_plaintext =
            cx_plaintext_fallback_allowed() || !effective_policy.require_encryption;
        let decision = filter_nodes_for_routing_policy(
            pre_policy_nodes.clone(),
            &effective_policy,
            allow_plaintext,
        );
        for n in &pre_policy_nodes {
            if n.cx_public_key.is_none() && !allow_plaintext {
                eprintln!(
                    "[iicp-cx] skipping keyless node {} — refusing plaintext by default \
                     (set IICP_CX_ALLOW_PLAINTEXT=1 or routing_profile=debug_override only for transitional debugging).",
                    node_short_id(&n.node_id)
                );
            }
        }

        if decision.eligible.is_empty()
            && decision.skipped_keyless > 0
            && decision.rejected_reasons.len() == decision.skipped_keyless
        {
            return Err(IicpError::Node(format!(
                "IICP-CX confidentiality required: {} discovered node(s) advertised no encryption key; refusing plaintext fallback",
                decision.skipped_keyless
            )));
        }
        if decision.eligible.is_empty() {
            return Err(IicpError::PolicyRefused {
                code: ROUTING_POLICY_REFUSAL_CODE.to_string(),
                message: routing_policy_refusal_message(
                    &request.intent,
                    &decision,
                    &effective_policy,
                ),
            });
        }

        let eligible_candidate_count = decision.eligible.len();
        let candidates: Vec<_> = {
            let mut rng = rand::thread_rng();
            let max_retries = MAX_RETRIES as usize;
            let safe_nodes = decision.eligible;
            if self.config.routing_strategy == "deterministic" || safe_nodes.len() <= 1 {
                safe_nodes.into_iter().take(max_retries).collect()
            } else if self.config.routing_strategy == "weighted_v1" {
                let top_k = self.config.routing_top_k.max(1).min(safe_nodes.len());
                let index = weighted_v1_index(
                    &safe_nodes[..top_k]
                        .iter()
                        .map(|node| node.score)
                        .collect::<Vec<_>>(),
                    &safe_nodes[..top_k]
                        .iter()
                        .map(|node| node.load)
                        .collect::<Vec<_>>(),
                    rng.gen::<f64>(),
                );
                let chosen = safe_nodes[index].clone();
                let mut c = vec![chosen.clone()];
                c.extend(
                    safe_nodes
                        .iter()
                        .take(max_retries)
                        .filter(|node| node.node_id != chosen.node_id)
                        .take(max_retries - 1)
                        .cloned(),
                );
                c
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
            let consumer_token: Option<String> = if self.config.consumer_auth_mode == "disabled" {
                None
            } else if let Some(ref tok) = self.config.node_token {
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
            if self.config.consumer_auth_mode == "required" && consumer_token.is_none() {
                return Err(IicpError::PolicyRefused {
                    code: "IICP-CONSUMER-AUTH-REQUIRED".into(),
                    message: "Consumer authentication is required but no directory-issued token is available".into(),
                });
            }

            // IICP-CX S.16: encryption is mandatory by default. Always encrypt when
            // the node advertises a cx_public_key. Plaintext fallback is refused unless
            // the caller explicitly sets IICP_CX_ALLOW_PLAINTEXT=1 for transitional debugging.
            let mut cx_shared_secret: Option<[u8; 32]> = None;
            let require_encrypted_response = node.cx_public_key.as_ref().is_some_and(|key| {
                key.features
                    .iter()
                    .any(|feature| feature == "response_encryption_v1")
            });
            let body: serde_json::Value = if let Some(ref cx_key) = node.cx_public_key {
                let (iicp_conf, shared_secret) = encrypt_payload_with_context(
                    &request.payload,
                    cx_key,
                    &request.task_id,
                    &request.intent,
                )?;
                cx_shared_secret = Some(shared_secret);
                let mut body = serde_json::to_value(&request)?;
                if let Some(obj) = body.as_object_mut() {
                    obj.remove("payload");
                    obj.insert("iicp_conf".to_string(), serde_json::to_value(iicp_conf)?);
                    if require_encrypted_response {
                        obj.insert(
                            "cx_response_encryption".to_string(),
                            serde_json::Value::String("required".to_string()),
                        );
                    }
                }
                body
            } else {
                eprintln!(
                    "[iicp-cx] node {} advertises no encryption key — sending UNENCRYPTED \
                     only because IICP_CX_ALLOW_PLAINTEXT=1 is set.",
                    node.node_id
                );
                serde_json::to_value(&request)?
            };

            for attempt in 0..MAX_RETRIES {
                match self
                    .http
                    .post_json_ct::<_, TaskResponse>(
                        &format!("{}/v1/task", node.endpoint),
                        &body,
                        None,
                        consumer_token.as_deref(),
                        Some(&tp),
                    )
                    .await
                {
                    Ok(mut resp) => {
                        if require_encrypted_response {
                            let envelope = resp.iicp_conf_resp.take().ok_or_else(|| {
                                IicpError::Node(
                                    "node advertised response encryption but returned plaintext"
                                        .to_string(),
                                )
                            })?;
                            let secret = cx_shared_secret.as_ref().ok_or_else(|| {
                                IicpError::Node("missing CX response context".to_string())
                            })?;
                            let opened = decrypt_response(&envelope, secret, &request.task_id)?;
                            resp = serde_json::from_value(opened).map_err(|err| {
                                IicpError::Node(format!("encrypted response decode failed: {err}"))
                            })?;
                        }
                        resp.generated_by_ai = true;
                        resp.dispatch_ticket_id_prefix = node.dispatch_ticket_id_prefix.clone();
                        resp.routing_receipt = Some(RoutingReceipt {
                            receipt_version: "iicp-routing-receipt-v1".into(),
                            selection_profile: if profile_negotiation.is_some()
                                || self.config.route_discovery_mode == "legacy"
                            {
                                self.config.routing_strategy.clone()
                            } else {
                                "directory_ticket_v1".into()
                            },
                            eligible_candidate_count,
                            selected_node_id_prefix: node_short_id(&node.node_id).to_string(),
                            profile_negotiation: profile_negotiation.clone(),
                            redaction: "prompt_response_endpoint_token_excluded".into(),
                        });
                        return Ok(resp);
                    }
                    Err(e) => {
                        last_err = Some(e);
                        let err = last_err.as_ref().unwrap();
                        if matches!(err, IicpError::EndpointRefused(_)) {
                            continue 'nodes;
                        }
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
        let requested_model = opts.model.clone();
        let request = TaskRequest {
            task_id: uuid::Uuid::new_v4().to_string(),
            intent: "urn:iicp:intent:llm:chat:v1".into(),
            payload,
            constraints: Some(TaskConstraints {
                timeout_ms: opts.timeout_ms,
                max_tokens: opts.max_tokens,
                model: requested_model.clone(),
                qos: opts.qos.clone().or_else(|| Some("interactive".into())),
                region: None,
                min_reputation: None,
            }),
            route_constraints: opts.route_constraints.or_else(|| {
                Some(crate::RouteConstraints {
                    region: opts.region,
                    qos: opts.qos.or_else(|| Some("interactive".into())),
                    model: requested_model,
                    min_reputation: opts.min_reputation,
                    limit: Some(10),
                    browser_usable_only: opts.browser_usable_only,
                    profile_request: opts.profile_request,
                })
            }),
            auth: None,
            source_node_id: None,
            routing_policy: opts.routing_policy,
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
        resp.generated_by_ai = true;
        Ok(resp)
    }

    fn validate_intent(&self, intent: &str) -> Result<()> {
        if !INTENT_RE.is_match(intent) {
            return Err(IicpError::InvalidIntent(intent.into()));
        }
        ensure_intent_allowed(intent)?;
        Ok(())
    }
}
