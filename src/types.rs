// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Client-side remote-routing profile (#585).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingProfile {
    #[default]
    Standard,
    Sensitive,
    EuRestricted,
    StrictPolicy,
    DebugOverride,
}

impl RoutingProfile {
    pub fn from_cli(value: &str) -> Self {
        match value.replace('-', "_").to_ascii_lowercase().as_str() {
            "sensitive" => Self::Sensitive,
            "eu_restricted" => Self::EuRestricted,
            "strict_policy" => Self::StrictPolicy,
            "debug_override" => Self::DebugOverride,
            _ => Self::Standard,
        }
    }
}

/// Client-side pre-dispatch routing policy (#585).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutingPolicy {
    pub profile: RoutingProfile,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_regions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_encryption: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_policy_manifest: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_no_payload_retention: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_remote_executor: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_operator_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_manifest_identity_level: Option<String>,
}

/// Client configuration (SDK-04: timeout_ms enforced at construction time).
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub directory_url: String,
    /// Maximum request timeout in milliseconds. Must be ≤ 120 000 (SDK-04).
    pub timeout_ms: u64,
    pub region: Option<String>,
    pub node_token: Option<String>,
    /// IICP-CX S.16: encrypt task payloads when the node advertises cx_public_key. Default: false.
    pub use_confidentiality: bool,
    /// ε-greedy exploration probability for provider selection (R4). Default: 0.05.
    /// Override with IICP_ROUTING_EPSILON env var. Set to 0.0 to disable.
    pub routing_epsilon: f64,
    /// Selection strategy: deterministic | epsilon | softmax_top_k.
    pub routing_strategy: String,
    /// Candidate pool size for softmax_top_k.
    pub routing_top_k: usize,
    /// Softmax temperature for softmax_top_k.
    pub routing_softmax_tau: f64,
    /// Phase 6 (#585): default client-side policy applied before remote dispatch.
    pub routing_policy: RoutingPolicy,
}

impl Default for ClientConfig {
    fn default() -> Self {
        let epsilon = std::env::var("IICP_ROUTING_EPSILON")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .map(|v| v.clamp(0.0, 1.0))
            .unwrap_or(0.05);
        let strategy = std::env::var("IICP_ROUTING_STRATEGY")
            .ok()
            .filter(|s| matches!(s.as_str(), "deterministic" | "epsilon" | "softmax_top_k"))
            .unwrap_or_else(|| "epsilon".into());
        let top_k = std::env::var("IICP_ROUTING_TOP_K")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .map(|v| v.max(1))
            .unwrap_or(3);
        let tau = std::env::var("IICP_ROUTING_SOFTMAX_TAU")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .map(|v| v.max(0.001))
            .unwrap_or(0.04);
        Self {
            directory_url: "https://iicp.network/api".into(),
            timeout_ms: 30_000,
            region: None,
            node_token: None,
            use_confidentiality: false,
            routing_epsilon: epsilon,
            routing_strategy: strategy,
            routing_top_k: top_k,
            routing_softmax_tau: tau,
            routing_policy: RoutingPolicy::default(),
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
    /// Browser-like consumers can keep only HTTPS/loopback endpoints. Native default: false.
    pub browser_usable_only: Option<bool>,
}

/// X25519 public key advertised by a CX-Provider node (IICP-CX S.16 §3.1).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CxPublicKey {
    pub algorithm: String,
    /// Encoding for `key`; directory validation expects base64url on REGISTER.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    /// Base64url-encoded 32-byte X25519 public key.
    pub key: String,
    /// Stable provider-key identifier, currently `cx-` plus 16 hex chars.
    pub key_id: String,
}

/// A single IICP node returned by `/v1/discover`.
#[derive(Debug, Clone)]
pub struct Node {
    pub node_id: String,
    pub endpoint: String,
    pub score: f64,
    pub available: bool,
    pub region: String,
    pub models: Option<Vec<String>>,
    pub cip_policy: Option<CipPolicy>,
    /// ADR-044 composed health label (healthy/degraded/impaired/critical/offline).
    /// `None` against a directory predating v1.10.0.
    pub health_label: Option<String>,
    /// ADR-043 8-category network exposure classification. `None` if unset.
    pub exposure_mode: Option<String>,
    /// IICP-CX S.16 §3.1 — X25519 public key for E2E payload confidentiality.
    /// Canonical IICP-CX key advertised by discovery; `public_key` is a deprecated alias.
    pub cx_public_key: Option<CxPublicKey>,
    /// #397 — transport protocols the node speaks (e.g. ["https","iicp-native"]).
    /// Empty/absent against a directory predating the field.
    pub transport: Vec<String>,
    /// Additive routing-signal split from directory v1.10.50+.
    pub directory_observed_reachable: Option<bool>,
    pub route_evidence: Option<String>,
    pub routing_hint: Option<String>,
    pub browser_usable: Option<bool>,
    /// Phase-1 compliance: public, self-attested node policy manifest.
    pub node_policy_manifest: Option<Value>,
}

#[derive(Deserialize)]
struct NodeWire {
    pub node_id: String,
    pub endpoint: String,
    pub score: f64,
    pub available: bool,
    pub region: String,
    pub models: Option<Vec<String>>,
    pub cip_policy: Option<CipPolicy>,
    #[serde(default)]
    pub health_label: Option<String>,
    #[serde(default)]
    pub exposure_mode: Option<String>,
    #[serde(default)]
    pub cx_public_key: Option<CxPublicKey>,
    #[serde(default)]
    pub public_key: Option<CxPublicKey>,
    #[serde(default)]
    pub transport: Vec<String>,
    #[serde(default)]
    pub directory_observed_reachable: Option<bool>,
    #[serde(default)]
    pub route_evidence: Option<String>,
    #[serde(default)]
    pub routing_hint: Option<String>,
    #[serde(default)]
    pub browser_usable: Option<bool>,
    #[serde(default)]
    pub node_policy_manifest: Option<Value>,
}

impl From<NodeWire> for Node {
    fn from(wire: NodeWire) -> Self {
        Self {
            node_id: wire.node_id,
            endpoint: wire.endpoint,
            score: wire.score,
            available: wire.available,
            region: wire.region,
            models: wire.models,
            cip_policy: wire.cip_policy,
            health_label: wire.health_label,
            exposure_mode: wire.exposure_mode,
            // Prefer the canonical field if both appear. The deprecated alias is
            // tolerated so a transitional directory response cannot break query
            // with serde's "duplicate field `cx_public_key`" error.
            cx_public_key: wire.cx_public_key.or(wire.public_key),
            transport: wire.transport,
            directory_observed_reachable: wire.directory_observed_reachable,
            route_evidence: wire.route_evidence,
            routing_hint: wire.routing_hint,
            browser_usable: wire.browser_usable,
            node_policy_manifest: wire.node_policy_manifest,
        }
    }
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        NodeWire::deserialize(deserializer).map(Self::from)
    }
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
    /// #488 — querying node identity for self-query neutrality at the directory.
    /// Set to the requester's node_id so the serving node can include it in the
    /// CIPWorkerReceipt, enabling the directory to detect same-operator loops.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_node_id: Option<String>,
    /// Phase 6 (#585): optional per-request policy. Never serialized to nodes.
    #[serde(skip)]
    pub routing_policy: Option<RoutingPolicy>,
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
    /// Structured error block on a non-success node response (carries the IICP error
    /// code the proxy surfaces). Defaults to None for success responses / older nodes.
    #[serde(default)]
    pub error: Option<serde_json::Value>,
}

/// Task execution metrics.
#[derive(Debug, Clone, Deserialize)]
pub struct TaskMetrics {
    pub latency_ms: Option<f64>,
    pub tokens_used: Option<u32>,
    pub node_id: Option<String>,
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
    pub temperature: Option<f64>,
    pub routing_policy: Option<RoutingPolicy>,
}

/// OpenAI-compatible chat completion response.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ChatResponse {
    pub choices: Vec<ChatChoice>,
    pub usage: Option<ChatUsage>,
    /// Task ID from the IICP task response (correlation handle).
    #[serde(default)]
    pub task_id: String,
    /// IICP node that served this request — from task metrics.
    #[serde(default)]
    pub node_id: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::Node;

    // ADR-044 — discover Node parses the composed health_label + exposure_mode.
    #[test]
    fn node_parses_health_label_and_exposure_mode() {
        let json = r#"{"node_id":"n1","endpoint":"https://x","score":0.9,"available":true,"region":"eu","health_label":"healthy","exposure_mode":"ipv4_public_direct","transport":["https","iicp-native"]}"#;
        let n: Node = serde_json::from_str(json).unwrap();
        assert_eq!(n.health_label.as_deref(), Some("healthy"));
        assert_eq!(n.exposure_mode.as_deref(), Some("ipv4_public_direct"));
        // #397 — transport parses from discover.
        assert_eq!(n.transport, vec!["https", "iicp-native"]);
    }

    // A directory predating v1.10.0 omits the fields; parsing must not break.
    #[test]
    fn node_health_fields_default_none_for_old_directory() {
        let json =
            r#"{"node_id":"n1","endpoint":"https://x","score":0.5,"available":true,"region":"eu"}"#;
        let n: Node = serde_json::from_str(json).unwrap();
        assert!(n.health_label.is_none());
        assert!(n.exposure_mode.is_none());
    }

    #[test]
    fn node_accepts_deprecated_public_key_alias_for_cx_key() {
        let json = r#"{
            "node_id":"n1",
            "endpoint":"https://x",
            "score":0.9,
            "available":true,
            "region":"eu",
            "public_key":{
                "algorithm":"X25519",
                "encoding":"base64url",
                "key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "key_id":"cx-alias"
            }
        }"#;
        let n: Node = serde_json::from_str(json).unwrap();
        assert_eq!(
            n.cx_public_key.as_ref().map(|key| key.key_id.as_str()),
            Some("cx-alias")
        );
    }

    #[test]
    fn node_accepts_both_canonical_and_alias_without_duplicate_field_error() {
        let json = r#"{
            "node_id":"n1",
            "endpoint":"https://x",
            "score":0.9,
            "available":true,
            "region":"eu",
            "cx_public_key":{
                "algorithm":"X25519",
                "encoding":"base64url",
                "key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "key_id":"cx-canonical"
            },
            "public_key":{
                "algorithm":"X25519",
                "encoding":"base64url",
                "key":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "key_id":"cx-alias"
            }
        }"#;
        let n: Node = serde_json::from_str(json).unwrap();
        assert_eq!(
            n.cx_public_key.as_ref().map(|key| key.key_id.as_str()),
            Some("cx-canonical")
        );
    }
}
