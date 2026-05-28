// SPDX-License-Identifier: Apache-2.0
//! Trust auditor — cross-node declaration consistency check (parity Block E, #340).
//!
//! Port of iicp-adapter `services/trust_auditor.py` (#118). Discovers active peers via the
//! directory, probes each peer's `/iicp/health`, and verifies the directory-registered
//! models actually appear in the peer's live health response. Missing models are a
//! "declaration divergence" reported to `/v1/audit-report`.
//!
//! Opt-in background capability (call [`run_audit_pass`] on a timer); not in the request
//! hot path. The pure [`models_diverge`] helper is the unit-testable core.

use std::time::Duration;

use serde_json::Value;

const DISCOVER_INTENT: &str = "urn:iicp:intent:llm:chat:v1";
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(8);
const AUDIT_REPORT_TIMEOUT: Duration = Duration::from_secs(5);

/// Registered models absent from the peer's health response (empty == consistent).
pub fn models_diverge(registered: &[String], health: &[String]) -> Vec<String> {
    registered
        .iter()
        .filter(|m| !health.contains(m))
        .cloned()
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct NodeAuditResult {
    pub node_id: String,
    pub endpoint: String,
    pub passed: bool,
    pub health_reachable: bool,
    pub declared_models_match: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuditReport {
    pub nodes_probed: usize,
    pub nodes_passed: usize,
    pub nodes_failed: usize,
    pub results: Vec<NodeAuditResult>,
}

fn models_of(v: &Value) -> Vec<String> {
    v.get("models")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

async fn discover_peers(client: &reqwest::Client, directory_url: &str, own: &str) -> Vec<Value> {
    let url = format!("{}/v1/discover", directory_url.trim_end_matches('/'));
    match client
        .get(&url)
        .query(&[("intent", DISCOVER_INTENT)])
        .timeout(DISCOVER_TIMEOUT)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => match r.json::<Value>().await {
            Ok(body) => body
                .get("nodes")
                .and_then(|n| n.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter(|n| n.get("node_id").and_then(Value::as_str) != Some(own))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default(),
            Err(_) => vec![],
        },
        _ => vec![],
    }
}

async fn probe_node(client: &reqwest::Client, node: &Value) -> NodeAuditResult {
    let node_id = node
        .get("node_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let endpoint = node
        .get("operator_url")
        .and_then(Value::as_str)
        .or_else(|| node.get("endpoint").and_then(Value::as_str))
        .unwrap_or("")
        .to_string();
    let registered = models_of(node);

    if endpoint.is_empty() {
        return NodeAuditResult {
            node_id,
            endpoint,
            passed: false,
            health_reachable: false,
            declared_models_match: false,
            detail: "no endpoint".into(),
        };
    }

    let health_url = format!("{}/iicp/health", endpoint.trim_end_matches('/'));
    match client.get(&health_url).timeout(PROBE_TIMEOUT).send().await {
        Ok(r) if r.status().is_success() => {
            let health = r.json::<Value>().await.unwrap_or(Value::Null);
            let missing = models_diverge(&registered, &models_of(&health));
            let ok = missing.is_empty();
            NodeAuditResult {
                node_id,
                endpoint,
                passed: ok,
                health_reachable: true,
                declared_models_match: ok,
                detail: if ok {
                    "OK".into()
                } else {
                    format!("registered {missing:?} absent from health")
                },
            }
        }
        Ok(r) => NodeAuditResult {
            node_id,
            endpoint,
            passed: false,
            health_reachable: false,
            declared_models_match: false,
            detail: format!("HTTP {}", r.status().as_u16()),
        },
        Err(e) => NodeAuditResult {
            node_id,
            endpoint,
            passed: false,
            health_reachable: false,
            declared_models_match: false,
            detail: format!("connection error: {e}"),
        },
    }
}

async fn report_divergence(
    client: &reqwest::Client,
    directory_url: &str,
    own: &str,
    token: &str,
    target: &str,
) {
    if own.is_empty() || token.is_empty() {
        return;
    }
    let url = format!("{}/v1/audit-report", directory_url.trim_end_matches('/'));
    let _ = client
        .post(&url)
        .bearer_auth(token)
        .timeout(AUDIT_REPORT_TIMEOUT)
        .json(&serde_json::json!({
            "node_id": own,
            "target_node_id": target,
            "finding": "declaration_divergence",
        }))
        .send()
        .await;
}

/// Discover peers, probe each, report divergences. One pass.
pub async fn run_audit_pass(
    directory_url: &str,
    own_node_id: &str,
    node_token: &str,
) -> AuditReport {
    let client = reqwest::Client::new();
    let nodes = discover_peers(&client, directory_url, own_node_id).await;
    let mut results = Vec::with_capacity(nodes.len());
    for n in &nodes {
        results.push(probe_node(&client, n).await);
    }
    for r in &results {
        if r.health_reachable && !r.declared_models_match {
            report_divergence(&client, directory_url, own_node_id, node_token, &r.node_id).await;
        }
    }
    let passed = results.iter().filter(|r| r.passed).count();
    AuditReport {
        nodes_probed: results.len(),
        nodes_passed: passed,
        nodes_failed: results.len() - passed,
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_divergence_when_health_superset() {
        let reg = vec!["a".to_string(), "b".to_string()];
        let health = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert!(models_diverge(&reg, &health).is_empty());
    }

    #[test]
    fn missing_model_is_divergence() {
        let reg = vec!["a".to_string(), "b".to_string()];
        let health = vec!["a".to_string()];
        assert_eq!(models_diverge(&reg, &health), vec!["b".to_string()]);
    }

    #[test]
    fn empty_registered_never_diverges() {
        assert!(models_diverge(&[], &["a".to_string()]).is_empty());
    }
}
