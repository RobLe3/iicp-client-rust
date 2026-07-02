// SPDX-License-Identifier: Apache-2.0
//! Remote-routing policy gates for prompt dispatch (#585).

use crate::types::{Node, RoutingPolicy, RoutingProfile};

pub const ROUTING_POLICY_REFUSAL_CODE: &str = "IICP-POLICY-ROUTING";

#[derive(Debug, Clone)]
pub struct EffectiveRoutingPolicy {
    pub profile: RoutingProfile,
    pub allowed_regions: Vec<String>,
    pub require_encryption: bool,
    pub require_policy_manifest: bool,
    pub require_no_payload_retention: bool,
    pub allow_remote_executor: bool,
    pub known_operator_only: bool,
}

#[derive(Debug, Clone)]
pub struct RoutingPolicyDecision {
    pub eligible: Vec<Node>,
    pub rejected_reasons: Vec<String>,
    pub skipped_keyless: usize,
}

pub fn resolved_policy(policy: Option<&RoutingPolicy>) -> EffectiveRoutingPolicy {
    let profile = policy
        .map(|p| p.profile.clone())
        .unwrap_or(RoutingProfile::Standard);
    let mut effective = match profile {
        RoutingProfile::Standard => EffectiveRoutingPolicy {
            profile,
            allowed_regions: vec![],
            require_encryption: true,
            require_policy_manifest: false,
            require_no_payload_retention: false,
            allow_remote_executor: true,
            known_operator_only: false,
        },
        RoutingProfile::Sensitive => EffectiveRoutingPolicy {
            profile,
            allowed_regions: vec![],
            require_encryption: true,
            require_policy_manifest: false,
            require_no_payload_retention: false,
            allow_remote_executor: false,
            known_operator_only: false,
        },
        RoutingProfile::EuRestricted => EffectiveRoutingPolicy {
            profile,
            allowed_regions: vec!["eu".into(), "eea".into()],
            require_encryption: true,
            require_policy_manifest: false,
            require_no_payload_retention: false,
            allow_remote_executor: true,
            known_operator_only: false,
        },
        RoutingProfile::StrictPolicy => EffectiveRoutingPolicy {
            profile,
            allowed_regions: vec![],
            require_encryption: true,
            require_policy_manifest: true,
            require_no_payload_retention: true,
            allow_remote_executor: true,
            known_operator_only: false,
        },
        RoutingProfile::DebugOverride => EffectiveRoutingPolicy {
            profile,
            allowed_regions: vec![],
            require_encryption: false,
            require_policy_manifest: false,
            require_no_payload_retention: false,
            allow_remote_executor: true,
            known_operator_only: false,
        },
    };

    if let Some(p) = policy {
        if !p.allowed_regions.is_empty() {
            effective.allowed_regions = p.allowed_regions.clone();
        }
        if let Some(v) = p.require_encryption {
            effective.require_encryption = v;
        }
        if let Some(v) = p.require_policy_manifest {
            effective.require_policy_manifest = v;
        }
        if let Some(v) = p.require_no_payload_retention {
            effective.require_no_payload_retention = v;
        }
        if let Some(v) = p.allow_remote_executor {
            effective.allow_remote_executor = v;
        }
        if let Some(v) = p.known_operator_only {
            effective.known_operator_only = v;
        }
    }

    effective
}

pub fn filter_nodes_for_routing_policy(
    nodes: Vec<Node>,
    policy: &EffectiveRoutingPolicy,
    allow_plaintext_debug: bool,
) -> RoutingPolicyDecision {
    let mut eligible = Vec::new();
    let mut rejected_reasons = Vec::new();
    let mut skipped_keyless = 0usize;

    for node in nodes {
        if let Some(reason) = node_rejection_reason(&node, policy, allow_plaintext_debug) {
            if reason == "missing_encryption_key" {
                skipped_keyless += 1;
            }
            rejected_reasons.push(reason.to_string());
            continue;
        }
        eligible.push(node);
    }

    RoutingPolicyDecision {
        eligible,
        rejected_reasons,
        skipped_keyless,
    }
}

pub fn routing_policy_refusal_message(
    intent: &str,
    decision: &RoutingPolicyDecision,
    policy: &EffectiveRoutingPolicy,
) -> String {
    format!(
        "Routing policy '{:?}' refused all discovered nodes for '{}' before prompt dispatch; no prompt was sent. Reasons: {}. Remote nodes can read prompts they execute; use local/browser mode for sensitive data or relax the policy explicitly.",
        policy.profile,
        intent,
        summarize(&decision.rejected_reasons)
    )
}

fn node_rejection_reason<'a>(
    node: &'a Node,
    policy: &'a EffectiveRoutingPolicy,
    allow_plaintext_debug: bool,
) -> Option<&'static str> {
    if !policy.allow_remote_executor {
        return Some("remote_executor_disabled");
    }
    if !policy.allowed_regions.is_empty() && !region_allowed(&node.region, &policy.allowed_regions)
    {
        return Some("region_not_allowed");
    }
    if policy.require_encryption && node.cx_public_key.is_none() && !allow_plaintext_debug {
        return Some("missing_encryption_key");
    }
    if policy.require_policy_manifest && node.node_policy_manifest.is_none() {
        return Some("missing_policy_manifest");
    }
    if policy.require_no_payload_retention && !declares_no_payload_retention(node) {
        return Some("payload_retention_not_none");
    }
    if policy.known_operator_only {
        return Some("known_operator_not_verified");
    }
    None
}

fn region_allowed(region: &str, allowed: &[String]) -> bool {
    let value = region.trim().to_ascii_lowercase();
    allowed.iter().any(|raw| {
        let item = raw.trim().to_ascii_lowercase();
        if item.is_empty() {
            return false;
        }
        value == item
            || value.starts_with(&format!("{item}-"))
            || (item == "eea" && value.starts_with("eu-"))
    })
}

fn declares_no_payload_retention(node: &Node) -> bool {
    node.node_policy_manifest
        .as_ref()
        .and_then(|m| m.get("retention"))
        .and_then(|r| r.get("task_payload"))
        .and_then(|v| v.as_str())
        == Some("none")
}

fn summarize(reasons: &[String]) -> String {
    if reasons.is_empty() {
        return "none".to_string();
    }
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    for reason in reasons {
        *counts.entry(reason.as_str()).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(reason, count)| format!("{reason}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}
