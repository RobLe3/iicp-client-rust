// SPDX-License-Identifier: Apache-2.0
//! Deterministic provider-node recovery signals.
//!
//! This module deliberately keeps recovery decisions rule-based and local.  It
//! gives `iicp-node serve` and `iicp-node doctor --json` the same vocabulary so
//! operators do not need to infer whether a node needs re-registration, cooldown,
//! backend attention, or a supervised restart from raw logs.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

pub const RECOVERY_EXIT_CODE: i32 = 76;
pub const DEFAULT_RECOVERY_GRACE_CHECKS: u32 = 3;
pub const DEFAULT_RECOVERY_CHECK_EVERY_HEARTBEATS: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    Healthy,
    LocalUnhealthy,
    BackendAttention,
    RouteMismatch,
    TunnelCoolingDown,
    DirectoryAbsent,
    LimitedReach,
    RestartRecommended,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    None,
    Reregister,
    WaitCooldown,
    MarkUnavailable,
    RestartSelf,
    OperatorEndpointNeeded,
    BackendAttention,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryPresence {
    Present,
    Absent,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryRouteStatus {
    pub presence: DirectoryPresence,
    pub route_needs_promotion: bool,
}

pub fn node_registry_prefix(node_id: &str) -> String {
    let is_uuid = node_id.len() == 36
        && node_id.chars().enumerate().all(|(idx, c)| {
            if matches!(idx, 8 | 13 | 18 | 23) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        });
    if is_uuid {
        node_id.chars().take(8).collect()
    } else {
        node_id.to_string()
    }
}

pub fn env_grace_checks() -> u32 {
    std::env::var("IICP_RECOVERY_GRACE_CHECKS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_RECOVERY_GRACE_CHECKS)
}

pub fn env_check_every_heartbeats() -> u64 {
    std::env::var("IICP_RECOVERY_CHECK_EVERY_HEARTBEATS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_RECOVERY_CHECK_EVERY_HEARTBEATS)
}

pub fn supervised_recovery_enabled() -> bool {
    let supervised = std::env::var("IICP_SUPERVISED")
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    let disabled = std::env::var("IICP_RECOVERY_SUPERVISED_EXIT")
        .ok()
        .map(|v| {
            matches!(
                v.to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(false);
    supervised && !disabled
}

pub fn classify(
    local_health_ok: bool,
    public_available: bool,
    directory_presence: DirectoryPresence,
    consecutive_failures: u32,
    grace_checks: u32,
    backend_attention: bool,
) -> (RecoveryState, RecoveryAction) {
    if !local_health_ok {
        return (RecoveryState::LocalUnhealthy, RecoveryAction::RestartSelf);
    }
    if backend_attention {
        return (
            RecoveryState::BackendAttention,
            RecoveryAction::BackendAttention,
        );
    }
    if !public_available {
        if consecutive_failures >= grace_checks {
            return (
                RecoveryState::RestartRecommended,
                RecoveryAction::RestartSelf,
            );
        }
        return (RecoveryState::LimitedReach, RecoveryAction::WaitCooldown);
    }
    match directory_presence {
        DirectoryPresence::Present => (RecoveryState::Healthy, RecoveryAction::None),
        DirectoryPresence::Absent if consecutive_failures >= grace_checks => {
            (RecoveryState::RouteMismatch, RecoveryAction::RestartSelf)
        }
        DirectoryPresence::Absent => (RecoveryState::DirectoryAbsent, RecoveryAction::Reregister),
        DirectoryPresence::Unknown => (RecoveryState::Unknown, RecoveryAction::None),
    }
}

pub async fn registry_node_presence(
    http: &Client,
    directory_url: &str,
    node_id: &str,
    timeout: Duration,
) -> DirectoryPresence {
    let prefix = node_registry_prefix(node_id);
    let url = format!(
        "{}/v1/registry/nodes/{}",
        directory_url.trim_end_matches('/'),
        prefix
    );
    match http.get(url).timeout(timeout).send().await {
        Ok(resp) if resp.status().is_success() => DirectoryPresence::Present,
        Ok(resp) if resp.status().as_u16() == 404 => DirectoryPresence::Absent,
        Ok(_) | Err(_) => DirectoryPresence::Unknown,
    }
}

pub fn route_needs_promotion_from_registry_json(data: &Value) -> bool {
    let node = data.get("node").unwrap_or(data);
    let summary = node.get("status_summary").unwrap_or(&Value::Null);

    if summary.get("state").and_then(Value::as_str) == Some("direct_unverified") {
        return true;
    }

    let route_evidence = node
        .get("route_evidence")
        .and_then(Value::as_str)
        .or_else(|| summary.get("evidence_source").and_then(Value::as_str));
    let routing_hint = node
        .get("routing_hint")
        .and_then(Value::as_str)
        .or_else(|| summary.get("routing_hint").and_then(Value::as_str));
    let browser_usable = node
        .get("browser_usable")
        .and_then(Value::as_bool)
        .or_else(|| summary.get("browser_usable").and_then(Value::as_bool));

    routing_hint == Some("http_ipv6")
        && route_evidence != Some("directory_observed")
        && browser_usable != Some(true)
}

pub async fn registry_route_status(
    http: &Client,
    directory_url: &str,
    node_id: &str,
    timeout: Duration,
) -> RegistryRouteStatus {
    let prefix = node_registry_prefix(node_id);
    let url = format!(
        "{}/v1/registry/nodes/{}",
        directory_url.trim_end_matches('/'),
        prefix
    );
    match http.get(url).timeout(timeout).send().await {
        Ok(resp) if resp.status().is_success() => {
            let route_needs_promotion = resp
                .json::<Value>()
                .await
                .map(|data| route_needs_promotion_from_registry_json(&data))
                .unwrap_or(false);
            RegistryRouteStatus {
                presence: DirectoryPresence::Present,
                route_needs_promotion,
            }
        }
        Ok(resp) if resp.status().as_u16() == 404 => RegistryRouteStatus {
            presence: DirectoryPresence::Absent,
            route_needs_promotion: false,
        },
        Ok(_) | Err(_) => RegistryRouteStatus {
            presence: DirectoryPresence::Unknown,
            route_needs_promotion: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_nodes_use_safe_eight_char_prefix() {
        assert_eq!(
            node_registry_prefix("b30aee67-9089-4337-806e-b560428cf97a"),
            "b30aee67"
        );
        assert_eq!(
            node_registry_prefix("relay-eu-e50fc7f9"),
            "relay-eu-e50fc7f9"
        );
    }

    #[test]
    fn recovery_classification_prefers_reregister_before_restart() {
        assert_eq!(
            classify(true, true, DirectoryPresence::Absent, 1, 3, false),
            (RecoveryState::DirectoryAbsent, RecoveryAction::Reregister)
        );
        assert_eq!(
            classify(true, true, DirectoryPresence::Absent, 3, 3, false),
            (RecoveryState::RouteMismatch, RecoveryAction::RestartSelf)
        );
    }

    #[test]
    fn unavailable_public_route_waits_then_restarts_when_supervised_by_caller() {
        assert_eq!(
            classify(true, false, DirectoryPresence::Absent, 1, 3, false),
            (RecoveryState::LimitedReach, RecoveryAction::WaitCooldown)
        );
        assert_eq!(
            classify(true, false, DirectoryPresence::Absent, 3, 3, false),
            (
                RecoveryState::RestartRecommended,
                RecoveryAction::RestartSelf
            )
        );
    }

    #[test]
    fn direct_ipv6_self_attested_registry_status_needs_route_promotion() {
        let status = serde_json::json!({
            "routing_hint": "http_ipv6",
            "route_evidence": "self_attested",
            "browser_usable": false,
            "status_summary": {"state": "direct_unverified"}
        });
        assert!(route_needs_promotion_from_registry_json(&status));

        let wrapped = serde_json::json!({
            "node": {
                "routing_hint": "http_ipv6",
                "route_evidence": "directory_observed",
                "browser_usable": false,
                "status_summary": {"state": "ready"}
            }
        });
        assert!(!route_needs_promotion_from_registry_json(&wrapped));
    }

    #[test]
    fn route_promotion_uses_limited_reach_until_restart_grace() {
        assert_eq!(
            classify(true, false, DirectoryPresence::Present, 1, 3, false),
            (RecoveryState::LimitedReach, RecoveryAction::WaitCooldown)
        );
        assert_eq!(
            classify(true, false, DirectoryPresence::Present, 3, 3, false),
            (
                RecoveryState::RestartRecommended,
                RecoveryAction::RestartSelf
            )
        );
    }
}
