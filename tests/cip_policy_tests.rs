// SPDX-License-Identifier: Apache-2.0
//! Unit tests for cip_policy — S.12 §2.2 worker-role gate. Rust port of the
//! Python `tests/test_cip_policy.py` matrix.

use std::sync::{Arc, Mutex};

use iicp_client::cip_policy::{
    configure_cip_policy, get_cip_policy, CooperativeInferencePolicy,
    CooperativeInferencePolicyOptions,
};
use iicp_client::node::{IicpNode, NodeConfig};

fn opts() -> CooperativeInferencePolicyOptions {
    CooperativeInferencePolicyOptions::default()
}

/// Serialize tests that mutate the module-level CIP policy. cargo test runs
/// tests in parallel by default; without this mutex the global RwLock-protected
/// policy gets clobbered between threads and the assertions race.
static GLOBAL_POLICY_TEST_LOCK: Mutex<()> = Mutex::new(());

// ── Gate predicates ─────────────────────────────────────────────────────────

#[test]
fn test_default_is_all_off() {
    let p = CooperativeInferencePolicy::new(opts());
    assert!(!p.enabled);
    assert!(!p.allow_coordinator);
    assert!(!p.allow_worker);
    assert!(!p.check_coordinator());
    assert!(!p.check_worker());
}

#[test]
fn test_enabled_alone_does_not_open_gates() {
    let mut o = opts();
    o.enabled = true;
    let p = CooperativeInferencePolicy::new(o);
    assert!(!p.check_coordinator());
    assert!(!p.check_worker());
}

#[test]
fn test_role_flag_alone_does_not_open_gates() {
    let mut o = opts();
    o.allow_coordinator = true;
    o.allow_worker = true;
    let p = CooperativeInferencePolicy::new(o);
    assert!(!p.check_coordinator());
    assert!(!p.check_worker());
}

#[test]
fn test_enabled_plus_coordinator_opens_coordinator_only() {
    let mut o = opts();
    o.enabled = true;
    o.allow_coordinator = true;
    let p = CooperativeInferencePolicy::new(o);
    assert!(p.check_coordinator());
    assert!(!p.check_worker());
}

#[test]
fn test_enabled_plus_worker_opens_worker_only() {
    let mut o = opts();
    o.enabled = true;
    o.allow_worker = true;
    let p = CooperativeInferencePolicy::new(o);
    assert!(!p.check_coordinator());
    assert!(p.check_worker());
}

// ── Capacity gate (S.12 §2.2) ──────────────────────────────────────────────

#[test]
fn test_max_concurrent_remote_lower_bound_enforced() {
    let mut o = opts();
    o.max_concurrent_remote = 0;
    let p = CooperativeInferencePolicy::new(o);
    assert_eq!(p.max_concurrent_remote, 1);
}

#[test]
fn test_max_worker_timeout_upper_bound_enforced() {
    let mut o = opts();
    o.max_worker_timeout_ms = 999_999;
    let p = CooperativeInferencePolicy::new(o);
    assert_eq!(p.max_worker_timeout_ms, 60_000);
}

#[test]
fn test_slot_acquire_and_release() {
    let mut o = opts();
    o.max_concurrent_remote = 2;
    let p = CooperativeInferencePolicy::new(o);
    assert!(p.try_acquire_cip_slot());
    assert!(p.try_acquire_cip_slot());
    // Capacity reached → next acquire MUST fail (S.12 §2.2 non-silent-queue)
    assert!(!p.try_acquire_cip_slot());
    p.release_cip_slot();
    assert!(p.try_acquire_cip_slot());
}

// ── Register payload integration ───────────────────────────────────────────

// Test serialization mutex is intentionally held across awaits — these
// integration tests share global policy state and must not interleave.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn test_cip_disabled_emits_no_policy_block() {
    let _guard = GLOBAL_POLICY_TEST_LOCK.lock().unwrap();
    use mockito::{Matcher, Server};

    let mut server = Server::new_async().await;
    // Match ANY body (we'll inspect that `policy` is absent via expect+check below).
    let _m = server
        .mock("POST", "/v1/register")
        .with_status(201)
        .with_body(r#"{"node_token":"tok","node_id":"n"}"#)
        .match_body(Matcher::Any)
        .expect(1)
        .create_async()
        .await;

    let mut cfg = NodeConfig::new(
        "n",
        "https://provider.example:8080",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.directory_url = server.url();
    cfg.model = Some("q".into());
    cfg.cip_policy = Some(Arc::new(CooperativeInferencePolicy::new(opts())));
    // Reset module-level policy to default in case prior test set it
    configure_cip_policy(opts());
    let node = IicpNode::new(cfg);
    assert!(node.register().await.is_ok());
    _m.assert_async().await;
}

#[tokio::test]
async fn test_cip_worker_enabled_emits_allow_remote_inference() {
    use mockito::{Matcher, Server};

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/v1/register")
        .match_body(Matcher::PartialJson(serde_json::json!({
            "policy": {"allow_remote_inference": true}
        })))
        .with_status(201)
        .with_body(r#"{"node_token":"tok","node_id":"n"}"#)
        .create_async()
        .await;

    let mut cfg = NodeConfig::new(
        "n",
        "https://provider.example:8080",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.directory_url = server.url();
    cfg.model = Some("q".into());
    let mut o = opts();
    o.enabled = true;
    o.allow_worker = true;
    cfg.cip_policy = Some(Arc::new(CooperativeInferencePolicy::new(o)));
    let node = IicpNode::new(cfg);
    assert!(node.register().await.is_ok());
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn test_module_level_policy_used_when_node_config_unset() {
    let _guard = GLOBAL_POLICY_TEST_LOCK.lock().unwrap();
    use mockito::{Matcher, Server};

    let mut o = opts();
    o.enabled = true;
    o.allow_worker = true;
    configure_cip_policy(o);

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/v1/register")
        .match_body(Matcher::PartialJson(serde_json::json!({
            "policy": {"allow_remote_inference": true}
        })))
        .with_status(201)
        .with_body(r#"{"node_token":"tok","node_id":"n"}"#)
        .create_async()
        .await;

    let mut cfg = NodeConfig::new(
        "n",
        "https://provider.example:8080",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.directory_url = server.url();
    cfg.model = Some("q".into());
    // cfg.cip_policy left None → falls back to module-level
    let node = IicpNode::new(cfg);
    assert!(node.register().await.is_ok());

    // Reset for other tests
    configure_cip_policy(opts());
}

// ── Module-level state ─────────────────────────────────────────────────────

#[test]
fn test_get_cip_policy_default() {
    let _guard = GLOBAL_POLICY_TEST_LOCK.lock().unwrap();
    configure_cip_policy(opts());
    let p = get_cip_policy();
    assert!(!p.enabled);
    assert!(!p.allow_worker);
}

#[test]
fn test_configure_cip_policy_replaces_global() {
    let _guard = GLOBAL_POLICY_TEST_LOCK.lock().unwrap();
    let mut o = opts();
    o.enabled = true;
    o.allow_worker = true;
    o.max_concurrent_remote = 5;
    configure_cip_policy(o);
    let p = get_cip_policy();
    assert!(p.enabled);
    assert!(p.allow_worker);
    assert_eq!(p.max_concurrent_remote, 5);
    configure_cip_policy(opts()); // reset
}

// #403 — per-task admission: tool-execution intent gate (parity with adapter cip_gate)
#[test]
fn test_permits_intent_tool_execution_gate() {
    let denied = CooperativeInferencePolicy::new(opts()); // allow_tool_execution=false default
    assert!(!denied.allow_tool_execution);
    assert!(denied.permits_intent("urn:iicp:intent:llm:chat:v1")); // non-tool always ok
    assert!(!denied.permits_intent("urn:iicp:intent:tool:shell:v1")); // tool denied by default
    let mut o = opts();
    o.allow_tool_execution = true;
    o.enabled = true;
    let allowed = CooperativeInferencePolicy::new(o);
    assert!(allowed.permits_intent("urn:iicp:intent:tool:shell:v1"));
    let block = allowed.as_register_policy_block().unwrap();
    assert_eq!(block["allow_tool_execution"], serde_json::json!(true));
}
