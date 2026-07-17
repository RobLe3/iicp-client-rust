// Phase 2 (#529/#55): re-register sends current_node_token after seed_token
#[test]
fn seed_token_then_payload_carries_current_node_token() {
    use iicp_client::{IicpNode, NodeConfig};
    let cfg = NodeConfig::new(
        "n-reg",
        "https://node.example.com".to_string(),
        "urn:iicp:intent:llm:chat:v1",
    );
    let node = IicpNode::new(cfg);
    // fresh node → no current_node_token
    assert!(node
        .register_payload_for_test()
        .get("current_node_token")
        .is_none());
    node.seed_token("tok-prior");
    let p = node.register_payload_for_test();
    assert_eq!(p["current_node_token"], "tok-prior");
}

// #527 — endpoint override (tunnel rotation) flows into the register payload
#[test]
fn endpoint_override_changes_register_payload() {
    use iicp_client::{IicpNode, NodeConfig};
    let cfg = NodeConfig::new(
        "n-rot",
        "https://old-tunnel.example.com".to_string(),
        "urn:iicp:intent:llm:chat:v1",
    );
    let node = IicpNode::new(cfg);
    // fresh: payload carries the configured endpoint
    assert_eq!(
        node.register_payload_for_test()["endpoint"],
        "https://old-tunnel.example.com"
    );
    // watchdog publishes a rotated URL via the override handle
    *node.endpoint_override_handle().write().unwrap() =
        Some("https://new-tunnel.example.com".to_string());
    assert_eq!(
        node.register_payload_for_test()["endpoint"],
        "https://new-tunnel.example.com"
    );
}

#[test]
fn register_payload_advertises_only_enabled_consumer_cosignature_profile() {
    use iicp_client::{IicpNode, NodeConfig};
    let mut cfg = NodeConfig::new(
        "n-receipt",
        "https://node.example.com".to_string(),
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.supported_receipt_profiles = vec![
        "unknown_v1".to_string(),
        "consumer_cosignature_v1".to_string(),
        "consumer_cosignature_v1".to_string(),
    ];
    let payload = IicpNode::new(cfg).register_payload_for_test();
    assert_eq!(
        payload["supported_receipt_profiles"],
        serde_json::json!(["consumer_cosignature_v1"])
    );
}
