// Phase 2 (#529/#55): re-register sends current_node_token after seed_token
use serde_json::Value;

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

#[test]
fn shared_e050_client_lifecycle_projects_current_tokens_and_rotated_endpoints() {
    use iicp_client::{IicpNode, NodeConfig};
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/e050-client-credential-lifecycle-v1.json"
    ))
    .unwrap();
    for scenario in fixture["scenarios"].as_array().unwrap() {
        let cfg = NodeConfig::new(
            "n-reg",
            "https://old-tunnel.example".to_string(),
            "urn:iicp:intent:llm:chat:v1",
        );
        let node = IicpNode::new(cfg);
        if let Some(token) = scenario["starting_token"].as_str() {
            node.seed_token(token);
        }
        node.set_endpoint(scenario["requested_endpoint"].as_str().unwrap().to_string());
        let payload = node.register_payload_for_test();
        assert_eq!(
            payload.get("current_node_token").and_then(Value::as_str),
            scenario["expected_request_token"].as_str(),
            "{}",
            scenario["id"]
        );
        assert_eq!(payload["endpoint"], scenario["requested_endpoint"]);
    }
}
