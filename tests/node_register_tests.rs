
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
    assert!(node.register_payload_for_test().get("current_node_token").is_none());
    node.seed_token("tok-prior");
    let p = node.register_payload_for_test();
    assert_eq!(p["current_node_token"], "tok-prior");
}
