use iicp_client::mcp_negotiation::{
    build_modern_mcp_request, evaluate_mcp_era, validate_modern_mcp_response, MODERN_MCP_REVISION,
};
use serde_json::{json, Map, Value};

#[test]
fn shared_mcp_era_fixture_passes() {
    let fixture: Value =
        serde_json::from_str(include_str!("../parity/mcp-era-negotiation-v0.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        assert_eq!(
            evaluate_mcp_era(&case["input"]),
            case["expected"],
            "{}",
            case["id"]
        );
    }
}

#[test]
fn modern_request_and_identity_are_bounded() {
    let mut params = Map::new();
    params.insert("name".into(), json!("format_json"));
    params.insert("arguments".into(), json!({}));
    let (headers, body) =
        build_modern_mcp_request(7, "tools/call", "format_json", &params, &["tasks".into()])
            .unwrap();
    assert!(headers
        .iter()
        .any(|(k, v)| k == "MCP-Protocol-Version" && v == MODERN_MCP_REVISION));
    assert!(!body.to_string().contains("dispatch_ticket"));
    validate_modern_mcp_response(
        &json!({"_meta":{"protocolVersion":MODERN_MCP_REVISION,"server":{"name":"local-mcp"}}}),
        "local-mcp",
    )
    .unwrap();
    assert_eq!(
        validate_modern_mcp_response(
            &json!({"_meta":{"protocolVersion":MODERN_MCP_REVISION,"server":{"name":"other"}}}),
            "local-mcp"
        ),
        Err("server_identity_mismatch")
    );
}
