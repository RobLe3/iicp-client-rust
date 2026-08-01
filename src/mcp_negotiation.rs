// SPDX-License-Identifier: Apache-2.0
//! MCP protocol-era negotiation and stateless request helpers.

use serde_json::{json, Map, Value};

pub const LEGACY_MCP_REVISION: &str = "2025-11-25";
pub const MODERN_MCP_REVISION: &str = "2026-07-28";
pub const SUPPORTED_MCP_REVISIONS: [&str; 2] = [LEGACY_MCP_REVISION, MODERN_MCP_REVISION];
pub type ModernMcpRequest = (Vec<(String, String)>, Value);

fn supported_extension(value: &str) -> bool {
    matches!(value, "tasks" | "skills" | "apps")
}

pub fn evaluate_mcp_era(input: &Value) -> Value {
    if input["downstream_credential_source"] == "caller" {
        return json!({"accepted":false,"reason":"credential_passthrough_prohibited"});
    }
    if input["server_identity_matches_selected_endpoint"] == false {
        return json!({"accepted":false,"reason":"server_identity_mismatch"});
    }
    if input["modern_request_failed"] == true && input["legacy_authentication_available"] != true {
        return json!({"accepted":false,"reason":"unauthenticated_downgrade"});
    }
    if let Some(extension) = input["extension"].as_str() {
        if !supported_extension(extension) {
            return json!({"accepted":false,"reason":"unsupported_extension"});
        }
    }
    match input["offered_revision"].as_str() {
        Some(MODERN_MCP_REVISION) => {
            if input["protocol_header_present"] == false {
                return json!({"accepted":false,"reason":"missing_protocol_version"});
            }
            if input["method_header_matches"] == false || input["name_header_matches"] == false {
                return json!({"accepted":false,"reason":"header_body_mismatch"});
            }
            if input["reserved_meta_valid"] == false {
                return json!({"accepted":false,"reason":"malformed_reserved_metadata"});
            }
            let peer = input["peer_supported_revisions"].as_array();
            let modern =
                peer.is_none_or(|v| v.is_empty() || v.iter().any(|r| r == MODERN_MCP_REVISION));
            if modern {
                return if input["request_state_explicit"] == true {
                    json!({"accepted":true,"state_source":"request"})
                } else {
                    json!({"accepted":true,"era":"modern","session_mode":"stateless"})
                };
            }
            let legacy = peer.is_some_and(|v| v.iter().any(|r| r == LEGACY_MCP_REVISION));
            if legacy
                && input["legacy_revision_explicitly_offered"] == true
                && input["security_requirements_preserved"] == true
            {
                return json!({"accepted":true,"era":"legacy","reason":"explicit_mutual_downgrade"});
            }
        }
        Some(LEGACY_MCP_REVISION) => {
            let peer = input["peer_supported_revisions"].as_array();
            if peer.is_none_or(|v| v.is_empty() || v.iter().any(|r| r == LEGACY_MCP_REVISION)) {
                return json!({"accepted":true,"era":"legacy","session_mode":"negotiated"});
            }
        }
        _ => {}
    }
    json!({"accepted":false,"reason":"unsupported_revision"})
}

pub fn build_modern_mcp_request(
    request_id: u64,
    method: &str,
    name: &str,
    params: &Map<String, Value>,
    extensions: &[String],
) -> Result<ModernMcpRequest, &'static str> {
    if extensions
        .iter()
        .any(|extension| !supported_extension(extension))
    {
        return Err("unsupported_extension");
    }
    let mut meta = json!({"protocolVersion":MODERN_MCP_REVISION,"client":{"name":"iicp-gateway"}});
    if !extensions.is_empty() {
        meta["extensions"] = json!(extensions);
    }
    let mut request_params = params.clone();
    request_params.insert("_meta".to_string(), meta);
    Ok((
        vec![
            ("MCP-Protocol-Version".into(), MODERN_MCP_REVISION.into()),
            ("Mcp-Method".into(), method.into()),
            ("Mcp-Name".into(), name.into()),
        ],
        json!({"jsonrpc":"2.0","id":request_id,"method":method,"params":request_params}),
    ))
}

pub fn validate_modern_mcp_response(
    data: &Value,
    expected_server_name: &str,
) -> Result<(), &'static str> {
    if data["_meta"]["protocolVersion"] != MODERN_MCP_REVISION {
        return Err("malformed_reserved_metadata");
    }
    if data["_meta"]["server"]["name"] != expected_server_name {
        return Err("server_identity_mismatch");
    }
    Ok(())
}
