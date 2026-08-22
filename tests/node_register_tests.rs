// Phase 2 (#529/#55): re-register sends current_node_token after seed_token
use serde_json::Value;

fn protected_membership_file() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("iicp-register-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, "member-token").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

#[tokio::test]
async fn restricted_registration_requires_authenticated_decision() {
    use axum::{http::HeaderMap, routing::post, Json, Router};
    use iicp_client::{
        runtime_config::SecretRef, IicpNode, NodeConfig, RestrictedDirectoryContext,
    };
    let app = Router::new().route(
        "/v1/register",
        post(|headers: HeaderMap| async move {
            assert_eq!(headers["x-iicp-membership"], "member-token");
            assert_eq!(headers["x-iicp-subject-id"], "node-a");
            Json(serde_json::json!({
                "node_token":"node-token", "node_hmac_key":"hmac",
                "restricted_domain_decision": {
                    "schema":"iicp.restricted-trust-domain.directory-decision.v0",
                    "profile":"urn:iicp:profile:restricted-trust-domain:v1",
                    "decision":"eligible", "operation":"registration",
                    "domain_id":"domain-a", "authority_id":"did:iicp:test:directory-a",
                    "subject_kind":"node", "membership_generation":7,
                    "membership_expires_at":u64::MAX
                }
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let path = protected_membership_file();
    let mut cfg = NodeConfig::new(
        "node-a",
        "https://node.example/task",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.directory_url = format!("http://{address}");
    cfg.restricted_directory = Some(RestrictedDirectoryContext {
        domain_id: "domain-a".into(),
        authority_id: "did:iicp:test:directory-a".into(),
        subject_id: "node-a".into(),
        subject_kind: "node".into(),
        minimum_membership_generation: 7,
        membership_credential: SecretRef::File {
            path: path.display().to_string(),
        },
    });
    assert_eq!(IicpNode::new(cfg).register().await.unwrap(), "node-token");
    server.abort();
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn restricted_registration_rejects_missing_decision() {
    use axum::{routing::post, Json, Router};
    use iicp_client::{
        runtime_config::SecretRef, IicpNode, NodeConfig, RestrictedDirectoryContext,
    };
    let app = Router::new().route(
        "/v1/register",
        post(|| async { Json(serde_json::json!({"node_token":"must-not-be-used"})) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let path = protected_membership_file();
    let mut cfg = NodeConfig::new(
        "node-a",
        "https://node.example/task",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.directory_url = format!("http://{address}");
    cfg.restricted_directory = Some(RestrictedDirectoryContext {
        domain_id: "domain-a".into(),
        authority_id: "did:iicp:test:directory-a".into(),
        subject_id: "node-a".into(),
        subject_kind: "node".into(),
        minimum_membership_generation: 7,
        membership_credential: SecretRef::File {
            path: path.display().to_string(),
        },
    });
    assert!(IicpNode::new(cfg).register().await.is_err());
    server.abort();
    let _ = std::fs::remove_file(path);
}

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
