// SPDX-License-Identifier: Apache-2.0
use iicp_client::{
    make_traceparent, ClientConfig, DiscoverOptions, IicpClient, IicpError, RoutingPolicy,
    RoutingProfile, TaskRequest,
};
use std::sync::{Mutex, OnceLock};

fn env_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

// is_transient() — used by retry logic (SDK-05)
#[test]
fn is_transient_on_429() {
    let e = IicpError::Protocol {
        code: "capacity_exceeded".into(),
        message: "".into(),
        status: 429,
    };
    assert!(e.is_transient());
}

#[test]
fn is_transient_on_503() {
    let e = IicpError::Protocol {
        code: "backend_unreachable".into(),
        message: "".into(),
        status: 503,
    };
    assert!(e.is_transient());
}

#[test]
fn is_not_transient_on_401() {
    let e = IicpError::Protocol {
        code: "token_invalid".into(),
        message: "".into(),
        status: 401,
    };
    assert!(!e.is_transient());
}

#[test]
fn is_not_transient_on_422() {
    let e = IicpError::Protocol {
        code: "validation_error".into(),
        message: "".into(),
        status: 422,
    };
    assert!(!e.is_transient());
}

#[test]
fn sdk04_rejects_oversized_timeout() {
    let cfg = ClientConfig {
        timeout_ms: 120_001,
        ..Default::default()
    };
    assert!(matches!(
        IicpClient::new(cfg),
        Err(IicpError::TimeoutTooLarge(120_001))
    ));
}

#[test]
fn sdk04_accepts_max_timeout() {
    let cfg = ClientConfig {
        timeout_ms: 120_000,
        ..Default::default()
    };
    assert!(IicpClient::new(cfg).is_ok());
}

// SDK-06: W3C traceparent format validation
#[test]
fn sdk06_traceparent_format() {
    let tp = make_traceparent();
    let parts: Vec<&str> = tp.split('-').collect();
    assert_eq!(parts.len(), 4, "expected 4 dash-separated parts: {tp}");
    assert_eq!(parts[0], "00");
    assert_eq!(parts[1].len(), 32, "trace-id must be 32 hex chars: {tp}");
    assert_eq!(parts[2].len(), 16, "parent-id must be 16 hex chars: {tp}");
    assert_eq!(parts[3], "01");
    // verify hex chars only
    assert!(parts[1].chars().all(|c| c.is_ascii_hexdigit()));
    assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn sdk06_traceparent_unique() {
    let tp1 = make_traceparent();
    let tp2 = make_traceparent();
    assert_ne!(tp1, tp2, "consecutive traceparents must differ");
}

#[tokio::test]
async fn sdk03_rejects_invalid_intent() {
    let client = IicpClient::new(ClientConfig::default()).unwrap();
    let err = client.discover("not-a-urn", None, None).await.unwrap_err();
    assert!(matches!(err, IicpError::InvalidIntent(_)));
}

#[tokio::test]
async fn policy_refuses_prohibited_intent_before_discovery() {
    let client = IicpClient::new(ClientConfig::default()).unwrap();
    let err = client
        .discover("urn:iicp:intent:social-scoring:score:v1", None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, IicpError::PolicyRefused { code, .. } if code == "IICP-POLICY-001"));
}

#[tokio::test]
async fn sdk03_accepts_valid_intent() {
    // Validates pattern only — no network call needed for intent check.
    // A network error here means the intent was accepted (correct).
    let client = IicpClient::new(ClientConfig {
        directory_url: "http://127.0.0.1:19999".into(), // unreachable
        ..Default::default()
    })
    .unwrap();
    let err = client
        .discover("urn:iicp:intent:llm:chat:v1", None, None)
        .await
        .unwrap_err();
    assert!(!matches!(err, IicpError::InvalidIntent(_)));
}

#[tokio::test]
async fn discover_accepts_deprecated_public_key_alias_for_cx_key() {
    use serde_json::json;

    let mut server = mockito::Server::new_async().await;
    let _discover = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "count": 1,
                "nodes": [{
                    "node_id": "n1",
                    "endpoint": "https://1.2.3.4:9484",
                    "score": 0.95,
                    "available": true,
                    "region": "eu",
                    "directory_observed_reachable": true,
                    "route_evidence": "directory_observed",
                    "routing_hint": "https_direct",
                    "browser_usable": true,
                    "node_policy_manifest": {
                        "jurisdiction": "DE",
                        "training_use": "none",
                        "evidence": "self_attested"
                    },
                    "public_key": {
                        "algorithm": "X25519",
                        "encoding": "base64url",
                        "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "key_id": "cx-1"
                    }
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let client = IicpClient::new(ClientConfig {
        directory_url: format!("{}/api", server.url()),
        ..Default::default()
    })
    .unwrap();

    let nodes = client
        .discover("urn:iicp:intent:llm:chat:v1", None, None)
        .await
        .unwrap();
    assert_eq!(nodes.nodes.len(), 1);
    assert_eq!(
        nodes.nodes[0]
            .cx_public_key
            .as_ref()
            .map(|key| key.key_id.as_str()),
        Some("cx-1")
    );
    assert_eq!(nodes.nodes[0].directory_observed_reachable, Some(true));
    assert_eq!(
        nodes.nodes[0].route_evidence.as_deref(),
        Some("directory_observed")
    );
    assert_eq!(nodes.nodes[0].routing_hint.as_deref(), Some("https_direct"));
    assert_eq!(nodes.nodes[0].browser_usable, Some(true));
    assert_eq!(
        nodes.nodes[0]
            .node_policy_manifest
            .as_ref()
            .and_then(|v| v.get("jurisdiction"))
            .and_then(|v| v.as_str()),
        Some("DE")
    );
}

#[tokio::test]
async fn discover_accepts_both_cx_public_key_and_public_key_without_duplicate_error() {
    use serde_json::json;

    let mut server = mockito::Server::new_async().await;
    let _discover = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "count": 1,
                "nodes": [{
                    "node_id": "n1",
                    "endpoint": "https://1.2.3.4:9484",
                    "score": 0.95,
                    "available": true,
                    "region": "eu",
                    "cx_public_key": {
                        "algorithm": "X25519",
                        "encoding": "base64url",
                        "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "key_id": "cx-canonical"
                    },
                    "public_key": {
                        "algorithm": "X25519",
                        "encoding": "base64url",
                        "key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                        "key_id": "cx-alias"
                    }
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let client = IicpClient::new(ClientConfig {
        directory_url: format!("{}/api", server.url()),
        ..Default::default()
    })
    .unwrap();

    let nodes = client
        .discover("urn:iicp:intent:llm:chat:v1", None, None)
        .await
        .unwrap();
    assert_eq!(
        nodes.nodes[0]
            .cx_public_key
            .as_ref()
            .map(|key| key.key_id.as_str()),
        Some("cx-canonical")
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn submit_skips_keyless_nodes_by_default() {
    use serde_json::json;

    let _guard = env_test_lock();
    unsafe { std::env::set_var("IICP_PROXY_ALLOW_LOOPBACK_NODES", "1") };
    unsafe { std::env::remove_var("IICP_CX_ALLOW_PLAINTEXT") };

    let mut server = mockito::Server::new_async().await;
    let keyed_endpoint = format!("{}/keyed", server.url());
    let keyless_endpoint = format!("{}/keyless", server.url());
    let _discover = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "count": 2,
                "nodes": [
                    {
                        "node_id": "n-keyless",
                        "endpoint": keyless_endpoint,
                        "score": 0.99,
                        "available": true,
                        "region": "eu"
                    },
                    {
                        "node_id": "n-keyed",
                        "endpoint": keyed_endpoint,
                        "score": 0.50,
                        "available": true,
                        "region": "eu",
                        "cx_public_key": {
                            "algorithm": "X25519",
                            "encoding": "base64url",
                            "key": "-LKZgrZEnFMr9ctB3uQDKsME07ZzS4Ce-SapFAePul0",
                            "key_id": "cx-fixture"
                        }
                    }
                ]
            })
            .to_string(),
        )
        .create_async()
        .await;
    let _keyless = server
        .mock("POST", "/keyless/v1/task")
        .with_status(500)
        .expect(0)
        .create_async()
        .await;
    let _keyed = server
        .mock("POST", "/keyed/v1/task")
        .match_body(mockito::Matcher::PartialJson(json!({
            "iicp_conf": {"recipient_key_id": "cx-fixture"}
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({"task_id":"t1","status":"success","result":{},"metrics":{"node_id":"n-keyed"}})
                .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let client = IicpClient::new(ClientConfig {
        directory_url: format!("{}/api", server.url()),
        routing_strategy: "deterministic".into(),
        ..Default::default()
    })
    .unwrap();
    let resp = client
        .submit(TaskRequest {
            task_id: String::new(),
            intent: "urn:iicp:intent:llm:chat:v1".into(),
            payload: json!({"messages": []}),
            constraints: None,
            auth: None,
            source_node_id: None,
            routing_policy: None,
        })
        .await
        .unwrap();
    assert_eq!(resp.status, "success");
    _keyless.assert_async().await;
    _keyed.assert_async().await;

    unsafe { std::env::remove_var("IICP_PROXY_ALLOW_LOOPBACK_NODES") };
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn submit_refuses_all_keyless_nodes_by_default() {
    use serde_json::json;

    let _guard = env_test_lock();
    unsafe { std::env::set_var("IICP_PROXY_ALLOW_LOOPBACK_NODES", "1") };
    unsafe { std::env::remove_var("IICP_CX_ALLOW_PLAINTEXT") };

    let mut server = mockito::Server::new_async().await;
    let endpoint = format!("{}/keyless", server.url());
    let _discover = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({"count":1,"nodes":[{"node_id":"n-keyless","endpoint":endpoint,"score":1.0,"available":true,"region":"eu"}]}).to_string())
        .create_async()
        .await;
    let _task = server
        .mock("POST", "/keyless/v1/task")
        .with_status(200)
        .expect(0)
        .create_async()
        .await;

    let client = IicpClient::new(ClientConfig {
        directory_url: format!("{}/api", server.url()),
        routing_strategy: "deterministic".into(),
        ..Default::default()
    })
    .unwrap();
    let err = client
        .submit(TaskRequest {
            task_id: String::new(),
            intent: "urn:iicp:intent:llm:chat:v1".into(),
            payload: json!({"messages": []}),
            constraints: None,
            auth: None,
            source_node_id: None,
            routing_policy: None,
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("confidentiality required"));
    _task.assert_async().await;

    unsafe { std::env::remove_var("IICP_PROXY_ALLOW_LOOPBACK_NODES") };
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn routing_policy_sensitive_refuses_remote_before_prompt_dispatch() {
    use serde_json::json;

    let _guard = env_test_lock();
    unsafe { std::env::set_var("IICP_PROXY_ALLOW_LOOPBACK_NODES", "1") };

    let mut server = mockito::Server::new_async().await;
    let endpoint = format!("{}/remote", server.url());
    let _discover = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({"count":1,"nodes":[{
                "node_id":"n-sensitive",
                "endpoint":endpoint,
                "score":1.0,
                "available":true,
                "region":"eu",
                "cx_public_key":{
                    "algorithm":"X25519",
                    "encoding":"base64url",
                    "key":"-LKZgrZEnFMr9ctB3uQDKsME07ZzS4Ce-SapFAePul0",
                    "key_id":"cx-fixture"
                }
            }]})
            .to_string(),
        )
        .create_async()
        .await;
    let _task = server
        .mock("POST", "/remote/v1/task")
        .with_status(200)
        .expect(0)
        .create_async()
        .await;

    let client = IicpClient::new(ClientConfig {
        directory_url: format!("{}/api", server.url()),
        ..Default::default()
    })
    .unwrap();
    let err = client
        .submit(TaskRequest {
            task_id: String::new(),
            intent: "urn:iicp:intent:llm:chat:v1".into(),
            payload: json!({"messages": [{"role":"user","content":"GDPR_CANARY_PROMPT_DO_NOT_SEND"}]}),
            constraints: None,
            auth: None,
            source_node_id: None,
            routing_policy: Some(RoutingPolicy {
                profile: RoutingProfile::Sensitive,
                ..Default::default()
            }),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, IicpError::PolicyRefused { code, .. } if code == "IICP-POLICY-ROUTING"));
    _task.assert_async().await;

    unsafe { std::env::remove_var("IICP_PROXY_ALLOW_LOOPBACK_NODES") };
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn routing_policy_eu_restricted_excludes_non_eu_and_routes_to_eu() {
    use serde_json::json;

    let _guard = env_test_lock();
    unsafe { std::env::set_var("IICP_PROXY_ALLOW_LOOPBACK_NODES", "1") };

    let mut server = mockito::Server::new_async().await;
    let us_endpoint = format!("{}/us", server.url());
    let eu_endpoint = format!("{}/eu", server.url());
    let key = json!({
        "algorithm":"X25519",
        "encoding":"base64url",
        "key":"-LKZgrZEnFMr9ctB3uQDKsME07ZzS4Ce-SapFAePul0",
        "key_id":"cx-fixture"
    });
    let _discover = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({"count":2,"nodes":[
            {"node_id":"us-node","endpoint":us_endpoint,"score":0.99,"available":true,"region":"us-east","cx_public_key":key},
            {"node_id":"eu-node","endpoint":eu_endpoint,"score":0.50,"available":true,"region":"eu-central","cx_public_key":key}
        ]}).to_string())
        .create_async()
        .await;
    let _us = server
        .mock("POST", "/us/v1/task")
        .with_status(500)
        .expect(0)
        .create_async()
        .await;
    let _eu = server
        .mock("POST", "/eu/v1/task")
        .match_body(mockito::Matcher::PartialJson(json!({
            "iicp_conf": {"recipient_key_id": "cx-fixture"}
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({"task_id":"t1","status":"success","result":{},"metrics":{"node_id":"eu-node"}})
                .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let client = IicpClient::new(ClientConfig {
        directory_url: format!("{}/api", server.url()),
        routing_strategy: "deterministic".into(),
        ..Default::default()
    })
    .unwrap();
    let resp = client
        .submit(TaskRequest {
            task_id: String::new(),
            intent: "urn:iicp:intent:llm:chat:v1".into(),
            payload: json!({"messages": []}),
            constraints: None,
            auth: None,
            source_node_id: None,
            routing_policy: Some(RoutingPolicy {
                profile: RoutingProfile::EuRestricted,
                ..Default::default()
            }),
        })
        .await
        .unwrap();
    assert_eq!(resp.status, "success");
    _us.assert_async().await;
    _eu.assert_async().await;

    unsafe { std::env::remove_var("IICP_PROXY_ALLOW_LOOPBACK_NODES") };
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn routing_policy_strict_requires_no_payload_retention_manifest() {
    use serde_json::json;

    let _guard = env_test_lock();
    unsafe { std::env::set_var("IICP_PROXY_ALLOW_LOOPBACK_NODES", "1") };

    let mut server = mockito::Server::new_async().await;
    let endpoint = format!("{}/retained", server.url());
    let _discover = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({"count":1,"nodes":[{
                "node_id":"n-retained",
                "endpoint":endpoint,
                "score":1.0,
                "available":true,
                "region":"eu",
                "cx_public_key":{
                    "algorithm":"X25519",
                    "encoding":"base64url",
                    "key":"-LKZgrZEnFMr9ctB3uQDKsME07ZzS4Ce-SapFAePul0",
                    "key_id":"cx-fixture"
                },
                "node_policy_manifest": {
                    "jurisdiction": "DE",
                    "retention": {"task_payload": "provider_defined"},
                    "evidence": "signed_verified",
                    "verification": {"status": "signed_valid"}
                }
            }]})
            .to_string(),
        )
        .create_async()
        .await;
    let _task = server
        .mock("POST", "/retained/v1/task")
        .with_status(200)
        .expect(0)
        .create_async()
        .await;

    let client = IicpClient::new(ClientConfig {
        directory_url: format!("{}/api", server.url()),
        ..Default::default()
    })
    .unwrap();
    let err = client
        .submit(TaskRequest {
            task_id: String::new(),
            intent: "urn:iicp:intent:llm:chat:v1".into(),
            payload: json!({"messages": []}),
            constraints: None,
            auth: None,
            source_node_id: None,
            routing_policy: Some(RoutingPolicy {
                profile: RoutingProfile::StrictPolicy,
                ..Default::default()
            }),
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("payload_retention_not_none"));
    _task.assert_async().await;

    unsafe { std::env::remove_var("IICP_PROXY_ALLOW_LOOPBACK_NODES") };
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn routing_policy_strict_requires_signed_policy_manifest() {
    use serde_json::json;

    let _guard = env_test_lock();
    unsafe { std::env::set_var("IICP_PROXY_ALLOW_LOOPBACK_NODES", "1") };

    let mut server = mockito::Server::new_async().await;
    let endpoint = format!("{}/self-attested", server.url());
    let _discover = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({"count":1,"nodes":[{
                "node_id":"n-self-attested",
                "endpoint":endpoint,
                "score":1.0,
                "available":true,
                "region":"eu",
                "cx_public_key":{
                    "algorithm":"X25519",
                    "encoding":"base64url",
                    "key":"-LKZgrZEnFMr9ctB3uQDKsME07ZzS4Ce-SapFAePul0",
                    "key_id":"cx-fixture"
                },
                "node_policy_manifest": {
                    "jurisdiction": "DE",
                    "retention": {"task_payload": "none"},
                    "evidence": "self_attested"
                }
            }]})
            .to_string(),
        )
        .create_async()
        .await;
    let _task = server
        .mock("POST", "/self-attested/v1/task")
        .with_status(200)
        .expect(0)
        .create_async()
        .await;

    let client = IicpClient::new(ClientConfig {
        directory_url: format!("{}/api", server.url()),
        ..Default::default()
    })
    .unwrap();
    let err = client
        .submit(TaskRequest {
            task_id: String::new(),
            intent: "urn:iicp:intent:llm:chat:v1".into(),
            payload: json!({"messages": []}),
            constraints: None,
            auth: None,
            source_node_id: None,
            routing_policy: Some(RoutingPolicy {
                profile: RoutingProfile::StrictPolicy,
                ..Default::default()
            }),
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("policy_manifest_not_signed"));
    _task.assert_async().await;

    unsafe { std::env::remove_var("IICP_PROXY_ALLOW_LOOPBACK_NODES") };
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn routing_policy_requires_operator_bound_manifest_identity_before_dispatch() {
    use serde_json::json;

    let _guard = env_test_lock();
    unsafe { std::env::set_var("IICP_PROXY_ALLOW_LOOPBACK_NODES", "1") };

    let mut server = mockito::Server::new_async().await;
    let endpoint = format!("{}/signed-only", server.url());
    let _discover = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({"count":1,"nodes":[{
                "node_id":"n-signed-only",
                "endpoint":endpoint,
                "score":1.0,
                "available":true,
                "region":"eu",
                "cx_public_key":{
                    "algorithm":"X25519",
                    "encoding":"base64url",
                    "key":"-LKZgrZEnFMr9ctB3uQDKsME07ZzS4Ce-SapFAePul0",
                    "key_id":"cx-fixture"
                },
                "node_policy_manifest": {
                    "jurisdiction": "DE",
                    "retention": {"task_payload": "none"},
                    "evidence": "signed_verified",
                    "verification": {"status": "signed_valid"},
                    "manifest_identity_level": "signed_valid"
                }
            }]})
            .to_string(),
        )
        .create_async()
        .await;
    let _task = server
        .mock("POST", "/signed-only/v1/task")
        .with_status(200)
        .expect(0)
        .create_async()
        .await;

    let client = IicpClient::new(ClientConfig {
        directory_url: format!("{}/api", server.url()),
        ..Default::default()
    })
    .unwrap();
    let err = client
        .submit(TaskRequest {
            task_id: String::new(),
            intent: "urn:iicp:intent:llm:chat:v1".into(),
            payload: json!({"messages": []}),
            constraints: None,
            auth: None,
            source_node_id: None,
            routing_policy: Some(RoutingPolicy {
                required_manifest_identity_level: Some("operator_bound".into()),
                ..Default::default()
            }),
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("manifest_identity_level_too_low"));
    _task.assert_async().await;

    unsafe { std::env::remove_var("IICP_PROXY_ALLOW_LOOPBACK_NODES") };
}

#[tokio::test]
async fn discover_browser_usable_only_filters_http_ipv6_nodes() {
    use serde_json::json;

    let mut server = mockito::Server::new_async().await;
    let _discover = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "count": 2,
                "nodes": [
                    {
                        "node_id": "n-ipv6",
                        "endpoint": "http://[2a0a:a543:df54::8ae]:9484",
                        "score": 0.9,
                        "available": true,
                        "region": "eu",
                        "routing_hint": "http_ipv6",
                        "browser_usable": false
                    },
                    {
                        "node_id": "n-https",
                        "endpoint": "https://relay.example.com",
                        "score": 0.8,
                        "available": true,
                        "region": "eu",
                        "routing_hint": "relay_service",
                        "browser_usable": true
                    }
                ]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let client = IicpClient::new(ClientConfig {
        directory_url: format!("{}/api", server.url()),
        ..Default::default()
    })
    .unwrap();

    let nodes = client
        .discover(
            "urn:iicp:intent:llm:chat:v1",
            Some(DiscoverOptions {
                browser_usable_only: Some(true),
                ..Default::default()
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(nodes.nodes.len(), 1);
    assert_eq!(nodes.nodes[0].node_id, "n-https");
    assert_eq!(nodes.count, 1);
}

// ε-greedy provider selection (R4 / #486)
// These tests verify the config plumbing without a live network.

#[test]
fn epsilon_greedy_default_is_0_05() {
    let _guard = env_test_lock();
    // ClientConfig::default() must set routing_epsilon = 0.05 (R4 / #486).
    // This test fails if the field is absent or defaults to 0.
    let cfg = ClientConfig::default();
    // IICP_ROUTING_EPSILON may be set in the test environment; only assert
    // when the env var is absent.
    if std::env::var("IICP_ROUTING_EPSILON").is_err() {
        assert!(
            (cfg.routing_epsilon - 0.05).abs() < 1e-9,
            "default routing_epsilon must be 0.05, got {}",
            cfg.routing_epsilon
        );
    }
}

#[test]
fn epsilon_greedy_explicit_zero_disables_exploration() {
    let cfg = ClientConfig {
        routing_epsilon: 0.0,
        ..Default::default()
    };
    assert_eq!(cfg.routing_epsilon, 0.0);
}

#[test]
fn epsilon_greedy_env_override() {
    let _guard = env_test_lock();
    // IICP_ROUTING_EPSILON env var must override the default (R4 / #486).
    // Run in a subprocess context to avoid polluting other parallel tests.
    // We just verify the parse/clamp logic by setting the env var before Default::default().
    // Note: env var is read at Default::default() call time.
    unsafe { std::env::set_var("IICP_ROUTING_EPSILON", "0.0") };
    let cfg = ClientConfig::default();
    unsafe { std::env::remove_var("IICP_ROUTING_EPSILON") };
    assert_eq!(
        cfg.routing_epsilon, 0.0,
        "env IICP_ROUTING_EPSILON=0.0 should set routing_epsilon to 0.0"
    );
}

#[test]
fn routing_strategy_env_overrides() {
    let _guard = env_test_lock();
    unsafe { std::env::set_var("IICP_ROUTING_STRATEGY", "softmax_top_k") };
    unsafe { std::env::set_var("IICP_ROUTING_TOP_K", "2") };
    unsafe { std::env::set_var("IICP_ROUTING_SOFTMAX_TAU", "0.02") };
    let cfg = ClientConfig::default();
    unsafe { std::env::remove_var("IICP_ROUTING_STRATEGY") };
    unsafe { std::env::remove_var("IICP_ROUTING_TOP_K") };
    unsafe { std::env::remove_var("IICP_ROUTING_SOFTMAX_TAU") };
    assert_eq!(cfg.routing_strategy, "softmax_top_k");
    assert_eq!(cfg.routing_top_k, 2);
    assert!((cfg.routing_softmax_tau - 0.02).abs() < 1e-9);
}
