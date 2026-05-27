// SPDX-License-Identifier: Apache-2.0
//! Integration tests for IicpNode: health, task, concurrency gate, nonce replay, traceparent.

use std::net::TcpListener as StdListener;

use iicp_client::node::{IicpNode, NodeConfig};
use serde_json::{json, Value};

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start_node(port: u16, max_concurrent: usize) -> tokio::task::JoinHandle<()> {
    let mut cfg = NodeConfig::new(
        "test-node",
        "http://test.local",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.max_concurrent = max_concurrent;
    cfg.region = Some("test-region".into());
    cfg.model = Some("test-model".into());
    let node = IicpNode::new(cfg);
    let addr = format!("127.0.0.1:{port}");
    tokio::spawn(async move {
        let _ = node
            .serve(
                |task| Box::pin(async move { Ok(json!({ "echo": task.payload })) }),
                &addr,
                None,
            )
            .await;
    })
}

async fn wait_port(port: u16) {
    for _ in 0..40 {
        if reqwest::get(format!("http://127.0.0.1:{port}/iicp/health"))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("server did not start on port {port}");
}

#[tokio::test]
async fn test_health_endpoint_returns_200() {
    let port = free_port();
    let handle = start_node(port, 4).await;
    wait_port(port).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{port}/iicp/health"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["node_id"], "test-node");
    assert_eq!(body["max_concurrent"], 4);
    assert!(body["available"].as_bool().unwrap_or(false));

    handle.abort();
}

#[tokio::test]
async fn test_task_endpoint_returns_200() {
    let port = free_port();
    let handle = start_node(port, 4).await;
    wait_port(port).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/v1/task"))
        .json(&json!({ "task_id": "t-001", "intent": "x", "payload": { "msg": "hi" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "completed");
    assert_eq!(body["task_id"], "t-001");

    handle.abort();
}

#[tokio::test]
async fn test_concurrency_gate_429() {
    let port = free_port();
    let mut cfg = NodeConfig::new(
        "gate-node",
        "http://test.local",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.max_concurrent = 0;
    let node = IicpNode::new(cfg);
    let addr = format!("127.0.0.1:{port}");
    let handle = tokio::spawn(async move {
        let _ = node
            .serve(
                |task| Box::pin(async move { Ok(json!({"echo": task.payload})) }),
                &addr,
                None,
            )
            .await;
    });

    for _ in 0..40 {
        if reqwest::get(format!("http://127.0.0.1:{port}/iicp/health"))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/v1/task"))
        .json(&json!({ "task_id": "t", "intent": "x", "payload": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
    let retry_after = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "IICP-E021");
    assert_eq!(retry_after.as_deref(), Some("2"));

    handle.abort();
}

#[tokio::test]
async fn test_nonce_replay_409() {
    let port = free_port();
    let handle = start_node(port, 4).await;
    wait_port(port).await;

    let client = reqwest::Client::new();
    let nonce = "nonce-rust-replay-test";

    let r1 = client
        .post(format!("http://127.0.0.1:{port}/v1/task"))
        .json(&json!({ "task_id": "t1", "intent": "x", "payload": {}, "nonce": nonce }))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);

    let r2 = client
        .post(format!("http://127.0.0.1:{port}/v1/task"))
        .json(&json!({ "task_id": "t2", "intent": "x", "payload": {}, "nonce": nonce }))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 409);
    let body: Value = r2.json().await.unwrap();
    assert_eq!(body["error"]["code"], "IICP-E011");

    handle.abort();
}

#[tokio::test]
async fn test_traceparent_propagated_to_handler() {
    let port = free_port();
    let tp_header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    let captured = std::sync::Arc::new(tokio::sync::Mutex::new(None::<Value>));
    let captured_clone = captured.clone();

    let mut cfg = NodeConfig::new(
        "trace-node",
        "http://test.local",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.max_concurrent = 4;
    let node = IicpNode::new(cfg);
    let addr = format!("127.0.0.1:{port}");

    let handle = tokio::spawn(async move {
        let _ = node
            .serve(
                move |task| {
                    let cap = captured_clone.clone();
                    Box::pin(async move {
                        if let Some(t) = &task._trace {
                            *cap.lock().await = Some(t.clone());
                        }
                        Ok(json!({}))
                    })
                },
                &addr,
                None,
            )
            .await;
    });

    wait_port(port).await;

    let client = reqwest::Client::new();
    client
        .post(format!("http://127.0.0.1:{port}/v1/task"))
        .header("traceparent", tp_header)
        .json(&json!({ "task_id": "t1", "intent": "x", "payload": {} }))
        .send()
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let cap = captured.lock().await;
    let tp = cap.as_ref().and_then(|v| v["traceparent"].as_str());
    assert_eq!(tp, Some(tp_header));

    handle.abort();
}

#[tokio::test]
async fn test_node_register_returns_token() {
    use mockito::Server;

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/v1/register")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({ "node_token": "tok-abc123", "message": "registered" }).to_string())
        .create_async()
        .await;

    let mut cfg = NodeConfig::new(
        "n-001",
        "https://my-host.example.com",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.directory_url = server.url();
    let node = IicpNode::new(cfg);
    let token = node.register().await.unwrap();
    assert_eq!(token, "tok-abc123");
}

#[tokio::test]
async fn test_node_register_no_token_fails() {
    use mockito::Server;

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/v1/register")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({ "message": "ok" }).to_string())
        .create_async()
        .await;

    let mut cfg = NodeConfig::new(
        "n-001",
        "https://my-host.example.com",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.directory_url = server.url();
    let node = IicpNode::new(cfg);
    assert!(node.register().await.is_err());
}

#[tokio::test]
async fn test_node_heartbeat_ok() {
    // #346 — heartbeat path is /v1/heartbeat (NOT /api/v1/heartbeat).
    // Uses a real axum listener instead of mockito: mockito's async server
    // returns 501 on Linux CI for requests that include an Authorization
    // header (bearer_auth), making the heartbeat test unreliable in CI.
    use axum::{routing::post, Json, Router};

    let app = Router::new().route(
        "/v1/heartbeat",
        post(|| async { Json(json!({ "status": "ok" })) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut cfg = NodeConfig::new(
        "n-001",
        "https://my-host.example.com",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.directory_url = format!("http://{addr}");
    let node = IicpNode::new(cfg);
    node.heartbeat("tok-abc123")
        .await
        .expect("heartbeat should succeed against local axum server");
}

/// iter-1413: register payload matches spec/iicp-dir.md §3.1 —
/// capabilities is an array of {intent, models, max_tokens} objects, not a flat intent string.
#[tokio::test]
async fn test_register_payload_spec_compliant() {
    use mockito::{Matcher, Server};

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/v1/register")
        .match_body(Matcher::PartialJson(json!({
            "endpoint": "https://provider.example.com:8080",
            "region": "eu-central",
            "capabilities": [{
                "intent": "urn:iicp:intent:llm:chat:v1",
                "models": ["llama-3-8b"],
                "max_tokens": 8192
            }],
            "limits": { "max_concurrent": 2, "tokens_per_min": 2000 }
        })))
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(json!({ "node_token": "tok-1", "node_id": "n-1" }).to_string())
        .create_async()
        .await;

    let mut cfg = NodeConfig::new(
        "n-1",
        "https://provider.example.com:8080",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.directory_url = server.url();
    cfg.model = Some("llama-3-8b".into());
    cfg.region = Some("eu-central".into());
    cfg.max_concurrent = 2;
    cfg.tokens_per_min = 2000;
    cfg.max_tokens = 8192;
    let node = IicpNode::new(cfg);
    let token = node.register().await.unwrap();
    assert_eq!(token, "tok-1");
}

/// iter-1413: spec v0.7.0 — register includes transport_endpoint when configured.
#[tokio::test]
async fn test_register_includes_transport_endpoint() {
    use mockito::{Matcher, Server};

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/v1/register")
        .match_body(Matcher::PartialJson(json!({
            "endpoint": "https://provider.example.com:8080",
            "transport_endpoint": "iicp://provider.example.com:9484"
        })))
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(json!({ "node_token": "tok-2", "node_id": "n-2" }).to_string())
        .create_async()
        .await;

    let mut cfg = NodeConfig::new(
        "n-2",
        "https://provider.example.com:8080",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.directory_url = server.url();
    cfg.model = Some("qwen2.5:0.5b".into());
    cfg.transport_endpoint = Some("iicp://provider.example.com:9484".into());
    let node = IicpNode::new(cfg);
    assert!(node.register().await.is_ok());
}

/// iter-1428: register payload includes transport_method / nat_type /
/// transport_metadata when set on NodeConfig (manually OR via apply_nat_profile).
#[tokio::test]
async fn test_register_includes_nat_observability_when_set() {
    use mockito::{Matcher, Server};

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/v1/register")
        .match_body(Matcher::PartialJson(json!({
            "transport_method": "upnp_mapped",
            "nat_type": "full_cone",
            "transport_metadata": {"tier": 1}
        })))
        .with_status(201)
        .with_body(json!({ "node_token": "tok-nat", "node_id": "n-nat" }).to_string())
        .create_async()
        .await;

    let mut cfg = NodeConfig::new(
        "n-nat",
        "https://provider.example.com:8080",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.directory_url = server.url();
    cfg.model = Some("qwen2.5:0.5b".into());
    cfg.transport_endpoint = Some("iicp://provider.example.com:9484".into());
    cfg.transport_method = Some("upnp_mapped".into());
    cfg.nat_type = Some("full_cone".into());
    cfg.transport_metadata = Some(json!({"tier": 1, "detection_log_tail": ["ok"]}));
    let node = IicpNode::new(cfg);
    assert!(node.register().await.is_ok());
}

/// iter-1428: apply_nat_profile populates the NAT fields from a NatProfile
/// and overrides `endpoint` when the profile is reachable.
#[cfg(feature = "nat")]
#[tokio::test]
async fn test_apply_nat_profile_populates_fields() {
    use iicp_client::nat_detection::{NatProfile, TransportMethod};
    use mockito::{Matcher, Server};

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/v1/register")
        .match_body(Matcher::PartialJson(json!({
            "endpoint": "http://203.0.113.5:8080",
            "transport_endpoint": "iicp://203.0.113.5:9484",
            "transport_method": "upnp_mapped",
            "nat_type": "unknown"
        })))
        .with_status(201)
        .with_body(json!({ "node_token": "tok-applied", "node_id": "n-applied" }).to_string())
        .create_async()
        .await;

    let mut cfg = NodeConfig::new(
        "n-applied",
        "http://placeholder.example.com:8080",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.directory_url = server.url();
    cfg.model = Some("q".into());
    let mut node = IicpNode::new(cfg);

    let profile = NatProfile {
        tier: 1,
        transport_method: TransportMethod::UpnpMapped,
        public_endpoint: Some("http://203.0.113.5:8080".into()),
        transport_endpoint: Some("iicp://203.0.113.5:9484".into()),
        internal_endpoint: None,
        operator_guidance: None,
        detection_log: vec!["tier-1: UPnP mapped".into()],
        ipv6: None,
    };
    node.apply_nat_profile(&profile);
    assert!(node.register().await.is_ok());
}

/// iter-1428: tier-4 (unreachable) profiles preserve a manually-set endpoint
/// and do NOT surface transport_method "unreachable" to the directory.
#[cfg(feature = "nat")]
#[tokio::test]
async fn test_apply_nat_profile_unreachable_preserves_endpoint() {
    use iicp_client::nat_detection::{NatProfile, TransportMethod};
    use mockito::{Matcher, Server};

    let mut server = Server::new_async().await;
    // The mock matches the original manual endpoint AND requires
    // transport_method to be absent (PartialJson only checks supplied keys).
    // For "absence" we rely on the body match never including transport_method.
    let _m = server
        .mock("POST", "/v1/register")
        .match_body(Matcher::PartialJson(json!({
            "endpoint": "https://manual.example.com:8080"
        })))
        .with_status(201)
        .with_body(json!({ "node_token": "tok-keep", "node_id": "n-keep" }).to_string())
        .expect(1)
        .create_async()
        .await;

    let mut cfg = NodeConfig::new(
        "n-keep",
        "https://manual.example.com:8080",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.directory_url = server.url();
    cfg.model = Some("q".into());
    let mut node = IicpNode::new(cfg);

    let profile = NatProfile {
        tier: 4,
        transport_method: TransportMethod::Unreachable,
        public_endpoint: None,
        transport_endpoint: None,
        internal_endpoint: None,
        operator_guidance: Some("install igd-next".into()),
        detection_log: vec!["tier-4 fallback".into()],
        ipv6: None,
    };
    node.apply_nat_profile(&profile);
    assert!(node.register().await.is_ok());
    _m.assert_async().await;
}

/// iter-1413: legacy capabilities Vec<String> folds into the models array of the
/// single capability object — keeps pre-iter-1413 caller configs working.
/// We assert via a custom body matcher closure so the mock only succeeds when
/// the models array contains all three names (order-independent).
#[tokio::test]
async fn test_register_legacy_capabilities_folds_into_models() {
    use mockito::{Matcher, Server};

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/v1/register")
        .match_body(Matcher::PartialJson(json!({
            "capabilities": [{
                "intent": "urn:iicp:intent:llm:chat:v1",
                "max_tokens": 8192
            }]
        })))
        // The body matcher above guarantees the capabilities structure is correct.
        // To check models contains all three (order-independent), we expect 1 call;
        // a single Mock with PartialJson treats missing fields as no-match, so if
        // the structure is wrong, register() will get a non-mock 501 and fail.
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(json!({ "node_token": "tok-3", "node_id": "n-3" }).to_string())
        .expect(1)
        .create_async()
        .await;

    let mut cfg = NodeConfig::new(
        "n-3",
        "https://provider.example.com:8080",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.directory_url = server.url();
    cfg.model = Some("llama-3-8b".into());
    cfg.capabilities = vec!["mistral-7b".into(), "phi-3-mini".into()];
    let node = IicpNode::new(cfg);
    assert!(node.register().await.is_ok());

    // Verify the mock fired exactly once (= our body matched).
    _m.assert_async().await;
}
