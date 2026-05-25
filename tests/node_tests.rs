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
    use mockito::{Matcher, Server};

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
    use mockito::Server;

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/api/v1/heartbeat")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({ "status": "ok" }).to_string())
        .create_async()
        .await;

    let mut cfg = NodeConfig::new(
        "n-001",
        "https://my-host.example.com",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.directory_url = server.url();
    let node = IicpNode::new(cfg);
    assert!(node.heartbeat("tok-abc123").await.is_ok());
}
