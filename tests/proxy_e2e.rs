// SPDX-License-Identifier: Apache-2.0
//! End-to-end function test for `iicp-node proxy` (ADR-050, maintainer req).
//!
//! Launches the REAL compiled `iicp-node` binary in `proxy` mode against a mockito
//! directory + node and drives a real HTTP request through each compat surface
//! (OpenAI/Ollama/Anthropic), asserting the full path incl. `Server: iicp-proxy`.
//! Complements the in-process golden-fixture conformance. #482 / WQ-074.
#![cfg(feature = "proxy")]

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};

/// Kills the proxy child on scope exit (incl. assertion panics).
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_e2e_all_surfaces_through_real_binary() {
    let mut server = mockito::Server::new_async().await;
    let node_endpoint = server.url(); // http://127.0.0.1:<port> — same server doubles as the node

    let discover = json!({
        "nodes": [{"node_id": "mock-node-1", "endpoint": node_endpoint, "region": "test", "score": 1.0, "available": true}],
        "count": 1, "query_ms": 1,
    })
    .to_string();
    let _m_dir = server
        .mock(
            "GET",
            mockito::Matcher::Regex(r"/api/v1/discover.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(discover)
        .expect_at_least(1)
        .create_async()
        .await;
    let _m_node = server
        .mock("POST", "/v1/task")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({"task_id": "t-e2e", "status": "success", "result": {"choices": [{"message": {"role": "assistant", "content": "E2E reply"}}], "usage": {}}})
                .to_string(),
        )
        .expect_at_least(1)
        .create_async()
        .await;

    let proxy_port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_iicp-node"))
        .args(["proxy", "--port", &proxy_port.to_string()])
        .env("IICP_DIRECTORY_URL", format!("{}/api", server.url()))
        .env("IICP_PROXY_ALLOW_LOOPBACK_NODES", "1")
        .env("IICP_NODE_TOKEN", "")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn iicp-node proxy");
    let _guard = ChildGuard(child);

    let base = format!("http://127.0.0.1:{proxy_port}");
    let client = reqwest::Client::new();

    // readiness
    let mut ready = false;
    for _ in 0..80 {
        if let Ok(r) = client.get(format!("{base}/status")).send().await {
            if r.status() == 200 {
                ready = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        ready,
        "iicp-node proxy did not become ready on :{proxy_port}"
    );

    let msgs = json!([{"role": "user", "content": "hi"}]);

    // OpenAI
    let r = client
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({"model": "iicp", "messages": msgs}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.headers().get("server").unwrap().to_str().unwrap(),
        "iicp-proxy"
    );
    let d: Value = r.json().await.unwrap();
    assert_eq!(d["choices"][0]["message"]["content"], "E2E reply");

    // Ollama (non-stream)
    let r = client
        .post(format!("{base}/api/chat"))
        .json(&json!({"model": "iicp", "stream": false, "messages": msgs}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.headers().get("server").unwrap().to_str().unwrap(),
        "iicp-proxy"
    );
    let d: Value = r.json().await.unwrap();
    assert_eq!(d["message"]["content"], "E2E reply");

    // Anthropic
    let r = client
        .post(format!("{base}/v1/messages"))
        .json(&json!({"model": "iicp", "max_tokens": 32, "messages": msgs}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.headers().get("server").unwrap().to_str().unwrap(),
        "iicp-proxy"
    );
    let d: Value = r.json().await.unwrap();
    assert_eq!(d["content"][0]["text"], "E2E reply");
}
