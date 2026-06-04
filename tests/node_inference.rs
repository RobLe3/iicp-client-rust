// SPDX-License-Identifier: Apache-2.0
//! #453 — CI-runnable client→node inference test.
//!
//! The gap #453 documents: the client→node `/v1/task` → real-inference path was never
//! asserted in CI — `test_task_flow` accepted a 502 (backend-down) as a pass, and
//! `test_rust_node` skipped unless a node was already running, so a real bug went
//! unnoticed (the success response emitted `status:"completed"` instead of the spec's
//! `success`). This test stands up a REAL node with a deterministic mock backend (the
//! handler closure) on an ephemeral loopback port and asserts the full round-trip:
//! `POST /v1/task` → 200, `status == "success"`, and an actual completion in `result`.
//! No skip, no 502-accept. Locks the cross-flavour status contract (parity with the
//! Python adapter, which also returns `"success"`).

use iicp_client::{IicpError, IicpNode, NodeConfig};
use serde_json::{json, Value};
use std::time::Duration;

const CHAT: &str = "urn:iicp:intent:llm:chat:v1";

/// Spawn a node whose mock backend either returns a canned completion (`ok`) or fails.
async fn spawn_node(port: u16, ok: bool) {
    let cfg = NodeConfig::new(
        "node-inference-test",
        format!("http://127.0.0.1:{port}"),
        CHAT,
    );
    let node = IicpNode::new(cfg);
    let addr = format!("127.0.0.1:{port}");
    tokio::spawn(async move {
        // The handler closure IS the backend boundary — a deterministic stub completion.
        let _ = node
            .serve(
                move |_req| async move {
                    if ok {
                        Ok(json!({
                            "choices": [{
                                "message": {"role": "assistant", "content": "4"},
                                "finish_reason": "stop"
                            }],
                            "model": "mock-backend",
                            "usage": {"prompt_tokens": 5, "completion_tokens": 1}
                        }))
                    } else {
                        Err(IicpError::Node("mock backend unavailable".into()))
                    }
                },
                &addr,
                None,
            )
            .await;
    });
}

/// Poll `/iicp/health` until the node is accepting connections.
async fn wait_ready(port: u16) {
    let client = reqwest::Client::new();
    for _ in 0..100 {
        if let Ok(r) = client
            .get(format!("http://127.0.0.1:{port}/iicp/health"))
            .send()
            .await
        {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("node never became ready on :{port}");
}

/// NODE-TASK-01 (real-inference): a valid task returns 200 with the spec-compliant
/// `status:"success"` AND a real completion — not a 502/empty accept, not "completed".
#[tokio::test]
async fn task_returns_real_completion_with_success_status() {
    let port = 19584;
    spawn_node(port, true).await;
    wait_ready(port).await;

    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/v1/task"))
        .json(&json!({
            "task_id": "infer-1",
            "intent": CHAT,
            "payload": {"messages": [{"role": "user", "content": "What is 2+2? Reply with only the number."}]},
            "constraints": {"timeout_ms": 5000}
        }))
        .send()
        .await
        .expect("POST /v1/task");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "task must return 200, not 502/skip"
    );
    let body: Value = resp.json().await.expect("json body");

    // The exact regression #453 surfaced: the spec status is "success" (was "completed").
    assert_eq!(
        body["status"], "success",
        "spec iicp-dir.md task status MUST be 'success' (parity with the Python adapter): {body}"
    );
    assert_eq!(body["task_id"], "infer-1");
    // A REAL completion must flow back — assert the actual content, not just a 200.
    assert_eq!(
        body["result"]["choices"][0]["message"]["content"], "4",
        "the node must return the backend completion in result: {body}"
    );
}

/// A backend failure surfaces as a 500 with `status:"error"` — the structured-error
/// contract, distinct from a missing-completion silent pass.
#[tokio::test]
async fn task_backend_failure_returns_error_status() {
    let port = 19585;
    spawn_node(port, false).await;
    wait_ready(port).await;

    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/v1/task"))
        .json(&json!({
            "task_id": "infer-fail-1",
            "intent": CHAT,
            "payload": {"messages": [{"role": "user", "content": "hi"}]},
            "constraints": {"timeout_ms": 5000}
        }))
        .send()
        .await
        .expect("POST /v1/task");

    assert_eq!(
        resp.status().as_u16(),
        500,
        "backend failure must be a 500, not a silent pass"
    );
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(
        body["status"], "error",
        "failure status must be 'error': {body}"
    );
}
