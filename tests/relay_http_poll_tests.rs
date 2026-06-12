// SPDX-License-Identifier: Apache-2.0
//! Behavior tests for the #450 HTTP long-poll relay worker transport
//! (Rust parity with iicp-client-python tests/test_relay_http_poll.py and
//! iicp-client-typescript tests/relay_http_poll.test.ts).
//!
//! Covers (fails if the #450 implementation is reverted):
//! - HttpPollWorkerSession queue/oneshot roundtrip + liveness semantics
//! - POST /v1/relay/bind (200 token, 409 alive-rebind — #510 interim-C parity)
//! - Bearer auth on pull/result/unbind (401 without/with-wrong token)
//! - Path-scoped /v1/relay-for/:wid/v1/task forwarding (R1 misattribution fix)
//! - /v1/relay-for/:wid/iicp/health session liveness view
//! - CORS headers + OPTIONS preflight (web pages are first-class callers)
#![cfg(feature = "iicp-tcp")]

use std::sync::Arc;
use std::time::Duration;

use iicp_client::node::{IicpNode, NodeConfig};
use iicp_client::relay_session::{HttpPollWorkerSession, RelaySession, RelaySessionRegistry};
use serde_json::{json, Value};

const INTENT: &str = "urn:iicp:intent:llm:chat:v1";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn spawn_relay() -> u16 {
    let port = free_port();
    let mut cfg = NodeConfig::new("relay-node", "http://relay.local", INTENT);
    cfg.relay_capable = true;
    cfg.relay_accept_port = free_port();
    let node = Arc::new(IicpNode::new(cfg));
    tokio::spawn(async move {
        let handler =
            move |_req: iicp_client::node::TaskRequest| async move { Ok(json!({"echo": true})) };
        let _ = node
            .serve(handler, &format!("127.0.0.1:{port}"), None)
            .await;
    });
    // wait for listen
    let client = reqwest::Client::new();
    for _ in 0..50 {
        if client
            .get(format!("http://127.0.0.1:{port}/iicp/health"))
            .timeout(Duration::from_millis(300))
            .send()
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    port
}

async fn bind(
    client: &reqwest::Client,
    port: u16,
    worker_id: &str,
    models: &[&str],
) -> reqwest::Response {
    client
        .post(format!("http://127.0.0.1:{port}/v1/relay/bind"))
        .json(&json!({"worker_id": worker_id, "intent": INTENT, "models": models}))
        .send()
        .await
        .unwrap()
}

// ── HttpPollWorkerSession unit behavior ──────────────────────────────────────

#[tokio::test]
async fn session_forward_pull_result_roundtrip() {
    let sess =
        HttpPollWorkerSession::new("w-browser".into(), INTENT.into(), vec!["tinyllama".into()]);
    let worker = {
        let sess = sess.clone();
        tokio::spawn(async move {
            let call = sess.next_call(Duration::from_secs(5)).await.unwrap();
            assert_eq!(call["task"]["payload"]["q"], 1);
            sess.on_response(
                call["call_id"].as_str().unwrap(),
                json!({"result": {"a": 2}}),
            );
        })
    };
    let result = sess
        .forward_task(&json!({"payload": {"q": 1}}), 5)
        .await
        .unwrap();
    worker.await.unwrap();
    assert_eq!(result, json!({"result": {"a": 2}}));
}

#[tokio::test]
async fn session_next_call_times_out_to_none() {
    let sess = HttpPollWorkerSession::new("w-idle".into(), String::new(), vec![]);
    assert!(sess.next_call(Duration::from_millis(50)).await.is_none());
}

#[tokio::test]
async fn session_liveness_window_and_close() {
    let sess = HttpPollWorkerSession::with_liveness_window(
        "w-live".into(),
        String::new(),
        vec![],
        Duration::from_millis(50),
    );
    assert!(sess.is_alive());
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(!sess.is_alive()); // stale — displaceable
    let fresh = HttpPollWorkerSession::new("w-fresh".into(), String::new(), vec![]);
    fresh.close();
    assert!(!fresh.is_alive());
}

#[test]
fn registry_get_by_token() {
    let reg = RelaySessionRegistry::new();
    let sess = HttpPollWorkerSession::new("w-tok".into(), String::new(), vec![]);
    let token = sess.session_token.clone();
    reg.bind("w-tok".into(), RelaySession::HttpPoll(sess));
    assert!(reg.get_by_token(&token).is_some());
    assert!(reg.get_by_token("wrong").is_none());
    assert!(reg.get_by_token("").is_none());
}

// ── HTTP endpoint behavior (real serve()) ────────────────────────────────────

#[tokio::test]
async fn bind_returns_token_and_cors() {
    let port = spawn_relay().await;
    let client = reqwest::Client::new();
    let resp = bind(&client, port, "w-bind-1", &["tinyllama-1.1b"]).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "*"
    );
    let body: Value = resp.json().await.unwrap();
    assert!(body["session_token"].as_str().unwrap().len() >= 32);
    assert_eq!(body["worker_endpoint_path"], "/v1/relay-for/w-bind-1");
}

#[tokio::test]
async fn alive_rebind_rejected_409() {
    let port = spawn_relay().await;
    let client = reqwest::Client::new();
    assert_eq!(bind(&client, port, "w-rebind", &[]).await.status(), 200);
    let resp2 = bind(&client, port, "w-rebind", &[]).await;
    assert_eq!(resp2.status(), 409);
    let body: Value = resp2.json().await.unwrap();
    assert_eq!(body["error"]["code"], "IICP-E038");
}

#[tokio::test]
async fn pull_and_result_require_bearer() {
    let port = spawn_relay().await;
    let client = reqwest::Client::new();
    let r = client
        .get(format!("http://127.0.0.1:{port}/v1/relay/pull"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = client
        .get(format!("http://127.0.0.1:{port}/v1/relay/pull"))
        .bearer_auth("nope")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = client
        .post(format!("http://127.0.0.1:{port}/v1/relay/result"))
        .bearer_auth("nope")
        .json(&json!({"call_id": "x", "result": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

#[tokio::test]
async fn full_dispatch_roundtrip_via_relay_for() {
    let port = spawn_relay().await;
    let client = reqwest::Client::new();
    let resp = bind(&client, port, "w-roundtrip", &["tinyllama-1.1b"]).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let token = body["session_token"].as_str().unwrap().to_string();

    // Worker side: one pull → answer.
    let worker = {
        let client = client.clone();
        tokio::spawn(async move {
            let pull = client
                .get(format!("http://127.0.0.1:{port}/v1/relay/pull"))
                .bearer_auth(&token)
                .timeout(Duration::from_secs(35))
                .send()
                .await
                .unwrap();
            assert_eq!(pull.status(), 200);
            let call: Value = pull.json().await.unwrap();
            assert_eq!(call["task"]["task_id"], "t-1");
            client
                .post(format!("http://127.0.0.1:{port}/v1/relay/result"))
                .bearer_auth(&token)
                .json(&json!({
                    "call_id": call["call_id"],
                    "result": {"result": {"text": "MESH OK from browser"}}
                }))
                .send()
                .await
                .unwrap();
        })
    };

    // Consumer side — exactly what a published SDK consumer sends.
    let dispatch = client
        .post(format!(
            "http://127.0.0.1:{port}/v1/relay-for/w-roundtrip/v1/task"
        ))
        .timeout(Duration::from_secs(40))
        .json(&json!({
            "task_id": "t-1",
            "intent": INTENT,
            "payload": {"messages": [{"role": "user", "content": "hi"}]},
            "constraints": {"timeout_ms": 120000, "qos": "best_effort"}
        }))
        .send()
        .await
        .unwrap();
    worker.await.unwrap();
    assert_eq!(dispatch.status(), 200);
    assert_eq!(
        dispatch
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "*"
    );
    let resp: Value = dispatch.json().await.unwrap();
    assert_eq!(resp["status"], "completed");
    assert_eq!(resp["result"]["text"], "MESH OK from browser");
}

#[tokio::test]
async fn relay_for_unknown_worker_404() {
    let port = spawn_relay().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "http://127.0.0.1:{port}/v1/relay-for/w-ghost/v1/task"
        ))
        .json(&json!({"task_id": "t-x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "IICP-E030");
}

#[tokio::test]
async fn relay_for_health_reflects_session() {
    let port = spawn_relay().await;
    let client = reqwest::Client::new();
    assert_eq!(
        bind(&client, port, "w-health", &["m1", "m2"])
            .await
            .status(),
        200
    );
    let resp = client
        .get(format!(
            "http://127.0.0.1:{port}/v1/relay-for/w-health/iicp/health"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let health: Value = resp.json().await.unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["via_relay"], true);
    assert_eq!(health["models"], json!(["m1", "m2"]));
}

#[tokio::test]
async fn unbind_releases_worker_id() {
    let port = spawn_relay().await;
    let client = reqwest::Client::new();
    let resp = bind(&client, port, "w-unbind", &[]).await;
    let body: Value = resp.json().await.unwrap();
    let token = body["session_token"].as_str().unwrap().to_string();
    let u = client
        .post(format!("http://127.0.0.1:{port}/v1/relay/unbind"))
        .bearer_auth(&token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(u.status(), 204);
    assert_eq!(bind(&client, port, "w-unbind", &[]).await.status(), 200);
}

#[tokio::test]
async fn options_preflight() {
    let port = spawn_relay().await;
    let client = reqwest::Client::new();
    let resp = client
        .request(
            reqwest::Method::OPTIONS,
            format!("http://127.0.0.1:{port}/v1/relay/bind"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "*"
    );
    assert!(resp
        .headers()
        .get("access-control-allow-headers")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Authorization"));
}
