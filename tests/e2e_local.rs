// SPDX-License-Identifier: Apache-2.0
//! Local E2E: Rust SDK serving node -> real Ollama -> client round-trip.
//! Exercises Block B (backends), C/D (health capacity), E (idempotency),
//! F (mesh /v1/peers + relay). Skips gracefully when Ollama is not running.

use std::sync::Arc;
use std::time::Duration;

use iicp_client::backends::invoke_backend;
use iicp_client::backends::openai_compat::OpenAiCompatOptions;
use iicp_client::node::{IicpNode, NodeConfig};
use serde_json::{json, Value};

const OLLAMA: &str = "http://localhost:11434/v1";
const MODEL: &str = "qwen2.5:0.5b";
const INTENT: &str = "urn:iicp:intent:llm:chat:v1";

fn opts() -> OpenAiCompatOptions {
    OpenAiCompatOptions {
        base_url: OLLAMA.to_string(),
        model: Some(MODEL.to_string()),
        api_key: None,
        timeout: Duration::from_secs(60),
    }
}

fn spawn_node(cfg: NodeConfig, port: u16) {
    let node = Arc::new(IicpNode::new(cfg));
    tokio::spawn(async move {
        let o = opts();
        let handler = move |req: iicp_client::node::TaskRequest| {
            let o = o.clone();
            async move {
                let v = invoke_backend("openai_compat", &o, &req.intent, &req.payload)
                    .await
                    .unwrap_or_else(|e| json!({ "error": e }));
                // serve() re-wraps in TaskResponse.result; unwrap the backend envelope
                // so the response is single-level (matches Python/TS SDKs).
                Ok(v.get("result").cloned().unwrap_or(v))
            }
        };
        let _ = node.serve(handler, &format!("127.0.0.1:{port}"), None).await;
    });
}

async fn ollama_up() -> bool {
    reqwest::Client::new()
        .get(format!("{OLLAMA}/models"))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

async fn post(client: &reqwest::Client, port: u16, path: &str, body: Value) -> (u16, Value) {
    let resp = client
        .post(format!("http://127.0.0.1:{port}{path}"))
        .timeout(Duration::from_secs(60))
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    let v = resp.json::<Value>().await.unwrap_or(Value::Null);
    (status, v)
}

#[tokio::test]
async fn e2e_rust_serving_node_local() {
    if !ollama_up().await {
        eprintln!("SKIP e2e_rust_serving_node_local: Ollama not reachable on :11434");
        return;
    }

    // Node B (plain), node A (relay-capable + mesh + idempotency).
    let cfg_b = NodeConfig::new("e2e-rs-B", "http://127.0.0.1:8604", INTENT);
    spawn_node(cfg_b, 8604);
    let mut cfg_a = NodeConfig::new("e2e-rs-A", "http://127.0.0.1:8603", INTENT);
    cfg_a.enable_mesh = true;
    cfg_a.relay_capable = true;
    cfg_a.enable_idempotency = true;
    spawn_node(cfg_a, 8603);
    tokio::time::sleep(Duration::from_millis(800)).await;

    let client = reqwest::Client::new();

    // [1] real round-trip via node A
    let (s1, b1) = post(
        &client,
        8603,
        "/v1/task",
        json!({"task_id":"550e8400-e29b-41d4-a716-446655440000","intent":INTENT,
               "payload":{"messages":[{"role":"user","content":"Reply with exactly: PONG"}]}}),
    )
    .await;
    assert_eq!(s1, 200, "task should return 200: {b1}");
    let content = b1["result"]["choices"][0]["message"]["content"].as_str().unwrap_or("");
    assert!(!content.is_empty(), "expected a real Ollama completion, got: {b1}");
    eprintln!("[1] model said: {content:?}");

    // [2] health capacity fields
    let h = client
        .get("http://127.0.0.1:8603/iicp/health")
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert!(h.get("effective_max_concurrent").is_some(), "health missing effective_max_concurrent: {h}");
    eprintln!("[2] health OK: effective_max_concurrent={}", h["effective_max_concurrent"]);

    // [3] idempotency: duplicate task_id -> 409 IICP-E010
    let dup = json!({"task_id":"11111111-1111-4111-8111-111111111111","intent":INTENT,
                     "payload":{"messages":[{"role":"user","content":"hi"}]}});
    let (d1, _) = post(&client, 8603, "/v1/task", dup.clone()).await;
    let (d2, db) = post(&client, 8603, "/v1/task", dup).await;
    assert_eq!(d1, 200, "first task should be 200");
    assert_eq!(d2, 409, "duplicate task_id should be 409: {db}");
    assert_eq!(db["error"]["code"], "IICP-E010");
    eprintln!("[3] idempotency OK: dup -> 409 IICP-E010");

    // [4] mesh: inject B into A via /v1/peers, then relay round-trip
    let (sp, peers) = post(
        &client,
        8603,
        "/v1/peers",
        json!({"known_peers":[{"node_id":"e2e-rs-B","endpoint":"http://127.0.0.1:8604"}]}),
    )
    .await;
    assert_eq!(sp, 200, "peers exchange should be 200: {peers}");
    assert!(
        peers["peers"].as_array().map(|a| a.iter().any(|p| p["node_id"] == "e2e-rs-B")).unwrap_or(false),
        "A should now know B: {peers}"
    );
    let (sr, rel) = post(
        &client,
        8603,
        "/v1/relay",
        json!({"target_node_id":"e2e-rs-B","task":{"task_id":"22222222-2222-4222-8222-222222222222",
               "intent":INTENT,"payload":{"messages":[{"role":"user","content":"Reply with exactly: RELAYOK"}]}}}),
    )
    .await;
    assert_eq!(sr, 200, "relay should return 200: {rel}");
    let rc = rel["result"]["choices"][0]["message"]["content"].as_str().unwrap_or("");
    assert!(!rc.is_empty(), "relay should produce a real completion from B: {rel}");
    eprintln!("[4] relay round-trip OK: B said {rc:?}");

    // relay unknown target -> 404 IICP-E030
    let (su, ub) = post(
        &client,
        8603,
        "/v1/relay",
        json!({"target_node_id":"nope","task":{"task_id":"33333333-3333-4333-8333-333333333333","intent":INTENT,"payload":{}}}),
    )
    .await;
    assert_eq!(su, 404, "unknown relay target should be 404");
    assert_eq!(ub["error"]["code"], "IICP-E030");
    eprintln!("[4] relay unknown target OK: 404 IICP-E030");
}
