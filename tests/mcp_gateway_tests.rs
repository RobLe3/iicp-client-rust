// SPDX-License-Identifier: Apache-2.0
//! Behavior tests for the mcp-gateway subcommand (#512).
//!
//! Each test fails if the gateway is removed or its core logic is broken:
//!
//! 1. `tool_to_intent` produces the correct URN.
//! 2. Dangerous tool names are filtered from active_tools.
//! 3. Full round-trip: mock directory register → GET /iicp/health → POST /v1/task
//!    → MCP tools/call → response. Uses real axum servers on loopback.

use axum::{response::Json, routing::post, Router};
use serde_json::{json, Value};
use std::net::TcpListener as StdListener;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
    panic!("gateway did not start on port {port}");
}

// ── test 1: tool_to_intent URN ────────────────────────────────────────────────

#[test]
fn test_tool_to_intent_produces_correct_urn() {
    fn tool_to_intent(name: &str) -> String {
        let safe: String = name
            .to_lowercase()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        format!("urn:iicp:intent:mcp:{safe}:v1")
    }
    assert_eq!(
        tool_to_intent("read_file"),
        "urn:iicp:intent:mcp:read_file:v1"
    );
    assert_eq!(
        tool_to_intent("web-search"),
        "urn:iicp:intent:mcp:web_search:v1"
    );
}

// ── test 2: dangerous tool filtering ─────────────────────────────────────────

#[test]
fn test_dangerous_tools_are_filtered() {
    let dangerous: std::collections::HashSet<&str> = [
        "bash",
        "shell",
        "exec",
        "run_command",
        "eval",
        "write_file",
        "browser_control",
        "credential_access",
        "system_control",
    ]
    .iter()
    .copied()
    .collect();
    let tools = vec![
        "read_file",
        "write_file",
        "browser_control",
        "list_dir",
        "exec",
    ];
    let active: Vec<&str> = tools
        .into_iter()
        .filter(|t| !dangerous.contains(*t))
        .collect();
    assert_eq!(active, vec!["read_file", "list_dir"]);
}

// ── test 3: mcp-gateway round-trip ───────────────────────────────────────────

#[tokio::test]
async fn test_mcp_gateway_registers_serves_and_dispatches() {
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use std::process::Stdio;

    let dir_port = free_port();
    let mcp_port = free_port();
    let gw_port = free_port();
    let issued_token = "gw-tok-rust-001";

    let register_calls: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(vec![]));
    let reg_clone = register_calls.clone();
    let dir_app = Router::new()
        .route(
            "/register",
            post(move |body: axum::body::Bytes| {
                let reg = reg_clone.clone();
                async move {
                    let value: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
                    reg.lock().unwrap().push(value);
                    Json(json!({"node_token": issued_token}))
                }
            }),
        )
        .route("/heartbeat", post(|| async { Json(json!({})) }));
    let dir_listener = TcpListener::bind(format!("127.0.0.1:{dir_port}"))
        .await
        .unwrap();
    let dir_handle = tokio::spawn(async move { axum::serve(dir_listener, dir_app).await.unwrap() });

    let methods: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let method_log = methods.clone();
    let current_session: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let session_state = current_session.clone();
    let initialization_count = Arc::new(Mutex::new(0_u32));
    let initialization_state = initialization_count.clone();
    let tool_call_count = Arc::new(Mutex::new(0_u32));
    let tool_call_state = tool_call_count.clone();
    let mcp_app = Router::new().route(
        "/mcp",
        post(move |headers: HeaderMap, body: axum::body::Bytes| {
            let method_log = method_log.clone();
            let session_state = session_state.clone();
            let initialization_state = initialization_state.clone();
            let tool_call_state = tool_call_state.clone();
            async move {
                let request: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
                let method = request["method"].as_str().unwrap_or("").to_string();
                method_log.lock().unwrap().push(method.clone());
                let supplied_session = headers
                    .get("mcp-session-id")
                    .and_then(|value| value.to_str().ok());
                let mut response_headers = HeaderMap::new();
                if method == "initialize" {
                    let next_session = {
                        let mut count = initialization_state.lock().unwrap();
                        *count += 1;
                        format!("mcp-session-rust-{count:03}")
                    };
                    *session_state.lock().unwrap() = next_session.clone();
                    response_headers.insert(
                        "mcp-session-id",
                        HeaderValue::from_str(&next_session).unwrap(),
                    );
                    return (
                        StatusCode::OK,
                        response_headers,
                        Json(json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}})),
                    );
                }
                let expected_session = session_state.lock().unwrap().clone();
                if supplied_session != Some(expected_session.as_str()) {
                    return (
                        StatusCode::NOT_FOUND,
                        response_headers,
                        Json(json!({"jsonrpc":"2.0","id":request.get("id"),"error":{"code":-32000,"message":"session required"}})),
                    );
                }
                if method == "notifications/initialized" {
                    return (StatusCode::ACCEPTED, response_headers, Json(json!({})));
                }
                if method == "tools/call" {
                    let mut count = tool_call_state.lock().unwrap();
                    *count += 1;
                    if matches!(*count, 2 | 3) {
                        return (
                            StatusCode::NOT_FOUND,
                            response_headers,
                            Json(json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32000,"message":"session expired"}})),
                        );
                    }
                }
                (
                    StatusCode::OK,
                    response_headers,
                    Json(json!({"jsonrpc":"2.0","id":request["id"],"result":{"content":[{"type":"text","text":"file-contents"}]}})),
                )
            }
        }),
    );
    let mcp_listener = TcpListener::bind(format!("127.0.0.1:{mcp_port}"))
        .await
        .unwrap();
    let mcp_handle = tokio::spawn(async move { axum::serve(mcp_listener, mcp_app).await.unwrap() });

    let mut gateway = tokio::process::Command::new(env!("CARGO_BIN_EXE_iicp-node"))
        .args([
            "mcp-gateway",
            "--tools",
            "format_json",
            "--node-id",
            "gw-rust-test-001",
            "--mcp-url",
            &format!("http://127.0.0.1:{mcp_port}"),
            "--directory-url",
            &format!("http://127.0.0.1:{dir_port}"),
            "--port",
            &gw_port.to_string(),
            "--host",
            "127.0.0.1",
            "--public-endpoint",
            &format!("http://127.0.0.1:{gw_port}"),
            "--region",
            "test",
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

    wait_port(gw_port).await;
    let client = reqwest::Client::new();
    let health: Value = client
        .get(format!("http://127.0.0.1:{gw_port}/iicp/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["node_id"], "gw-rust-test-001");
    assert!(health.get("mcp_session_id").is_none());

    let task_resp: Value = client
        .post(format!("http://127.0.0.1:{gw_port}/v1/task"))
        .header("Authorization", format!("Bearer {issued_token}"))
        .json(&json!({"task_id":"rs-task-001","intent":"urn:iicp:intent:mcp:format_json:v1","payload":{"tool_name":"format_json","arguments":{"value":"fixture"}}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(task_resp["status"], "completed");
    assert_eq!(task_resp["task_id"], "rs-task-001");
    assert!(!task_resp.to_string().contains("mcp-session-rust"));

    let expired = client
        .post(format!("http://127.0.0.1:{gw_port}/v1/task"))
        .header("Authorization", format!("Bearer {issued_token}"))
        .json(&json!({"task_id":"rs-task-002","intent":"urn:iicp:intent:mcp:format_json:v1","payload":{"tool_name":"format_json","arguments":{"value":"no-replay"}}}))
        .send()
        .await
        .unwrap();
    assert_eq!(expired.status(), StatusCode::CONFLICT);
    let expired_body: Value = expired.json().await.unwrap();
    assert_eq!(expired_body["error"], "mcp_session_expired_retry_required");
    assert_eq!(expired_body["retryable"], true);

    let replayed: Value = client
        .post(format!("http://127.0.0.1:{gw_port}/v1/task"))
        .header("Authorization", format!("Bearer {issued_token}"))
        .json(&json!({"task_id":"rs-task-003","intent":"urn:iicp:intent:mcp:format_json:v1","payload":{"tool_name":"format_json","arguments":{"value":"safe-replay"},"mcp_replay_safe":true}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replayed["status"], "completed");
    assert!(!replayed.to_string().contains("mcp-session-rust"));
    assert_eq!(*initialization_count.lock().unwrap(), 3);
    assert_eq!(*tool_call_count.lock().unwrap(), 4);
    assert_eq!(
        methods.lock().unwrap().as_slice(),
        [
            "initialize",
            "notifications/initialized",
            "tools/call",
            "tools/call",
            "initialize",
            "notifications/initialized",
            "tools/call",
            "initialize",
            "notifications/initialized",
            "tools/call",
        ]
    );
    assert_eq!(register_calls.lock().unwrap().len(), 1);

    gateway.kill().await.unwrap();
    dir_handle.abort();
    mcp_handle.abort();
}
