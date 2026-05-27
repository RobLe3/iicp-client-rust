// SPDX-License-Identifier: Apache-2.0
//! Unit tests for the 4 CONF self-conformance probes. Rust port of the
//! Python/TS test matrix using mockito for HTTP mocks + a local std HTTP
//! server for the /iicp/health probe.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use iicp_client::conformance::run_conformance_checks;
use iicp_client::node::{IicpNode, NodeConfig};

/// Tiny synchronous HTTP server that returns a configurable JSON body for
/// /iicp/health. Spawns once per test and shuts down via a flag.
struct LocalHealth {
    // Held by the spawned listener thread (via clones); the test fixture
    // itself never reads them back after `new()` — clippy flags them dead.
    #[allow(dead_code)]
    body: Arc<Mutex<String>>,
    #[allow(dead_code)]
    status: Arc<Mutex<u16>>,
    stop: Arc<Mutex<bool>>,
    port: u16,
}

impl LocalHealth {
    fn new(body: &str, status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let body_a = Arc::new(Mutex::new(body.to_string()));
        let status_a = Arc::new(Mutex::new(status));
        let stop_a = Arc::new(Mutex::new(false));
        let body_t = body_a.clone();
        let status_t = status_a.clone();
        let stop_t = stop_a.clone();
        thread::spawn(move || {
            loop {
                if *stop_t.lock().unwrap() {
                    return;
                }
                match listener.accept() {
                    Ok((mut sock, _)) => {
                        let _ = sock.set_nonblocking(false);
                        // Drain request
                        let mut buf = [0u8; 1024];
                        let _ = sock.read(&mut buf);
                        let body = body_t.lock().unwrap().clone();
                        let status = *status_t.lock().unwrap();
                        let resp = format!(
                            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = sock.write_all(resp.as_bytes());
                    }
                    Err(_) => thread::sleep(std::time::Duration::from_millis(10)),
                }
            }
        });
        Self {
            body: body_a,
            status: status_a,
            stop: stop_a,
            port,
        }
    }
}

impl Drop for LocalHealth {
    fn drop(&mut self) {
        *self.stop.lock().unwrap() = true;
    }
}

fn make_node(node_id: &str, endpoint: &str, directory_url: &str) -> IicpNode {
    let mut cfg = NodeConfig::new(node_id, endpoint, "urn:iicp:intent:llm:chat:v1");
    cfg.directory_url = directory_url.to_string();
    cfg.model = Some("m".into());
    IicpNode::new(cfg)
}

// ── CONF-REG-01 ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_reg01_passes_with_node_id_and_token() {
    let mut server = mockito::Server::new_async().await;
    let _m_probe = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/probe.*".into()))
        .with_status(200)
        .with_body(r#"{"reachable":true}"#)
        .create_async()
        .await;
    let _m_disc = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_body(r#"{"nodes":[{"node_id":"n-test"}]}"#)
        .create_async()
        .await;
    let health = LocalHealth::new(
        r#"{"status":"ok","node_id":"n-test","region":"eu","load":0.1,"models":["m"]}"#,
        200,
    );
    let node = make_node(
        "n-test",
        "https://node.iicpnet.test-host.org:8080",
        &format!("{}/api", server.url()),
    );
    let report = run_conformance_checks(&node, health.port, Some("tok")).await;
    let reg = report
        .tests
        .iter()
        .find(|t| t.test_id == "CONF-REG-01")
        .unwrap();
    assert!(reg.passed, "{}", reg.message);
    assert!(reg.message.contains("Registered"));
}

#[tokio::test]
async fn test_reg01_passes_with_node_id_only_when_token_not_tracked() {
    let mut server = mockito::Server::new_async().await;
    let _ = server
        .mock("GET", mockito::Matcher::Regex(".*".into()))
        .with_status(200)
        .with_body(r#"{"nodes":[],"reachable":true}"#)
        .create_async()
        .await;
    let health = LocalHealth::new(
        r#"{"status":"ok","node_id":"x","region":"eu","load":0.1,"models":["m"]}"#,
        200,
    );
    let node = make_node(
        "n-test",
        "https://node.iicpnet.test-host.org:8080",
        &format!("{}/api", server.url()),
    );
    let report = run_conformance_checks(&node, health.port, None).await;
    let reg = report
        .tests
        .iter()
        .find(|t| t.test_id == "CONF-REG-01")
        .unwrap();
    assert!(reg.passed);
    assert!(reg.message.contains("not tracked"));
}

#[tokio::test]
async fn test_reg01_fails_when_node_id_empty() {
    let server = mockito::Server::new_async().await;
    let health = LocalHealth::new(r#"{"status":"ok"}"#, 200);
    let node = make_node(
        "",
        "https://node.iicpnet.test-host.org:8080",
        &format!("{}/api", server.url()),
    );
    let report = run_conformance_checks(&node, health.port, None).await;
    let reg = report
        .tests
        .iter()
        .find(|t| t.test_id == "CONF-REG-01")
        .unwrap();
    assert!(!reg.passed);
}

// ── CONF-HEALTH-01 ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_health01_passes_with_complete_schema() {
    let mut server = mockito::Server::new_async().await;
    let _ = server
        .mock("GET", mockito::Matcher::Regex(".*".into()))
        .with_status(200)
        .with_body(r#"{"nodes":[{"node_id":"n-test"}],"reachable":true}"#)
        .create_async()
        .await;
    let health = LocalHealth::new(
        r#"{"status":"ok","node_id":"n","region":"eu","load":0.1,"models":["m"]}"#,
        200,
    );
    let node = make_node(
        "n-test",
        "https://node.iicpnet.test-host.org:8080",
        &format!("{}/api", server.url()),
    );
    let report = run_conformance_checks(&node, health.port, None).await;
    let h = report
        .tests
        .iter()
        .find(|t| t.test_id == "CONF-HEALTH-01")
        .unwrap();
    assert!(h.passed, "{}", h.message);
}

#[tokio::test]
async fn test_health01_fails_when_required_field_missing() {
    let mut server = mockito::Server::new_async().await;
    let _ = server
        .mock("GET", mockito::Matcher::Regex(".*".into()))
        .with_status(200)
        .with_body(r#"{"nodes":[],"reachable":true}"#)
        .create_async()
        .await;
    // Missing "models"
    let health = LocalHealth::new(
        r#"{"status":"ok","node_id":"n","region":"eu","load":0.1}"#,
        200,
    );
    let node = make_node(
        "n-test",
        "https://node.iicpnet.test-host.org:8080",
        &format!("{}/api", server.url()),
    );
    let report = run_conformance_checks(&node, health.port, None).await;
    let h = report
        .tests
        .iter()
        .find(|t| t.test_id == "CONF-HEALTH-01")
        .unwrap();
    assert!(!h.passed);
    assert!(h.message.contains("models"));
}

// ── CONF-REACH-01 ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_reach01_skips_for_non_routable_endpoint() {
    let server = mockito::Server::new_async().await;
    let health = LocalHealth::new(r#"{"status":"ok"}"#, 200);
    let node = make_node(
        "n-test",
        "http://localhost:8080", // non-routable
        &format!("{}/api", server.url()),
    );
    let report = run_conformance_checks(&node, health.port, None).await;
    let reach = report
        .tests
        .iter()
        .find(|t| t.test_id == "CONF-REACH-01")
        .unwrap();
    assert!(!reach.passed);
    assert!(reach.message.contains("non-routable"));
}

#[tokio::test]
async fn test_reach01_passes_when_directory_reports_reachable() {
    let mut server = mockito::Server::new_async().await;
    let _ = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/probe.*".into()))
        .with_status(200)
        .with_body(r#"{"reachable":true}"#)
        .create_async()
        .await;
    let _ = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_body(r#"{"nodes":[]}"#)
        .create_async()
        .await;
    let health = LocalHealth::new(r#"{"status":"ok"}"#, 200);
    let node = make_node(
        "n-test",
        "https://node.iicpnet.test-host.org:8080",
        &format!("{}/api", server.url()),
    );
    let report = run_conformance_checks(&node, health.port, None).await;
    let reach = report
        .tests
        .iter()
        .find(|t| t.test_id == "CONF-REACH-01")
        .unwrap();
    assert!(reach.passed, "{}", reach.message);
}

#[tokio::test]
async fn test_reach01_fails_when_directory_reports_unreachable() {
    let mut server = mockito::Server::new_async().await;
    let _ = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/probe.*".into()))
        .with_status(200)
        .with_body(r#"{"reachable":false,"error":"timeout"}"#)
        .create_async()
        .await;
    let _ = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_body(r#"{"nodes":[]}"#)
        .create_async()
        .await;
    let health = LocalHealth::new(r#"{"status":"ok"}"#, 200);
    let node = make_node(
        "n-test",
        "https://node.iicpnet.test-host.org:8080",
        &format!("{}/api", server.url()),
    );
    let report = run_conformance_checks(&node, health.port, None).await;
    let reach = report
        .tests
        .iter()
        .find(|t| t.test_id == "CONF-REACH-01")
        .unwrap();
    assert!(!reach.passed);
    assert!(reach.message.contains("timeout"));
}

// ── CONF-DISC-01 ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_disc01_passes_when_node_id_in_nodelist() {
    let mut server = mockito::Server::new_async().await;
    let _ = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/probe.*".into()))
        .with_status(200)
        .with_body(r#"{"reachable":true}"#)
        .create_async()
        .await;
    let _ = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_body(r#"{"nodes":[{"node_id":"other"},{"node_id":"n-test"}]}"#)
        .create_async()
        .await;
    let health = LocalHealth::new(r#"{"status":"ok"}"#, 200);
    let node = make_node(
        "n-test",
        "https://node.iicpnet.test-host.org:8080",
        &format!("{}/api", server.url()),
    );
    let report = run_conformance_checks(&node, health.port, None).await;
    let disc = report
        .tests
        .iter()
        .find(|t| t.test_id == "CONF-DISC-01")
        .unwrap();
    assert!(disc.passed, "{}", disc.message);
    assert!(disc.message.contains("Found"));
}

#[tokio::test]
async fn test_disc01_fails_when_node_id_absent() {
    let mut server = mockito::Server::new_async().await;
    let _ = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/probe.*".into()))
        .with_status(200)
        .with_body(r#"{"reachable":true}"#)
        .create_async()
        .await;
    let _ = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_body(r#"{"nodes":[{"node_id":"other"}]}"#)
        .create_async()
        .await;
    let health = LocalHealth::new(r#"{"status":"ok"}"#, 200);
    let node = make_node(
        "n-test",
        "https://node.iicpnet.test-host.org:8080",
        &format!("{}/api", server.url()),
    );
    let report = run_conformance_checks(&node, health.port, None).await;
    let disc = report
        .tests
        .iter()
        .find(|t| t.test_id == "CONF-DISC-01")
        .unwrap();
    assert!(!disc.passed);
    assert!(disc.message.contains("absent"));
}

// ── Orchestrator ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_orchestrator_counts_pass_and_fail() {
    let mut server = mockito::Server::new_async().await;
    let _ = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/probe.*".into()))
        .with_status(200)
        .with_body(r#"{"reachable":false,"error":"timeout"}"#) // FAIL
        .create_async()
        .await;
    let _ = server
        .mock("GET", mockito::Matcher::Regex("/api/v1/discover.*".into()))
        .with_status(200)
        .with_body(r#"{"nodes":[{"node_id":"n-test"}]}"#)
        .create_async()
        .await;
    let health = LocalHealth::new(
        r#"{"status":"ok","node_id":"n","region":"eu","load":0.1,"models":["m"]}"#,
        200,
    );
    let node = make_node(
        "n-test",
        "https://node.iicpnet.test-host.org:8080",
        &format!("{}/api", server.url()),
    );
    let report = run_conformance_checks(&node, health.port, Some("tok")).await;
    assert_eq!(report.pass_count, 3);
    assert_eq!(report.fail_count, 1);
    assert_eq!(report.tests.len(), 4);
}
