// SPDX-License-Identifier: Apache-2.0
//! #457 / ADR-040 — `iicp-node serve` multiplexes the HTTP control plane and the native
//! IICP binary transport on ONE port (first-byte detection). Proves BOTH planes answer on
//! the same socket, and that transport_endpoint derives from the HTTP endpoint.
//!
//! Fails without the fix: pre-#457 serve() bound only the axum HTTP server on the port, so
//! a native IICP CALL would hit the HTTP parser and never get a RESPONSE.

use std::net::TcpListener as StdListener;

use iicp_client::node::{derive_native_endpoint, IicpNode, NodeConfig};
use serde_json::json;

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn test_derive_native_endpoint() {
    assert_eq!(
        derive_native_endpoint("http://203.0.113.5:9484").as_deref(),
        Some("iicp://203.0.113.5:9484")
    );
    assert_eq!(
        derive_native_endpoint("https://node.example:9484").as_deref(),
        Some("iicpsec://node.example:9484")
    );
    // Authority only — any path is dropped.
    assert_eq!(
        derive_native_endpoint("http://h:9484/v1/task").as_deref(),
        Some("iicp://h:9484")
    );
    assert_eq!(derive_native_endpoint("not-a-url"), None);
}

#[cfg(feature = "iicp-tcp")]
#[tokio::test]
async fn test_http_and_native_call_share_one_port() {
    use iicp_client::iicp_tcp::IicpTcpClient;

    let port = free_port();
    let mut cfg = NodeConfig::new(
        "mux-node",
        "http://test.local",
        "urn:iicp:intent:llm:chat:v1",
    );
    cfg.region = Some("test-region".into());
    cfg.model = Some("test-model".into());
    let node = IicpNode::new(cfg);
    let addr = format!("127.0.0.1:{port}");
    tokio::spawn(async move {
        let _ = node
            .serve(
                |task| Box::pin(async move { Ok(json!({ "echo": task.payload })) }),
                &addr,
                None, // no token → no heartbeat / no register
            )
            .await;
    });

    // Wait for the port (HTTP control plane answers on it).
    let mut up = false;
    for _ in 0..40 {
        if reqwest::get(format!("http://127.0.0.1:{port}/iicp/health"))
            .await
            .is_ok()
        {
            up = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(up, "server did not start on port {port}");

    let resp = reqwest::get(format!("http://127.0.0.1:{port}/iicp/health"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "HTTP /iicp/health on the shared port");

    // Native IICP CALL on the SAME port (pre-#457 this hit the HTTP parser → no RESPONSE).
    let mut client = IicpTcpClient::connect("127.0.0.1", port).await.unwrap();
    client.handshake().await.unwrap();
    let result = client
        .call(
            "urn:iicp:intent:llm:chat:v1",
            json!({ "messages": [{ "role": "user", "content": "hi" }] }),
            None,
        )
        .await
        .expect("native CALL returned a RESPONSE over the multiplexed port");
    assert!(result.is_object(), "native CALL result is a JSON object");
}
