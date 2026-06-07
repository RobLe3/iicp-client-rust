// SPDX-License-Identifier: Apache-2.0
//! Live-mesh integration tests (#5) — OPT-IN.
//!
//! The unit tests mock the directory; nothing exercises a REAL IICP node. These do, against the
//! live mesh, and are `#[ignore]`d so a plain `cargo test` skips them. Run intentionally with:
//!
//!     cargo test --test integration -- --ignored          # discover (read-only)
//!     cargo test --test integration live_chat -- --ignored # sends a real task to a live node
//!
//! Override the directory with IICP_DIRECTORY_URL. Unblocked once a node registered a routable
//! public endpoint (W-011 resolved; an external operator runs https://iicp.shaal.dev).
use iicp_client::{ChatMessage, ChatOptions, ClientConfig, IicpClient};

fn live_config() -> ClientConfig {
    let mut cfg = ClientConfig::default();
    if let Ok(url) = std::env::var("IICP_DIRECTORY_URL") {
        cfg.directory_url = url;
    }
    cfg
}

#[tokio::test]
#[ignore = "live mesh — run with --ignored"]
async fn live_discover_returns_routable_nodes() {
    let client = IicpClient::new(live_config()).expect("client init");
    let nodes = client
        .discover("urn:iicp:intent:llm:chat:v1", None, None)
        .await
        .expect("discover failed");
    assert!(
        !nodes.nodes.is_empty(),
        "live directory returned no chat nodes"
    );
    assert!(
        nodes.nodes[0].endpoint.starts_with("http"),
        "node endpoint is not routable: {}",
        nodes.nodes[0].endpoint
    );
}

#[tokio::test]
#[ignore = "live mesh — sends a real task to a live operator's node; run with --ignored"]
async fn live_chat_returns_reply() {
    let client = IicpClient::new(live_config()).expect("client init");
    let resp = client
        .chat(
            vec![ChatMessage {
                role: "user".into(),
                content: "Reply with the single word: OK".into(),
            }],
            Some(ChatOptions {
                max_tokens: Some(16),
                ..Default::default()
            }),
        )
        .await
        .expect("chat failed");
    assert!(!resp.choices.is_empty(), "chat response had no choices");
    assert!(
        !resp.choices[0].message.content.is_empty(),
        "chat reply was empty"
    );
}
