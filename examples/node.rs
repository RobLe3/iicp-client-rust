// SPDX-License-Identifier: Apache-2.0
//! Example: run an IICP provider node.
//!
//! Environment variables (all optional):
//!   NODE_ID       — unique node identifier (default: "rust-node-001")
//!   NODE_ENDPOINT — public URL of this node (default: "http://localhost:8020")
//!   INTENT        — intent URN served (default: urn:iicp:intent:llm:chat:v1)
//!   LISTEN        — bind address (default: "0.0.0.0:8020")
//!   MODEL         — model name to advertise
//!   REGION        — region tag to advertise

use iicp_client::node::{IicpNode, NodeConfig};
use serde_json::json;

#[tokio::main]
async fn main() -> iicp_client::Result<()> {
    tracing_subscriber::fmt::init();

    let node_id = std::env::var("NODE_ID").unwrap_or_else(|_| "rust-node-001".into());
    let endpoint =
        std::env::var("NODE_ENDPOINT").unwrap_or_else(|_| "http://localhost:8020".into());
    let intent = std::env::var("INTENT").unwrap_or_else(|_| "urn:iicp:intent:llm:chat:v1".into());
    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:8020".into());

    let mut cfg = NodeConfig::new(&node_id, &endpoint, &intent);
    cfg.model = std::env::var("MODEL").ok();
    cfg.region = std::env::var("REGION").ok();
    cfg.max_concurrent = 4;

    let node = IicpNode::new(cfg);

    let token = node.register().await.ok();
    if let Some(ref t) = token {
        tracing::info!("registered — token: {t}");
    }

    tracing::info!("serving on {listen}");
    node.serve(
        move |task| {
            let nid = node_id.clone();
            Box::pin(async move {
                let prompt = task.payload["messages"]
                    .as_array()
                    .and_then(|m| m.last())
                    .and_then(|m| m["content"].as_str())
                    .unwrap_or("(empty)");
                Ok(json!({
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "content": format!("Echo from {nid}: {prompt}")
                        }
                    }]
                }))
            })
        },
        &listen,
        token,
    )
    .await
}
