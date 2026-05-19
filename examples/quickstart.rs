// SPDX-License-Identifier: Apache-2.0
//! Quickstart example — discover nodes and run a chat task.
use iicp_client::{ChatMessage, ChatOptions, ClientConfig, DiscoverOptions, IicpClient};

#[tokio::main]
async fn main() -> iicp_client::Result<()> {
    let client = IicpClient::new(ClientConfig::default())?;

    let nodes = client
        .discover("urn:iicp:intent:llm:chat:v1", None)
        .await?;
    let node = nodes.nodes.into_iter().next().expect("no nodes available");

    let reply = client
        .chat(
            &node,
            vec![
                ChatMessage { role: "system".into(), content: "You are a helpful assistant.".into() },
                ChatMessage { role: "user".into(),   content: "What is IICP?".into() },
            ],
            Some(ChatOptions {
                timeout_ms: Some(30_000),
                ..Default::default()
            }),
        )
        .await?;

    println!("{}", reply.choices[0].message.content);
    Ok(())
}
