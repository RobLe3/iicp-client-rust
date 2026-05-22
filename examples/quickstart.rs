// SPDX-License-Identifier: Apache-2.0
//! Quickstart example — discover + chat in a single call.
use iicp_client::{ChatMessage, ChatOptions, ClientConfig, IicpClient};

#[tokio::main]
async fn main() -> iicp_client::Result<()> {
    let client = IicpClient::new(ClientConfig::default())?;

    // chat() discovers the best node and submits internally (SDK-01).
    let reply = client
        .chat(
            vec![
                ChatMessage {
                    role: "system".into(),
                    content: "You are a helpful assistant.".into(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: "What is IICP?".into(),
                },
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
