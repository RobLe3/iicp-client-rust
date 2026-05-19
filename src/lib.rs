// SPDX-License-Identifier: Apache-2.0
//! IICP Rust client SDK — ADR-016 §1 (SDK-01..SDK-06)
//!
//! # Quickstart
//! ```rust,no_run
//! use iicp_client::{IicpClient, ClientConfig, DiscoverOptions};
//!
//! #[tokio::main]
//! async fn main() -> iicp_client::Result<()> {
//!     let client = IicpClient::new(ClientConfig::default())?;
//!     let nodes = client.discover("urn:iicp:intent:llm:chat:v1", None).await?;
//!     println!("Found {} nodes", nodes.nodes.len());
//!     Ok(())
//! }
//! ```

mod client;
mod errors;
mod http;
mod types;

pub use client::IicpClient;
pub use errors::{IicpError, Result};
pub use types::{
    ChatChoice, ChatMessage, ChatOptions, ChatResponse, ChatUsage,
    ClientConfig, DiscoverOptions, Node, NodeList, TaskAuth,
    TaskConstraints, TaskRequest, TaskResponse,
};
