// SPDX-License-Identifier: Apache-2.0
//! IICP Rust client SDK — ADR-016 §1 (SDK-01..SDK-06)
//!
//! # Quickstart
//! ```rust,no_run
//! use iicp_client::{ChatMessage, ChatOptions, ClientConfig, IicpClient};
//!
//! #[tokio::main]
//! async fn main() -> iicp_client::Result<()> {
//!     let client = IicpClient::new(ClientConfig::default())?;
//!     let reply = client.chat(
//!         vec![ChatMessage { role: "user".into(), content: "What is IICP?".into() }],
//!         None,
//!     ).await?;
//!     println!("{}", reply.choices[0].message.content);
//!     Ok(())
//! }
//! ```

mod client;
mod errors;
mod http;
pub mod node;
mod types;

#[cfg(feature = "iicp-tcp")]
pub mod iicp_tcp;

#[cfg(feature = "nat")]
pub mod nat_detection;

pub mod backends;

pub use client::IicpClient;
pub use errors::{IicpError, Result};
pub use http::make_traceparent;
pub use node::{IicpNode, NodeConfig};
pub use types::{
    ChatChoice, ChatMessage, ChatOptions, ChatResponse, ChatUsage, ClientConfig, DiscoverOptions,
    Node, NodeList, TaskAuth, TaskConstraints, TaskRequest, TaskResponse,
};
