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
pub mod consumer_token;
pub mod dispatch_ticket;
mod endpoint_security;
mod errors;
mod http;
pub mod node;
pub mod node_log;
mod types;

#[cfg(feature = "iicp-tcp")]
pub mod iicp_tcp;

#[cfg(feature = "nat")]
pub mod nat_detection;

// ADR-050 unified client — the compat proxy gateway (`iicp-node proxy`).
#[cfg(feature = "proxy")]
pub mod proxy;

#[cfg(feature = "nat")]
pub mod qualify;

pub mod availability;
pub mod backend_stability;
pub mod backends;
pub mod cip_policy;
pub mod concurrency;
pub mod confidentiality;
pub mod conformance;
pub mod delegation;
pub mod idempotency;
pub mod identity;
pub mod instance_lock;
pub mod mcp_policy;
pub mod operator_crypto;
pub mod peer_manager;
pub mod policy;
pub mod policy_manifest;
pub mod pricing;
pub mod profile_compatibility;
pub mod recovery;
#[cfg(feature = "iicp-tcp")]
pub mod relay_session;
#[cfg(feature = "iicp-tcp")]
pub mod relay_ticket;
#[cfg(feature = "iicp-tcp")]
pub mod relay_worker_client;
pub mod request_projection;
pub mod routing_policy;
pub mod scheduler;
pub mod selection;
pub mod service_lifecycle;
pub mod token_validator;
pub mod trust_auditor;
pub mod tunnel;
pub mod updater;

#[cfg(feature = "nat")]
pub use qualify::{
    qualify_service, qualify_service_async, ExposureMode, ExposureQualification, Ipv4Qualification,
    Ipv6Qualification, ServiceQualification,
};

pub use client::IicpClient;
pub use errors::{IicpError, Result};
pub use http::make_traceparent;
pub use node::{IicpNode, NodeConfig};
pub use policy::{
    classify_intent, ensure_intent_allowed, prohibited_intent_reason, IntentRiskCategory,
    ProhibitedIntentRule, HIGH_RISK_INTENT_RULES, POLICY_REFUSAL_CODE, PROHIBITED_INTENT_RULES,
};
pub use routing_policy::{
    filter_nodes_for_routing_policy, resolved_policy, routing_policy_refusal_message,
    ROUTING_POLICY_REFUSAL_CODE,
};
pub use types::{
    ChatChoice, ChatMessage, ChatOptions, ChatResponse, ChatUsage, ClientConfig, CxPublicKey,
    DiscoverOptions, Node, NodeList, ProfileRequest, RouteConstraints, RoutingPolicy,
    RoutingProfile, TaskAuth, TaskConstraints, TaskRequest, TaskResponse,
};
