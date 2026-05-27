// SPDX-License-Identifier: Apache-2.0
//! Drop-in backend handlers for iicp-client.
//!
//! Each helper returns a closure suitable for use as the task handler in
//! `IicpNode::serve()` or as the `TcpTaskHandler` for `IicpTcpServer`.
//!
//! - [`openai_compat`] — drives Ollama, vLLM, LM Studio, or any
//!                       OpenAI-compatible HTTP server.

pub mod openai_compat;
