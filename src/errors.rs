// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;

/// All errors emitted by the IICP client SDK.
#[derive(Debug, Error)]
pub enum IicpError {
    /// Network or HTTP transport failure.
    #[error("network error: {0}")]
    Http(#[from] reqwest::Error),

    /// Directory or node returned an IICP error response.
    #[error("[{code}] {message} (HTTP {status})")]
    Protocol {
        code: String,
        message: String,
        status: u16,
    },

    /// SDK-03: intent URN does not match the required pattern.
    #[error("SDK-03: invalid intent URN: {0}")]
    InvalidIntent(String),

    /// Intent refused by local client policy before discovery/routing.
    #[error("[{code}] {message}")]
    PolicyRefused { code: String, message: String },

    /// SDK-04: timeout_ms exceeds the maximum of 120 000 ms.
    #[error("SDK-04: timeout_ms must be ≤ 120000; got {0}")]
    TimeoutTooLarge(u64),

    /// Discover returned an empty node list.
    #[error("no nodes available for intent {intent}")]
    NoNodes { intent: String },

    /// JSON serialization / deserialization failure.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// Node registration, heartbeat, or server bind failure.
    #[error("node error: {0}")]
    Node(String),
}

impl IicpError {
    /// True for errors where retrying a different attempt may succeed (SDK-05).
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            IicpError::Protocol {
                status: 429 | 502 | 503 | 504,
                ..
            } | IicpError::Http(_)
        )
    }
}

pub type Result<T> = std::result::Result<T, IicpError>;
