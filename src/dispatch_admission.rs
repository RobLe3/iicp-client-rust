// SPDX-License-Identifier: Apache-2.0
//! Provider-local admission for the pre-normative dispatch-v2 profile.
//!
//! The ordinary node does not invoke this module. Applications must first
//! verify a ticket using the separate trust profile and explicitly provide a
//! durable store. No task content or Directory call belongs here.

use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};

pub const PROFILE: &str = "urn:iicp:profile:dispatch-admission:v2";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DispatchAdmissionClaim {
    pub jti: String,
    pub provider_id: String,
    pub intent: String,
    pub not_before: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchAdmissionDecision {
    pub code: &'static str,
    pub accepted: bool,
    pub state: Option<String>,
}

impl DispatchAdmissionDecision {
    pub fn reject(code: &'static str) -> Self {
        Self {
            code,
            accepted: false,
            state: None,
        }
    }

    pub fn accepted() -> Self {
        Self {
            code: "accepted",
            accepted: true,
            state: Some("accepted".into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchAdmissionRecord {
    pub jti: String,
    pub provider_digest: String,
    pub intent_digest: String,
    pub state: String,
    pub expires_at: u64,
    pub consumed_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum DispatchAdmissionError {
    #[error("dispatch admission storage unavailable: {0}")]
    Storage(String),
    #[error("unknown dispatch admission")]
    Unknown,
    #[error("invalid dispatch admission transition: {0}")]
    Transition(String),
}

pub trait DispatchAdmissionStore: Send + Sync {
    fn consume<'a>(
        &'a self,
        claim: &'a DispatchAdmissionClaim,
        expected_provider_id: &'a str,
        expected_intent: &'a str,
        now: u64,
        clock_skew_s: u64,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<DispatchAdmissionDecision, DispatchAdmissionError>>
                + Send
                + 'a,
        >,
    >;

    fn transition<'a>(
        &'a self,
        jti: &'a str,
        state: &'a str,
        now: u64,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<DispatchAdmissionRecord, DispatchAdmissionError>>
                + Send
                + 'a,
        >,
    >;

    fn cleanup(
        &self,
        now: u64,
        retention_s: u64,
        limit: usize,
    ) -> Result<usize, DispatchAdmissionError>;

    fn lookup(&self, jti: &str) -> Result<Option<DispatchAdmissionRecord>, DispatchAdmissionError>;
}

pub async fn evaluate_dispatch_admission(
    store: &dyn DispatchAdmissionStore,
    claim: &DispatchAdmissionClaim,
    expected_provider_id: &str,
    expected_intent: &str,
    now: u64,
    trust_verified: bool,
    clock_skew_s: u64,
) -> DispatchAdmissionDecision {
    if !trust_verified {
        return DispatchAdmissionDecision::reject("reject_issuer_key");
    }
    store
        .consume(
            claim,
            expected_provider_id,
            expected_intent,
            now,
            clock_skew_s,
        )
        .await
        .unwrap_or_else(|_| DispatchAdmissionDecision::reject("reject_store_unavailable"))
}

pub fn terminal(state: &str) -> bool {
    matches!(
        state,
        "completed" | "failed" | "cancelled" | "expired" | "rejected"
    )
}
