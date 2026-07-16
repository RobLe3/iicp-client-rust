//! Opt-in evaluator for pre-normative policy operational evidence.
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyEvidenceDecision {
    pub eligible: bool,
    pub reason: &'static str,
}

fn reject(reason: &'static str) -> PolicyEvidenceDecision {
    PolicyEvidenceDecision {
        eligible: false,
        reason,
    }
}

pub fn evaluate_policy_operational_evidence(
    requirement: &Value,
    context: &Value,
    evaluated_at: &str,
) -> PolicyEvidenceDecision {
    let known: HashSet<&str> = [
        "retention_control",
        "subprocessor_disclosure",
        "approval_event",
    ]
    .into_iter()
    .collect();
    let required: Vec<&str> = requirement
        .get("required_evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if required.iter().any(|kind| !known.contains(kind)) {
        return reject("unsupported_evidence_requirement");
    }
    if requirement.get("manifest_sha256") != context.get("manifest_sha256") {
        return reject("manifest_digest_mismatch");
    }
    let now = evaluated_at
        .parse::<DateTime<Utc>>()
        .expect("validated evaluation timestamp");
    let evidence = context.get("evidence").and_then(Value::as_array);
    for kind in required {
        let matches: Vec<&Value> = evidence
            .into_iter()
            .flatten()
            .filter(|item| item.get("type").and_then(Value::as_str) == Some(kind))
            .collect();
        if matches.is_empty() {
            return reject("evidence_missing");
        }
        let verified: Vec<&Value> = matches
            .into_iter()
            .filter(|item| item.get("verified").and_then(Value::as_bool) == Some(true))
            .collect();
        if verified.is_empty() {
            return reject("evidence_unauthenticated");
        }
        let current = verified.iter().any(|item| {
            item.get("expires_at")
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<DateTime<Utc>>().ok())
                .is_some_and(|expires| expires > now)
        });
        if !current {
            return reject("evidence_expired");
        }
    }
    PolicyEvidenceDecision {
        eligible: true,
        reason: "compatible",
    }
}
