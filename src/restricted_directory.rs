// SPDX-License-Identifier: Apache-2.0
//! Fail-closed validation for restricted trust-domain directory decisions.

use serde::Deserialize;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::{IicpError, Result};
use crate::types::{RestrictedDirectoryContext, RestrictedEligibility};

pub const PROFILE_ID: &str = "urn:iicp:profile:restricted-trust-domain:v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryDecision {
    schema: String,
    profile: String,
    decision: String,
    operation: String,
    domain_id: String,
    authority_id: String,
    subject_kind: String,
    membership_generation: u64,
    membership_expires_at: u64,
}

fn refused(message: &'static str) -> IicpError {
    IicpError::PolicyRefused {
        code: "restricted_directory_decision_refused".into(),
        message: message.into(),
    }
}

pub(crate) fn validate_context(context: &RestrictedDirectoryContext) -> Result<()> {
    if context.domain_id.trim().is_empty()
        || context.authority_id.trim().is_empty()
        || context.subject_id.trim().is_empty()
        || !matches!(
            context.subject_kind.as_str(),
            "node" | "client" | "directory"
        )
        || context.minimum_membership_generation == 0
    {
        return Err(refused("restricted directory context is incomplete"));
    }
    Ok(())
}

pub(crate) fn validate_decision(
    body: &Value,
    context: &RestrictedDirectoryContext,
    operation: &str,
) -> Result<RestrictedEligibility> {
    let raw = body
        .get("restricted_domain_decision")
        .cloned()
        .ok_or_else(|| refused("restricted directory decision is missing"))?;
    let decision: DirectoryDecision = serde_json::from_value(raw)
        .map_err(|_| refused("restricted directory decision is malformed"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if decision.schema != "iicp.restricted-trust-domain.directory-decision.v0"
        || decision.profile != PROFILE_ID
        || decision.decision != "eligible"
        || decision.operation != operation
        || decision.domain_id != context.domain_id
        || decision.authority_id != context.authority_id
        || decision.subject_kind != context.subject_kind
        || decision.membership_generation < context.minimum_membership_generation
        || decision.membership_expires_at <= now
    {
        return Err(refused(
            "restricted directory decision does not match the request context",
        ));
    }
    Ok(RestrictedEligibility {
        domain_id: decision.domain_id,
        authority_id: decision.authority_id,
        membership_generation: decision.membership_generation,
        membership_expires_at: decision.membership_expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_config::SecretRef;
    use serde_json::json;

    fn context() -> RestrictedDirectoryContext {
        RestrictedDirectoryContext {
            domain_id: "domain-a".into(),
            authority_id: "did:iicp:test:directory-a".into(),
            subject_id: "client-a".into(),
            subject_kind: "client".into(),
            minimum_membership_generation: 7,
            membership_credential: SecretRef::Environment {
                name: "IICP_TEST_MEMBERSHIP".into(),
            },
        }
    }

    #[test]
    fn accepts_matching_current_decision() {
        let body = json!({"restricted_domain_decision": {
            "schema": "iicp.restricted-trust-domain.directory-decision.v0",
            "profile": PROFILE_ID,
            "decision": "eligible",
            "operation": "discovery",
            "domain_id": "domain-a",
            "authority_id": "did:iicp:test:directory-a",
            "subject_kind": "client",
            "membership_generation": 8,
            "membership_expires_at": u64::MAX
        }});
        assert_eq!(
            validate_decision(&body, &context(), "discovery")
                .unwrap()
                .membership_generation,
            8
        );
    }

    #[test]
    fn rejects_missing_mismatch_stale_and_unknown_fields() {
        assert!(validate_decision(&json!({}), &context(), "discovery").is_err());
        for (field, value) in [
            ("operation", json!("bootstrap")),
            ("domain_id", json!("domain-b")),
            ("authority_id", json!("did:iicp:test:other")),
            ("membership_generation", json!(6)),
            ("membership_expires_at", json!(1)),
        ] {
            let mut decision = json!({
                "schema": "iicp.restricted-trust-domain.directory-decision.v0",
                "profile": PROFILE_ID, "decision": "eligible", "operation": "discovery",
                "domain_id": "domain-a", "authority_id": "did:iicp:test:directory-a",
                "subject_kind": "client", "membership_generation": 7,
                "membership_expires_at": u64::MAX
            });
            decision[field] = value;
            assert!(validate_decision(
                &json!({"restricted_domain_decision": decision}),
                &context(),
                "discovery"
            )
            .is_err());
        }
        let mut extra = json!({
            "schema": "iicp.restricted-trust-domain.directory-decision.v0",
            "profile": PROFILE_ID, "decision": "eligible", "operation": "discovery",
            "domain_id": "domain-a", "authority_id": "did:iicp:test:directory-a",
            "subject_kind": "client", "membership_generation": 7,
            "membership_expires_at": u64::MAX, "unexpected": true
        });
        assert!(validate_decision(
            &json!({"restricted_domain_decision": extra.take()}),
            &context(),
            "discovery"
        )
        .is_err());
    }
}
