// SPDX-License-Identifier: Apache-2.0
//! Pre-normative provider-side policy-detail authorization and redaction.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

const CONSUMER_TOKEN_DOMAIN: &[u8] = b"iicp:consumer-token:v1\n";

pub const ALLOWED_DETAIL_FIELDS: [&str; 4] = [
    "retention_intervals",
    "subprocessor_references",
    "approval_evidence_references",
    "operational_evidence_references",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDetailDisclosureDecision {
    pub status: u16,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConsumerTokenVerification {
    pub status: &'static str,
    pub claims: Option<Value>,
}

pub fn verify_policy_detail_consumer_token(
    token: &str,
    public_key_hex: &str,
    target_node_id: &str,
    intent: &str,
    now_s: i64,
) -> ConsumerTokenVerification {
    let invalid = || ConsumerTokenVerification {
        status: "invalid",
        claims: None,
    };
    let Some((payload, signature_hex)) = token.split_once('.') else {
        return invalid();
    };
    if signature_hex.len() != 128 {
        return invalid();
    }
    let Ok(key_bytes) = hex::decode(public_key_hex).and_then(|bytes| {
        bytes
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)
    }) else {
        return invalid();
    };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
        return invalid();
    };
    let Ok(sig_bytes) = hex::decode(signature_hex).and_then(|bytes| {
        bytes
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)
    }) else {
        return invalid();
    };
    let signature = Signature::from_bytes(&sig_bytes);
    if key
        .verify(
            &[CONSUMER_TOKEN_DOMAIN, payload.as_bytes()].concat(),
            &signature,
        )
        .is_err()
    {
        return invalid();
    }
    let Ok(claims) = URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .ok_or(())
    else {
        return invalid();
    };
    if claims["v"] != 1
        || claims["aud"] != target_node_id
        || claims["intent"] != intent
        || claims["sub"].as_str().is_none()
    {
        return invalid();
    }
    if claims["exp"].as_i64().is_none_or(|exp| exp <= now_s) {
        return ConsumerTokenVerification {
            status: "expired",
            claims: Some(claims),
        };
    }
    ConsumerTokenVerification {
        status: "valid",
        claims: Some(claims),
    }
}

/// Apply the portable disclosure contract. `consumer_auth` must be produced by
/// a cryptographic adapter; this helper intentionally does not parse raw tokens.
pub fn evaluate_policy_detail_disclosure(context: &Value) -> PolicyDetailDisclosureDecision {
    let auth = context["consumer_auth"].as_str();
    if auth == Some("missing") {
        return decision(401, "consumer_auth_required");
    }
    if !matches!(auth, Some("valid" | "expired")) {
        return decision(401, "consumer_auth_invalid");
    }
    if auth == Some("expired") {
        return decision(401, "consumer_auth_expired");
    }
    if context["disclosure_allowed"].as_bool() != Some(true) {
        return decision(403, "disclosure_forbidden");
    }

    let provider = context["provider_node_id"]
        .as_str()
        .filter(|value| !value.is_empty());
    let intent = context["consumer_intent"]
        .as_str()
        .filter(|value| !value.is_empty());
    let digest = context["manifest_sha256"]
        .as_str()
        .filter(|value| !value.is_empty());
    let bound = provider.is_some()
        && provider == context["consumer_target_node_id"].as_str()
        && provider == context["ticket_target_node_id"].as_str()
        && intent.is_some()
        && intent == context["ticket_intent"].as_str()
        && digest.is_some()
        && digest == context["ticket_manifest_sha256"].as_str();
    if !bound {
        return decision(404, "resource_concealed");
    }

    let source = context["details"].as_object();
    let mut details = Map::new();
    if let Some(source) = source {
        for field in ALLOWED_DETAIL_FIELDS {
            if let Some(value) = source.get(field) {
                details.insert(field.to_string(), value.clone());
            }
        }
    }
    PolicyDetailDisclosureDecision {
        status: 200,
        reason: "compatible".into(),
        body: Some(json!({
            "profile": "urn:iicp:profile:policy-detail-disclosure:v0",
            "manifest_sha256": digest.expect("checked above"),
            "details": details,
            "claim_status": "provider_declared",
        })),
    }
}

fn decision(status: u16, reason: &str) -> PolicyDetailDisclosureDecision {
    PolicyDetailDisclosureDecision {
        status,
        reason: reason.into(),
        body: None,
    }
}
