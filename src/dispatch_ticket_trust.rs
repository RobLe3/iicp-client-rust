//! Opt-in verifier for the pre-normative dispatch-ticket trust v2 profile.
//!
//! The default v1 same-origin route-ticket behavior is intentionally unchanged.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

pub const PROFILE: &str = "dispatch_ticket_v2";
const DOMAIN: &[u8] = b"IICP-DISPATCH-TICKET-V2\0";

#[derive(Clone, Debug, Deserialize)]
pub struct DispatchTrustKey {
    pub key_id: String,
    pub public_key_b64url: String,
    pub state: String,
    pub valid_from: u64,
    pub valid_until: u64,
    #[serde(default)]
    pub allowed_profiles: Vec<String>,
    #[serde(default)]
    pub issuers: Vec<String>,
    #[serde(default)]
    pub audiences: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DispatchTrustBundle {
    pub bundle_version: u64,
    pub keys: Vec<DispatchTrustKey>,
    pub issuer: Option<String>,
    pub valid_from: Option<u64>,
    pub valid_until: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct DispatchTicketBindings {
    pub issuer: String,
    pub provider_id: String,
    pub intent: String,
    pub constraints_digest: String,
    pub audience: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DispatchTrustDecision {
    pub accepted: bool,
    pub code: String,
    pub anchored: bool,
    pub key_id: Option<String>,
}

impl DispatchTrustDecision {
    fn reject(code: &str, key_id: Option<&str>) -> Self {
        Self {
            accepted: false,
            code: code.into(),
            anchored: false,
            key_id: key_id.map(str::to_owned),
        }
    }
}

#[derive(Default)]
pub struct LocalDispatchReplayCache {
    seen: HashMap<String, u64>,
}

impl LocalDispatchReplayCache {
    pub fn contains(&mut self, jti: &str, now: u64) -> bool {
        self.seen.retain(|_, expiry| *expiry > now);
        self.seen.contains_key(jti)
    }

    pub fn remember(&mut self, jti: impl Into<String>, expires_at: u64) {
        self.seen.insert(jti.into(), expires_at);
    }
}

pub fn canonical_ticket_claims(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let sorted = map.iter().collect::<BTreeMap<_, _>>();
            format!(
                "{{{}}}",
                sorted
                    .into_iter()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap(),
                        canonical_ticket_claims(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_ticket_claims)
                .collect::<Vec<_>>()
                .join(",")
        ),
        _ => serde_json::to_string(value).unwrap(),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_dispatch_ticket_v2(
    claims: &Value,
    signature_b64url: &str,
    bundle: &DispatchTrustBundle,
    bindings: &DispatchTicketBindings,
    now: u64,
    minimum_bundle_version: u64,
    mut replay_cache: Option<&mut LocalDispatchReplayCache>,
) -> DispatchTrustDecision {
    if bundle.bundle_version < minimum_bundle_version {
        return DispatchTrustDecision::reject("reject_bundle_rollback", None);
    }
    if bundle.valid_from.is_some_and(|start| now < start) {
        return DispatchTrustDecision::reject("reject_bundle_not_yet_valid", None);
    }
    if bundle.valid_until.is_some_and(|end| now > end) {
        return DispatchTrustDecision::reject("reject_bundle_expired", None);
    }
    if claims["profile"] != PROFILE {
        return DispatchTrustDecision::reject("reject_required_profile_downgrade", None);
    }
    let Some(key_id) = claims["key_id"].as_str() else {
        return DispatchTrustDecision::reject("reject_unknown_key", None);
    };
    let Some(key) = bundle
        .keys
        .iter()
        .find(|candidate| candidate.key_id == key_id)
    else {
        return DispatchTrustDecision::reject("reject_unknown_key", Some(key_id));
    };
    if key.state == "revoked" {
        return DispatchTrustDecision::reject("reject_key_revoked", Some(key_id));
    }
    if now < key.valid_from || now > key.valid_until {
        return DispatchTrustDecision::reject("reject_key_expired", Some(key_id));
    }
    if !key.allowed_profiles.is_empty()
        && !key
            .allowed_profiles
            .iter()
            .any(|profile| profile == PROFILE)
    {
        return DispatchTrustDecision::reject("reject_profile_not_allowed", Some(key_id));
    }
    if !key.issuers.is_empty() && !key.issuers.iter().any(|issuer| claims["issuer"] == *issuer) {
        return DispatchTrustDecision::reject("reject_issuer", Some(key_id));
    }
    if !key.audiences.is_empty()
        && !key
            .audiences
            .iter()
            .any(|audience| claims["audience"] == *audience)
    {
        return DispatchTrustDecision::reject("reject_audience", Some(key_id));
    }
    let bound = claims["issuer"] == bindings.issuer
        && claims["provider_id"] == bindings.provider_id
        && claims["intent"] == bindings.intent
        && claims["constraints_digest"] == bindings.constraints_digest
        && bindings
            .audience
            .as_ref()
            .is_none_or(|audience| claims["audience"] == *audience);
    if !bound {
        return DispatchTrustDecision::reject("reject_claim_mismatch", Some(key_id));
    }
    let (Some(expires_at), Some(jti)) = (claims["expires_at"].as_u64(), claims["jti"].as_str())
    else {
        return DispatchTrustDecision::reject("reject_claim_mismatch", Some(key_id));
    };
    if expires_at <= now || jti.is_empty() {
        return DispatchTrustDecision::reject("reject_claim_mismatch", Some(key_id));
    }
    let signature_valid = (|| {
        let public_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&key.public_key_b64url)
            .ok()?
            .try_into()
            .ok()?;
        let signature_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(signature_b64url)
            .ok()?
            .try_into()
            .ok()?;
        let verifier = VerifyingKey::from_bytes(&public_bytes).ok()?;
        let signature = Signature::from_bytes(&signature_bytes);
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(canonical_ticket_claims(claims).as_bytes());
        Some(verifier.verify(&message, &signature).is_ok())
    })()
    .unwrap_or(false);
    if !signature_valid {
        return DispatchTrustDecision::reject("reject_signature", Some(key_id));
    }
    if replay_cache
        .as_deref_mut()
        .is_some_and(|cache| cache.contains(jti, now))
    {
        return DispatchTrustDecision::reject("reject_local_replay", Some(key_id));
    }
    if let Some(cache) = replay_cache {
        cache.remember(jti, expires_at);
    }
    DispatchTrustDecision {
        accepted: true,
        code: "accept_anchored".into(),
        anchored: true,
        key_id: Some(key_id.into()),
    }
}
