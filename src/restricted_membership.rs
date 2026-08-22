// SPDX-License-Identifier: Apache-2.0
//! Pre-normative restricted trust-domain membership and gossip verification.
//!
//! This module deliberately verifies peer-portable assertions. Opaque directory
//! bearer credentials are not accepted here and must never enter gossip.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MEMBERSHIP_SCHEMA: &str = "iicp.restricted-trust-domain.membership-assertion.v0";
pub const RESTRICTED_PROFILE: &str = "urn:iicp:profile:restricted-trust-domain:v1";
const MEMBERSHIP_DOMAIN: &[u8] = b"IICP-RTD-MEMBERSHIP-V0\n";
const GOSSIP_DOMAIN: &[u8] = b"IICP-RTD-GOSSIP-V0\n";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipSubject {
    pub kind: String,
    pub id: String,
    pub key_id: String,
    pub public_key_ed25519: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipIssuer {
    pub id: String,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipAssertion {
    pub schema: String,
    pub profile: String,
    pub assertion_id: String,
    pub domain_id: String,
    pub subject: MembershipSubject,
    pub issuer: MembershipIssuer,
    pub issued_at: u64,
    pub expires_at: u64,
    pub generation: u64,
    pub scopes: Vec<String>,
    pub audience: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedSignature {
    pub algorithm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipEnvelope {
    pub assertion: MembershipAssertion,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GossipProof {
    pub sender_id: String,
    pub domain_id: String,
    pub sent_at: u64,
    pub replay_id: String,
    pub payload_sha256: String,
    pub membership_assertion_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GossipEnvelope {
    pub proof: GossipProof,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipPolicy {
    pub domain_id: String,
    pub authority_id: String,
    pub authority_key_id: String,
    pub authority_public_key_ed25519: String,
    pub minimum_generation: u64,
    pub maximum_clock_skew_seconds: u64,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestrictedPeerBundle {
    pub policy: MembershipPolicy,
    pub membership: MembershipEnvelope,
    pub signing_seed_ed25519: String,
    pub directory_membership_bearer: String,
}

impl RestrictedPeerBundle {
    pub fn into_admission(
        self,
        expected_node_id: &str,
        now: u64,
    ) -> Result<crate::peer_manager::PeerAdmissionMode, MembershipRefusal> {
        if self.directory_membership_bearer.trim().is_empty() {
            return Err(MembershipRefusal::MissingDirectoryCredential);
        }
        verify_membership(
            &self.membership,
            &self.policy,
            expected_node_id,
            "peers",
            now,
        )?;
        let signing_seed = signing_seed(
            &self.signing_seed_ed25519,
            &self.membership.assertion.subject.public_key_ed25519,
        )?;
        Ok(crate::peer_manager::PeerAdmissionMode::Restricted(
            Box::new(crate::peer_manager::RestrictedPeerAdmission {
                policy: self.policy,
                directory_membership_bearer: self.directory_membership_bearer,
                directory_context: None,
                local: Some(crate::peer_manager::RestrictedLocalIdentity {
                    membership: self.membership,
                    signing_seed,
                }),
            }),
        ))
    }
}

fn signing_seed(value: &str, expected_public_key: &str) -> Result<[u8; 32], MembershipRefusal> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| MembershipRefusal::MalformedEvidence)?;
    let seed = bytes
        .try_into()
        .map_err(|_| MembershipRefusal::MalformedEvidence)?;
    let signing_key = SigningKey::from_bytes(&seed);
    if URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()) != expected_public_key {
        return Err(MembershipRefusal::WrongSubject);
    }
    Ok(seed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MembershipRefusal {
    MalformedEvidence,
    UnsupportedEvidence,
    InvalidAuthority,
    InvalidSignature,
    WrongDomain,
    WrongSubject,
    Expired,
    NotYetValid,
    RevokedGeneration,
    MissingScope,
    InvalidPayloadBinding,
    ReplayDetected,
    ReplayCapacity,
    StaleGossip,
    MissingDirectoryCredential,
}

impl MembershipRefusal {
    pub const fn code(self) -> &'static str {
        const CODES: [&str; 15] = [
            "membership_malformed",
            "membership_unsupported",
            "membership_authority_invalid",
            "membership_signature_invalid",
            "membership_domain_mismatch",
            "membership_subject_mismatch",
            "membership_expired",
            "membership_not_yet_valid",
            "membership_generation_revoked",
            "membership_scope_missing",
            "gossip_payload_mismatch",
            "gossip_replay",
            "gossip_replay_capacity",
            "gossip_stale",
            "directory_membership_missing",
        ];
        CODES[self as usize]
    }
}

pub fn verify_membership(
    envelope: &MembershipEnvelope,
    policy: &MembershipPolicy,
    expected_subject: &str,
    required_scope: &str,
    now: u64,
) -> Result<(), MembershipRefusal> {
    let assertion = &envelope.assertion;
    validate_membership_shape(assertion)?;
    validate_membership_identity(envelope, policy, expected_subject)?;
    validate_membership_lifecycle(assertion, policy, required_scope, now)?;
    verify_membership_signature(envelope, policy)
}

fn validate_membership_shape(assertion: &MembershipAssertion) -> Result<(), MembershipRefusal> {
    if uuid::Uuid::parse_str(&assertion.assertion_id).is_err()
        || assertion.domain_id.trim().is_empty()
        || assertion.subject.id.trim().is_empty()
        || assertion.subject.key_id.trim().is_empty()
    {
        return Err(MembershipRefusal::MalformedEvidence);
    }
    validate_membership_collections(assertion)
}

fn validate_membership_collections(
    assertion: &MembershipAssertion,
) -> Result<(), MembershipRefusal> {
    validate_membership_issuer(assertion)?;
    if assertion.audience.is_empty()
        || assertion.scopes.is_empty()
        || assertion.expires_at <= assertion.issued_at
    {
        return Err(MembershipRefusal::MalformedEvidence);
    }
    Ok(())
}

fn validate_membership_issuer(assertion: &MembershipAssertion) -> Result<(), MembershipRefusal> {
    if assertion.issuer.id.trim().is_empty() || assertion.issuer.key_id.trim().is_empty() {
        return Err(MembershipRefusal::MalformedEvidence);
    }
    Ok(())
}

fn validate_membership_identity(
    envelope: &MembershipEnvelope,
    policy: &MembershipPolicy,
    expected_subject: &str,
) -> Result<(), MembershipRefusal> {
    let assertion = &envelope.assertion;
    validate_membership_format(envelope)?;
    validate_membership_authority(assertion, policy)?;
    if assertion.subject.kind != "node" || assertion.subject.id != expected_subject {
        return Err(MembershipRefusal::WrongSubject);
    }
    Ok(())
}

fn validate_membership_format(envelope: &MembershipEnvelope) -> Result<(), MembershipRefusal> {
    if envelope.assertion.schema != MEMBERSHIP_SCHEMA
        || envelope.assertion.profile != RESTRICTED_PROFILE
        || envelope.signature.algorithm != "Ed25519"
    {
        return Err(MembershipRefusal::UnsupportedEvidence);
    }
    Ok(())
}

fn validate_membership_authority(
    assertion: &MembershipAssertion,
    policy: &MembershipPolicy,
) -> Result<(), MembershipRefusal> {
    if assertion.issuer.id != policy.authority_id
        || assertion.issuer.key_id != policy.authority_key_id
    {
        return Err(MembershipRefusal::InvalidAuthority);
    }
    if assertion.domain_id != policy.domain_id
        || !assertion
            .audience
            .iter()
            .any(|item| item == &policy.domain_id)
    {
        return Err(MembershipRefusal::WrongDomain);
    }
    Ok(())
}

fn validate_membership_lifecycle(
    assertion: &MembershipAssertion,
    policy: &MembershipPolicy,
    required_scope: &str,
    now: u64,
) -> Result<(), MembershipRefusal> {
    validate_membership_time(assertion, policy, now)?;
    validate_membership_generation(assertion, policy)?;
    if !assertion.scopes.iter().any(|scope| scope == required_scope) {
        return Err(MembershipRefusal::MissingScope);
    }
    Ok(())
}

fn validate_membership_time(
    assertion: &MembershipAssertion,
    policy: &MembershipPolicy,
    now: u64,
) -> Result<(), MembershipRefusal> {
    if assertion.issued_at > now.saturating_add(policy.maximum_clock_skew_seconds) {
        return Err(MembershipRefusal::NotYetValid);
    }
    if assertion.expires_at <= now {
        return Err(MembershipRefusal::Expired);
    }
    Ok(())
}

fn validate_membership_generation(
    assertion: &MembershipAssertion,
    policy: &MembershipPolicy,
) -> Result<(), MembershipRefusal> {
    if assertion.generation < policy.minimum_generation {
        return Err(MembershipRefusal::RevokedGeneration);
    }
    Ok(())
}

fn verify_membership_signature(
    envelope: &MembershipEnvelope,
    policy: &MembershipPolicy,
) -> Result<(), MembershipRefusal> {
    let key = verifying_key(&policy.authority_public_key_ed25519)?;
    let signature = signature(&envelope.signature.value)?;
    let canonical =
        serde_jcs::to_vec(&envelope.assertion).map_err(|_| MembershipRefusal::MalformedEvidence)?;
    let mut message = Vec::with_capacity(MEMBERSHIP_DOMAIN.len() + canonical.len());
    message.extend_from_slice(MEMBERSHIP_DOMAIN);
    message.extend_from_slice(&canonical);
    key.verify(&message, &signature)
        .map_err(|_| MembershipRefusal::InvalidSignature)
}

pub fn verify_gossip(
    gossip: &GossipEnvelope,
    membership: &MembershipEnvelope,
    policy: &MembershipPolicy,
    payload: &[u8],
    now: u64,
    replay_seen: bool,
) -> Result<(), MembershipRefusal> {
    verify_membership(membership, policy, &gossip.proof.sender_id, "peers", now)?;
    validate_gossip_identity(gossip, membership, policy, replay_seen)?;
    validate_gossip_freshness_and_payload(gossip, policy, payload, now)?;
    verify_gossip_signature(gossip, membership)
}

fn validate_gossip_identity(
    gossip: &GossipEnvelope,
    membership: &MembershipEnvelope,
    policy: &MembershipPolicy,
    replay_seen: bool,
) -> Result<(), MembershipRefusal> {
    if uuid::Uuid::parse_str(&gossip.proof.replay_id).is_err() {
        return Err(MembershipRefusal::MalformedEvidence);
    }
    validate_gossip_format(gossip, membership)?;
    validate_gossip_binding(gossip, membership, policy)?;
    if replay_seen {
        return Err(MembershipRefusal::ReplayDetected);
    }
    Ok(())
}

fn validate_gossip_format(
    gossip: &GossipEnvelope,
    membership: &MembershipEnvelope,
) -> Result<(), MembershipRefusal> {
    if gossip.signature.algorithm != "Ed25519"
        || gossip.signature.key_id.as_deref() != Some(&membership.assertion.subject.key_id)
    {
        return Err(MembershipRefusal::UnsupportedEvidence);
    }
    Ok(())
}

fn validate_gossip_binding(
    gossip: &GossipEnvelope,
    membership: &MembershipEnvelope,
    policy: &MembershipPolicy,
) -> Result<(), MembershipRefusal> {
    if gossip.proof.domain_id != policy.domain_id {
        return Err(MembershipRefusal::WrongDomain);
    }
    if gossip.proof.membership_assertion_id != membership.assertion.assertion_id {
        return Err(MembershipRefusal::WrongSubject);
    }
    Ok(())
}

fn validate_gossip_freshness_and_payload(
    gossip: &GossipEnvelope,
    policy: &MembershipPolicy,
    payload: &[u8],
    now: u64,
) -> Result<(), MembershipRefusal> {
    if gossip.proof.sent_at > now.saturating_add(policy.maximum_clock_skew_seconds)
        || now.saturating_sub(gossip.proof.sent_at) > policy.maximum_clock_skew_seconds
    {
        return Err(MembershipRefusal::StaleGossip);
    }
    let digest = format!("{:x}", Sha256::digest(payload));
    if digest != gossip.proof.payload_sha256 {
        return Err(MembershipRefusal::InvalidPayloadBinding);
    }
    Ok(())
}

fn verify_gossip_signature(
    gossip: &GossipEnvelope,
    membership: &MembershipEnvelope,
) -> Result<(), MembershipRefusal> {
    let key = verifying_key(&membership.assertion.subject.public_key_ed25519)?;
    let signature = signature(&gossip.signature.value)?;
    let canonical =
        serde_jcs::to_vec(&gossip.proof).map_err(|_| MembershipRefusal::MalformedEvidence)?;
    let mut message = Vec::with_capacity(GOSSIP_DOMAIN.len() + canonical.len());
    message.extend_from_slice(GOSSIP_DOMAIN);
    message.extend_from_slice(&canonical);
    key.verify(&message, &signature)
        .map_err(|_| MembershipRefusal::InvalidSignature)
}

pub fn sign_gossip(
    membership: &MembershipEnvelope,
    signing_seed: &[u8; 32],
    domain_id: &str,
    payload: &[u8],
    sent_at: u64,
    replay_id: String,
) -> Result<GossipEnvelope, MembershipRefusal> {
    let signing_key = SigningKey::from_bytes(signing_seed);
    if URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes())
        != membership.assertion.subject.public_key_ed25519
    {
        return Err(MembershipRefusal::WrongSubject);
    }
    let proof = GossipProof {
        sender_id: membership.assertion.subject.id.clone(),
        domain_id: domain_id.to_string(),
        sent_at,
        replay_id,
        payload_sha256: format!("{:x}", Sha256::digest(payload)),
        membership_assertion_id: membership.assertion.assertion_id.clone(),
    };
    let canonical = serde_jcs::to_vec(&proof).map_err(|_| MembershipRefusal::MalformedEvidence)?;
    let mut message = Vec::with_capacity(GOSSIP_DOMAIN.len() + canonical.len());
    message.extend_from_slice(GOSSIP_DOMAIN);
    message.extend_from_slice(&canonical);
    let value = URL_SAFE_NO_PAD.encode(signing_key.sign(&message).to_bytes());
    Ok(GossipEnvelope {
        proof,
        signature: DetachedSignature {
            algorithm: "Ed25519".into(),
            key_id: Some(membership.assertion.subject.key_id.clone()),
            value,
        },
    })
}

fn verifying_key(value: &str) -> Result<VerifyingKey, MembershipRefusal> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| MembershipRefusal::MalformedEvidence)?;
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| MembershipRefusal::MalformedEvidence)?;
    VerifyingKey::from_bytes(&raw).map_err(|_| MembershipRefusal::MalformedEvidence)
}

fn signature(value: &str) -> Result<Signature, MembershipRefusal> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| MembershipRefusal::MalformedEvidence)?;
    Signature::from_slice(&bytes).map_err(|_| MembershipRefusal::MalformedEvidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_membership() -> (MembershipPolicy, MembershipEnvelope, [u8; 32]) {
        let authority = SigningKey::from_bytes(&[7u8; 32]);
        let member_seed = [9u8; 32];
        let member = SigningKey::from_bytes(&member_seed);
        let assertion = MembershipAssertion {
            schema: MEMBERSHIP_SCHEMA.into(),
            profile: RESTRICTED_PROFILE.into(),
            assertion_id: "00000000-0000-4000-8000-000000000001".into(),
            domain_id: "domain-a".into(),
            subject: MembershipSubject {
                kind: "node".into(),
                id: "node-a".into(),
                key_id: "node-a#key-1".into(),
                public_key_ed25519: URL_SAFE_NO_PAD.encode(member.verifying_key().to_bytes()),
            },
            issuer: MembershipIssuer {
                id: "directory-a".into(),
                key_id: "directory-a#key-1".into(),
            },
            issued_at: 1_000,
            expires_at: 2_000,
            generation: 3,
            scopes: vec!["bootstrap".into(), "peers".into()],
            audience: vec!["domain-a".into()],
        };
        let canonical = serde_jcs::to_vec(&assertion).unwrap();
        let mut message = MEMBERSHIP_DOMAIN.to_vec();
        message.extend_from_slice(&canonical);
        let envelope = MembershipEnvelope {
            assertion,
            signature: DetachedSignature {
                algorithm: "Ed25519".into(),
                key_id: None,
                value: URL_SAFE_NO_PAD.encode(authority.sign(&message).to_bytes()),
            },
        };
        let policy = MembershipPolicy {
            domain_id: "domain-a".into(),
            authority_id: "directory-a".into(),
            authority_key_id: "directory-a#key-1".into(),
            authority_public_key_ed25519: URL_SAFE_NO_PAD
                .encode(authority.verifying_key().to_bytes()),
            minimum_generation: 3,
            maximum_clock_skew_seconds: 60,
        };
        (policy, envelope, member_seed)
    }

    #[test]
    fn locally_signed_gossip_round_trips_and_binds_payload() {
        let (policy, membership, seed) = signed_membership();
        let payload = br#"{"known_peers":[]}"#;
        let gossip = sign_gossip(
            &membership,
            &seed,
            "domain-a",
            payload,
            1_100,
            "00000000-0000-4000-8000-000000000002".into(),
        )
        .unwrap();
        assert_eq!(
            verify_gossip(&gossip, &membership, &policy, payload, 1_100, false),
            Ok(())
        );
        assert_eq!(
            verify_gossip(&gossip, &membership, &policy, b"tampered", 1_100, false),
            Err(MembershipRefusal::InvalidPayloadBinding)
        );
    }

    #[test]
    fn peer_bundle_rejects_a_key_that_does_not_match_the_assertion() {
        let (policy, membership, _) = signed_membership();
        let bundle = RestrictedPeerBundle {
            policy,
            membership,
            signing_seed_ed25519: URL_SAFE_NO_PAD.encode([8u8; 32]),
            directory_membership_bearer: "secret-bearer".into(),
        };
        assert!(matches!(
            bundle.into_admission("node-a", 1_100),
            Err(MembershipRefusal::WrongSubject)
        ));
    }

    #[test]
    fn peer_bundle_rejects_an_empty_directory_credential() {
        let (policy, membership, seed) = signed_membership();
        let bundle = RestrictedPeerBundle {
            policy,
            membership,
            signing_seed_ed25519: URL_SAFE_NO_PAD.encode(seed),
            directory_membership_bearer: "  ".into(),
        };
        assert!(matches!(
            bundle.into_admission("node-a", 1_100),
            Err(MembershipRefusal::MissingDirectoryCredential)
        ));
    }
}
