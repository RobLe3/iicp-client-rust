// SPDX-License-Identifier: Apache-2.0

use iicp_client::restricted_membership::{
    verify_gossip, verify_membership, GossipEnvelope, MembershipEnvelope, MembershipPolicy,
    MembershipRefusal,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    authority_public_key_ed25519: String,
    vectors: Vec<MembershipVector>,
    gossip_vectors: Vec<GossipVector>,
}

#[derive(Deserialize)]
struct MembershipVector {
    id: String,
    envelope: MembershipEnvelope,
    expected: String,
}

#[derive(Deserialize)]
struct GossipVector {
    id: String,
    membership: MembershipEnvelope,
    gossip: GossipEnvelope,
    payload_utf8: String,
    #[serde(default)]
    seen_replay_ids: Vec<String>,
    expected: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "fixtures/restricted-trust-domain-membership-v0.json"
    ))
    .expect("fixture parses")
}

fn policy(fixture: &Fixture) -> MembershipPolicy {
    MembershipPolicy {
        domain_id: "domain-test-a".into(),
        authority_id: "did:iicp:test:directory-a".into(),
        authority_key_id: "did:iicp:test:directory-a#key-1".into(),
        authority_public_key_ed25519: fixture.authority_public_key_ed25519.clone(),
        minimum_generation: 7,
        maximum_clock_skew_seconds: 60,
    }
}

#[test]
fn canonical_membership_vectors_are_enforced() {
    let fixture = fixture();
    for vector in &fixture.vectors {
        let result = verify_membership(
            &vector.envelope,
            &policy(&fixture),
            "did:iicp:test:node-a",
            "peers",
            1_800_000_010,
        );
        match vector.expected.as_str() {
            "valid" => assert!(result.is_ok(), "{}: {result:?}", vector.id),
            "invalid_signature" => {
                assert_eq!(result, Err(MembershipRefusal::WrongDomain), "{}", vector.id)
            }
            other => panic!("unsupported expected result {other}"),
        }
    }
}

#[test]
fn canonical_gossip_vectors_are_enforced() {
    let fixture = fixture();
    for vector in &fixture.gossip_vectors {
        let seen = vector
            .seen_replay_ids
            .iter()
            .any(|id| id == &vector.gossip.proof.replay_id);
        let result = verify_gossip(
            &vector.gossip,
            &vector.membership,
            &policy(&fixture),
            vector.payload_utf8.as_bytes(),
            1_800_000_010,
            seen,
        );
        match vector.expected.as_str() {
            "valid" => assert!(result.is_ok(), "{}: {result:?}", vector.id),
            "replay_detected" => assert_eq!(
                result,
                Err(MembershipRefusal::ReplayDetected),
                "{}",
                vector.id
            ),
            other => panic!("unsupported expected result {other}"),
        }
    }
}

#[test]
fn stale_generation_and_missing_scope_fail_closed() {
    let fixture = fixture();
    let envelope = fixture.vectors[0].envelope.clone();
    let mut stale_policy = policy(&fixture);
    stale_policy.minimum_generation = 8;
    assert_eq!(
        verify_membership(
            &envelope,
            &stale_policy,
            "did:iicp:test:node-a",
            "peers",
            1_800_000_010,
        ),
        Err(MembershipRefusal::RevokedGeneration)
    );
    assert_eq!(
        verify_membership(
            &envelope,
            &policy(&fixture),
            "did:iicp:test:node-a",
            "cip",
            1_800_000_010,
        ),
        Err(MembershipRefusal::MissingScope)
    );
}
