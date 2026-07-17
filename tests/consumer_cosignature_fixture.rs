use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use iicp_client::jcs::canonicalize_jcs;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"IICP-CIP-CONSUMER-COSIGNATURE-V1\0";

fn pre_signature_refusal(v: &Value) -> Option<Value> {
    let s = |key: &str| v[key].as_str().unwrap();
    if s("binding") != "match" {
        let reason = match s("binding") {
            "response_hash_mismatch" => "response_hash_mismatch",
            "cost_mismatch" => "cost_mismatch",
            _ => "receipt_binding_mismatch",
        };
        return Some(json!({"action":"refuse_signing","reason":reason,"trust_weight":"0.0"}));
    }
    if s("consumer_key") == "revoked" {
        return Some(
            json!({"action":"reject","reason":"consumer_key_revoked","trust_weight":"0.0"}),
        );
    }
    if s("consumer_key") == "rotated_outside_validity" {
        return Some(
            json!({"action":"reject","reason":"consumer_key_not_valid_at_completion","trust_weight":"0.0"}),
        );
    }
    if s("time") != "valid" {
        return Some(json!({"action":"reject","reason":"receipt_expired","trust_weight":"0.0"}));
    }
    if s("nonce") != "fresh" {
        return Some(
            json!({"action":"reject","reason":"dispatch_nonce_replayed","trust_weight":"0.0"}),
        );
    }
    None
}

fn signature_refusal(v: &Value) -> Option<Value> {
    let s = |key: &str| v[key].as_str().unwrap();
    if s("provider_signature") != "valid" {
        return Some(
            json!({"action":"reject","reason":"provider_signature_invalid","trust_weight":"0.0"}),
        );
    }
    if s("consumer_signature") != "valid" {
        if s("consumer_signature") == "missing" && s("mode") == "optional" {
            return Some(
                json!({"action":"accept_legacy","reason":"consumer_signature_missing_optional","trust_weight":"0.0"}),
            );
        }
        let reason = if s("consumer_signature") == "missing" {
            "consumer_signature_required"
        } else {
            "consumer_signature_invalid"
        };
        return Some(json!({"action":"reject","reason":reason,"trust_weight":"0.0"}));
    }
    None
}

fn evaluate(v: &Value) -> Value {
    if let Some(refusal) = pre_signature_refusal(v).or_else(|| signature_refusal(v)) {
        return refusal;
    }
    let s = |key: &str| v[key].as_str().unwrap();
    if s("relationship") == "same_node" {
        return json!({"action":"exclude","reason":"self_node","trust_weight":"0.0"});
    }
    if s("relationship") == "same_operator" {
        return json!({"action":"exclude","reason":"self_operator","trust_weight":"0.0"});
    }
    json!({"action":"accept","reason":"cosignature_verified","trust_weight":"1.0"})
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("../parity/cip-consumer-cosignature-v1.json")).unwrap()
}

fn verify_canonical_vector(vector: &Value) {
    let canonical = canonicalize_jcs(&vector["receipt"]).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&canonical),
        vector["canonical_json_utf8"].as_str().unwrap()
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&canonical)),
        vector["canonical_json_sha256"]
    );
    let digest = Sha256::digest([DOMAIN, canonical.as_slice()].concat());
    assert_eq!(format!("{digest:x}"), vector["receipt_digest_hex"]);

    for role in ["provider", "consumer"] {
        let public: [u8; 32] = URL_SAFE_NO_PAD
            .decode(
                vector[format!("{role}_public_key_b64url")]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap();
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(vector[format!("{role}_signature_b64url")].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        VerifyingKey::from_bytes(&public)
            .unwrap()
            .verify(&digest, &signature)
            .unwrap();
    }
}

fn verify_semantic_cases(data: &Value) {
    for case in data["conformance_cases"].as_array().unwrap() {
        assert_eq!(
            evaluate(&case["input"]),
            case["expected"],
            "{}",
            case["name"]
        );
    }
}

fn verify_settlement_cases(data: &Value) {
    for case in data["settlement_cases"].as_array().unwrap() {
        let input = &case["input"];
        let actual = if input["reservation"] != "held" {
            json!({"action":"refuse_dispatch","awards":0,"debits":0})
        } else if matches!(
            input["outcome"].as_str(),
            Some("timeout" | "cancelled" | "partial")
        ) {
            json!({"action":"release","awards":0,"debits":0})
        } else {
            json!({"action":"settle_once","awards":1,"debits":1})
        };
        assert_eq!(actual, case["expected"], "{}", case["name"]);
    }
}

fn verify_privacy_contract(data: &Value) {
    let vector = &data["canonical_vector"];
    let receipt_fields = vector["receipt"].as_object().unwrap();
    for forbidden in data["privacy_contract"]["forbidden_fields"]
        .as_array()
        .unwrap()
    {
        assert!(!receipt_fields.contains_key(forbidden.as_str().unwrap()));
    }
    assert_eq!(
        data["privacy_contract"]["self_reported_metrics_have_authority"],
        false
    );
}

#[test]
fn consumer_cosignature_fixture_is_portable() {
    let data = fixture();
    verify_canonical_vector(&data["canonical_vector"]);
    verify_semantic_cases(&data);
    verify_settlement_cases(&data);
    verify_privacy_contract(&data);
}

#[test]
fn full_jcs_vectors_and_unsafe_integers_fail_closed() {
    let data = fixture();
    for vector in data["jcs_vectors"].as_array().unwrap() {
        let canonical = canonicalize_jcs(&vector["input"]).unwrap();
        assert_eq!(
            String::from_utf8(canonical).unwrap(),
            vector["canonical_json_utf8"]
        );
    }
    assert!(canonicalize_jcs(&json!({"invalid": 9_007_199_254_740_992_u64})).is_err());
}
