use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use std::collections::BTreeMap;

fn canonical(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let sorted = map.iter().collect::<BTreeMap<_, _>>();
            let fields = sorted
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap(),
                        canonical(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{fields}}}")
        }
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        _ => serde_json::to_string(value).unwrap(),
    }
}

fn decision(vector: &Value, keys: &BTreeMap<&str, &Value>, signature_valid: bool) -> &'static str {
    let key_id = vector["claims"]["key_id"].as_str().unwrap();
    let trusted = vector["trust_bundle_key_ids"]
        .as_array()
        .unwrap()
        .iter()
        .any(|candidate| candidate == key_id);
    if !trusted {
        return "reject_unknown_key";
    }
    let key = keys[key_id];
    if key["state"] == "revoked" {
        return "reject_key_revoked";
    }
    let now = vector["now"].as_u64().unwrap();
    if now < key["valid_from"].as_u64().unwrap() || now > key["valid_until"].as_u64().unwrap() {
        return "reject_key_expired";
    }
    if !signature_valid {
        return "reject_signature";
    }
    if vector["jti_seen"].as_bool().unwrap() {
        return "reject_local_replay";
    }
    "accept_anchored"
}

#[test]
fn dispatch_ticket_v2_signed_vectors_are_portable() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../parity/dispatch-ticket-trust-v2-crypto.json"
    ))
    .unwrap();
    let domain = URL_SAFE_NO_PAD
        .decode(fixture["domain_separator_b64url"].as_str().unwrap())
        .unwrap();
    let keys = fixture["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| (key["key_id"].as_str().unwrap(), key))
        .collect::<BTreeMap<_, _>>();

    for vector in fixture["vectors"].as_array().unwrap() {
        let key = keys[vector["claims"]["key_id"].as_str().unwrap()];
        let public_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(key["public_key_b64url"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let verifier = VerifyingKey::from_bytes(&public_bytes).unwrap();
        let signature_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(vector["signature_b64url"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let signature = Signature::from_bytes(&signature_bytes);
        let mut message = domain.clone();
        message.extend_from_slice(canonical(&vector["claims"]).as_bytes());
        let signature_valid = verifier.verify(&message, &signature).is_ok();
        assert_eq!(
            signature_valid,
            vector["expected_signature_valid"].as_bool().unwrap(),
            "{}",
            vector["id"]
        );
        assert_eq!(
            decision(vector, &keys, signature_valid),
            vector["expected"].as_str().unwrap(),
            "{}",
            vector["id"]
        );
    }
}
