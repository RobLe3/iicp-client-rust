use iicp_client::policy_detail_disclosure::{
    evaluate_policy_detail_disclosure, verify_policy_detail_consumer_token, ALLOWED_DETAIL_FIELDS,
};
use serde_json::Value;

#[test]
fn policy_detail_disclosure_fixture() {
    let fixture: Value =
        serde_json::from_str(include_str!("../parity/policy-detail-disclosure-v0.json")).unwrap();
    assert_eq!(
        fixture["allowed_detail_fields"],
        serde_json::json!(ALLOWED_DETAIL_FIELDS)
    );
    for case in fixture["cases"].as_array().unwrap() {
        let result = evaluate_policy_detail_disclosure(&case["context"]);
        assert_eq!(
            result.status,
            case["expected"]["status"].as_u64().unwrap() as u16,
            "{}",
            case["id"]
        );
        assert_eq!(
            result.reason,
            case["expected"]["reason"].as_str().unwrap(),
            "{}",
            case["id"]
        );
        if result.status == 200 {
            let encoded = serde_json::to_string(&result.body).unwrap();
            for forbidden in [
                "must-not-leak",
                "private.example",
                "backend_topology",
                "natural_person_contact",
            ] {
                assert!(!encoded.contains(forbidden));
            }
        }
    }
}

#[test]
fn self_asserted_authentication_is_invalid() {
    let result = evaluate_policy_detail_disclosure(&serde_json::json!({
        "consumer_auth": "self_asserted",
        "disclosure_allowed": true
    }));
    assert_eq!(
        (result.status, result.reason.as_str()),
        (401, "consumer_auth_invalid")
    );
}

#[test]
fn consumer_token_crypto_vectors() {
    let fixture: Value =
        serde_json::from_str(include_str!("../parity/policy-detail-disclosure-v0.json")).unwrap();
    let v = &fixture["crypto_vectors"];
    let verify = |token: &str| {
        verify_policy_detail_consumer_token(
            token,
            v["public_key_hex"].as_str().unwrap(),
            v["expected_target_node_id"].as_str().unwrap(),
            v["expected_intent"].as_str().unwrap(),
            v["evaluated_at_unix"].as_i64().unwrap(),
        )
    };
    let valid = verify(v["valid_consumer_token"].as_str().unwrap());
    assert_eq!(valid.status, "valid");
    assert_eq!(valid.claims.unwrap()["sub"], v["expected_subject"]);
    assert_eq!(
        verify(v["expired_consumer_token"].as_str().unwrap()).status,
        "expired"
    );
    assert_eq!(
        verify(v["tampered_consumer_token"].as_str().unwrap()).status,
        "invalid"
    );
}
