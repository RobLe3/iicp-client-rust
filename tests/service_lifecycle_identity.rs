use iicp_client::service_lifecycle_identity::evaluate_lifecycle_identity;
use serde_json::Value;

#[test]
fn lifecycle_identity_fixture() {
    let fixture: Value =
        serde_json::from_str(include_str!("../parity/service-lifecycle-identity-v1.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        assert_eq!(
            evaluate_lifecycle_identity(case, fixture["audit_retention_seconds"].as_i64().unwrap()),
            case["expected"].as_str().unwrap(),
            "{}",
            case["id"]
        );
    }
}
