use iicp_client::policy_data_handling::evaluate_policy_data_handling;
use serde_json::Value;
#[test]
fn shared_policy_data_handling_vectors() {
    let fixture: Value =
        serde_json::from_str(include_str!("../parity/policy-data-handling-v0.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let decision = evaluate_policy_data_handling(
            &case["requirement"],
            &case["declaration"],
            case.get("context").unwrap_or(&Value::Null),
        );
        let expected = case["expected"].as_str().unwrap();
        assert_eq!(decision.reason, expected, "{}", case["id"]);
        assert_eq!(
            decision.eligible,
            expected == "compatible",
            "{}",
            case["id"]
        );
    }
}
