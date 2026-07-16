use iicp_client::service_lifecycle_accounting::decide_lifecycle_accounting;
use serde_json::Value;

#[test]
fn service_lifecycle_accounting_fixture() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../parity/service-lifecycle-accounting-v1.json"
    ))
    .expect("fixture JSON");
    for case in fixture["cases"].as_array().expect("cases") {
        let decision = decide_lifecycle_accounting(&case["input"]);
        let expected = &case["expected"];
        assert_eq!(decision.decision, expected["decision"].as_str().unwrap());
        assert_eq!(
            decision.reservation_action,
            expected["reservation_action"].as_str().unwrap()
        );
        assert_eq!(
            decision.settlement_action,
            expected["settlement_action"].as_str().unwrap()
        );
        assert_eq!(
            decision.new_execution,
            expected["new_execution"].as_bool().unwrap()
        );
    }
}

#[test]
fn invalid_input_fails_closed() {
    let decision = decide_lifecycle_accounting(&serde_json::json!({"operation": "settle"}));
    assert_eq!(decision.decision, "reject_invalid_input");
    assert!(!decision.new_execution);
}
