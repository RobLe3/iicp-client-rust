use iicp_client::policy_operational_evidence::evaluate_policy_operational_evidence;
use serde_json::Value;

#[test]
fn policy_operational_evidence_fixture() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../parity/policy-operational-evidence-v0.json"
    ))
    .unwrap();
    let evaluated_at = fixture["evaluated_at"].as_str().unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let decision = evaluate_policy_operational_evidence(
            &case["requirement"],
            &case["context"],
            evaluated_at,
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
