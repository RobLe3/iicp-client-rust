use std::process::Command;

#[test]
fn blank_systemd_operator_record_is_valid_but_not_evidence() {
    let output = Command::new("python3")
        .args(["scripts/check_systemd_operator_validation.py"])
        .output()
        .expect("validator should execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let record: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string("evidence/systemd-operator-validation-v1.json").unwrap(),
    )
    .unwrap();
    assert_eq!(record["result_present"], false);
    assert_eq!(
        record["claim_boundary"]["authorizes_default_enablement"],
        false
    );
}
