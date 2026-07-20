use serde_json::Value;
use std::collections::HashSet;

#[test]
fn consumer_cosignature_transcript_is_content_free_and_fail_closed() {
    let data: Value = serde_json::from_str(include_str!(
        "../parity/cip-consumer-cosignature-transcript-v1.json"
    ))
    .unwrap();
    let messages: Vec<&Value> = data["transcript"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| &step["message"])
        .collect();
    let types: Vec<&str> = messages
        .iter()
        .map(|message| message["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        types,
        ["receipt_offer", "receipt_acceptance", "settlement_request"]
    );
    let digests: HashSet<&str> = messages
        .iter()
        .map(|message| message["receipt_digest_hex"].as_str().unwrap())
        .collect();
    assert_eq!(digests.len(), 1);
    assert_eq!(data["privacy_contract"]["content_free"], true);
    let rendered = serde_json::to_string(&data).unwrap();
    for field in data["privacy_contract"]["forbidden_fields"]
        .as_array()
        .unwrap()
    {
        assert!(!rendered.contains(&format!("\"{}\":", field.as_str().unwrap())));
    }
    let modes = data["transition_modes"].as_array().unwrap();
    assert!(modes
        .iter()
        .all(|mode| mode["strict_enforcement_authorized"] == false));
    assert_eq!(
        modes
            .iter()
            .find(|mode| mode["mode"] == "required")
            .unwrap()["runtime_status"],
        "unavailable"
    );
}
