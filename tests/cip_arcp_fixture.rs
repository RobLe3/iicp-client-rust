use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

fn cip(value: &Value) -> Value {
    let replicas = value["replicas"].as_i64().unwrap_or(-1);
    if !(1..=10).contains(&replicas) {
        return json!({"envelope":"reject","execution":"reject","error":"IICP-E028"});
    }
    let quorum = value.get("quorum").and_then(Value::as_i64);
    if value.get("quorum").is_some_and(|v| !v.is_null())
        && quorum.is_none_or(|q| q < 1 || q > replicas)
    {
        return json!({"envelope":"reject","execution":"reject","error":"IICP-E028"});
    }
    let mut out = Map::from_iter([("envelope".into(), json!("accept"))]);
    if value["sensitivity"] == "high" && value["send_sensitive_prompts"] != true {
        out.extend([
            ("execution".into(), json!("local")),
            ("remote_eligible".into(), json!(false)),
        ]);
        return Value::Object(out);
    }
    let intent = value["intent"].as_str().unwrap_or("");
    if intent.starts_with("urn:iicp:intent:mcp:") || intent.starts_with("urn:iicp:intent:tool:") {
        out.extend([
            ("execution".into(), json!("reject")),
            ("remote_eligible".into(), json!(false)),
        ]);
        return Value::Object(out);
    }
    let operator_max = value["operator_max_replicas"]
        .as_i64()
        .unwrap_or(10)
        .clamp(1, 10);
    match value["policy"].as_str().unwrap_or("") {
        "" if replicas == 1 => out.extend([
            ("execution".into(), json!("accept")),
            ("quorum".into(), Value::Null),
        ]),
        "" => out.extend([
            ("execution".into(), json!("reject")),
            ("error".into(), json!("IICP-E028")),
        ]),
        "best_of_n" if replicas >= 2 && replicas <= operator_max => out.extend([
            ("execution".into(), json!("accept")),
            ("quorum".into(), Value::Null),
        ]),
        "best_of_n" => out.extend([
            ("execution".into(), json!("reject")),
            ("error".into(), json!("IICP-E028")),
        ]),
        "majority_vote" if replicas < 3 || replicas % 2 == 0 => out.extend([
            ("execution".into(), json!("reject")),
            ("error".into(), json!("IICP-E025")),
        ]),
        "majority_vote" if replicas > operator_max => out.extend([
            ("execution".into(), json!("reject")),
            ("error".into(), json!("IICP-E028")),
        ]),
        "majority_vote" => out.extend([
            ("execution".into(), json!("accept")),
            ("quorum".into(), json!(quorum.unwrap_or(replicas / 2 + 1))),
        ]),
        "map_reduce"
            if !value["implemented_modes"]
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v == "map_reduce")) =>
        {
            out.extend([
                ("execution".into(), json!("unsupported")),
                ("advertise".into(), json!(false)),
            ])
        }
        _ => out.extend([
            ("execution".into(), json!("reject")),
            ("error".into(), json!("IICP-E028")),
        ]),
    }
    Value::Object(out)
}

fn schema_valid(value: &Value, schema: &Value) -> bool {
    let type_ok = match schema["type"].as_str() {
        Some("object") => value.is_object(),
        Some("array") => value.is_array(),
        Some("string") => value.is_string(),
        Some("integer") => value.is_i64() || value.is_u64(),
        Some("number") => value.is_number(),
        Some("boolean") => value.is_boolean(),
        _ => true,
    };
    if !type_ok {
        return false;
    }
    if let Some(object) = value.as_object() {
        let properties = schema["properties"].as_object();
        if schema["required"].as_array().is_some_and(|required| {
            required
                .iter()
                .any(|k| !object.contains_key(k.as_str().unwrap_or("")))
        }) {
            return false;
        }
        if schema["additionalProperties"] == false
            && object
                .keys()
                .any(|k| !properties.is_some_and(|p| p.contains_key(k)))
        {
            return false;
        }
        if properties.is_some_and(|p| {
            p.iter()
                .any(|(k, s)| object.get(k).is_some_and(|v| !schema_valid(v, s)))
        }) {
            return false;
        }
    }
    if let Some(number) = value.as_f64() {
        if number < schema["minimum"].as_f64().unwrap_or(f64::NEG_INFINITY)
            || number > schema["maximum"].as_f64().unwrap_or(f64::INFINITY)
        {
            return false;
        }
    }
    true
}

fn evaluate(case: &Value) -> Value {
    let candidate = &case["candidate"];
    let (passed, score) = match case["evaluator"].as_str().unwrap() {
        "exact_match" => {
            let actual: String = candidate.as_str().unwrap().trim().nfc().collect();
            let expected: String = case["expected_value"]
                .as_str()
                .unwrap()
                .trim()
                .nfc()
                .collect();
            (
                actual == expected,
                if actual == expected { 1.0 } else { 0.0 },
            )
        }
        "numeric_tolerance" => {
            let actual: f64 = candidate.as_str().unwrap().parse().unwrap();
            let expected: f64 = case["expected_value"].as_str().unwrap().parse().unwrap();
            let abs: f64 = case["absolute_tolerance"]
                .as_str()
                .unwrap_or("0")
                .parse()
                .unwrap();
            let rel: f64 = case["relative_tolerance"]
                .as_str()
                .unwrap_or("0")
                .parse()
                .unwrap();
            let ok = (actual - expected).abs() <= abs.max(expected.abs() * rel);
            (ok, if ok { 1.0 } else { 0.0 })
        }
        "json_schema_subset" => {
            let ok = schema_valid(candidate, &case["schema"]);
            (ok, if ok { 1.0 } else { 0.0 })
        }
        "constraints" => {
            let ok = case["constraints"].as_array().unwrap().iter().all(|c| {
                let actual = &candidate[c["path"].as_str().unwrap()];
                match c["op"].as_str().unwrap() {
                    "equals" => actual == &c["value"],
                    "in" => c["value"].as_array().unwrap().contains(actual),
                    "min_items" => actual
                        .as_array()
                        .is_some_and(|a| a.len() >= c["value"].as_u64().unwrap() as usize),
                    "max_items" => actual
                        .as_array()
                        .is_some_and(|a| a.len() <= c["value"].as_u64().unwrap() as usize),
                    _ => false,
                }
            });
            (ok, if ok { 1.0 } else { 0.0 })
        }
        "unit_test_summary" => {
            let passed_count = candidate["passed"].as_u64().unwrap();
            let failed = candidate["failed"].as_u64().unwrap();
            let total = passed_count + failed;
            (
                total > 0
                    && failed == 0
                    && candidate["suite_digest"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty()),
                if total > 0 {
                    passed_count as f64 / total as f64
                } else {
                    0.0
                },
            )
        }
        other => panic!("unsupported evaluator {other}"),
    };
    json!({"passed":passed,"score":(score * 1_000_000.0_f64).round() / 1_000_000.0})
}

fn coordinator_transcript(case: &Value) -> Value {
    use std::collections::BTreeSet;
    let mut dispatched = BTreeSet::new();
    let mut results = BTreeSet::new();
    let mut terminal = "running";
    let mut settlement = "release_unspent";
    let mut duplicates = 0_u64;
    for event in case["events"].as_array().unwrap() {
        let kind = event["type"].as_str().unwrap();
        let worker = event["worker"].as_str().unwrap_or("");
        match kind {
            "dispatch" if terminal == "running" => {
                dispatched.insert(worker);
            }
            "duplicate_result" => duplicates += 1,
            "result"
                if terminal == "running"
                    && dispatched.contains(worker)
                    && !results.contains(worker) =>
            {
                if event["attribution"] == "same_operator" {
                    settlement = "exclude_self_dealing";
                    continue;
                }
                results.insert(worker);
                if results.len() as u64 >= case["quorum"].as_u64().unwrap() {
                    terminal = "completed";
                    settlement = "settle_contributors";
                }
            }
            "cancel" if terminal == "running" => terminal = "cancelled",
            "timeout" if terminal == "running" => {
                terminal = if case["strict_replicas"] == true {
                    "local_fallback"
                } else {
                    "failed"
                };
            }
            "coordinator_failure" if terminal == "running" => terminal = "failed",
            _ => {}
        }
    }
    json!({"terminal":terminal,"counted_results":results.len(),"duplicates_ignored":duplicates,"settlement":settlement})
}

#[test]
fn cip_fixture_is_portable() {
    let data: Value =
        serde_json::from_str(include_str!("../parity/cip-conformance-v0.json")).unwrap();
    for case in data["cases"].as_array().unwrap() {
        assert_eq!(cip(&case["input"]), case["expected"], "{}", case["name"]);
    }
    let v = &data["canonical_receipt_vectors"][0];
    assert_eq!(
        hex::encode(Sha256::digest(
            v["canonical_result_json"].as_str().unwrap().as_bytes()
        )),
        v["response_hash"]
    );
    let mut mac =
        Hmac::<Sha256>::new_from_slice(v["hmac_key_utf8"].as_str().unwrap().as_bytes()).unwrap();
    mac.update(v["canonical_message"].as_str().unwrap().as_bytes());
    assert_eq!(
        hex::encode(mac.finalize().into_bytes()),
        v["signature_hmac_sha256"]
    );
}

#[test]
fn evaluator_fixture_is_portable() {
    let data: Value =
        serde_json::from_str(include_str!("../parity/arcp-evaluator-v0.json")).unwrap();
    for case in data["cases"].as_array().unwrap() {
        assert_eq!(evaluate(case), case["expected"], "{}", case["name"]);
    }
}

#[test]
fn coordinator_transcript_fixture_is_portable() {
    let data: Value = serde_json::from_str(include_str!(
        "../parity/arcp-coordinator-transcript-v0.json"
    ))
    .unwrap();
    assert_eq!(data["status"], "pre-normative");
    for case in data["cases"].as_array().unwrap() {
        assert_eq!(
            coordinator_transcript(case),
            case["expected"],
            "{}",
            case["name"]
        );
    }
}
