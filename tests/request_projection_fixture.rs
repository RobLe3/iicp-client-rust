use std::fs;
use std::path::PathBuf;

use iicp_client::request_projection::project_route_options;
use iicp_client::{ClientConfig, ProfileRequest, RouteConstraints, TaskConstraints, TaskRequest};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn profile(value: Option<&Value>) -> Option<ProfileRequest> {
    value.and_then(|v| {
        if v.is_null() {
            None
        } else {
            Some(ProfileRequest {
                profile_id: v["profile_id"].as_str()?.to_owned(),
                profile_version: v["profile_version"].as_str()?.to_owned(),
                profile_fixture_sha256: v["profile_fixture_sha256"].as_str()?.to_owned(),
                required: v["required"].as_bool().unwrap_or(false),
            })
        }
    })
}

#[test]
fn shared_sdk_request_projection_fixture() {
    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("parity/sdk-request-projection-v0.json");
    let fixture_bytes = fs::read(fixture_path).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&fixture_bytes)),
        "0a89ae1ee02aca25f7989576b0ab88640bf382bf2d13e37e489798c81d010d8c"
    );
    let fixture: Value = serde_json::from_slice(&fixture_bytes).unwrap();

    for case in fixture["cases"].as_array().unwrap() {
        let mut config = ClientConfig::default();
        config.region = case["config"]["region"].as_str().map(str::to_owned);
        config.profile_request = profile(case["config"].get("profile_request"));

        let raw = &case["task"]["constraints"];
        let constraints = TaskConstraints {
            timeout_ms: raw["timeout_ms"].as_u64(),
            max_tokens: None,
            model: raw["model"].as_str().map(str::to_owned),
            qos: raw["qos"].as_str().map(str::to_owned),
            region: raw["region"].as_str().map(str::to_owned),
            min_reputation: raw["min_reputation"].as_f64(),
        };
        let route = case["task"]
            .get("route_constraints")
            .map(|value| RouteConstraints {
                region: value["region"].as_str().map(str::to_owned),
                qos: value["qos"].as_str().map(str::to_owned),
                model: value["model"].as_str().map(str::to_owned),
                min_reputation: value["min_reputation"].as_f64(),
                limit: value["limit"].as_u64().map(|v| v as u32),
                browser_usable_only: value["browser_usable_only"].as_bool(),
                profile_request: profile(value.get("profile_request")),
            });
        let request = TaskRequest {
            task_id: "fixture".into(),
            intent: "urn:iicp:intent:llm:chat:v1".into(),
            payload: json!({}),
            constraints: Some(constraints.clone()),
            route_constraints: route,
            auth: None,
            source_node_id: None,
            routing_policy: None,
        };

        let projected = project_route_options(&request, &config);
        let actual_route = json!({
            "region": projected.region,
            "qos": projected.qos,
            "model": projected.model,
            "min_reputation": projected.min_reputation,
            "browser_usable_only": projected.browser_usable_only.unwrap_or(false),
            "limit": projected.limit.unwrap_or(10),
            "profile_request": projected.profile_request.map(|p| json!({
                "profile_id": p.profile_id,
                "profile_version": p.profile_version,
                "profile_fixture_sha256": p.profile_fixture_sha256,
                "required": p.required,
            })),
        });
        assert_eq!(
            actual_route, case["expected"]["route_options"],
            "{}",
            case["name"]
        );

        let execution = serde_json::to_value(constraints).unwrap();
        assert_eq!(
            execution, case["expected"]["execution_constraints"],
            "{}",
            case["name"]
        );
    }
}
