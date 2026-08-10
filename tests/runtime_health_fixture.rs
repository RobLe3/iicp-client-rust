use iicp_client::runtime_health::{classify_input, ClassificationInput, ClassificationOutput};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    scenarios: Vec<Scenario>,
}
#[derive(Deserialize)]
struct Scenario {
    id: String,
    input: ClassificationInput,
    expected: ClassificationOutput,
}

#[test]
fn canonical_runtime_health_scenarios_match() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/runtime-health-v1.json")).unwrap();
    assert_eq!(fixture.scenarios.len(), 12);
    for scenario in fixture.scenarios {
        assert_eq!(
            classify_input(&scenario.input),
            scenario.expected,
            "{}",
            scenario.id
        );
    }
}
