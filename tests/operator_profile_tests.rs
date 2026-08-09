use iicp_client::operator_profile::{evaluate_managed_operator, ManagedOperatorInput};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    input: ManagedOperatorInput,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    accepted: bool,
    reason: String,
}

#[test]
fn managed_operator_decisions_match_shared_vectors() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/managed-operator-v1.json")).unwrap();
    for vector in fixture.vectors {
        let actual = evaluate_managed_operator(&vector.input);
        assert_eq!(
            (vector.expected.accepted, vector.expected.reason.as_str()),
            actual,
            "{}",
            vector.name
        );
    }
}
