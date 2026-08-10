use iicp_client::native_call_identity::{NativeCallIdentityError, NativeCallIdentityRegistry};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../parity/service-profiles-v1.json")).unwrap()
}

fn calls(vector_id: &str) -> Vec<Value> {
    fixture()["lifecycle_vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["id"] == vector_id)
        .unwrap()["calls"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn accepts_native_call_identity_vectors() {
    for vector_id in ["SERVICE-LIFECYCLE-21", "SERVICE-LIFECYCLE-22"] {
        let mut registry = NativeCallIdentityRegistry::default();
        for call in calls(vector_id) {
            registry.accept(&call).unwrap();
        }
    }
}

#[test]
fn rejects_missing_and_conflicting_task_identity() {
    let mut registry = NativeCallIdentityRegistry::default();
    let errors: Vec<_> = calls("SERVICE-LIFECYCLE-23")
        .iter()
        .filter_map(|call| registry.accept(call).err())
        .collect();
    assert_eq!(
        errors,
        vec![
            NativeCallIdentityError::MissingTaskId,
            NativeCallIdentityError::TaskIdentityConflict,
        ]
    );
}

#[test]
fn unnegotiated_call_does_not_require_task_identity() {
    let mut registry = NativeCallIdentityRegistry::default();
    registry
        .accept(&serde_json::json!({"call_id": "base-call"}))
        .unwrap();
}
