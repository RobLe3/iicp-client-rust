use iicp_client::native_response_sequence::{
    NativeResponseFrame, NativeResponseSequence, NativeResponseSequenceError,
};
use serde_json::Value;

fn vectors() -> Vec<Value> {
    let fixture: Value =
        serde_json::from_str(include_str!("../parity/service-profiles-v1.json")).unwrap();
    fixture["lifecycle_vectors"].as_array().unwrap().clone()
}

fn vector(id: &str) -> Value {
    vectors()
        .into_iter()
        .find(|vector| vector["id"] == id)
        .unwrap()
}

fn evaluate(id: &str) -> Result<(), NativeResponseSequenceError> {
    let vector = vector(id);
    let input = &vector["input"];
    let mut sequence = NativeResponseSequence::new(
        input["session_id"].as_str().unwrap(),
        input["call_id"].as_str().unwrap(),
        input["task_id"].as_str().unwrap(),
    );
    for frame in vector["native_frames"].as_array().unwrap() {
        sequence.accept(&serde_json::from_value::<NativeResponseFrame>(frame.clone()).unwrap())?;
    }
    sequence.finish()
}

#[test]
fn accepts_valid_native_sequences() {
    for id in [
        "SERVICE-LIFECYCLE-14",
        "SERVICE-LIFECYCLE-15",
        "SERVICE-LIFECYCLE-16",
    ] {
        assert_eq!(Ok(()), evaluate(id));
    }
}

#[test]
fn rejects_invalid_native_sequences() {
    for (id, code) in [
        ("SERVICE-LIFECYCLE-17", "call_id_drift"),
        ("SERVICE-LIFECYCLE-18", "sequence_drift"),
        ("SERVICE-LIFECYCLE-19", "finality_disagreement"),
        ("SERVICE-LIFECYCLE-20", "response_after_terminal"),
    ] {
        assert_eq!(code, evaluate(id).unwrap_err().code);
    }
}

#[test]
fn rejects_transport_close_before_terminal() {
    let sequence = NativeResponseSequence::new("session", "call", "task");
    assert_eq!(
        "missing_terminal_response",
        sequence.finish().unwrap_err().code
    );
}
