use std::fs;
use std::path::PathBuf;

use iicp_client::iicp_tcp::{decode_frame, encode_frame, MsgType, FRAME_HEADER_LEN};
use serde_json::Value;

fn fixture() -> Value {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native-framing-v1.json");
    serde_json::from_str(&fs::read_to_string(path).expect("read native framing fixture"))
        .expect("parse native framing fixture")
}

#[test]
fn native_frame_decoder_matches_canonical_implementation_backed_vectors() {
    let fixture = fixture();
    assert_eq!(
        fixture["frame"]["header_bytes"].as_u64(),
        Some(FRAME_HEADER_LEN as u64)
    );

    for scenario in fixture["scenarios"].as_array().expect("scenario array") {
        let name = scenario["name"].as_str().expect("scenario name");
        let wire = hex::decode(scenario["wire_hex"].as_str().expect("wire hex")).expect("hex");
        let expected = &scenario["expected"];
        if expected["outcome"] == "accept" {
            let (frame, consumed) = decode_frame(&wire)
                .unwrap_or_else(|error| panic!("{name}: expected acceptance, got {error}"));
            assert_eq!(
                frame.version,
                expected["version"].as_u64().unwrap() as u8,
                "{name}"
            );
            assert_eq!(
                frame.msg_type,
                expected["message_type"].as_u64().unwrap() as u8,
                "{name}"
            );
            assert_eq!(
                frame.flags,
                expected["flags"].as_u64().unwrap() as u8,
                "{name}"
            );
            assert_eq!(
                frame.payload,
                hex::decode(expected["payload_hex"].as_str().unwrap()).unwrap(),
                "{name}"
            );
            assert_eq!(
                consumed,
                expected["consumed"].as_u64().unwrap() as usize,
                "{name}"
            );
        } else {
            let error = decode_frame(&wire).expect_err("fixture must reject");
            let expected_text = match expected["reason"].as_str().unwrap() {
                "invalid_magic" => "Invalid IICP magic",
                "truncated_header" => "frame too short",
                "truncated_payload" => "payload truncated",
                other => panic!("{name}: unsupported expected reason {other}"),
            };
            assert!(error.contains(expected_text), "{name}: {error}");
        }
    }
}

#[test]
fn native_frame_encoder_emits_the_canonical_empty_ping_vector() {
    let fixture = fixture();
    let scenario = fixture["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["name"] == "ping_empty")
        .unwrap();
    assert_eq!(
        encode_frame(MsgType::Ping as u8, &[], 0),
        hex::decode(scenario["wire_hex"].as_str().unwrap()).unwrap()
    );
}
