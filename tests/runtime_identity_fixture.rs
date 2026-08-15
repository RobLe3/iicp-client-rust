use iicp_client::runtime_identity::{
    compose_runtime_identity, RuntimeIdentityInstructionChannel, RuntimeIdentityMode,
    RuntimeIdentityOptions, RUNTIME_IDENTITY_CHAT_INTENT, RUNTIME_IDENTITY_MARKER,
    RUNTIME_IDENTITY_MAX_BYTES,
};
use iicp_client::ChatMessage;
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE_SHA256: &str = "a31064ca630ab5409fb2f57edd1ef29a5c79532b8960927f6a0d2b52d7d71c81";

fn fixture() -> Value {
    serde_json::from_slice(include_bytes!(
        "../parity/runtime-identity-context-v0/fixture.json"
    ))
    .unwrap()
}

fn message(role: &str, content: &str) -> ChatMessage {
    ChatMessage {
        role: role.into(),
        content: content.into(),
    }
}

#[test]
fn exact_shared_fixture_is_pinned() {
    let bytes = include_bytes!("../parity/runtime-identity-context-v0/fixture.json");
    assert_eq!(hex::encode(Sha256::digest(bytes)), FIXTURE_SHA256);
    let fixture = fixture();
    assert_eq!(fixture["context_marker"], RUNTIME_IDENTITY_MARKER);
    assert_eq!(
        fixture["composition"]["eligible_intent"],
        RUNTIME_IDENTITY_CHAT_INTENT
    );
}

#[test]
fn disabled_and_non_chat_messages_are_unchanged() {
    let messages = vec![message("user", "hello")];
    assert!(
        compose_runtime_identity(&messages, RUNTIME_IDENTITY_CHAT_INTENT, None).unwrap()
            != messages
    );
    let disabled = RuntimeIdentityOptions {
        mode: RuntimeIdentityMode::Disabled,
        ..Default::default()
    };
    assert_eq!(
        compose_runtime_identity(&messages, RUNTIME_IDENTITY_CHAT_INTENT, Some(&disabled)).unwrap(),
        messages
    );
    let explicit = RuntimeIdentityOptions {
        mode: RuntimeIdentityMode::Explicit,
        ..Default::default()
    };
    assert_eq!(
        compose_runtime_identity(
            &messages,
            "urn:iicp:intent:llm:embedding:v1",
            Some(&explicit)
        )
        .unwrap(),
        messages
    );
}

#[test]
fn context_follows_leading_instructions_and_precedes_user() {
    let messages = vec![
        message("system", "Answer briefly."),
        message("developer", "Use plain text."),
        message("user", "What is this?"),
    ];
    let options = RuntimeIdentityOptions {
        mode: RuntimeIdentityMode::Explicit,
        ..Default::default()
    };
    let result =
        compose_runtime_identity(&messages, RUNTIME_IDENTITY_CHAT_INTENT, Some(&options)).unwrap();
    assert_eq!(&result[..2], &messages[..2]);
    assert_eq!(result[2].role, "system");
    assert!(result[2].content.contains(RUNTIME_IDENTITY_MARKER));
    assert_eq!(result[3].content, messages[2].content);
}

#[test]
fn existing_marker_suppresses_duplicate() {
    let messages = vec![
        message("system", &format!("[{RUNTIME_IDENTITY_MARKER}] existing")),
        message("user", "hello"),
    ];
    let options = RuntimeIdentityOptions {
        mode: RuntimeIdentityMode::Explicit,
        ..Default::default()
    };
    assert_eq!(
        compose_runtime_identity(&messages, RUNTIME_IDENTITY_CHAT_INTENT, Some(&options)).unwrap(),
        messages
    );
}

#[test]
fn supplied_facts_are_bounded() {
    let options = RuntimeIdentityOptions {
        mode: RuntimeIdentityMode::Explicit,
        selected_model: Some("model-a".into()),
        effective_capabilities: vec!["input_modality:image".into()],
        selection_reason: Some("matched_intent_and_constraints".into()),
        client_name: Some("iicp-client-rust".into()),
        client_version: Some("0.7.105".into()),
        connection_mode: Some(iicp_client::runtime_identity::RuntimeIdentityConnectionMode::Routed),
        ..Default::default()
    };
    let result = compose_runtime_identity(
        &[message("user", "Which model?")],
        RUNTIME_IDENTITY_CHAT_INTENT,
        Some(&options),
    )
    .unwrap();
    assert!(result[0].content.contains("model-a"));
    assert!(result[0].content.contains("input_modality:image"));
    assert!(!result[0].content.contains("candidate set"));
    assert!(result[0].content.len() <= RUNTIME_IDENTITY_MAX_BYTES);
}

#[test]
fn unsupported_channel_degrades_optional_and_refuses_required() {
    let messages = vec![message("user", "hello")];
    let optional = RuntimeIdentityOptions {
        mode: RuntimeIdentityMode::Explicit,
        instruction_channel: RuntimeIdentityInstructionChannel::Unsupported,
        ..Default::default()
    };
    assert_eq!(
        compose_runtime_identity(&messages, RUNTIME_IDENTITY_CHAT_INTENT, Some(&optional)).unwrap(),
        messages
    );
    let required = RuntimeIdentityOptions {
        mode: RuntimeIdentityMode::Required,
        instruction_channel: RuntimeIdentityInstructionChannel::Unsupported,
        ..Default::default()
    };
    assert_eq!(
        compose_runtime_identity(&messages, RUNTIME_IDENTITY_CHAT_INTENT, Some(&required)),
        Err("required_identity_context_unsupported")
    );
}

#[test]
fn default_auto_renders_client_and_rejects_control_character_facts() {
    let options = RuntimeIdentityOptions {
        client_name: Some("iicp-client-rust".into()),
        client_version: Some("0.7.105".into()),
        ..Default::default()
    };
    let result = compose_runtime_identity(
        &[message("user", "What is this?")],
        RUNTIME_IDENTITY_CHAT_INTENT,
        Some(&options),
    )
    .unwrap();
    assert!(result[0]
        .content
        .contains("client: iicp-client-rust 0.7.105"));
    let invalid = RuntimeIdentityOptions {
        selected_model: Some("model\ninjected".into()),
        ..Default::default()
    };
    assert_eq!(
        compose_runtime_identity(
            &[message("user", "hello")],
            RUNTIME_IDENTITY_CHAT_INTENT,
            Some(&invalid),
        ),
        Err("runtime_identity_selected_model_invalid")
    );
}
