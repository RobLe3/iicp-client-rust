// SPDX-License-Identifier: Apache-2.0
//! Lean model-visible IICP runtime identity context for compatible chat calls.

use crate::ChatMessage;

pub const RUNTIME_IDENTITY_PROFILE_ID: &str = "urn:iicp:profile:runtime-identity-context:v0";
pub const RUNTIME_IDENTITY_MARKER: &str = "IICP-RUNTIME-CONTEXT/1";
pub const RUNTIME_IDENTITY_CHAT_INTENT: &str = "urn:iicp:intent:llm:chat:v1";
pub const RUNTIME_IDENTITY_MAX_BYTES: usize = 2048;
const MAX_FACT_BYTES: usize = 160;
const MAX_CAPABILITIES: usize = 32;

const BASE_CAPSULE: &str = "This request reached you through IICP, the Intent-based Inter-agent Communication Protocol. IICP discovers eligible services and routes requests. You are the selected model or service, not IICP. When asked about this connection, use only supplied runtime facts; do not guess missing facts.";
const SELECTION_TEXT: [(&str, &str); 5] = [
    (
        "matched_intent_and_constraints",
        "This service matched the requested intent and constraints.",
    ),
    (
        "explicit_model_match",
        "This service matched the requested model and constraints.",
    ),
    (
        "fallback_after_unavailable_candidate",
        "This service was selected after an earlier candidate was unavailable.",
    ),
    (
        "intentional_exploration",
        "This service was selected for an intentional routing exploration.",
    ),
    (
        "local_browser_execution",
        "This model is running locally in the browser.",
    ),
];
const CONNECTION_TEXT: [&str; 2] = [
    "routed through IICP to an eligible provider.",
    "This model is running locally in the browser; no remote IICP provider was selected.",
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RuntimeIdentityMode {
    #[default]
    Auto,
    Disabled,
    Explicit,
    Required,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RuntimeIdentityInstructionChannel {
    #[default]
    System,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum RuntimeIdentityConnectionMode {
    Routed,
    LocalBrowser,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeIdentityOptions {
    pub mode: RuntimeIdentityMode,
    pub instruction_channel: RuntimeIdentityInstructionChannel,
    pub selected_model: Option<String>,
    pub effective_capabilities: Vec<String>,
    pub selection_reason: Option<String>,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub connection_mode: Option<RuntimeIdentityConnectionMode>,
}

pub fn with_runtime_facts(
    options: Option<RuntimeIdentityOptions>,
    client_name: &str,
    client_version: &str,
    connection_mode: RuntimeIdentityConnectionMode,
    selected_model: Option<String>,
    effective_capabilities: Vec<String>,
    selection_reason: &str,
) -> RuntimeIdentityOptions {
    let mut resolved = options.unwrap_or_default();
    resolved.client_name = Some(client_name.into());
    resolved.client_version = Some(client_version.into());
    resolved.connection_mode = Some(connection_mode);
    resolved.selected_model = selected_model;
    resolved.effective_capabilities = effective_capabilities;
    resolved.selection_reason = Some(selection_reason.into());
    resolved
}

fn bounded_fact<'a>(value: &'a str, invalid_code: &'static str) -> Result<&'a str, &'static str> {
    (!value.is_empty()).then_some(()).ok_or(invalid_code)?;
    value
        .chars()
        .all(|ch| !ch.is_control())
        .then_some(())
        .ok_or(invalid_code)?;
    (value.len() <= MAX_FACT_BYTES)
        .then_some(value)
        .ok_or("runtime_identity_fact_too_large")
}

fn append_client_fact(
    lines: &mut Vec<String>,
    options: &RuntimeIdentityOptions,
) -> Result<(), &'static str> {
    (options.client_name.is_some() == options.client_version.is_some())
        .then_some(())
        .ok_or("runtime_identity_client_incomplete")?;
    let rendered = options
        .client_name
        .iter()
        .zip(options.client_version.iter())
        .map(|(name, version)| {
            Ok(format!(
                "- client: {} {}",
                bounded_fact(name, "runtime_identity_client_invalid")?,
                bounded_fact(version, "runtime_identity_client_invalid")?
            ))
        })
        .collect::<Result<Vec<_>, &'static str>>()?;
    lines.extend(rendered);
    Ok(())
}

fn append_connection_fact(lines: &mut Vec<String>, options: &RuntimeIdentityOptions) {
    lines.extend(
        options
            .connection_mode
            .map(|mode| format!("- connection: {}", CONNECTION_TEXT[mode as usize])),
    );
}

fn append_capability_fact(
    lines: &mut Vec<String>,
    options: &RuntimeIdentityOptions,
) -> Result<(), &'static str> {
    (options.effective_capabilities.len() <= MAX_CAPABILITIES)
        .then_some(())
        .ok_or("runtime_identity_effective_capabilities_too_many")?;
    let capabilities = options
        .effective_capabilities
        .iter()
        .map(|value| bounded_fact(value, "runtime_identity_effective_capability_invalid"))
        .collect::<Result<Vec<_>, _>>()?;
    lines.extend(
        (!capabilities.is_empty())
            .then(|| format!("- effective capabilities: {}", capabilities.join(", "))),
    );
    Ok(())
}

fn selection_text(reason: Option<&str>) -> Result<Option<&'static str>, &'static str> {
    let Some(reason) = reason else {
        return Ok(None);
    };
    SELECTION_TEXT
        .iter()
        .find_map(|(value, text)| (*value == reason).then_some(Some(*text)))
        .ok_or("runtime_identity_selection_reason_invalid")
}

pub fn render_runtime_identity(
    intent: &str,
    options: &RuntimeIdentityOptions,
) -> Result<String, &'static str> {
    let mut lines = vec![
        format!("[{RUNTIME_IDENTITY_MARKER}]"),
        BASE_CAPSULE.to_string(),
        "Runtime facts:".to_string(),
        format!(
            "- intent: {}",
            bounded_fact(intent, "runtime_identity_fact_invalid")?
        ),
    ];
    append_client_fact(&mut lines, options)?;
    append_connection_fact(&mut lines, options);
    if let Some(model) = &options.selected_model {
        lines.push(format!(
            "- selected model: {}",
            bounded_fact(model, "runtime_identity_selected_model_invalid")?
        ));
    }
    append_capability_fact(&mut lines, options)?;
    if let Some(selection) = selection_text(options.selection_reason.as_deref())? {
        lines.push(format!("- selection: {selection}"));
    }
    let rendered = lines.join("\n");
    if rendered.len() > RUNTIME_IDENTITY_MAX_BYTES {
        return Err("runtime_identity_context_too_large");
    }
    Ok(rendered)
}

pub fn compose_runtime_identity(
    messages: &[ChatMessage],
    intent: &str,
    options: Option<&RuntimeIdentityOptions>,
) -> Result<Vec<ChatMessage>, &'static str> {
    let default_options = RuntimeIdentityOptions::default();
    let options = options.unwrap_or(&default_options);
    if options.mode == RuntimeIdentityMode::Disabled || intent != RUNTIME_IDENTITY_CHAT_INTENT {
        return Ok(messages.to_vec());
    }
    if options.instruction_channel == RuntimeIdentityInstructionChannel::Unsupported {
        if options.mode == RuntimeIdentityMode::Required {
            return Err("required_identity_context_unsupported");
        }
        return Ok(messages.to_vec());
    }
    if messages.iter().any(|message| {
        matches!(message.role.as_str(), "system" | "developer")
            && message.content.contains(RUNTIME_IDENTITY_MARKER)
    }) {
        return Ok(messages.to_vec());
    }

    let insertion = messages
        .iter()
        .take_while(|message| matches!(message.role.as_str(), "system" | "developer"))
        .count();
    let mut result = Vec::with_capacity(messages.len() + 1);
    result.extend_from_slice(&messages[..insertion]);
    result.push(ChatMessage {
        role: "system".into(),
        content: render_runtime_identity(intent, options)?,
    });
    result.extend_from_slice(&messages[insertion..]);
    Ok(result)
}
