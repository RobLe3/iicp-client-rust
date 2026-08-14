// SPDX-License-Identifier: Apache-2.0
//! Opt-in model-visible IICP runtime identity context.

use crate::ChatMessage;

pub const RUNTIME_IDENTITY_PROFILE_ID: &str = "urn:iicp:profile:runtime-identity-context:v0";
pub const RUNTIME_IDENTITY_MARKER: &str = "IICP-RUNTIME-CONTEXT/1";
pub const RUNTIME_IDENTITY_CHAT_INTENT: &str = "urn:iicp:intent:llm:chat:v1";
pub const RUNTIME_IDENTITY_MAX_BYTES: usize = 2048;

const BASE_CAPSULE: &str = "This request reached you through IICP, the Intent-based Inter-agent Communication Protocol. IICP discovers eligible services and routes requests. You are the selected model or service, not IICP. When asked about this connection, use only supplied runtime facts; do not guess missing facts.";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RuntimeIdentityMode {
    #[default]
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeIdentityOptions {
    pub mode: RuntimeIdentityMode,
    pub instruction_channel: RuntimeIdentityInstructionChannel,
    pub selected_model: Option<String>,
    pub effective_capabilities: Vec<String>,
    pub selection_reason: Option<String>,
}

pub fn render_runtime_identity(
    intent: &str,
    options: &RuntimeIdentityOptions,
) -> Result<String, &'static str> {
    let mut lines = vec![
        format!("[{RUNTIME_IDENTITY_MARKER}]"),
        BASE_CAPSULE.to_string(),
        "Runtime facts:".to_string(),
        format!("- intent: {intent}"),
    ];
    if let Some(model) = &options.selected_model {
        lines.push(format!("- selected model (provider assertion): {model}"));
    }
    if !options.effective_capabilities.is_empty() {
        lines.push(format!(
            "- effective capabilities: {}",
            options.effective_capabilities.join(", ")
        ));
    }
    match options.selection_reason.as_deref() {
        Some("matched_intent_and_constraints") => lines
            .push("- selection: This service matched the requested intent and constraints.".into()),
        Some(_) => return Err("runtime_identity_selection_reason_invalid"),
        None => {}
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
    let Some(options) = options else {
        return Ok(messages.to_vec());
    };
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
