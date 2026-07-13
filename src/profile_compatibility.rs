//! Additive evaluator for the fixture-gated pre-normative profile draft.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileCompatibilityDecision {
    pub eligible: bool,
    pub reason: &'static str,
}

pub fn evaluate_pre_normative_profile(
    request: &Value,
    provider: &Value,
    aliases: &Value,
    now_s: i64,
) -> ProfileCompatibilityDecision {
    if request.get("policy").and_then(Value::as_str) == Some("deny") {
        return reject("policy_refusal");
    }
    if let Some(binding) = request.get("mapping_kind").and_then(Value::as_str) {
        if !matches!(binding, "a2a_skill" | "mcp_tool") {
            return reject("unsupported_binding");
        }
    }
    let requested_intent = resolve(request.get("intent").and_then(Value::as_str), aliases);
    let provider_intent = resolve(provider.get("intent").and_then(Value::as_str), aliases);
    if requested_intent != provider_intent {
        return reject("intent_mismatch");
    }
    if let Some(digest) = request.get("schema_digest").and_then(Value::as_str) {
        if provider.get("schema_digest").and_then(Value::as_str) != Some(digest) {
            return reject("schema_digest_mismatch");
        }
    }
    for extension in request
        .get("extensions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if extension.get("required").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        if extension.get("experimental").and_then(Value::as_bool) == Some(true)
            && extension
                .get("review_expires_at_s")
                .and_then(Value::as_i64)
                .unwrap_or_default()
                <= now_s
        {
            return reject("experimental_extension_expired");
        }
        let uri = extension.get("uri").and_then(Value::as_str);
        let supported = provider
            .get("extensions")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item.get("uri").and_then(Value::as_str) == uri)
            });
        if !supported {
            return reject("required_extension_missing");
        }
    }
    ProfileCompatibilityDecision {
        eligible: true,
        reason: "compatible",
    }
}

fn reject(reason: &'static str) -> ProfileCompatibilityDecision {
    ProfileCompatibilityDecision {
        eligible: false,
        reason,
    }
}

fn resolve<'a>(intent: Option<&'a str>, aliases: &'a Value) -> Option<&'a str> {
    let intent = intent?;
    aliases
        .as_array()
        .and_then(|items| {
            items.iter().find_map(|item| {
                (item.get("from").and_then(Value::as_str) == Some(intent))
                    .then(|| item.get("to").and_then(Value::as_str))
                    .flatten()
            })
        })
        .or(Some(intent))
}
