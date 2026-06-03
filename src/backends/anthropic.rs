// SPDX-License-Identifier: Apache-2.0
//! Native Anthropic Messages-API backend helper.
//!
//! Unlike [`openai_compat`](super::openai_compat) / `vllm` / `llamacpp` (which share
//! the OpenAI `/v1/*` dialect), Anthropic speaks the Messages API
//! (`POST /v1/messages`): a top-level `system` string instead of a system-role
//! message, `x-api-key` + `anthropic-version` headers instead of a bearer token, a
//! **required** `max_tokens`, and `content` blocks instead of OpenAI's
//! `message.content`.
//!
//! This handler translates an IICP `llm:chat:v1` task (OpenAI chat shape) → an
//! Anthropic Messages request, then translates the response **back** to the OpenAI
//! chat-completion shape — so a Claude-backed node looks identical to an Ollama/vLLM
//! node to any IICP client. First-class Claude support (prompt caching, native
//! content blocks) without the OpenAI-compat shim (which strips audio + disables
//! caching).
//!
//! Capability roadmap C1 (reports/capability-gaps-implementation-plan-2026-06-03.md;
//! research #414). Reuses [`OpenAiCompatOptions`](super::openai_compat::OpenAiCompatOptions)
//! so the `invoke_backend` dispatch stays uniform; `anthropic-version` and the default
//! `max_tokens` are module constants.

#[cfg(feature = "iicp-tcp")]
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::openai_compat::OpenAiCompatOptions;

const CHAT_INTENT: &str = "urn:iicp:intent:llm:chat:v1";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const DEFAULT_MAX_TOKENS: u64 = 4096;

/// Translate one OpenAI message `content` into Anthropic content. A string passes
/// through; an array of OpenAI parts is mapped block-by-block (`text` → text block;
/// `image_url` data-URL → base64 image block, remote URL → url image block). Unknown
/// parts are dropped.
fn to_anthropic_content(content: &Value) -> Value {
    let arr = match content {
        Value::Array(a) => a,
        other => return other.clone(),
    };
    let mut blocks: Vec<Value> = Vec::new();
    for part in arr {
        let obj = match part.as_object() {
            Some(o) => o,
            None => continue,
        };
        match obj.get("type").and_then(Value::as_str) {
            Some("text") => {
                blocks.push(json!({
                    "type": "text",
                    "text": obj.get("text").and_then(Value::as_str).unwrap_or(""),
                }));
            }
            Some("image_url") => {
                let url = obj
                    .get("image_url")
                    .and_then(|v| v.get("url"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if let Some(rest) = url.strip_prefix("data:") {
                    // data:<media_type>;base64,<data>
                    if let Some((header, b64)) = rest.split_once(',') {
                        let media_type = header
                            .split(';')
                            .next()
                            .filter(|s| !s.is_empty())
                            .unwrap_or("image/png");
                        blocks.push(json!({
                            "type": "image",
                            "source": {"type": "base64", "media_type": media_type, "data": b64},
                        }));
                    }
                } else if !url.is_empty() {
                    blocks.push(json!({"type": "image", "source": {"type": "url", "url": url}}));
                }
            }
            _ => {}
        }
    }
    Value::Array(blocks)
}

/// Translate an OpenAI chat payload → an Anthropic Messages request body. System-role
/// messages are hoisted into the top-level `system` param; `max_tokens` is defaulted
/// (Anthropic requires it); `stop` → `stop_sequences`.
fn to_anthropic_request(
    payload: &Map<String, Value>,
    model: &Option<String>,
) -> Map<String, Value> {
    let mut body = Map::new();
    let model_val = payload
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| model.clone());
    if let Some(m) = model_val {
        body.insert("model".into(), json!(m));
    }

    let mut system_parts: Vec<String> = Vec::new();
    let mut messages: Vec<Value> = Vec::new();
    if let Some(msgs) = payload.get("messages").and_then(Value::as_array) {
        for msg in msgs {
            let obj = match msg.as_object() {
                Some(o) => o,
                None => continue,
            };
            let role = obj.get("role").and_then(Value::as_str).unwrap_or("");
            if role == "system" {
                match obj.get("content") {
                    Some(Value::String(s)) => system_parts.push(s.clone()),
                    Some(Value::Array(parts)) => {
                        for p in parts {
                            if p.get("type").and_then(Value::as_str) == Some("text") {
                                system_parts.push(
                                    p.get("text")
                                        .and_then(Value::as_str)
                                        .unwrap_or("")
                                        .to_string(),
                                );
                            }
                        }
                    }
                    _ => {}
                }
                continue;
            }
            let content = obj
                .get("content")
                .map(to_anthropic_content)
                .unwrap_or(Value::Null);
            messages.push(json!({"role": role, "content": content}));
        }
    }
    body.insert("messages".into(), Value::Array(messages));
    let sys: String = system_parts
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    if !sys.is_empty() {
        body.insert("system".into(), json!(sys));
    }

    let max_tokens = payload
        .get("max_tokens")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_TOKENS);
    body.insert("max_tokens".into(), json!(max_tokens));
    for k in ["temperature", "top_p"] {
        if let Some(v) = payload.get(k) {
            if !v.is_null() {
                body.insert(k.into(), v.clone());
            }
        }
    }
    match payload.get("stop") {
        Some(Value::String(s)) => {
            body.insert("stop_sequences".into(), json!([s]));
        }
        Some(Value::Array(a)) => {
            body.insert("stop_sequences".into(), Value::Array(a.clone()));
        }
        _ => {}
    }
    body
}

fn stop_reason_to_finish(reason: Option<&str>) -> &'static str {
    match reason {
        Some("end_turn") | Some("stop_sequence") => "stop",
        Some("max_tokens") => "length",
        Some("tool_use") => "tool_calls",
        _ => "stop",
    }
}

/// Translate an Anthropic Messages response → the OpenAI chat-completion shape, so
/// IICP clients consume one shape regardless of backend.
fn to_openai_response(data: &Value) -> Value {
    let text: String = data
        .get("content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                .map(|b| b.get("text").and_then(Value::as_str).unwrap_or(""))
                .collect::<String>()
        })
        .unwrap_or_default();
    let usage = data.get("usage");
    let prompt = usage
        .and_then(|u| u.get("input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let completion = usage
        .and_then(|u| u.get("output_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    json!({
        "id": data.get("id").and_then(Value::as_str).unwrap_or(""),
        "object": "chat.completion",
        "model": data.get("model").and_then(Value::as_str).unwrap_or(""),
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": text},
            "finish_reason": stop_reason_to_finish(data.get("stop_reason").and_then(Value::as_str)),
        }],
        "usage": {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
        },
    })
}

/// Resolve the Anthropic API base. The shared `OpenAiCompatOptions` default is Ollama's
/// localhost `/v1`; when an operator selects the `anthropic` backend without overriding
/// `base_url`, fall back to the Anthropic API.
fn resolve_base(base_url: &str) -> &str {
    let trimmed = base_url.trim_end_matches('/');
    if trimmed.is_empty()
        || trimmed == "http://localhost:11434/v1"
        || trimmed == "http://localhost:11434"
    {
        "https://api.anthropic.com/v1"
    } else {
        trimmed
    }
}

/// Stand-alone async invocation (shared by `invoke_backend` dispatch + the handler).
pub async fn invoke(opts: &OpenAiCompatOptions, intent: &str, payload: &Value) -> Value {
    if intent != CHAT_INTENT {
        return json!({
            "error_code": 400,
            "error_message": format!(
                "anthropic: unsupported intent {intent:?}; the Messages API serves only {CHAT_INTENT}"
            ),
        });
    }
    let payload_map = match payload {
        Value::Object(o) => o.clone(),
        Value::Null => Map::new(),
        _ => {
            return json!({
                "error_code": 400,
                "error_message": "anthropic: task.payload must be a JSON object",
            });
        }
    };

    let body = to_anthropic_request(&payload_map, &opts.model);
    if body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        return json!({
            "error_code": 400,
            "error_message": "anthropic: no model — pass `model` to the backend options or include `model` in the task payload",
        });
    }

    let base = resolve_base(&opts.base_url);
    let url = format!("{base}/messages");

    let mut req = match reqwest::Client::builder().timeout(opts.timeout).build() {
        Ok(c) => c
            .post(&url)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .json(&Value::Object(body)),
        Err(e) => {
            return json!({"error_code": 500, "error_message": format!("anthropic: client build failed: {e}")});
        }
    };
    if let Some(key) = &opts.api_key {
        if !key.is_empty() {
            req = req.header("x-api-key", key);
        }
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) if e.is_timeout() => {
            return json!({"error_code": 408, "error_message": "anthropic: backend timed out"});
        }
        Err(e) => {
            return json!({"error_code": 502, "error_message": format!("anthropic: HTTP transport error: {e}")});
        }
    };

    let status = resp.status().as_u16();
    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let truncated: String = text.chars().take(512).collect();
        return json!({"error_code": status, "error_message": format!("anthropic: upstream {status}: {truncated}")});
    }

    match resp.json::<Value>().await {
        Ok(data) => json!({"result": to_openai_response(&data)}),
        Err(e) => {
            json!({"error_code": 502, "error_message": format!("anthropic: upstream returned non-JSON: {e}")})
        }
    }
}

/// Build a task-handler closure for `IicpTcpServer` that proxies chat CALLs to the
/// Anthropic Messages API.
#[cfg(feature = "iicp-tcp")]
pub fn anthropic_handler(opts: OpenAiCompatOptions) -> crate::iicp_tcp::TcpTaskHandler {
    let opts = Arc::new(opts);
    Arc::new(move |task| {
        let opts = Arc::clone(&opts);
        Box::pin(async move { invoke(&opts, &task.intent, &task.payload).await })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> OpenAiCompatOptions {
        OpenAiCompatOptions {
            base_url: "https://api.anthropic.com/v1".into(),
            model: Some("claude-opus-4-8".into()),
            api_key: Some("sk-ant-test".into()),
            ..Default::default()
        }
    }

    #[test]
    fn request_hoists_system_and_defaults_max_tokens() {
        let payload = serde_json::Map::from_iter([(
            "messages".to_string(),
            json!([
                {"role": "system", "content": "Be terse."},
                {"role": "user", "content": "ping"},
            ]),
        )]);
        let body = to_anthropic_request(&payload, &Some("claude-opus-4-8".into()));
        assert_eq!(body.get("system").unwrap(), "Be terse.");
        assert_eq!(body.get("max_tokens").unwrap(), 4096);
        let msgs = body.get("messages").unwrap().as_array().unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].get("role").unwrap(), "user");
        assert_eq!(msgs[0].get("content").unwrap(), "ping");
    }

    #[test]
    fn request_maps_image_url_data_to_base64_block() {
        let payload = serde_json::Map::from_iter([(
            "messages".to_string(),
            json!([{
                "role": "user",
                "content": [
                    {"type": "text", "text": "what is this?"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
                ],
            }]),
        )]);
        let body = to_anthropic_request(&payload, &None);
        let content = body.get("messages").unwrap()[0]
            .get("content")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(content[0], json!({"type": "text", "text": "what is this?"}));
        assert_eq!(
            content[1],
            json!({"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}})
        );
    }

    #[test]
    fn request_passes_explicit_max_tokens_and_stop() {
        let payload = serde_json::Map::from_iter([
            (
                "messages".to_string(),
                json!([{"role": "user", "content": "hi"}]),
            ),
            ("max_tokens".to_string(), json!(256)),
            ("stop".to_string(), json!("END")),
        ]);
        let body = to_anthropic_request(&payload, &None);
        assert_eq!(body.get("max_tokens").unwrap(), 256);
        assert_eq!(body.get("stop_sequences").unwrap(), &json!(["END"]));
    }

    #[test]
    fn response_maps_to_openai_chat_shape() {
        let data = json!({
            "id": "msg_01abc",
            "model": "claude-opus-4-8",
            "content": [{"type": "text", "text": "PONG"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 11, "output_tokens": 2},
        });
        let out = to_openai_response(&data);
        assert_eq!(out.get("object").unwrap(), "chat.completion");
        assert_eq!(out["choices"][0]["message"]["content"], "PONG");
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
        assert_eq!(
            out["usage"],
            json!({"prompt_tokens": 11, "completion_tokens": 2, "total_tokens": 13})
        );
    }

    #[tokio::test]
    async fn invoke_rejects_non_chat_intent() {
        let out = invoke(
            &opts(),
            "urn:iicp:intent:llm:embedding:v1",
            &json!({"input": "x"}),
        )
        .await;
        assert_eq!(out.get("error_code").unwrap(), 400);
        assert!(out
            .get("error_message")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("only"));
    }
}
