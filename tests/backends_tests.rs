// SPDX-License-Identifier: Apache-2.0
//! Unit tests for the openai_compat backend helper. Uses mockito to mock
//! the upstream provider so the tests don't need a real Ollama / vLLM.

use std::time::Duration;

use iicp_client::backends::openai_compat::{invoke, OpenAiCompatOptions};
use iicp_client::backends::{invoke_backend, llamacpp, vllm, BACKEND_TYPES};
use serde_json::json;

fn opts(base_url: String, model: Option<&str>) -> OpenAiCompatOptions {
    OpenAiCompatOptions {
        base_url,
        model: model.map(String::from),
        api_key: None,
        timeout: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn test_chat_completion_happy_path() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"chatcmpl-test","choices":[{"message":{"content":"PONG"}}]}"#)
        .create_async()
        .await;

    let result = invoke(
        &opts(server.url(), Some("qwen2.5:0.5b")),
        "urn:iicp:intent:llm:chat:v1",
        &json!({"messages": [{"role":"user","content":"hi"}]}),
    )
    .await;
    assert!(
        result.get("error_code").is_none(),
        "unexpected error: {result}"
    );
    assert_eq!(
        result["result"]["id"].as_str().unwrap_or(""),
        "chatcmpl-test"
    );
}

#[tokio::test]
async fn test_factory_model_is_injected_when_payload_missing() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/chat/completions")
        .match_body(mockito::Matcher::PartialJson(json!({
            "model": "qwen2.5:0.5b"
        })))
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let result = invoke(
        &opts(server.url(), Some("qwen2.5:0.5b")),
        "urn:iicp:intent:llm:chat:v1",
        &json!({"messages": []}),
    )
    .await;
    assert!(result.get("error_code").is_none(), "unexpected: {result}");
}

#[tokio::test]
async fn test_task_payload_model_overrides_factory() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/chat/completions")
        .match_body(mockito::Matcher::PartialJson(json!({
            "model": "llama-3-8b"
        })))
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let result = invoke(
        &opts(server.url(), Some("qwen2.5:0.5b")),
        "urn:iicp:intent:llm:chat:v1",
        &json!({"messages": [], "model": "llama-3-8b"}),
    )
    .await;
    assert!(result.get("error_code").is_none(), "unexpected: {result}");
}

#[tokio::test]
async fn test_completion_intent_routes_to_completions_path() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/completions")
        .with_status(200)
        .with_body(r#"{"choices":[{"text":"PONG"}]}"#)
        .create_async()
        .await;

    let result = invoke(
        &opts(server.url(), Some("q")),
        "urn:iicp:intent:llm:completion:v1",
        &json!({"prompt":"ping"}),
    )
    .await;
    assert_eq!(
        result["result"]["choices"][0]["text"].as_str(),
        Some("PONG")
    );
}

#[tokio::test]
async fn test_embedding_intent_routes_to_embeddings_path() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/embeddings")
        .with_status(200)
        .with_body(r#"{"data":[{"embedding":[0.1,0.2]}]}"#)
        .create_async()
        .await;

    let result = invoke(
        &opts(server.url(), Some("text-embedding-3-small")),
        "urn:iicp:intent:llm:embedding:v1",
        &json!({"input":"hello"}),
    )
    .await;
    assert!(result["result"]["data"][0]["embedding"].is_array());
}

#[tokio::test]
async fn test_unsupported_intent_returns_400() {
    let server = mockito::Server::new_async().await;
    let result = invoke(
        &opts(server.url(), Some("q")),
        "urn:iicp:intent:llm:fancy:v1",
        &json!({}),
    )
    .await;
    assert_eq!(result["error_code"].as_u64(), Some(400));
    assert!(result["error_message"]
        .as_str()
        .unwrap_or("")
        .contains("unsupported intent"));
}

#[tokio::test]
async fn test_no_model_returns_400() {
    let server = mockito::Server::new_async().await;
    let result = invoke(
        &opts(server.url(), None),
        "urn:iicp:intent:llm:chat:v1",
        &json!({"messages": []}),
    )
    .await;
    assert_eq!(result["error_code"].as_u64(), Some(400));
    assert!(result["error_message"]
        .as_str()
        .unwrap_or("")
        .contains("no model"));
}

#[tokio::test]
async fn test_non_object_payload_returns_400() {
    let server = mockito::Server::new_async().await;
    let result = invoke(
        &opts(server.url(), Some("q")),
        "urn:iicp:intent:llm:chat:v1",
        &json!("string-not-object"),
    )
    .await;
    assert_eq!(result["error_code"].as_u64(), Some(400));
    assert!(result["error_message"]
        .as_str()
        .unwrap_or("")
        .contains("must be a JSON object"));
}

#[tokio::test]
async fn test_upstream_500_is_surfaced() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/chat/completions")
        .with_status(500)
        .with_body("model not loaded")
        .create_async()
        .await;

    let result = invoke(
        &opts(server.url(), Some("q")),
        "urn:iicp:intent:llm:chat:v1",
        &json!({"messages": []}),
    )
    .await;
    assert_eq!(result["error_code"].as_u64(), Some(500));
    assert!(result["error_message"]
        .as_str()
        .unwrap_or("")
        .contains("model not loaded"));
}

#[tokio::test]
async fn test_upstream_429_rate_limit_surfaced() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/chat/completions")
        .with_status(429)
        .with_body("rate limit exceeded")
        .create_async()
        .await;

    let result = invoke(
        &opts(server.url(), Some("q")),
        "urn:iicp:intent:llm:chat:v1",
        &json!({"messages": []}),
    )
    .await;
    assert_eq!(result["error_code"].as_u64(), Some(429));
}

#[tokio::test]
async fn test_api_key_sets_bearer_auth() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/chat/completions")
        .match_header("authorization", "Bearer sk-test-1234")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let mut o = opts(server.url(), Some("q"));
    o.api_key = Some("sk-test-1234".into());
    let result = invoke(&o, "urn:iicp:intent:llm:chat:v1", &json!({"messages": []})).await;
    assert!(result.get("error_code").is_none(), "unexpected: {result}");
}

#[tokio::test]
async fn test_base_url_trailing_slash_normalized() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    // server.url() ends without a trailing slash; we add one to test normalization.
    let result = invoke(
        &opts(format!("{}/", server.url()), Some("q")),
        "urn:iicp:intent:llm:chat:v1",
        &json!({"messages": []}),
    )
    .await;
    assert!(result.get("error_code").is_none(), "unexpected: {result}");
}

// ── Dedicated backends (vLLM / llama.cpp) + selector — parity Block B ────────

#[tokio::test]
async fn test_vllm_invoke_happy_path() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_body(r#"{"id":"ok"}"#)
        .create_async()
        .await;
    let result = vllm::invoke(
        &opts(server.url(), Some("mistral-7b")),
        "urn:iicp:intent:llm:chat:v1",
        &json!({"messages": []}),
    )
    .await;
    assert!(result.get("error_code").is_none(), "unexpected: {result}");
    assert_eq!(result["result"]["id"].as_str(), Some("ok"));
}

#[tokio::test]
async fn test_vllm_error_message_uses_engine_label() {
    let server = mockito::Server::new_async().await;
    let result = vllm::invoke(
        &opts(server.url(), Some("m")),
        "urn:iicp:intent:bogus:v1",
        &json!({}),
    )
    .await;
    assert_eq!(result["error_code"].as_u64(), Some(400));
    assert!(result["error_message"]
        .as_str()
        .unwrap_or("")
        .starts_with("vllm:"));
}

#[tokio::test]
async fn test_llamacpp_invoke_happy_path() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_body(r#"{"id":"ok"}"#)
        .create_async()
        .await;
    let result = llamacpp::invoke(
        &opts(server.url(), Some("gguf")),
        "urn:iicp:intent:llm:chat:v1",
        &json!({"messages": []}),
    )
    .await;
    assert!(result.get("error_code").is_none(), "unexpected: {result}");
}

#[test]
fn test_default_options_ports() {
    assert!(vllm::default_options().base_url.contains(":8000"));
    assert!(llamacpp::default_options().base_url.contains(":8080"));
}

#[tokio::test]
async fn test_invoke_backend_dispatches_and_rejects_unknown() {
    let server = mockito::Server::new_async().await;
    let o = opts(server.url(), Some("m"));
    for t in BACKEND_TYPES {
        // unsupported intent → 400 from the engine, but dispatch itself is Ok(_)
        let r = invoke_backend(t, &o, "urn:iicp:intent:bogus:v1", &json!({})).await;
        assert!(r.is_ok(), "dispatch for {t} should be Ok");
    }
    let bad = invoke_backend("nope", &o, "urn:iicp:intent:llm:chat:v1", &json!({})).await;
    assert!(bad.is_err());
    assert!(bad.unwrap_err().contains("unknown backend_type"));
}
