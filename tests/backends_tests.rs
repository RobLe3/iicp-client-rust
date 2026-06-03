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

// ── #414 audio:transcribe (STT) — multipart file upload ──────────────────────

#[tokio::test]
async fn test_audio_transcribe_posts_multipart_and_returns_text() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/audio/transcriptions")
        .match_header(
            "content-type",
            mockito::Matcher::Regex("multipart/form-data".into()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"text":"hello world"}"#)
        .create_async()
        .await;

    let payload = json!({
        "audio": STANDARD.encode(b"RIFF....fake-wav-bytes"),
        "filename": "clip.wav",
        "language": "en",
    });
    let result = invoke(
        &opts(server.url(), Some("whisper-1")),
        "urn:iicp:intent:audio:transcribe:v1",
        &payload,
    )
    .await;
    assert!(
        result.get("error_code").is_none(),
        "unexpected error: {result}"
    );
    assert_eq!(
        result["result"]["text"].as_str().unwrap_or(""),
        "hello world"
    );
}

#[tokio::test]
async fn test_audio_transcribe_rejects_invalid_base64() {
    let result = invoke(
        &opts("http://127.0.0.1:1".into(), Some("whisper-1")),
        "urn:iicp:intent:audio:transcribe:v1",
        &json!({"audio": "!!not-base64!!"}),
    )
    .await;
    assert_eq!(result["error_code"].as_u64(), Some(400));
    assert!(result["error_message"]
        .as_str()
        .unwrap_or("")
        .contains("base64"));
}

#[tokio::test]
async fn test_audio_transcribe_requires_audio_field() {
    let result = invoke(
        &opts("http://127.0.0.1:1".into(), Some("whisper-1")),
        "urn:iicp:intent:audio:transcribe:v1",
        &json!({}),
    )
    .await;
    assert_eq!(result["error_code"].as_u64(), Some(400));
    assert!(result["error_message"]
        .as_str()
        .unwrap_or("")
        .contains("audio"));
}

/// Live end-to-end ratification (#414, #408 discipline). Requires a running
/// whisper.cpp `whisper-server` on :8090 serving /v1/audio/transcriptions:
///   whisper-server -m ggml-tiny.en.bin --port 8090 \
///     --inference-path /v1/audio/transcriptions
/// Run with: cargo test --test backends_tests -- --ignored audio_transcribe_live
#[tokio::test]
#[ignore]
async fn test_audio_transcribe_live_whisper_server() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let wav = std::fs::read("/opt/homebrew/Cellar/whisper-cpp/1.8.6/share/whisper-cpp/jfk.wav")
        .expect("jfk.wav sample");
    let payload = json!({"audio": STANDARD.encode(&wav), "filename": "jfk.wav"});
    let result = invoke(
        &opts("http://127.0.0.1:8090/v1".into(), None),
        "urn:iicp:intent:audio:transcribe:v1",
        &payload,
    )
    .await;
    let text = result["result"]["text"]
        .as_str()
        .unwrap_or("")
        .to_lowercase();
    assert!(
        text.contains("country"),
        "expected transcription, got {result}"
    );
}

// ── #414 audio:speech (TTS) — JSON request, binary audio response ────────────

#[tokio::test]
async fn test_audio_speech_returns_base64_audio() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/audio/speech")
        .match_body(mockito::Matcher::PartialJson(
            json!({"input": "hello world"}),
        ))
        .with_status(200)
        .with_header("content-type", "audio/wav")
        .with_body(b"RIFF....fake-wav-audio")
        .create_async()
        .await;

    let result = invoke(
        &opts(server.url(), Some("tts-1")),
        "urn:iicp:intent:audio:speech:v1",
        &json!({"input": "hello world", "voice": "alloy"}),
    )
    .await;
    assert!(
        result.get("error_code").is_none(),
        "unexpected error: {result}"
    );
    assert_eq!(
        result["result"]["content_type"].as_str().unwrap_or(""),
        "audio/wav"
    );
    let decoded = STANDARD
        .decode(result["result"]["audio"].as_str().unwrap_or(""))
        .unwrap();
    assert_eq!(decoded, b"RIFF....fake-wav-audio");
}

#[tokio::test]
async fn test_audio_speech_requires_input_field() {
    let result = invoke(
        &opts("http://127.0.0.1:1".into(), Some("tts-1")),
        "urn:iicp:intent:audio:speech:v1",
        &json!({}),
    )
    .await;
    assert_eq!(result["error_code"].as_u64(), Some(400));
    assert!(result["error_message"]
        .as_str()
        .unwrap_or("")
        .contains("input"));
}

/// Live ratification (#414): requires an OpenAI-compat /v1/audio/speech backend on
/// :8091 (e.g. the espeak-ng shim documented in FORGE_STATE iter-2026).
/// Run with: cargo test --test backends_tests -- --ignored audio_speech_live
#[tokio::test]
#[ignore]
async fn test_audio_speech_live_espeak_server() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let result = invoke(
        &opts("http://127.0.0.1:8091/v1".into(), None),
        "urn:iicp:intent:audio:speech:v1",
        &json!({"input": "Ask not what your country can do for you.", "voice": "en"}),
    )
    .await;
    let audio = STANDARD
        .decode(result["result"]["audio"].as_str().unwrap_or(""))
        .expect("base64 audio");
    assert_eq!(&audio[..4], b"RIFF", "expected wav audio, got {result}");
    assert!(audio.len() > 1000, "expected real audio bytes");
}
