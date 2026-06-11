// SPDX-License-Identifier: Apache-2.0
//! Behavior tests for Phase-2 consumer token acquisition (#496).
//!
//! Each test fails if the fix is reverted:
//! - ConsumerTokenCache removed → compilation error
//! - Cache lookup skipped → directory hit on every task call
//! - Expired entry not refreshed → stale token forwarded

use std::time::{SystemTime, UNIX_EPOCH};

use iicp_client::consumer_token::{acquire_consumer_token, ConsumerTokenCache};
use mockito::ServerOpts;

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn returns_token_on_201_response() {
    let mut server = mockito::Server::new_with_opts_async(ServerOpts::default()).await;
    let exp = now_s() + 300;
    let mock = server
        .mock("POST", "/api/v1/consumer-token")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"token":"tok.sig","expires_at":{exp}}}"#))
        .create_async()
        .await;

    let cache = ConsumerTokenCache::new();
    let http = reqwest::Client::new();
    let result = acquire_consumer_token(
        &cache,
        &http,
        &server.url(),
        "my-jwt",
        "node-abc",
        "urn:iicp:intent:llm:chat:v1",
        5.0,
    )
    .await;

    assert_eq!(result.as_deref(), Some("tok.sig"));
    mock.assert_async().await;
}

#[tokio::test]
async fn returns_none_on_non_201() {
    let mut server = mockito::Server::new_with_opts_async(ServerOpts::default()).await;
    let mock = server
        .mock("POST", "/api/v1/consumer-token")
        .with_status(503)
        .with_body("{}")
        .create_async()
        .await;

    let cache = ConsumerTokenCache::new();
    let http = reqwest::Client::new();
    let result = acquire_consumer_token(
        &cache,
        &http,
        &server.url(),
        "my-jwt",
        "node-fail",
        "urn:iicp:intent:llm:chat:v1",
        5.0,
    )
    .await;

    assert!(result.is_none());
    mock.assert_async().await;
}

#[tokio::test]
async fn caches_token_and_avoids_second_directory_call() {
    let mut server = mockito::Server::new_with_opts_async(ServerOpts::default()).await;
    let exp = now_s() + 300;
    let mock = server
        .mock("POST", "/api/v1/consumer-token")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"token":"cached.sig","expires_at":{exp}}}"#))
        .expect(1) // must be called exactly once
        .create_async()
        .await;

    let cache = ConsumerTokenCache::new();
    let http = reqwest::Client::new();

    let first = acquire_consumer_token(
        &cache,
        &http,
        &server.url(),
        "jwt",
        "node-x",
        "intent:a",
        5.0,
    )
    .await;
    let second = acquire_consumer_token(
        &cache,
        &http,
        &server.url(),
        "jwt",
        "node-x",
        "intent:a",
        5.0,
    )
    .await;

    assert_eq!(first.as_deref(), Some("cached.sig"));
    assert_eq!(second.as_deref(), Some("cached.sig"));
    mock.assert_async().await; // exactly 1 call, not 2
}

#[tokio::test]
async fn refreshes_expired_cached_entry() {
    let mut server = mockito::Server::new_with_opts_async(ServerOpts::default()).await;
    let exp_fresh = now_s() + 300;
    let mock = server
        .mock("POST", "/api/v1/consumer-token")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"token":"new.sig","expires_at":{exp_fresh}}}"#))
        .expect(1)
        .create_async()
        .await;

    let cache = ConsumerTokenCache::new();
    // Pre-seed with an expired entry (exp in the past)
    let expired_exp = now_s().saturating_sub(10);
    cache.set(
        ("jwt".to_owned(), "node-y".to_owned(), "intent:b".to_owned()),
        "old.sig".to_owned(),
        expired_exp,
    );

    let http = reqwest::Client::new();
    let result = acquire_consumer_token(
        &cache,
        &http,
        &server.url(),
        "jwt",
        "node-y",
        "intent:b",
        5.0,
    )
    .await;

    assert_eq!(result.as_deref(), Some("new.sig"));
    mock.assert_async().await;
}
