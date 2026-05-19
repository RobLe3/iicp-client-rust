// SPDX-License-Identifier: Apache-2.0
use iicp_client::{ClientConfig, IicpClient, IicpError};

#[test]
fn sdk04_rejects_oversized_timeout() {
    let cfg = ClientConfig { timeout_ms: 120_001, ..Default::default() };
    assert!(matches!(
        IicpClient::new(cfg),
        Err(IicpError::TimeoutTooLarge(120_001))
    ));
}

#[test]
fn sdk04_accepts_max_timeout() {
    let cfg = ClientConfig { timeout_ms: 120_000, ..Default::default() };
    assert!(IicpClient::new(cfg).is_ok());
}

#[tokio::test]
async fn sdk03_rejects_invalid_intent() {
    let client = IicpClient::new(ClientConfig::default()).unwrap();
    let err = client.discover("not-a-urn", None).await.unwrap_err();
    assert!(matches!(err, IicpError::InvalidIntent(_)));
}

#[tokio::test]
async fn sdk03_accepts_valid_intent() {
    // Validates pattern only — no network call needed for intent check.
    // A network error here means the intent was accepted (correct).
    let client = IicpClient::new(ClientConfig {
        directory_url: "http://127.0.0.1:19999".into(), // unreachable
        ..Default::default()
    })
    .unwrap();
    let err = client
        .discover("urn:iicp:intent:llm:chat:v1", None)
        .await
        .unwrap_err();
    assert!(!matches!(err, IicpError::InvalidIntent(_)));
}
