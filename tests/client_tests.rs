// SPDX-License-Identifier: Apache-2.0
use iicp_client::{ClientConfig, IicpClient, IicpError, make_traceparent};

// is_transient() — used by retry logic (SDK-05)
#[test]
fn is_transient_on_429() {
    let e = IicpError::Protocol { code: "capacity_exceeded".into(), message: "".into(), status: 429 };
    assert!(e.is_transient());
}

#[test]
fn is_transient_on_503() {
    let e = IicpError::Protocol { code: "backend_unreachable".into(), message: "".into(), status: 503 };
    assert!(e.is_transient());
}

#[test]
fn is_not_transient_on_401() {
    let e = IicpError::Protocol { code: "token_invalid".into(), message: "".into(), status: 401 };
    assert!(!e.is_transient());
}

#[test]
fn is_not_transient_on_422() {
    let e = IicpError::Protocol { code: "validation_error".into(), message: "".into(), status: 422 };
    assert!(!e.is_transient());
}

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

// SDK-06: W3C traceparent format validation
#[test]
fn sdk06_traceparent_format() {
    let tp = make_traceparent();
    let parts: Vec<&str> = tp.split('-').collect();
    assert_eq!(parts.len(), 4, "expected 4 dash-separated parts: {tp}");
    assert_eq!(parts[0], "00");
    assert_eq!(parts[1].len(), 32, "trace-id must be 32 hex chars: {tp}");
    assert_eq!(parts[2].len(), 16, "parent-id must be 16 hex chars: {tp}");
    assert_eq!(parts[3], "01");
    // verify hex chars only
    assert!(parts[1].chars().all(|c| c.is_ascii_hexdigit()));
    assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn sdk06_traceparent_unique() {
    let tp1 = make_traceparent();
    let tp2 = make_traceparent();
    assert_ne!(tp1, tp2, "consecutive traceparents must differ");
}

#[tokio::test]
async fn sdk03_rejects_invalid_intent() {
    let client = IicpClient::new(ClientConfig::default()).unwrap();
    let err = client.discover("not-a-urn", None, None).await.unwrap_err();
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
        .discover("urn:iicp:intent:llm:chat:v1", None, None)
        .await
        .unwrap_err();
    assert!(!matches!(err, IicpError::InvalidIntent(_)));
}
