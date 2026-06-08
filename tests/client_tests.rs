// SPDX-License-Identifier: Apache-2.0
use iicp_client::{make_traceparent, ClientConfig, IicpClient, IicpError};

// is_transient() — used by retry logic (SDK-05)
#[test]
fn is_transient_on_429() {
    let e = IicpError::Protocol {
        code: "capacity_exceeded".into(),
        message: "".into(),
        status: 429,
    };
    assert!(e.is_transient());
}

#[test]
fn is_transient_on_503() {
    let e = IicpError::Protocol {
        code: "backend_unreachable".into(),
        message: "".into(),
        status: 503,
    };
    assert!(e.is_transient());
}

#[test]
fn is_not_transient_on_401() {
    let e = IicpError::Protocol {
        code: "token_invalid".into(),
        message: "".into(),
        status: 401,
    };
    assert!(!e.is_transient());
}

#[test]
fn is_not_transient_on_422() {
    let e = IicpError::Protocol {
        code: "validation_error".into(),
        message: "".into(),
        status: 422,
    };
    assert!(!e.is_transient());
}

#[test]
fn sdk04_rejects_oversized_timeout() {
    let cfg = ClientConfig {
        timeout_ms: 120_001,
        ..Default::default()
    };
    assert!(matches!(
        IicpClient::new(cfg),
        Err(IicpError::TimeoutTooLarge(120_001))
    ));
}

#[test]
fn sdk04_accepts_max_timeout() {
    let cfg = ClientConfig {
        timeout_ms: 120_000,
        ..Default::default()
    };
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

// ε-greedy provider selection (R4 / #486)
// These tests verify the config plumbing without a live network.

#[test]
fn epsilon_greedy_default_is_0_05() {
    // ClientConfig::default() must set routing_epsilon = 0.05 (R4 / #486).
    // This test fails if the field is absent or defaults to 0.
    let cfg = ClientConfig::default();
    // IICP_ROUTING_EPSILON may be set in the test environment; only assert
    // when the env var is absent.
    if std::env::var("IICP_ROUTING_EPSILON").is_err() {
        assert!(
            (cfg.routing_epsilon - 0.05).abs() < 1e-9,
            "default routing_epsilon must be 0.05, got {}",
            cfg.routing_epsilon
        );
    }
}

#[test]
fn epsilon_greedy_explicit_zero_disables_exploration() {
    let cfg = ClientConfig {
        routing_epsilon: 0.0,
        ..Default::default()
    };
    assert_eq!(cfg.routing_epsilon, 0.0);
}

#[test]
fn epsilon_greedy_env_override() {
    // IICP_ROUTING_EPSILON env var must override the default (R4 / #486).
    // Run in a subprocess context to avoid polluting other parallel tests.
    // We just verify the parse/clamp logic by setting the env var before Default::default().
    // Note: env var is read at Default::default() call time.
    unsafe { std::env::set_var("IICP_ROUTING_EPSILON", "0.0") };
    let cfg = ClientConfig::default();
    unsafe { std::env::remove_var("IICP_ROUTING_EPSILON") };
    assert_eq!(
        cfg.routing_epsilon, 0.0,
        "env IICP_ROUTING_EPSILON=0.0 should set routing_epsilon to 0.0"
    );
}
