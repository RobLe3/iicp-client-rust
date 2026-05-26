// SPDX-License-Identifier: Apache-2.0
//! Unit tests for the `nat_detection` module's pure-logic helpers
//! (looks_routable, probe_external_ip body parsing, detect_nat tier 0).
//!
//! UPnP discovery + reverse-DNS aren't reachable in CI so the tier-1 UPnP
//! happy path is exercised by operators at runtime, not here.
//!
//! Behind `--features nat` so the SDK builds for HTTP-only consumers without
//! pulling in igd-next.

#![cfg(feature = "nat")]

use std::time::Duration;

use iicp_client::nat_detection::{
    detect_nat, looks_routable, DetectNatOptions, TransportMethod,
};

// ── looks_routable ──────────────────────────────────────────────────────────

#[test]
fn test_looks_routable_public_dns() {
    assert!(looks_routable("http://node.example.com:8080"));
}

#[test]
fn test_looks_routable_public_ipv4() {
    assert!(looks_routable("http://8.8.8.8:8080"));
    assert!(looks_routable("http://1.1.1.1:443"));
}

#[test]
fn test_looks_routable_rejects_localhost() {
    assert!(!looks_routable("http://localhost:8080"));
    assert!(!looks_routable("http://127.0.0.1:8080"));
}

#[test]
fn test_looks_routable_rejects_rfc1918() {
    assert!(!looks_routable("http://192.168.1.1:8080"));
    assert!(!looks_routable("http://10.0.0.5:8080"));
    assert!(!looks_routable("http://172.20.0.5:8080"));
}

#[test]
fn test_looks_routable_rejects_link_local() {
    assert!(!looks_routable("http://169.254.5.5:8080"));
}

#[test]
fn test_looks_routable_rejects_documentation_ranges() {
    assert!(!looks_routable("http://203.0.113.5:8080"));
    assert!(!looks_routable("http://192.0.2.5:8080"));
    assert!(!looks_routable("http://198.18.0.1:8080"));
}

#[test]
fn test_looks_routable_rejects_cgnat() {
    assert!(!looks_routable("http://100.65.0.1:8080"));
}

#[test]
fn test_looks_routable_rejects_reserved_suffixes() {
    assert!(!looks_routable("http://node.local:8080"));
    assert!(!looks_routable("http://node.test:8080"));
    assert!(!looks_routable("http://service.internal:8080"));
    assert!(!looks_routable("http://node.example:8080"));
}

#[test]
fn test_looks_routable_rejects_bare_hostname() {
    assert!(!looks_routable("http://adapter-llama:8080"));
}

#[test]
fn test_looks_routable_rejects_ipv6_loopback() {
    assert!(!looks_routable("http://[::1]:8080"));
    assert!(!looks_routable("http://[::]:8080"));
}

#[test]
fn test_looks_routable_rejects_garbage() {
    assert!(!looks_routable("not-a-url"));
}

// ── detect_nat tier 0 ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_detect_nat_tier_0_accepts_routable_operator_endpoint() {
    let opts = DetectNatOptions {
        bind_host: "0.0.0.0".into(),
        bind_port: 8080,
        operator_public_endpoint: Some("http://node.example.com:8080".into()),
        transport_port: None,
        ..DetectNatOptions::default()
    };
    let p = detect_nat(opts).await;
    assert_eq!(p.tier, 0);
    assert_eq!(p.transport_method, TransportMethod::Direct);
    assert_eq!(p.public_endpoint.as_deref(), Some("http://node.example.com:8080"));
    assert!(p.is_reachable());
}

#[tokio::test]
async fn test_detect_nat_tier_0_falls_through_when_non_routable() {
    // operator_public_endpoint is localhost → fails looks_routable → tier 1
    // UPnP attempted with very short timeout → tier 4 unreachable.
    let opts = DetectNatOptions {
        bind_host: "0.0.0.0".into(),
        bind_port: 8080,
        operator_public_endpoint: Some("http://localhost:8080".into()),
        timeout: Duration::from_millis(50), // UPnP discovery times out fast
        transport_port: None,
        ..DetectNatOptions::default()
    };
    let p = detect_nat(opts).await;
    assert_eq!(p.tier, 4);
    assert_eq!(p.transport_method, TransportMethod::Unreachable);
    assert!(p
        .detection_log
        .iter()
        .any(|line| line.contains("non-routable")));
}

#[tokio::test]
async fn test_detect_nat_no_operator_endpoint_runs_tier_1() {
    let opts = DetectNatOptions {
        bind_host: "0.0.0.0".into(),
        bind_port: 8080,
        timeout: Duration::from_millis(50),
        transport_port: None,
        ..DetectNatOptions::default()
    };
    let p = detect_nat(opts).await;
    // tier 1 will fail in CI (no UPnP-capable router) → tier 4 with guidance.
    assert_eq!(p.tier, 4);
    assert!(p.operator_guidance.is_some());
}
