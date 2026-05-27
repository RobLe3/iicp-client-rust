// SPDX-License-Identifier: Apache-2.0
//! Unit tests for ADR-019 pricing + HMAC signing. Rust port of the Python
//! test matrix. Same wire-compat check for PHP float→integer collapse.

use hmac::{Hmac, Mac};
use iicp_client::node::{IicpNode, NodeConfig};
use iicp_client::pricing::{
    build_pricing_block, php_canonical_sign_body, sign_body, verify_signature, PricingConfig,
};
use serde_json::json;
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

// ── HMAC primitive ─────────────────────────────────────────────────────────

#[test]
fn test_sign_body_matches_hmac_crate_reference() {
    let body = b"hello world";
    let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
    mac.update(body);
    let expected = hex::encode(mac.finalize().into_bytes());
    let got = sign_body(body, "secret");
    assert_eq!(got, expected);
}

#[test]
fn test_verify_signature_round_trip() {
    let body = b"hello";
    let sig = sign_body(body, "k");
    assert!(verify_signature(body, "k", &sig));
    assert!(!verify_signature(body, "k", "deadbeef"));
    assert!(!verify_signature(body, "wrong-key", &sig));
}

// ── PHP canonical body (wire-compat) ───────────────────────────────────────

#[test]
fn test_whole_float_emits_integer_form() {
    let body = php_canonical_sign_body(1.0, "per_token");
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        "{\"credit_cost_multiplier\":1,\"pricing_model\":\"per_token\"}"
    );
}

#[test]
fn test_fractional_float_emits_decimal() {
    let body = php_canonical_sign_body(1.5, "per_token");
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        "{\"credit_cost_multiplier\":1.5,\"pricing_model\":\"per_token\"}"
    );
}

#[test]
fn test_byte_equal_hmac_vs_reference() {
    let body = php_canonical_sign_body(1.5, "per_token");
    let mut mac = HmacSha256::new_from_slice(b"test-secret-key").unwrap();
    mac.update(&body);
    let expected = hex::encode(mac.finalize().into_bytes());
    assert_eq!(sign_body(&body, "test-secret-key"), expected);
}

// ── build_pricing_block ────────────────────────────────────────────────────

#[test]
fn test_unsigned_when_sign_disabled() {
    let p = PricingConfig {
        credit_cost_multiplier: 1.5,
        ..Default::default()
    };
    let block = build_pricing_block(&p, "k");
    assert!(block.get("declaration_signature").is_none());
    assert_eq!(block["credit_cost_multiplier"], 1.5);
    assert_eq!(block["pricing_model"], "per_token");
}

#[test]
fn test_unsigned_when_enabled_but_no_key() {
    let p = PricingConfig {
        credit_cost_multiplier: 1.5,
        sign_declarations: true,
        ..Default::default()
    };
    let block = build_pricing_block(&p, "");
    assert!(block.get("declaration_signature").is_none());
}

#[test]
fn test_signed_when_enabled_with_key() {
    let p = PricingConfig {
        credit_cost_multiplier: 1.5,
        sign_declarations: true,
        ..Default::default()
    };
    let block = build_pricing_block(&p, "k");
    let sig = block["declaration_signature"].as_str().unwrap();
    let body = php_canonical_sign_body(1.5, "per_token");
    assert!(verify_signature(&body, "k", sig));
}

#[test]
fn test_effective_window_pass_through() {
    let p = PricingConfig {
        credit_cost_multiplier: 1.0,
        effective_from: Some("2026-06-01T00:00:00Z".into()),
        effective_until: Some("2026-12-31T23:59:59Z".into()),
        ..Default::default()
    };
    let block = build_pricing_block(&p, "");
    assert_eq!(block["effective_from"], "2026-06-01T00:00:00Z");
    assert_eq!(block["effective_until"], "2026-12-31T23:59:59Z");
}

// ── Register payload integration ───────────────────────────────────────────

#[tokio::test]
async fn test_register_without_pricing_emits_no_block() {
    use mockito::{Matcher, Server};

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/v1/register")
        .with_status(201)
        .with_body(r#"{"node_token":"t","node_id":"n"}"#)
        .match_body(Matcher::Any)
        .create_async()
        .await;

    let mut cfg = NodeConfig::new("n", "https://provider:8080", "urn:iicp:intent:llm:chat:v1");
    cfg.directory_url = server.url();
    cfg.model = Some("q".into());
    let node = IicpNode::new(cfg);
    assert!(node.register().await.is_ok());
}

#[tokio::test]
async fn test_register_with_pricing_emits_block() {
    use mockito::{Matcher, Server};

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/v1/register")
        .match_body(Matcher::PartialJson(json!({
            "pricing": {
                "credit_cost_multiplier": 1.5,
                "pricing_model": "per_token"
            }
        })))
        .with_status(201)
        .with_body(r#"{"node_token":"t","node_id":"n"}"#)
        .create_async()
        .await;

    let mut cfg = NodeConfig::new("n", "https://provider:8080", "urn:iicp:intent:llm:chat:v1");
    cfg.directory_url = server.url();
    cfg.model = Some("q".into());
    cfg.pricing = Some(PricingConfig {
        credit_cost_multiplier: 1.5,
        ..Default::default()
    });
    let node = IicpNode::new(cfg);
    assert!(node.register().await.is_ok());
}

#[tokio::test]
async fn test_register_signs_with_operator_key() {
    use mockito::{Matcher, Server};

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/v1/register")
        .match_body(Matcher::PartialJson(json!({
            "node_hmac_key": "op-key"
        })))
        .with_status(201)
        .with_body(r#"{"node_token":"t","node_id":"n"}"#)
        .create_async()
        .await;

    let mut cfg = NodeConfig::new("n", "https://provider:8080", "urn:iicp:intent:llm:chat:v1");
    cfg.directory_url = server.url();
    cfg.model = Some("q".into());
    cfg.pricing = Some(PricingConfig {
        credit_cost_multiplier: 1.5,
        sign_declarations: true,
        ..Default::default()
    });
    cfg.node_hmac_key = "op-key".into();
    let node = IicpNode::new(cfg);
    assert!(node.register().await.is_ok());
}

#[tokio::test]
async fn test_register_captures_directory_issued_hmac_key() {
    use mockito::Server;

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/v1/register")
        .with_status(201)
        .with_body(r#"{"node_token":"t","node_id":"n","node_hmac_key":"dir-key-deadbeef"}"#)
        .create_async()
        .await;

    let mut cfg = NodeConfig::new("n", "https://provider:8080", "urn:iicp:intent:llm:chat:v1");
    cfg.directory_url = server.url();
    cfg.model = Some("q".into());
    let node = IicpNode::new(cfg);
    assert!(node.register().await.is_ok());
    assert_eq!(node.node_hmac_key(), "dir-key-deadbeef");
}

#[tokio::test]
async fn test_operator_key_wins_over_directory_issued() {
    use mockito::Server;

    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/v1/register")
        .with_status(201)
        .with_body(r#"{"node_token":"t","node_id":"n","node_hmac_key":"dir-tried"}"#)
        .create_async()
        .await;

    let mut cfg = NodeConfig::new("n", "https://provider:8080", "urn:iicp:intent:llm:chat:v1");
    cfg.directory_url = server.url();
    cfg.model = Some("q".into());
    cfg.node_hmac_key = "op-set".into();
    let node = IicpNode::new(cfg);
    assert!(node.register().await.is_ok());
    assert_eq!(node.node_hmac_key(), "op-set");
}
