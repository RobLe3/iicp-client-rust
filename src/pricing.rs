// SPDX-License-Identifier: Apache-2.0
//! ADR-019 declarative pricing + HMAC-SHA256 signing — provider-side.
//!
//! Rust port of iicp-client-python `pricing.py` (iter-1432) and
//! iicp-client-typescript `pricing.ts` (iter-1433). Tier 2 Item 3 of #340
//! closing across all 3 hybrid SDKs.
//!
//! Same wire-compat handling: PHP's `json_encode(1.0)` returns `"1"` (drops
//! zero fraction). [`php_canonical_sign_body`] mirrors that exactly so HMAC
//! signatures verify byte-for-byte against the directory's
//! NodeRegistry::resolvePricingBlock.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// ADR-019 pricing declaration block (operator-controlled).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingConfig {
    /// Float ≥ 0 applied to base rate. Default 1.0.
    pub credit_cost_multiplier: f64,
    /// Only `"per_token"` defined in v1.
    #[serde(default = "default_pricing_model")]
    pub pricing_model: String,
    /// When true AND a node_hmac_key is set, sign the body so the directory
    /// marks `pricing.attested=true` in /v1/discover.
    #[serde(default)]
    pub sign_declarations: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
}

fn default_pricing_model() -> String {
    "per_token".into()
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            credit_cost_multiplier: 1.0,
            pricing_model: default_pricing_model(),
            sign_declarations: false,
            effective_from: None,
            effective_until: None,
        }
    }
}

// ── HMAC helpers ────────────────────────────────────────────────────────

/// HMAC-SHA256 hex digest. Matches PHP's `hash_hmac('sha256', $body, $key)`.
pub fn sign_body(body: &[u8], secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
    mac.update(body);
    hex_encode(&mac.finalize().into_bytes())
}

/// Constant-time signature comparison.
pub fn verify_signature(body: &[u8], secret: &str, signature: &str) -> bool {
    let expected = sign_body(body, secret);
    expected.as_bytes().ct_eq(signature.as_bytes()).into()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Encode the pricing-block signature body the way the directory's PHP
/// `json_encode(ksort($body))` does, so HMAC verification succeeds across
/// the language gap.
///
/// Mirrors the Python `_php_canonical_sign_body` byte-for-byte:
///   - keys sorted alphabetically
///   - whole-float values emit WITHOUT a fractional zero (PHP collapses
///     `json_encode(1.0)` to `"1"`)
///   - non-whole floats use the natural decimal representation
///   - no whitespace
pub fn php_canonical_sign_body(credit_cost_multiplier: f64, pricing_model: &str) -> Vec<u8> {
    let num = if credit_cost_multiplier.is_finite()
        && credit_cost_multiplier == credit_cost_multiplier.trunc()
        && credit_cost_multiplier.abs() < 1e15
    {
        // Whole-number float — emit as integer to match PHP
        format!("{}", credit_cost_multiplier as i64)
    } else {
        // Fractional or out-of-int-range — use natural decimal repr.
        // f64's Display is RFC-compliant minimal decimal which matches
        // PHP json_encode for typical pricing multipliers (0.1..1000.0).
        format!("{credit_cost_multiplier}")
    };
    // pricing_model: JSON-escape via serde so weird chars don't break the body.
    let model_json = serde_json::to_string(pricing_model).unwrap_or_else(|_| "\"\"".into());
    format!("{{\"credit_cost_multiplier\":{num},\"pricing_model\":{model_json}}}").into_bytes()
}

/// Build the `pricing` sub-object the directory accepts in /v1/register.
pub fn build_pricing_block(pricing: &PricingConfig, hmac_key: &str) -> serde_json::Value {
    let mut block = serde_json::json!({
        "credit_cost_multiplier": pricing.credit_cost_multiplier,
        "pricing_model": pricing.pricing_model,
    });
    if pricing.sign_declarations && !hmac_key.is_empty() {
        let body = php_canonical_sign_body(pricing.credit_cost_multiplier, &pricing.pricing_model);
        block["declaration_signature"] = serde_json::Value::String(sign_body(&body, hmac_key));
    }
    if let Some(f) = &pricing.effective_from {
        block["effective_from"] = serde_json::Value::String(f.clone());
    }
    if let Some(u) = &pricing.effective_until {
        block["effective_until"] = serde_json::Value::String(u.clone());
    }
    block
}
