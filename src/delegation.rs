// SPDX-License-Identifier: Apache-2.0
//! ADR-045 Phase A — operator→node delegation (Ed25519).
//!
//! A fleet operator holds an Ed25519 keypair and issues a compact, offline-signed token
//! asserting "node `<node_id>` is operated by `<operator_pub>` until `<not_after>`". The node
//! attaches it at REGISTER; any federated directory verifies it offline (PHP
//! `OperatorDelegationVerifier`). The CANONICAL signing bytes MUST be byte-identical across the
//! PHP verifier, the TypeScript signer, the Python signer, and this one — pinned by a
//! cross-language known-answer test (KAT). Short-TTL `not_after` is the revocation baseline
//! (ADR-045 OPEN-3 C).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// A delegation token (matches the PHP/TS wire shape): `node_id`, `operator_pub` (base64 of the
/// 32-byte Ed25519 pubkey), `not_after` (unix seconds), `sig` (base64 of the 64-byte signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    pub node_id: String,
    pub operator_pub: String,
    pub not_after: u64,
    pub sig: String,
}

/// Exact bytes the operator signs / the directory verifies. Key order is
/// `node_id < not_after < operator_pub` (alphabetical), no spaces — byte-identical to PHP
/// `OperatorDelegationVerifier::canonicalBytes` and the TS signer (cross-language KAT).
pub fn canonical_bytes(node_id: &str, operator_pub_b64: &str, not_after: u64) -> Vec<u8> {
    #[derive(Serialize)]
    struct Canonical<'a> {
        node_id: &'a str,
        not_after: u64,
        operator_pub: &'a str,
    }
    serde_json::to_vec(&Canonical {
        node_id,
        not_after,
        operator_pub: operator_pub_b64,
    })
    .expect("canonical delegation json is infallible")
}

/// #460 — exact bytes the operator signs to rename their public `display_name`. Key order is
/// `display_name < operator_pub < ts` (alphabetical), no spaces — byte-identical to PHP
/// `OperatorController::canonicalBytes`, the Rust directory `canonical_rename_bytes`, and the
/// Python/TS signers (cross-impl rename KAT). Do NOT reorder.
pub fn canonical_rename_bytes(display_name: &str, operator_pub_b64: &str, ts: i64) -> Vec<u8> {
    #[derive(Serialize)]
    struct Canonical<'a> {
        display_name: &'a str,
        operator_pub: &'a str,
        ts: i64,
    }
    serde_json::to_vec(&Canonical {
        display_name,
        operator_pub: operator_pub_b64,
        ts,
    })
    .expect("canonical rename json is infallible")
}

/// #460 — operator signs a display_name rename; returns base64 of the Ed25519 signature. Only
/// the operator key-holder can produce this, so the directory authenticates the mutation by
/// the signature alone (no node token).
pub fn sign_rename(
    key: &SigningKey,
    display_name: &str,
    operator_pub_b64: &str,
    ts: i64,
) -> String {
    let sig = key.sign(&canonical_rename_bytes(display_name, operator_pub_b64, ts));
    STANDARD.encode(sig.to_bytes())
}

/// Canonical #599/#609 operator acceptance/DSR challenge bytes. The caller supplies
/// all action-specific fields except `sig`; top-level keys are serialized in lexical order.
pub fn canonical_operator_self_service_bytes(
    action: &str,
    fields: &BTreeMap<String, Value>,
) -> Vec<u8> {
    let mut payload = fields.clone();
    payload.remove("sig");
    payload.insert("action".to_string(), Value::String(action.to_string()));
    let mut out = b"iicp:operator:self-service:v1\n".to_vec();
    out.extend(serde_json::to_vec(&payload).expect("canonical operator self-service json"));
    out
}

/// Sign an operator acceptance or DSR request without exposing the private key.
pub fn sign_operator_self_service(
    key: &SigningKey,
    action: &str,
    fields: &BTreeMap<String, Value>,
) -> String {
    STANDARD.encode(
        key.sign(&canonical_operator_self_service_bytes(action, fields))
            .to_bytes(),
    )
}

/// Base64 (standard, padded) of the operator's raw 32-byte Ed25519 public key — the form the
/// directory stores and the token carries.
pub fn operator_pub_b64(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().to_bytes())
}

/// Operator (offline) signs a delegation for one node. `ttl_seconds` sets `not_after` =
/// now + ttl (short TTL = revocation baseline, OPEN-3 C).
pub fn issue_delegation(key: &SigningKey, node_id: &str, ttl_seconds: u64) -> Delegation {
    let pub_b64 = operator_pub_b64(key);
    let not_after = now_unix() + ttl_seconds;
    let sig = key.sign(&canonical_bytes(node_id, &pub_b64, not_after));
    Delegation {
        node_id: node_id.to_string(),
        operator_pub: pub_b64,
        not_after,
        sig: STANDARD.encode(sig.to_bytes()),
    }
}

/// Verify a delegation against the node_id it is claimed for. Mirrors the PHP verifier order:
/// node_id match → not expired → signature valid over the canonical bytes. `Ok(())` or an error
/// reason ∈ {node_id_mismatch, expired, bad_operator_pub, bad_sig, bad_signature}.
pub fn verify_delegation(
    token: &Delegation,
    claimed_node_id: &str,
    now: u64,
) -> Result<(), &'static str> {
    if token.node_id != claimed_node_id {
        return Err("node_id_mismatch");
    }
    if now >= token.not_after {
        return Err("expired");
    }
    let pub_raw: [u8; 32] = STANDARD
        .decode(&token.operator_pub)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("bad_operator_pub")?;
    let sig_raw: [u8; 64] = STANDARD
        .decode(&token.sig)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("bad_sig")?;
    let vk = VerifyingKey::from_bytes(&pub_raw).map_err(|_| "bad_operator_pub")?;
    let sig = Signature::from_bytes(&sig_raw);
    vk.verify(
        &canonical_bytes(&token.node_id, &token.operator_pub, token.not_after),
        &sig,
    )
    .map_err(|_| "bad_signature")
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    // Cross-language KAT — MUST equal the PHP OperatorDelegationVerifier::canonicalBytes and
    // the TS signer (iicp-client-typescript/tests/delegation.test.ts).
    const KAT: &str =
        r#"{"node_id":"node-kat-1","not_after":1893456000,"operator_pub":"T3BQdWJLZXlCYXNlNjQ="}"#;

    #[test]
    fn canonical_bytes_match_cross_language_kat() {
        let b = canonical_bytes("node-kat-1", "T3BQdWJLZXlCYXNlNjQ=", 1_893_456_000);
        assert_eq!(String::from_utf8(b).unwrap(), KAT);
    }

    #[test]
    fn issue_then_verify_roundtrips() {
        let key = SigningKey::generate(&mut OsRng);
        let tok = issue_delegation(&key, "node-1", 3600);
        assert_eq!(STANDARD.decode(&tok.operator_pub).unwrap().len(), 32);
        assert_eq!(STANDARD.decode(&tok.sig).unwrap().len(), 64);
        assert_eq!(verify_delegation(&tok, "node-1", now_unix()), Ok(()));
    }

    // #460 rename KAT — MUST equal PHP OperatorController::canonicalBytes / the Rust directory
    // delegation::canonical_rename_bytes / the Python+TS signers for the same inputs.
    const RENAME_KAT: &str =
        r#"{"display_name":"New Name","operator_pub":"T3BQdWI=","ts":1893456000}"#;

    #[test]
    fn canonical_rename_bytes_match_cross_language_kat() {
        let b = canonical_rename_bytes("New Name", "T3BQdWI=", 1_893_456_000);
        assert_eq!(String::from_utf8(b).unwrap(), RENAME_KAT);
    }

    #[test]
    fn sign_rename_verifies_with_operator_pubkey() {
        // The operator_pub used to sign IS the operator_id (== base64 ed25519 pubkey, #464).
        let key = SigningKey::generate(&mut OsRng);
        let pub_b64 = operator_pub_b64(&key);
        let sig_b64 = sign_rename(&key, "Rebel Two", &pub_b64, 1_893_456_000);
        let sig_raw: [u8; 64] = STANDARD.decode(&sig_b64).unwrap().try_into().unwrap();
        let sig = Signature::from_bytes(&sig_raw);
        key.verifying_key()
            .verify(
                &canonical_rename_bytes("Rebel Two", &pub_b64, 1_893_456_000),
                &sig,
            )
            .expect("operator pubkey verifies its own rename signature");
    }

    #[test]
    fn operator_self_service_bytes_match_cross_language_kat() {
        let fields = BTreeMap::from([
            ("operator_pub".to_string(), Value::String("T3BQdWI=".to_string())),
            ("nonce".to_string(), Value::String("nonce-1234567890".to_string())),
            ("ts".to_string(), Value::from(1_893_456_000_i64)),
            ("terms_version".to_string(), Value::String("2026-07".to_string())),
            ("dpa_version".to_string(), Value::String("2026-07".to_string())),
        ]);
        assert_eq!(
            String::from_utf8(canonical_operator_self_service_bytes("accept", &fields)).unwrap(),
            "iicp:operator:self-service:v1\n{\"action\":\"accept\",\"dpa_version\":\"2026-07\",\"nonce\":\"nonce-1234567890\",\"operator_pub\":\"T3BQdWI=\",\"terms_version\":\"2026-07\",\"ts\":1893456000}"
        );
    }

    #[test]
    fn verify_rejects_mismatch_expiry_and_tamper() {
        let key = SigningKey::generate(&mut OsRng);
        let tok = issue_delegation(&key, "node-1", 3600);
        assert_eq!(
            verify_delegation(&tok, "other-node", now_unix()),
            Err("node_id_mismatch")
        );
        assert_eq!(
            verify_delegation(&tok, "node-1", tok.not_after + 1),
            Err("expired")
        );
        let mut tampered = tok.clone();
        tampered.not_after += 1; // signature no longer matches the canonical bytes
        assert_eq!(
            verify_delegation(&tampered, "node-1", now_unix()),
            Err("bad_signature")
        );
    }
}
