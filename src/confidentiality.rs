// SPDX-License-Identifier: Apache-2.0
//! IICP-CX S.16 Tier-1 confidentiality: X25519-HKDF-SHA256 + AES-256-GCM.
//!
//! CX-Consumer side: encrypts task payloads for nodes advertising cx_public_key.
//! CX-Provider side (decryption) is also provided for adapter/testing use.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hkdf::Hkdf;
use rand::RngCore;
use serde_json::Value;
use sha2::Sha256;
use std::collections::HashMap;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::errors::{IicpError, Result};
use crate::types::CxPublicKey;

fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn b64url_decode(s: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}

/// Encrypt a task payload using the node's X25519 public key (CX-Consumer, IICP-CX §5).
pub fn encrypt_payload(
    payload: &Value,
    cx_public_key: &CxPublicKey,
    task_id: &str,
    intent: &str,
) -> Result<HashMap<String, Value>> {
    if cx_public_key.algorithm != "X25519" {
        return Err(IicpError::Node(format!(
            "Unsupported cx_public_key algorithm: {}",
            cx_public_key.algorithm
        )));
    }

    let node_pub_bytes = b64url_decode(&cx_public_key.key)
        .map_err(|e| IicpError::Node(format!("cx_public_key decode error: {e}")))?;
    if node_pub_bytes.len() != 32 {
        return Err(IicpError::Node(
            "cx_public_key must be 32 bytes".to_string(),
        ));
    }
    let mut node_pub_arr = [0u8; 32];
    node_pub_arr.copy_from_slice(&node_pub_bytes);
    let node_pub = PublicKey::from(node_pub_arr);

    // Generate ephemeral X25519 key pair
    let ephem_priv = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephem_pub = PublicKey::from(&ephem_priv);
    let shared_secret = ephem_priv.diffie_hellman(&node_pub);

    // Generate nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // HKDF-SHA256
    let info = format!("IICP-CX-v1{task_id}{intent}");
    let hk = Hkdf::<Sha256>::new(Some(&nonce_bytes), shared_secret.as_bytes());
    let mut key_material = [0u8; 32];
    hk.expand(info.as_bytes(), &mut key_material)
        .map_err(|_| IicpError::Node("HKDF expand failed".to_string()))?;

    // AES-256-GCM encrypt
    let payload_json = serde_json::to_vec(payload)
        .map_err(|e| IicpError::Node(format!("payload serialization: {e}")))?;
    let aad = format!("{task_id}|{intent}");
    let cipher = Aes256Gcm::new_from_slice(&key_material)
        .map_err(|_| IicpError::Node("AES key error".to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &payload_json,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| IicpError::Node("AES-GCM encrypt failed".to_string()))?;

    let plaintext_size = payload_json.len() as u64;
    let mut envelope = HashMap::new();
    envelope.insert("version".to_string(), Value::Number(1.into()));
    envelope.insert(
        "recipient_key_id".to_string(),
        Value::String(cx_public_key.key_id.clone()),
    );
    envelope.insert(
        "kem_ciphertext".to_string(),
        Value::String(b64url_encode(ephem_pub.as_bytes())),
    );
    envelope.insert(
        "encrypted_body".to_string(),
        Value::String(b64url_encode(&ciphertext)),
    );
    envelope.insert(
        "nonce".to_string(),
        Value::String(b64url_encode(&nonce_bytes)),
    );
    envelope.insert(
        "aad".to_string(),
        Value::String(b64url_encode(aad.as_bytes())),
    );
    envelope.insert(
        "plaintext_size".to_string(),
        Value::Number(plaintext_size.into()),
    );
    Ok(envelope)
}

/// Decrypt an iicp_conf envelope (CX-Provider / adapter side, IICP-CX §5).
pub fn decrypt_payload(
    iicp_conf: &HashMap<String, Value>,
    private_key_bytes: &[u8; 32],
) -> Result<Value> {
    let static_priv = StaticSecret::from(*private_key_bytes);

    let kem_ct = iicp_conf
        .get("kem_ciphertext")
        .and_then(Value::as_str)
        .ok_or_else(|| IicpError::Node("missing kem_ciphertext".to_string()))?;
    let ephem_pub_bytes = b64url_decode(kem_ct)
        .map_err(|e| IicpError::Node(format!("kem_ciphertext decode: {e}")))?;
    if ephem_pub_bytes.len() != 32 {
        return Err(IicpError::Node(
            "kem_ciphertext must be 32 bytes".to_string(),
        ));
    }
    let mut ephem_pub_arr = [0u8; 32];
    ephem_pub_arr.copy_from_slice(&ephem_pub_bytes);
    let ephem_pub = PublicKey::from(ephem_pub_arr);
    let shared_secret = static_priv.diffie_hellman(&ephem_pub);

    let nonce_str = iicp_conf
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| IicpError::Node("missing nonce".to_string()))?;
    let nonce_bytes =
        b64url_decode(nonce_str).map_err(|e| IicpError::Node(format!("nonce decode: {e}")))?;

    let aad_str = iicp_conf
        .get("aad")
        .and_then(Value::as_str)
        .ok_or_else(|| IicpError::Node("missing aad".to_string()))?;
    let aad_bytes =
        b64url_decode(aad_str).map_err(|e| IicpError::Node(format!("aad decode: {e}")))?;
    let aad_text = String::from_utf8(aad_bytes.clone())
        .map_err(|e| IicpError::Node(format!("aad utf8: {e}")))?;
    let pipe = aad_text
        .find('|')
        .ok_or_else(|| IicpError::Node("aad missing task_id|intent separator".to_string()))?;
    let task_id = &aad_text[..pipe];
    let intent = &aad_text[pipe + 1..];

    let info = format!("IICP-CX-v1{task_id}{intent}");
    let hk = Hkdf::<Sha256>::new(Some(&nonce_bytes), shared_secret.as_bytes());
    let mut key_material = [0u8; 32];
    hk.expand(info.as_bytes(), &mut key_material)
        .map_err(|_| IicpError::Node("HKDF expand failed".to_string()))?;

    let enc_body_str = iicp_conf
        .get("encrypted_body")
        .and_then(Value::as_str)
        .ok_or_else(|| IicpError::Node("missing encrypted_body".to_string()))?;
    let enc_body = b64url_decode(enc_body_str)
        .map_err(|e| IicpError::Node(format!("encrypted_body decode: {e}")))?;

    let cipher = Aes256Gcm::new_from_slice(&key_material)
        .map_err(|_| IicpError::Node("AES key error".to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &enc_body,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| {
            IicpError::Node("AES-GCM decrypt failed (wrong key or tampered)".to_string())
        })?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| IicpError::Node(format!("plaintext JSON parse: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

    fn generate_test_keypair() -> (CxPublicKey, [u8; 32]) {
        let priv_key = StaticSecret::random_from_rng(rand::thread_rng());
        let pub_key = X25519Pub::from(&priv_key);
        let pub_bytes = pub_key.as_bytes();
        let key_id = format!(
            "{:x}",
            u64::from_be_bytes(pub_bytes[..8].try_into().unwrap())
        );
        let cx_public_key = CxPublicKey {
            algorithm: "X25519".to_string(),
            key: b64url_encode(pub_bytes),
            key_id,
        };
        let priv_bytes: [u8; 32] = *priv_key.as_bytes();
        (cx_public_key, priv_bytes)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (cx_key, priv_bytes) = generate_test_keypair();
        let payload = serde_json::json!({"messages": [{"role": "user", "content": "hi"}]});
        let env =
            encrypt_payload(&payload, &cx_key, "task-001", "urn:iicp:intent:llm:chat:v1").unwrap();
        let recovered = decrypt_payload(&env, &priv_bytes).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_encrypt_fields_present() {
        let (cx_key, _) = generate_test_keypair();
        let env = encrypt_payload(
            &serde_json::json!({}),
            &cx_key,
            "t1",
            "urn:iicp:intent:llm:chat:v1",
        )
        .unwrap();
        assert_eq!(env["version"], serde_json::json!(1));
        assert!(env.contains_key("kem_ciphertext"));
        assert!(env.contains_key("encrypted_body"));
        assert!(env.contains_key("nonce"));
        assert!(env.contains_key("aad"));
    }

    #[test]
    fn test_nonces_are_unique() {
        let (cx_key, _) = generate_test_keypair();
        let env1 = encrypt_payload(
            &serde_json::json!({}),
            &cx_key,
            "t1",
            "urn:iicp:intent:llm:chat:v1",
        )
        .unwrap();
        let env2 = encrypt_payload(
            &serde_json::json!({}),
            &cx_key,
            "t1",
            "urn:iicp:intent:llm:chat:v1",
        )
        .unwrap();
        assert_ne!(env1["nonce"], env2["nonce"]);
    }

    #[test]
    fn test_wrong_key_fails() {
        let (cx_key, _) = generate_test_keypair();
        let (_, wrong_priv) = generate_test_keypair();
        let env = encrypt_payload(
            &serde_json::json!({}),
            &cx_key,
            "t1",
            "urn:iicp:intent:llm:chat:v1",
        )
        .unwrap();
        assert!(decrypt_payload(&env, &wrong_priv).is_err());
    }

    #[test]
    fn test_unsupported_algorithm_fails() {
        let bad_key = CxPublicKey {
            algorithm: "RSA".to_string(),
            key: "abc".to_string(),
            key_id: "00000000".to_string(),
        };
        assert!(encrypt_payload(&serde_json::json!({}), &bad_key, "t1", "intent").is_err());
    }
}
