// SPDX-License-Identifier: Apache-2.0
//! #460 — at-rest encryption of the operator secret (ed25519 seed) in `operator.json`.
//!
//! The operator_secret is the private key behind the operator_id; by default it is stored as
//! plaintext base64 in a 0600 file. An operator may opt in to passphrase encryption: the seed
//! is sealed with AES-256-GCM, the key derived from the passphrase with PBKDF2-HMAC-SHA256
//! (OWASP-2023 iteration count). Both primitives use crates ALREADY present in this SDK
//! (`aes-gcm`, `hmac`, `sha2`, `rand`) — no new dependency, so this never trips the
//! third-party due-diligence gate (TC-11). PBKDF2 is built directly from the present
//! `hmac`+`sha2` (RFC 8018 §5.2) rather than adding a `pbkdf2` crate.
//!
//! The encrypted record byte-shape is identical to the Python/TS SDKs — a file sealed by one
//! opens in another given the passphrase (pinned by a cross-language KAT). The operator_id is
//! bound as AES-GCM additional authenticated data (AAD): a sealed seed cannot be transplanted
//! onto a different identity. Unlock is headless via `$IICP_OPERATOR_PASSPHRASE`.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// OWASP 2023 minimum for PBKDF2-HMAC-SHA256. Stored in the record so it can be raised later
/// without breaking existing files (decrypt reads the stored count).
pub const PBKDF2_ITERATIONS: u32 = 600_000;
const KDF: &str = "pbkdf2-hmac-sha256";
const VERSION: u8 = 1;
/// Headless unlock env var.
pub const ENV_PASSPHRASE: &str = "IICP_OPERATOR_PASSPHRASE";

/// The AES-256-GCM-sealed seed record. Field set/names are byte-shape-identical across SDKs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecret {
    pub v: u8,
    pub kdf: String,
    pub iter: u32,
    pub salt: String,
    pub nonce: String,
    /// base64(ciphertext || 16-byte GCM tag) — matches Python `cryptography` AESGCM / Node.
    pub ct: String,
}

/// PBKDF2-HMAC-SHA256, single 32-byte output block (dkLen == hLen). RFC 8018 §5.2.
fn pbkdf2_hmac_sha256_32(passphrase: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let prf = |data: &[u8]| -> [u8; 32] {
        // Disambiguate new_from_slice: both aes_gcm::KeyInit and hmac::Mac are in scope.
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(passphrase).expect("hmac accepts any key length");
        mac.update(data);
        let mut block = [0u8; 32];
        block.copy_from_slice(&mac.finalize().into_bytes());
        block
    };
    // U_1 = PRF(P, S || INT_32_BE(1)); F = U_1 xor U_2 xor ... xor U_c.
    let mut salt_idx = Vec::with_capacity(salt.len() + 4);
    salt_idx.extend_from_slice(salt);
    salt_idx.extend_from_slice(&1u32.to_be_bytes());
    let mut u = prf(&salt_idx);
    let mut out = u;
    for _ in 1..iterations {
        u = prf(&u);
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out
}

/// Seal the raw 32-byte ed25519 seed (given as base64) under `passphrase`. operator_id is AAD.
pub fn encrypt_seed(
    passphrase: &str,
    seed_b64: &str,
    operator_id: &str,
) -> Result<EncryptedSecret, String> {
    if passphrase.is_empty() {
        return Err("passphrase must not be empty".into());
    }
    let seed = STANDARD
        .decode(seed_b64)
        .map_err(|e| format!("bad seed base64: {e}"))?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = pbkdf2_hmac_sha256_32(passphrase.as_bytes(), &salt, PBKDF2_ITERATIONS);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "AES key error".to_string())?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &seed,
                aad: operator_id.as_bytes(),
            },
        )
        .map_err(|_| "AES-GCM encrypt failed".to_string())?;
    Ok(EncryptedSecret {
        v: VERSION,
        kdf: KDF.to_string(),
        iter: PBKDF2_ITERATIONS,
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce),
        ct: STANDARD.encode(ct),
    })
}

/// Open an encrypted record → base64 seed. Errors on wrong passphrase / tamper / wrong AAD.
pub fn decrypt_seed(
    passphrase: &str,
    enc: &EncryptedSecret,
    operator_id: &str,
) -> Result<String, String> {
    if enc.kdf != KDF || enc.v != VERSION {
        return Err(format!(
            "unsupported operator_secret_enc format: {} v{}",
            enc.kdf, enc.v
        ));
    }
    let salt = STANDARD
        .decode(&enc.salt)
        .map_err(|e| format!("bad salt: {e}"))?;
    let nonce = STANDARD
        .decode(&enc.nonce)
        .map_err(|e| format!("bad nonce: {e}"))?;
    let ct = STANDARD
        .decode(&enc.ct)
        .map_err(|e| format!("bad ct: {e}"))?;
    let key = pbkdf2_hmac_sha256_32(passphrase.as_bytes(), &salt, enc.iter);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "AES key error".to_string())?;
    let seed = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ct,
                aad: operator_id.as_bytes(),
            },
        )
        .map_err(|_| {
            "operator secret decryption failed (wrong passphrase or corrupt file)".to_string()
        })?;
    Ok(STANDARD.encode(seed))
}

/// Headless unlock source — never an interactive prompt for a serving node.
pub fn passphrase_from_env() -> Option<String> {
    std::env::var(ENV_PASSPHRASE).ok().filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cross-language KAT — MUST decrypt identically in the Python and TS SDKs (same inputs).
    const PASSPHRASE: &str = "correct horse battery staple";
    const OPERATOR_ID: &str = "T3BQdWI="; // AAD
    const SEED_B64: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";

    fn kat_record() -> EncryptedSecret {
        EncryptedSecret {
            v: 1,
            kdf: "pbkdf2-hmac-sha256".to_string(),
            iter: 600_000,
            salt: "AAECAwQFBgcICQoLDA0ODw==".to_string(),
            nonce: "EBESExQVFhcYGRob".to_string(),
            ct: "LDNf5jTajlDjk7Pj4N5a1SEJqNeyUuCc+wkh0fSEftCq1ypsedl8nLMPuMZQ7Xvl".to_string(),
        }
    }

    #[test]
    fn opens_cross_language_kat_record() {
        // Pins KDF params + AEAD + AAD + byte-shape against the Python/TS SDKs.
        assert_eq!(
            decrypt_seed(PASSPHRASE, &kat_record(), OPERATOR_ID).unwrap(),
            SEED_B64
        );
    }

    #[test]
    fn encrypt_then_decrypt_round_trip() {
        let enc = encrypt_seed("hunter2", SEED_B64, OPERATOR_ID).unwrap();
        assert_eq!(enc.kdf, "pbkdf2-hmac-sha256");
        assert_ne!(enc.ct, kat_record().ct); // fresh salt/nonce
        assert_eq!(
            decrypt_seed("hunter2", &enc, OPERATOR_ID).unwrap(),
            SEED_B64
        );
    }

    #[test]
    fn wrong_passphrase_fails() {
        let enc = encrypt_seed("right", SEED_B64, OPERATOR_ID).unwrap();
        assert!(decrypt_seed("WRONG", &enc, OPERATOR_ID).is_err());
    }

    #[test]
    fn aad_binds_operator_id() {
        let enc = encrypt_seed("pw", SEED_B64, OPERATOR_ID).unwrap();
        assert!(decrypt_seed("pw", &enc, "different-operator-id").is_err());
    }
}
