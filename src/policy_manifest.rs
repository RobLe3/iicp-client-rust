// SPDX-License-Identifier: Apache-2.0
//! Local signed node-policy manifest producer (#588).

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort();
            let mut normalized = Map::new();
            for key in keys {
                normalized.insert(key.clone(), sorted(&object[key]));
            }
            Value::Object(normalized)
        }
        Value::Array(values) => Value::Array(values.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// Return the exact compact JSON bytes verified by the directory.
///
/// The detached signature value itself is excluded while the remaining
/// signature metadata stays bound into the signed payload.
pub fn canonical_policy_manifest(manifest: &Value) -> Result<Vec<u8>, String> {
    let mut copy = manifest.clone();
    let object = copy
        .as_object_mut()
        .ok_or_else(|| "policy manifest must be a JSON object".to_string())?;
    match object.get_mut("signature") {
        Some(Value::Object(signature)) => {
            signature.remove("signature");
        }
        _ => {
            object.remove("signature");
        }
    }
    serde_json::to_vec(&sorted(&copy)).map_err(|e| format!("cannot serialize policy manifest: {e}"))
}

/// Load a local JSON policy manifest and attach a 90-day Ed25519 signature.
pub fn load_and_sign_policy_manifest(
    path: impl AsRef<Path>,
    operator_id: &str,
    signing_key: &SigningKey,
    now: Option<DateTime<Utc>>,
) -> Result<Value, String> {
    let bytes =
        std::fs::read(path.as_ref()).map_err(|e| format!("cannot read policy manifest: {e}"))?;
    let mut manifest: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("cannot read policy manifest: {e}"))?;
    let object = manifest
        .as_object_mut()
        .ok_or_else(|| "policy manifest must be a JSON object".to_string())?;
    object.remove("signature");

    let public_key = STANDARD
        .decode(operator_id)
        .map_err(|e| format!("operator_id is not valid base64: {e}"))?;
    if public_key.as_slice() != signing_key.verifying_key().as_bytes() {
        return Err("operator_id does not match the operator signing key".to_string());
    }
    let instant = now.unwrap_or_else(Utc::now);
    let signature_block = serde_json::json!({
        "algorithm": "Ed25519",
        "key_id": hex::encode(Sha256::digest(&public_key))[..12].to_string(),
        "public_key": operator_id,
        "signed_at": instant.to_rfc3339_opts(SecondsFormat::Secs, true),
        "expires_at": (instant + Duration::days(90)).to_rfc3339_opts(SecondsFormat::Secs, true),
    });
    manifest["signature"] = signature_block;
    let canonical = canonical_policy_manifest(&manifest)?;
    let detached = signing_key.sign(&canonical);
    manifest["signature"]["signature"] = Value::String(STANDARD.encode(detached.to_bytes()));
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    #[test]
    fn signs_directory_compatible_manifest_and_replaces_old_signature() {
        let dir = std::env::temp_dir().join(format!("iicp-policy-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(
            &dir,
            r#"{"version":"1","jurisdiction":"DE","retention":{"task_payload":"none"},"signature":{"signature":"stale"}}"#,
        )
        .unwrap();
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let operator_id = STANDARD.encode(signing_key.verifying_key().to_bytes());
        let now = DateTime::parse_from_rfc3339("2026-07-10T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let manifest =
            load_and_sign_policy_manifest(&dir, &operator_id, &signing_key, Some(now)).unwrap();
        let encoded = manifest["signature"]["signature"].as_str().unwrap();
        let bytes: [u8; 64] = STANDARD.decode(encoded).unwrap().try_into().unwrap();
        signing_key
            .verifying_key()
            .verify(
                &canonical_policy_manifest(&manifest).unwrap(),
                &Signature::from_bytes(&bytes),
            )
            .unwrap();
        assert_eq!(
            manifest["signature"]["key_id"],
            hex::encode(Sha256::digest(signing_key.verifying_key().to_bytes()))[..12]
        );
        assert_eq!(manifest["signature"]["signed_at"], "2026-07-10T00:00:00Z");
        assert_eq!(manifest["signature"]["expires_at"], "2026-10-08T00:00:00Z");
        assert_eq!(
            manifest["signature"]["signature"],
            "Horps0SnJ4lenW97Z/vAEEihQ4/ICfBFo//uF4r808FuZzopAXzz2V3vgFXarl1FdPMXwndIo/7qP2/aXMZrAw=="
        );
        let _ = std::fs::remove_file(dir);
    }

    #[test]
    fn rejects_non_object_and_mismatched_identity() {
        let dir = std::env::temp_dir().join(format!("iicp-policy-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&dir, "[]").unwrap();
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        assert!(load_and_sign_policy_manifest(&dir, "bad", &signing_key, None).is_err());
        std::fs::write(&dir, "{}").unwrap();
        let wrong = STANDARD.encode(
            SigningKey::from_bytes(&[8u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(load_and_sign_policy_manifest(&dir, &wrong, &signing_key, None).is_err());
        let _ = std::fs::remove_file(dir);
    }
}
