// SPDX-License-Identifier: Apache-2.0
//! Persistent on-disk identity for the IICP Rust SDK CLI.
//!
//! Mirrors `iicp_client.identity` (Python) and `identity.ts` (TypeScript)
//! so operators can switch SDK flavour without rewriting their config.
//!
//!  - Operator identity at `~/.iicp/operator.json` (one per machine)
//!  - Node identity at `~/.iicp/nodes/<name>.json` (one per provider node)
//!
//! Stable `node_id` survives restarts (#215). Files are chmod 0600 on
//! creation so other local users can't read tokens / identity.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use uuid::Uuid;

fn now_iso() -> String {
    // chrono-free format: YYYY-MM-DDTHH:MM:SSZ via std + simple math.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Compose a YYYY-MM-DDTHH:MM:SSZ stamp from secs since epoch.
    let (y, m, d, hh, mm, ss) = ymdhms_from_unix(now as i64);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn ymdhms_from_unix(t: i64) -> (i32, u32, u32, u32, u32, u32) {
    // Days since 1970-01-01 (Howard Hinnant's date algorithms — public domain).
    let secs = t.rem_euclid(86_400) as u32;
    let days = t.div_euclid(86_400);
    let hh = secs / 3600;
    let mm = (secs % 3600) / 60;
    let ss = secs % 60;
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i32 + (era as i32) * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, hh, mm, ss)
}

#[cfg(unix)]
fn chmod_600(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn chmod_600(_path: &Path) -> io::Result<()> {
    Ok(())
}

pub fn config_dir() -> io::Result<PathBuf> {
    let base = match std::env::var("IICP_HOME") {
        Ok(v) if !v.is_empty() => PathBuf::from(shellexpand_home(&v)),
        _ => {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".iicp")
        }
    };
    fs::create_dir_all(&base)?;
    fs::create_dir_all(base.join("nodes"))?;
    Ok(base)
}

fn shellexpand_home(s: &str) -> String {
    if let Some(rest) = s.strip_prefix('~') {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}{rest}");
        }
    }
    s.to_string()
}

/// #464 — the operator identity is an ed25519 keypair: `operator_id` IS the base64 public
/// key (== the directory's `operator_pubkey` via the ADR-045 delegation), so it is
/// cryptographically verifiable rather than a random UUID. `operator_secret` is the base64
/// 32-byte private seed — LOCAL ONLY (0600 file), never sent to the directory (password-at-rest
/// = #460). `operator_integrity_hash` binds the immutable fields (pinned by the directory on
/// first-use; the directory's own clock — not `created_at` — is authoritative for founder
/// ordinals). `display_name` is the public, mutable handle; `contact` is private.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorIdentity {
    pub operator_id: String,
    pub created_at: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub contact: String,
    /// base64 ed25519 private key (32-byte seed). Local-only secret.
    #[serde(default)]
    pub operator_secret: String,
    /// SHA256(operator_id ':' created_at), pinned by the directory on first use.
    #[serde(default)]
    pub operator_integrity_hash: String,
    /// #460 — AES-256-GCM-sealed seed when the operator opts into at-rest encryption; None for
    /// a plaintext (default/legacy) identity. Omitted from the file when None (clean plaintext).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_secret_enc: Option<crate::operator_crypto::EncryptedSecret>,
}

impl OperatorIdentity {
    pub fn generate(display_name: &str, contact: &str) -> Self {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let operator_id = STANDARD.encode(sk.verifying_key().to_bytes());
        let operator_secret = STANDARD.encode(sk.to_bytes());
        let created_at = now_iso();
        let operator_integrity_hash = Self::compute_integrity_hash(&operator_id, &created_at);
        Self {
            operator_id,
            created_at,
            display_name: display_name.to_string(),
            contact: contact.to_string(),
            operator_secret,
            operator_integrity_hash,
            operator_secret_enc: None,
        }
    }

    /// SHA256(operator_id ':' created_at), hex.
    pub fn compute_integrity_hash(operator_id: &str, created_at: &str) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(
            format!("{operator_id}:{created_at}").as_bytes(),
        ))
    }

    /// True when operator_id is a real ed25519 pubkey (not a legacy `op-<uuid>`).
    pub fn is_key_backed(&self) -> bool {
        (!self.operator_secret.is_empty() || self.operator_secret_enc.is_some())
            && !self.operator_id.starts_with("op-")
    }

    /// #460 — true when the seed is sealed at rest and a passphrase is needed to sign.
    pub fn is_encrypted(&self) -> bool {
        self.operator_secret_enc.is_some() && self.operator_secret.is_empty()
    }

    /// Resolve the base64 seed: plaintext if present, else decrypt the sealed seed with
    /// `passphrase` (falling back to `$IICP_OPERATOR_PASSPHRASE` for headless serve).
    fn seed_b64(&self, passphrase: Option<&str>) -> Result<String, String> {
        if !self.operator_secret.is_empty() {
            return Ok(self.operator_secret.clone());
        }
        if let Some(enc) = &self.operator_secret_enc {
            let pw = passphrase
                .map(str::to_string)
                .or_else(crate::operator_crypto::passphrase_from_env)
                .ok_or_else(|| {
                    "operator secret is encrypted — set $IICP_OPERATOR_PASSPHRASE (or pass a \
                     passphrase) to unlock it (#460)"
                        .to_string()
                })?;
            return crate::operator_crypto::decrypt_seed(&pw, enc, &self.operator_id);
        }
        Err(
            "legacy operator identity has no key (operator_id is a UUID, not a public key) — regenerate (#464)".into(),
        )
    }

    /// The ed25519 signing key for delegations / mutations. Decrypts the sealed seed when the
    /// identity is encrypted (via `$IICP_OPERATOR_PASSPHRASE`). Err on a legacy keyless identity.
    pub fn signing_key(&self) -> Result<ed25519_dalek::SigningKey, String> {
        self.signing_key_with(None)
    }

    /// Like [`signing_key`](Self::signing_key) but with an explicit unlock passphrase (#460).
    pub fn signing_key_with(
        &self,
        passphrase: Option<&str>,
    ) -> Result<ed25519_dalek::SigningKey, String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let seed_b64 = self.seed_b64(passphrase)?;
        let bytes = STANDARD
            .decode(&seed_b64)
            .map_err(|e| format!("bad operator_secret base64: {e}"))?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "operator_secret is not 32 bytes".to_string())?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
    }

    /// #460 — return a copy with the seed sealed under `passphrase` (operator_secret cleared).
    pub fn encrypt_at_rest(&self, passphrase: &str) -> Result<Self, String> {
        let enc = crate::operator_crypto::encrypt_seed(
            passphrase,
            &self.seed_b64(None)?,
            &self.operator_id,
        )?;
        Ok(Self {
            operator_secret: String::new(),
            operator_secret_enc: Some(enc),
            ..self.clone()
        })
    }

    /// #460 — return a copy with the plaintext seed restored (operator_secret_enc cleared).
    pub fn decrypt_at_rest(&self, passphrase: &str) -> Result<Self, String> {
        let seed = self.seed_b64(Some(passphrase))?;
        Ok(Self {
            operator_secret: seed,
            operator_secret_enc: None,
            ..self.clone()
        })
    }
}

pub fn operator_path() -> io::Result<PathBuf> {
    Ok(config_dir()?.join("operator.json"))
}

pub fn load_operator() -> io::Result<Option<OperatorIdentity>> {
    let p = operator_path()?;
    if !p.exists() {
        return Ok(None);
    }
    let txt = fs::read_to_string(&p)?;
    let op: OperatorIdentity =
        serde_json::from_str(&txt).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(op))
}

pub fn save_operator(op: &OperatorIdentity) -> io::Result<PathBuf> {
    let p = operator_path()?;
    let json = serde_json::to_string_pretty(op)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(&p, format!("{json}\n"))?;
    let _ = chmod_600(&p);
    Ok(p)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub node_id: String,
    pub operator_id: String,
    pub name: String,
    pub backend_url: String,
    pub model: String,
    #[serde(default = "default_intent")]
    pub intent: String,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default = "default_directory_url")]
    pub directory_url: String,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: u32,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default)]
    pub public_endpoint: String,
    #[serde(default)]
    pub auto_detect_nat: bool,
    #[serde(default)]
    pub external_ip_probe_url: String,
    /// #456 — node_token cached after register so read-only commands (`iicp-node credits`)
    /// can authenticate without re-registering. Bearer credential, not a secret key;
    /// stored in the chmod-600 config alongside the operator identity. Absent until the
    /// node first registers (via `serve`).
    #[serde(default)]
    pub node_token: Option<String>,
    /// TC-9c — HMAC key for CIPWorkerReceipt signing. Returned by the directory on
    /// registration and persisted here so receipts work immediately on restart without
    /// waiting for the next re-registration cycle. Absent until first `serve`.
    #[serde(default)]
    pub node_hmac_key: Option<String>,
    pub created_at: String,
}

fn default_intent() -> String {
    "urn:iicp:intent:llm:chat:v1".to_string()
}
fn default_region() -> String {
    "unknown".to_string()
}
fn default_directory_url() -> String {
    "https://iicp.network/api".to_string()
}
fn default_max_concurrent() -> u32 {
    4
}
fn default_port() -> u16 {
    8020
}
fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn validate_name(name: &str) -> io::Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "node name length must be 1..=63",
        ));
    }
    let first_ok = bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit();
    if !first_ok {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "node name must start with [a-z0-9]",
        ));
    }
    for &b in &bytes[1..] {
        let ok =
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-';
        if !ok {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "node name must match [a-z0-9][a-z0-9._-]{0,62}",
            ));
        }
    }
    Ok(())
}

pub fn node_path(name: &str) -> io::Result<PathBuf> {
    validate_name(name)?;
    Ok(config_dir()?.join("nodes").join(format!("{name}.json")))
}

pub fn load_node(name: &str) -> io::Result<Option<NodeIdentity>> {
    let p = node_path(name)?;
    if !p.exists() {
        return Ok(None);
    }
    let txt = fs::read_to_string(&p)?;
    let node: NodeIdentity =
        serde_json::from_str(&txt).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(node))
}

pub fn save_node(node: &NodeIdentity) -> io::Result<PathBuf> {
    validate_name(&node.name)?;
    let p = node_path(&node.name)?;
    let json = serde_json::to_string_pretty(node)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(&p, format!("{json}\n"))?;
    let _ = chmod_600(&p);
    Ok(p)
}

pub fn list_nodes() -> io::Result<Vec<NodeIdentity>> {
    let dir = config_dir()?.join("nodes");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(&dir)?
        .filter_map(|r| r.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    entries.sort();
    let mut out = Vec::new();
    for p in entries {
        if let Ok(txt) = fs::read_to_string(&p) {
            if let Ok(node) = serde_json::from_str::<NodeIdentity>(&txt) {
                out.push(node);
            }
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn generate_node(
    operator_id: &str,
    name: &str,
    backend_url: &str,
    model: &str,
    intent: &str,
    region: &str,
    directory_url: &str,
    port: u16,
    host: &str,
    public_endpoint: &str,
    auto_detect_nat: bool,
    external_ip_probe_url: &str,
) -> io::Result<NodeIdentity> {
    validate_name(name)?;
    Ok(NodeIdentity {
        node_id: Uuid::new_v4().to_string(),
        operator_id: operator_id.to_string(),
        name: name.to_string(),
        backend_url: backend_url.to_string(),
        model: model.to_string(),
        intent: intent.to_string(),
        region: region.to_string(),
        directory_url: directory_url.to_string(),
        max_concurrent: 4,
        port,
        host: host.to_string(),
        public_endpoint: public_endpoint.to_string(),
        auto_detect_nat,
        external_ip_probe_url: external_ip_probe_url.to_string(),
        node_token: None,    // cached on first register (#456)
        node_hmac_key: None, // cached on first register (TC-9c)
        created_at: now_iso(),
    })
}

#[cfg(test)]
mod operator_identity_tests {
    //! #464 — OperatorIdentity is the ed25519 operator key: operator_id is the verifiable
    //! public key (== the directory's operator_pubkey via the ADR-045 delegation), not a
    //! random UUID. Fails without the fix (old operator_id was `op-<uuid>` with no key).
    use super::OperatorIdentity;
    use crate::delegation::{issue_delegation, operator_pub_b64, verify_delegation};
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn operator_id_is_the_base64_ed25519_pubkey() {
        let op = OperatorIdentity::generate("Rebel One", "me@example.com");
        assert!(!op.operator_id.starts_with("op-"));
        assert_eq!(STANDARD.decode(&op.operator_id).unwrap().len(), 32);
        assert_eq!(STANDARD.decode(&op.operator_secret).unwrap().len(), 32);
        assert!(op.is_key_backed());
    }

    #[test]
    fn signing_key_public_matches_operator_id() {
        let op = OperatorIdentity::generate("", "");
        let sk = op.signing_key().unwrap();
        assert_eq!(operator_pub_b64(&sk), op.operator_id);
    }

    #[test]
    fn delegation_uses_the_identity_key_and_verifies() {
        let op = OperatorIdentity::generate("", "");
        let token = issue_delegation(&op.signing_key().unwrap(), "node-123", 3600);
        assert_eq!(token.operator_pub, op.operator_id);
        // now=0 ≤ not_after (issued now+3600) → not expired; node_id check is independent.
        assert!(verify_delegation(&token, "node-123", 0).is_ok());
        assert!(verify_delegation(&token, "other-node", 0).is_err());
    }

    #[test]
    fn integrity_hash_binds_operator_id_and_created_at() {
        let op = OperatorIdentity::generate("", "");
        assert_eq!(
            op.operator_integrity_hash,
            OperatorIdentity::compute_integrity_hash(&op.operator_id, &op.created_at)
        );
        assert_ne!(
            OperatorIdentity::compute_integrity_hash(&op.operator_id, "1999-01-01T00:00:00Z"),
            op.operator_integrity_hash
        );
    }

    #[test]
    fn legacy_uuid_identity_is_not_key_backed() {
        let legacy = OperatorIdentity {
            operator_id: "op-deadbeef".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            display_name: String::new(),
            contact: String::new(),
            operator_secret: String::new(),
            operator_integrity_hash: String::new(),
            operator_secret_enc: None,
        };
        assert!(!legacy.is_key_backed());
        assert!(legacy.signing_key().is_err());
    }

    // #460 — encrypt at rest → sign once unlocked (same pubkey) → decrypt restores plaintext.
    #[test]
    fn operator_encrypt_sign_decrypt_cycle() {
        let op = OperatorIdentity::generate("Padme", "");
        assert!(!op.is_encrypted());
        let pub_before = op.signing_key().unwrap().verifying_key().to_bytes();

        let enc = op.encrypt_at_rest("s3cret").unwrap();
        assert!(enc.is_encrypted());
        assert!(enc.operator_secret.is_empty()); // plaintext seed gone from the record
        assert!(enc.is_key_backed());

        // Signs once unlocked; the recovered key matches the original.
        let sk = enc.signing_key_with(Some("s3cret")).unwrap();
        assert_eq!(sk.verifying_key().to_bytes(), pub_before);
        assert!(enc.signing_key_with(Some("WRONG")).is_err());

        let back = enc.decrypt_at_rest("s3cret").unwrap();
        assert!(!back.is_encrypted());
        assert_eq!(back.operator_secret, op.operator_secret);
    }
}

#[cfg(test)]
mod node_identity_tests {
    use super::NodeIdentity;

    #[test]
    fn node_identity_region_default_is_unknown() {
        // NodeIdentity loaded from a config file missing the `region` field must
        // default to "unknown", not "eu-central" (#484). Fails without the fix.
        let json = r#"{"node_id":"n1","operator_id":"o1","name":"test","backend_url":"http://x","model":"llama3","created_at":"2026-01-01T00:00:00Z"}"#;
        let identity: NodeIdentity = serde_json::from_str(json).unwrap();
        assert_eq!(
            identity.region, "unknown",
            "missing region field must default to 'unknown', not 'eu-central' (#484)"
        );
    }
}
