//! Opt-in verifier for the pre-normative dispatch-ticket trust v2 profile.
//!
//! The default v1 same-origin route-ticket behavior is intentionally unchanged.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

pub const PROFILE: &str = "dispatch_ticket_v2";
const DOMAIN: &[u8] = b"IICP-DISPATCH-TICKET-V2\0";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DispatchTrustKey {
    pub key_id: String,
    pub public_key_b64url: String,
    pub state: String,
    pub valid_from: u64,
    pub valid_until: u64,
    #[serde(default)]
    pub allowed_profiles: Vec<String>,
    #[serde(default)]
    pub issuers: Vec<String>,
    #[serde(default)]
    pub audiences: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DispatchTrustBundle {
    pub bundle_version: u64,
    pub keys: Vec<DispatchTrustKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
}

pub fn canonical_dispatch_trust_bundle(
    bundle: &DispatchTrustBundle,
) -> Result<Vec<u8>, TrustBundleStoreError> {
    let mut value = serde_json::to_value(bundle)?;
    if let Some(keys) = value.get_mut("keys").and_then(Value::as_array_mut) {
        keys.sort_by(|left, right| left["key_id"].as_str().cmp(&right["key_id"].as_str()));
        for key in keys {
            if key
                .get("allowed_profiles")
                .and_then(Value::as_array)
                .is_some_and(|values| values.is_empty())
            {
                key["allowed_profiles"] = serde_json::json!([PROFILE]);
            }
            for name in ["allowed_profiles", "issuers", "audiences"] {
                if let Some(values) = key.get_mut(name).and_then(Value::as_array_mut) {
                    values.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
                }
            }
        }
    }
    Ok(canonical_ticket_claims(&value).into_bytes())
}

#[derive(Clone, Debug)]
pub struct StoredDispatchTrustBundle {
    pub bundle: DispatchTrustBundle,
    pub canonical_bytes: Vec<u8>,
    pub digest: String,
    pub high_water: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustBundleInstallStatus {
    Installed,
    Unchanged,
    Stale,
    Conflict,
    Recovered,
    RecoveryRequired,
}

#[derive(Clone, Debug)]
pub struct TrustBundleInstallResult {
    pub status: TrustBundleInstallStatus,
    pub state: Option<StoredDispatchTrustBundle>,
}

#[derive(Clone, Debug)]
pub struct AdminRecoveryAuthorization {
    pub reason: String,
    pub minimum_high_water: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum TrustBundleStoreError {
    #[error("trust store is corrupt: {0}")]
    Corrupt(String),
    #[error("trust store lock is held")]
    Locked,
    #[error("trust store requires owner-only permissions")]
    Permissions,
    #[error("trust store I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("trust store JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub trait TrustBundleStore {
    fn load(&self) -> Result<Option<StoredDispatchTrustBundle>, TrustBundleStoreError>;
    fn install(
        &self,
        bundle: &DispatchTrustBundle,
        expected_current_version: Option<u64>,
    ) -> Result<TrustBundleInstallResult, TrustBundleStoreError>;
    fn recover(
        &self,
        bundle: &DispatchTrustBundle,
        authorization: Option<&AdminRecoveryAuthorization>,
    ) -> Result<TrustBundleInstallResult, TrustBundleStoreError>;
}

#[derive(Debug)]
pub struct FileDispatchTrustBundleStore {
    path: PathBuf,
    lock_path: PathBuf,
    lock_timeout: Duration,
}

#[derive(Deserialize, Serialize)]
struct TrustStoreState {
    bundle_b64: String,
    bundle_digest: String,
    bundle_version: u64,
    high_water: u64,
}

struct StoreLock {
    path: PathBuf,
    file: Option<File>,
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        self.file.take();
        let _ = fs::remove_file(&self.path);
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(unix)]
fn owner_only(path: &Path) -> Result<(), TrustBundleStoreError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(TrustBundleStoreError::Corrupt(
            "trust store path must not be a symbolic link".into(),
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(TrustBundleStoreError::Permissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn owner_only(_path: &Path) -> Result<(), TrustBundleStoreError> {
    Ok(())
}

impl FileDispatchTrustBundleStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_lock_timeout(path, Duration::from_secs(2))
    }

    pub fn with_lock_timeout(path: impl Into<PathBuf>, lock_timeout: Duration) -> Self {
        let path = path.into();
        let lock_path = path.with_file_name(format!(
            "{}.lock",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("trust-store")
        ));
        Self {
            path,
            lock_path,
            lock_timeout,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    fn prepare_directory(&self) -> Result<(), TrustBundleStoreError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| TrustBundleStoreError::Corrupt("missing parent directory".into()))?;
        if !parent.exists() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }
        owner_only(parent)
    }

    fn acquire_lock(&self) -> Result<StoreLock, TrustBundleStoreError> {
        self.prepare_directory()?;
        let deadline = Instant::now() + self.lock_timeout;
        loop {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&self.lock_path) {
                Ok(mut file) => {
                    writeln!(file, "{}", std::process::id())?;
                    file.sync_all()?;
                    return Ok(StoreLock {
                        path: self.lock_path.clone(),
                        file: Some(file),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if Instant::now() >= deadline {
                        return Err(TrustBundleStoreError::Locked);
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn commit(
        &self,
        bundle: &DispatchTrustBundle,
        high_water: u64,
    ) -> Result<StoredDispatchTrustBundle, TrustBundleStoreError> {
        let canonical_bytes = canonical_dispatch_trust_bundle(bundle)?;
        let digest = sha256_digest(&canonical_bytes);
        let state = TrustStoreState {
            bundle_b64: STANDARD.encode(&canonical_bytes),
            bundle_digest: digest.clone(),
            bundle_version: bundle.bundle_version,
            high_water,
        };
        let payload = canonical_ticket_claims(&serde_json::to_value(&state)?).into_bytes();
        let temporary = self.path.with_file_name(format!(
            "{}.tmp-{}-{}",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("trust-store"),
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&payload)?;
        file.sync_all()?;
        drop(file);
        let result = fs::rename(&temporary, &self.path);
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
        }
        if let Some(parent) = self.path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(StoredDispatchTrustBundle {
            bundle: bundle.clone(),
            canonical_bytes,
            digest,
            high_water,
        })
    }
}

impl TrustBundleStore for FileDispatchTrustBundleStore {
    fn load(&self) -> Result<Option<StoredDispatchTrustBundle>, TrustBundleStoreError> {
        if !self.path.exists() {
            return Ok(None);
        }
        if !fs::symlink_metadata(&self.path)?.file_type().is_file() {
            return Err(TrustBundleStoreError::Corrupt(
                "trust store must be a regular file".into(),
            ));
        }
        owner_only(&self.path)
            .map_err(|error| TrustBundleStoreError::Corrupt(error.to_string()))?;
        let mut raw = Vec::new();
        File::open(&self.path)?
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut raw)?;
        if raw.len() > 4 * 1024 * 1024 {
            return Err(TrustBundleStoreError::Corrupt(
                "state exceeds size limit".into(),
            ));
        }
        let state: TrustStoreState = serde_json::from_slice(&raw)
            .map_err(|error| TrustBundleStoreError::Corrupt(error.to_string()))?;
        let canonical_bytes = STANDARD
            .decode(&state.bundle_b64)
            .map_err(|error| TrustBundleStoreError::Corrupt(error.to_string()))?;
        let digest = sha256_digest(&canonical_bytes);
        if digest != state.bundle_digest {
            return Err(TrustBundleStoreError::Corrupt(
                "bundle digest mismatch".into(),
            ));
        }
        let bundle: DispatchTrustBundle = serde_json::from_slice(&canonical_bytes)
            .map_err(|error| TrustBundleStoreError::Corrupt(error.to_string()))?;
        if bundle.bundle_version != state.bundle_version || state.high_water < bundle.bundle_version
        {
            return Err(TrustBundleStoreError::Corrupt(
                "bundle version/high-water mismatch".into(),
            ));
        }
        if canonical_dispatch_trust_bundle(&bundle)? != canonical_bytes {
            return Err(TrustBundleStoreError::Corrupt(
                "bundle is not canonical".into(),
            ));
        }
        Ok(Some(StoredDispatchTrustBundle {
            bundle,
            canonical_bytes,
            digest,
            high_water: state.high_water,
        }))
    }

    fn install(
        &self,
        bundle: &DispatchTrustBundle,
        expected_current_version: Option<u64>,
    ) -> Result<TrustBundleInstallResult, TrustBundleStoreError> {
        let _lock = self.acquire_lock()?;
        let current = self.load()?;
        let current_version = current.as_ref().map(|state| state.bundle.bundle_version);
        if expected_current_version.is_some() && expected_current_version != current_version {
            return Ok(TrustBundleInstallResult {
                status: TrustBundleInstallStatus::Conflict,
                state: current,
            });
        }
        let candidate_digest = sha256_digest(&canonical_dispatch_trust_bundle(bundle)?);
        let high_water = current.as_ref().map_or(0, |state| state.high_water);
        if bundle.bundle_version < high_water {
            return Ok(TrustBundleInstallResult {
                status: TrustBundleInstallStatus::Stale,
                state: current,
            });
        }
        if current_version == Some(bundle.bundle_version) {
            let status = if current
                .as_ref()
                .is_some_and(|state| state.digest == candidate_digest)
            {
                TrustBundleInstallStatus::Unchanged
            } else {
                TrustBundleInstallStatus::Conflict
            };
            return Ok(TrustBundleInstallResult {
                status,
                state: current,
            });
        }
        let state = self.commit(bundle, high_water.max(bundle.bundle_version))?;
        Ok(TrustBundleInstallResult {
            status: TrustBundleInstallStatus::Installed,
            state: Some(state),
        })
    }

    fn recover(
        &self,
        bundle: &DispatchTrustBundle,
        authorization: Option<&AdminRecoveryAuthorization>,
    ) -> Result<TrustBundleInstallResult, TrustBundleStoreError> {
        let Some(authorization) = authorization.filter(|auth| !auth.reason.trim().is_empty())
        else {
            return Ok(TrustBundleInstallResult {
                status: TrustBundleInstallStatus::RecoveryRequired,
                state: None,
            });
        };
        let _lock = self.acquire_lock()?;
        let current = match self.load() {
            Ok(state) => state,
            Err(TrustBundleStoreError::Corrupt(_)) => None,
            Err(error) => return Err(error),
        };
        let high_water = current
            .as_ref()
            .map_or(0, |state| state.high_water)
            .max(authorization.minimum_high_water)
            .max(bundle.bundle_version);
        let state = self.commit(bundle, high_water)?;
        Ok(TrustBundleInstallResult {
            status: TrustBundleInstallStatus::Recovered,
            state: Some(state),
        })
    }
}

#[derive(Clone, Debug)]
pub struct DispatchTicketBindings {
    pub issuer: String,
    pub provider_id: String,
    pub intent: String,
    pub constraints_digest: String,
    pub audience: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DispatchTrustDecision {
    pub accepted: bool,
    pub code: String,
    pub anchored: bool,
    pub key_id: Option<String>,
}

impl DispatchTrustDecision {
    fn reject(code: &str, key_id: Option<&str>) -> Self {
        Self {
            accepted: false,
            code: code.into(),
            anchored: false,
            key_id: key_id.map(str::to_owned),
        }
    }
}

#[derive(Default)]
pub struct LocalDispatchReplayCache {
    seen: HashMap<String, u64>,
}

impl LocalDispatchReplayCache {
    pub fn contains(&mut self, jti: &str, now: u64) -> bool {
        self.seen.retain(|_, expiry| *expiry > now);
        self.seen.contains_key(jti)
    }

    pub fn remember(&mut self, jti: impl Into<String>, expires_at: u64) {
        self.seen.insert(jti.into(), expires_at);
    }
}

pub fn canonical_ticket_claims(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let sorted = map.iter().collect::<BTreeMap<_, _>>();
            format!(
                "{{{}}}",
                sorted
                    .into_iter()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap(),
                        canonical_ticket_claims(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_ticket_claims)
                .collect::<Vec<_>>()
                .join(",")
        ),
        _ => serde_json::to_string(value).unwrap(),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_dispatch_ticket_v2(
    claims: &Value,
    signature_b64url: &str,
    bundle: &DispatchTrustBundle,
    bindings: &DispatchTicketBindings,
    now: u64,
    minimum_bundle_version: u64,
    mut replay_cache: Option<&mut LocalDispatchReplayCache>,
) -> DispatchTrustDecision {
    if bundle.bundle_version < minimum_bundle_version {
        return DispatchTrustDecision::reject("reject_bundle_rollback", None);
    }
    if bundle.valid_from.is_some_and(|start| now < start) {
        return DispatchTrustDecision::reject("reject_bundle_not_yet_valid", None);
    }
    if bundle.valid_until.is_some_and(|end| now > end) {
        return DispatchTrustDecision::reject("reject_bundle_expired", None);
    }
    if claims["profile"] != PROFILE {
        return DispatchTrustDecision::reject("reject_required_profile_downgrade", None);
    }
    let Some(key_id) = claims["key_id"].as_str() else {
        return DispatchTrustDecision::reject("reject_unknown_key", None);
    };
    let Some(key) = bundle
        .keys
        .iter()
        .find(|candidate| candidate.key_id == key_id)
    else {
        return DispatchTrustDecision::reject("reject_unknown_key", Some(key_id));
    };
    if key.state == "revoked" {
        return DispatchTrustDecision::reject("reject_key_revoked", Some(key_id));
    }
    if now < key.valid_from || now > key.valid_until {
        return DispatchTrustDecision::reject("reject_key_expired", Some(key_id));
    }
    if !key.allowed_profiles.is_empty()
        && !key
            .allowed_profiles
            .iter()
            .any(|profile| profile == PROFILE)
    {
        return DispatchTrustDecision::reject("reject_profile_not_allowed", Some(key_id));
    }
    if !key.issuers.is_empty() && !key.issuers.iter().any(|issuer| claims["issuer"] == *issuer) {
        return DispatchTrustDecision::reject("reject_issuer", Some(key_id));
    }
    if !key.audiences.is_empty()
        && !key
            .audiences
            .iter()
            .any(|audience| claims["audience"] == *audience)
    {
        return DispatchTrustDecision::reject("reject_audience", Some(key_id));
    }
    let bound = claims["issuer"] == bindings.issuer
        && claims["provider_id"] == bindings.provider_id
        && claims["intent"] == bindings.intent
        && claims["constraints_digest"] == bindings.constraints_digest
        && bindings
            .audience
            .as_ref()
            .is_none_or(|audience| claims["audience"] == *audience);
    if !bound {
        return DispatchTrustDecision::reject("reject_claim_mismatch", Some(key_id));
    }
    let (Some(expires_at), Some(jti)) = (claims["expires_at"].as_u64(), claims["jti"].as_str())
    else {
        return DispatchTrustDecision::reject("reject_claim_mismatch", Some(key_id));
    };
    if expires_at <= now || jti.is_empty() {
        return DispatchTrustDecision::reject("reject_claim_mismatch", Some(key_id));
    }
    let signature_valid = (|| {
        let public_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&key.public_key_b64url)
            .ok()?
            .try_into()
            .ok()?;
        let signature_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(signature_b64url)
            .ok()?
            .try_into()
            .ok()?;
        let verifier = VerifyingKey::from_bytes(&public_bytes).ok()?;
        let signature = Signature::from_bytes(&signature_bytes);
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(canonical_ticket_claims(claims).as_bytes());
        Some(verifier.verify(&message, &signature).is_ok())
    })()
    .unwrap_or(false);
    if !signature_valid {
        return DispatchTrustDecision::reject("reject_signature", Some(key_id));
    }
    if replay_cache
        .as_deref_mut()
        .is_some_and(|cache| cache.contains(jti, now))
    {
        return DispatchTrustDecision::reject("reject_local_replay", Some(key_id));
    }
    if let Some(cache) = replay_cache {
        cache.remember(jti, expires_at);
    }
    DispatchTrustDecision {
        accepted: true,
        code: "accept_anchored".into(),
        anchored: true,
        key_id: Some(key_id.into()),
    }
}
