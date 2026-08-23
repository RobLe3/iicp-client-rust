// SPDX-License-Identifier: Apache-2.0
//! Opt-in verified local-directory candidate resolution.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::runtime_config::OperatingMode;

pub const SERVICE_TYPE: &str = "_iicp-dir._tcp.local.";
pub const DESCRIPTOR_PATH: &str = "/.well-known/iicp-directory.json";
pub const DEFAULT_COLLECTION_WINDOW_MS: u64 = 1_000;
pub const MAX_COLLECTION_WINDOW_MS: u64 = 3_000;
pub const MAX_CACHE_SECONDS: i64 = 300;
const MAX_TXT_BYTES: usize = 512;
const SIGNATURE_DOMAIN: &[u8] = b"IICP-LOCAL-DIRECTORY-DESCRIPTOR-V0\n";

#[derive(Clone, Debug)]
pub struct ResolveRequest {
    pub enabled: bool,
    pub mode: OperatingMode,
    pub explicit_directory: Option<String>,
    pub trusted_directory_did: Option<String>,
    pub allow_public_fallback: bool,
    pub collection_window_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionSource {
    Explicit,
    Mdns,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DirectoryResolution {
    pub endpoint: String,
    pub directory_did: Option<String>,
    pub source: ResolutionSource,
    pub observed_hostname: Option<String>,
    pub observed_addresses: Vec<String>,
    pub descriptor_sha256: Option<String>,
    pub expires_at: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum LocalDirectoryError {
    #[error("local directory discovery is unavailable in local-only mode")]
    LocalOnly,
    #[error("local directory discovery requires an explicit trusted directory DID")]
    MissingTrustAnchor,
    #[error("local directory discovery failed: {0}")]
    Discovery(String),
    #[error("no trusted local directory candidate was available")]
    NoTrustedCandidate,
}

#[derive(Clone, Debug)]
struct Candidate {
    hostname: String,
    port: u16,
    addresses: HashSet<IpAddr>,
    txt: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct DescriptorSignature {
    algorithm: String,
    key_id: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct Descriptor {
    schema: String,
    profile: String,
    profile_version: String,
    directory_did: String,
    role: String,
    api_endpoints: Vec<String>,
    issued_at: i64,
    expires_at: i64,
    signature: DescriptorSignature,
}

pub async fn resolve(
    request: ResolveRequest,
) -> Result<Option<DirectoryResolution>, LocalDirectoryError> {
    if let Some(endpoint) = request
        .explicit_directory
        .filter(|value| !value.trim().is_empty())
    {
        return Ok(Some(DirectoryResolution {
            endpoint,
            directory_did: request.trusted_directory_did,
            source: ResolutionSource::Explicit,
            observed_hostname: None,
            observed_addresses: Vec::new(),
            descriptor_sha256: None,
            expires_at: None,
        }));
    }
    if !request.enabled {
        return Ok(None);
    }
    if request.mode == OperatingMode::LocalOnly {
        return Err(LocalDirectoryError::LocalOnly);
    }
    let trusted_did = request
        .trusted_directory_did
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(LocalDirectoryError::MissingTrustAnchor)?;
    let window = request
        .collection_window_ms
        .clamp(1, MAX_COLLECTION_WINDOW_MS);
    let candidates = tokio::task::spawn_blocking(move || browse(Duration::from_millis(window)))
        .await
        .map_err(|error| LocalDirectoryError::Discovery(error.to_string()))??;
    let mut verified = Vec::new();
    for candidate in candidates {
        if let Ok(resolution) = verify_candidate(&candidate, trusted_did).await {
            verified.push(resolution);
        }
    }
    verified.sort_by(|left, right| {
        left.directory_did
            .cmp(&right.directory_did)
            .then_with(|| left.endpoint.cmp(&right.endpoint))
    });
    match verified.into_iter().next() {
        Some(candidate) => Ok(Some(candidate)),
        None if request.mode == OperatingMode::Public && request.allow_public_fallback => Ok(None),
        None => Err(LocalDirectoryError::NoTrustedCandidate),
    }
}

fn browse(window: Duration) -> Result<Vec<Candidate>, LocalDirectoryError> {
    let daemon =
        ServiceDaemon::new().map_err(|error| LocalDirectoryError::Discovery(error.to_string()))?;
    let receiver = daemon
        .browse(SERVICE_TYPE)
        .map_err(|error| LocalDirectoryError::Discovery(error.to_string()))?;
    let deadline = Instant::now() + window;
    let mut candidates = Vec::new();
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if let Some(candidate) = candidate_from_service(&info) {
                    candidates.push(candidate);
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = daemon.stop_browse(SERVICE_TYPE);
    let _ = daemon.shutdown();
    Ok(candidates)
}

fn candidate_from_service(info: &ResolvedService) -> Option<Candidate> {
    let mut txt = BTreeMap::new();
    let mut txt_bytes = 0usize;
    for property in info.get_properties().iter() {
        let key = property.key().to_ascii_lowercase();
        let value = property.val_str().to_string();
        txt_bytes += 1 + key.len() + 1 + value.len();
        if txt.insert(key, value).is_some() {
            return None;
        }
    }
    if txt_bytes > MAX_TXT_BYTES
        || txt.get("pv").map(String::as_str) != Some("0")
        || txt.get("path").map(String::as_str) != Some(DESCRIPTOR_PATH)
        || txt.get("transport").map(String::as_str) != Some("https")
        || txt_contains_secret(&txt)
    {
        return None;
    }
    let addresses = info
        .get_addresses()
        .iter()
        .map(|address| address.to_ip_addr())
        .collect::<HashSet<_>>();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !allowed_local_address(*address))
    {
        return None;
    }
    Some(Candidate {
        hostname: info.get_hostname().trim_end_matches('.').to_string(),
        port: info.get_port(),
        addresses,
        txt,
    })
}

async fn verify_candidate(
    candidate: &Candidate,
    trusted_did: &str,
) -> Result<DirectoryResolution, LocalDirectoryError> {
    let origin = format!("https://{}:{}", candidate.hostname, candidate.port);
    // Bind the HTTPS request to the addresses actually observed through DNS-SD.
    // This preserves TLS hostname verification while closing the gap in which a
    // second DNS lookup could redirect the verification fetch elsewhere.
    let mut resolved_addresses = candidate
        .addresses
        .iter()
        .copied()
        .map(|address| SocketAddr::new(address, candidate.port))
        .collect::<Vec<_>>();
    resolved_addresses.sort();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .use_rustls_tls()
        .resolve_to_addrs(&candidate.hostname, &resolved_addresses)
        .build()
        .map_err(|error| LocalDirectoryError::Discovery(error.to_string()))?;
    let response = client
        .get(format!("{origin}{DESCRIPTOR_PATH}"))
        .send()
        .await
        .map_err(|error| LocalDirectoryError::Discovery(error.to_string()))?;
    if !response.status().is_success() || response.status().is_redirection() {
        return Err(LocalDirectoryError::Discovery(
            "descriptor fetch rejected".into(),
        ));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| LocalDirectoryError::Discovery(error.to_string()))?;
    if bytes.len() > 32 * 1024 {
        return Err(LocalDirectoryError::Discovery(
            "descriptor is oversized".into(),
        ));
    }
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| LocalDirectoryError::Discovery(error.to_string()))?;
    let descriptor: Descriptor = serde_json::from_value(value.clone())
        .map_err(|error| LocalDirectoryError::Discovery(error.to_string()))?;
    validate_descriptor(
        &descriptor,
        &value,
        candidate,
        trusted_did,
        &client,
        &origin,
    )
    .await?;
    let endpoint = descriptor
        .api_endpoints
        .iter()
        .filter(|endpoint| endpoint.starts_with("https://"))
        .min()
        .cloned()
        .ok_or_else(|| {
            LocalDirectoryError::Discovery("descriptor has no HTTPS API endpoint".into())
        })?;
    let endpoint_url = reqwest::Url::parse(&endpoint)
        .map_err(|_| LocalDirectoryError::Discovery("descriptor API endpoint is invalid".into()))?;
    if endpoint_url.host_str() != Some(candidate.hostname.as_str())
        || endpoint_url.port_or_known_default() != Some(candidate.port)
    {
        return Err(LocalDirectoryError::Discovery(
            "descriptor API endpoint does not match the discovered origin".into(),
        ));
    }
    Ok(DirectoryResolution {
        endpoint,
        directory_did: Some(descriptor.directory_did),
        source: ResolutionSource::Mdns,
        observed_hostname: Some(candidate.hostname.clone()),
        observed_addresses: {
            let mut values = candidate
                .addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            values.sort();
            values
        },
        descriptor_sha256: Some(hex::encode(Sha256::digest(&bytes))),
        expires_at: Some(
            descriptor
                .expires_at
                .min(chrono::Utc::now().timestamp() + MAX_CACHE_SECONDS),
        ),
    })
}

async fn validate_descriptor(
    descriptor: &Descriptor,
    value: &Value,
    candidate: &Candidate,
    trusted_did: &str,
    client: &reqwest::Client,
    origin: &str,
) -> Result<(), LocalDirectoryError> {
    let now = chrono::Utc::now().timestamp();
    if descriptor.schema != "iicp.local-directory-descriptor.v0"
        || descriptor.profile != "urn:iicp:profile:local-directory-discovery:v1"
        || descriptor.profile_version != "0"
        || !matches!(descriptor.role.as_str(), "seed" | "replica" | "standalone")
        || descriptor.directory_did != trusted_did
        || candidate
            .txt
            .get("did")
            .is_some_and(|did| did != &descriptor.directory_did)
        || candidate
            .txt
            .get("role")
            .is_some_and(|role| role != &descriptor.role)
        || descriptor.issued_at > now + 30
        || descriptor.expires_at <= now
        || descriptor.expires_at - descriptor.issued_at > MAX_CACHE_SECONDS
        || descriptor.signature.algorithm != "Ed25519"
        || descriptor.signature.key_id != format!("{}#key-1", descriptor.directory_did)
    {
        return Err(LocalDirectoryError::Discovery(
            "descriptor validation failed".into(),
        ));
    }
    let did_response = client
        .get(format!("{origin}/.well-known/did.json"))
        .send()
        .await
        .map_err(|error| LocalDirectoryError::Discovery(error.to_string()))?;
    if !did_response.status().is_success() || did_response.status().is_redirection() {
        return Err(LocalDirectoryError::Discovery(
            "DID document fetch rejected".into(),
        ));
    }
    let did: Value = did_response
        .json()
        .await
        .map_err(|error| LocalDirectoryError::Discovery(error.to_string()))?;
    if did.get("id").and_then(Value::as_str) != Some(descriptor.directory_did.as_str()) {
        return Err(LocalDirectoryError::Discovery(
            "DID document identity mismatch".into(),
        ));
    }
    let public_key = did["verificationMethod"]
        .as_array()
        .and_then(|methods| {
            methods
                .iter()
                .find(|method| method["id"] == descriptor.signature.key_id)
        })
        .and_then(|method| method["publicKeyJwk"]["x"].as_str())
        .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        .ok_or_else(|| LocalDirectoryError::Discovery("DID verification key unavailable".into()))?;
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .ok_or_else(|| LocalDirectoryError::Discovery("descriptor is not an object".into()))?
        .remove("signature");
    let canonical = serde_jcs::to_vec(&unsigned)
        .map_err(|error| LocalDirectoryError::Discovery(error.to_string()))?;
    let mut message = SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&canonical);
    let signature_bytes = hex::decode(&descriptor.signature.value)
        .map_err(|_| LocalDirectoryError::Discovery("invalid descriptor signature".into()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| LocalDirectoryError::Discovery("invalid descriptor signature".into()))?;
    public_key
        .verify(&message, &signature)
        .map_err(|_| LocalDirectoryError::Discovery("descriptor signature mismatch".into()))
}

fn allowed_local_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => {
            !value.is_loopback()
                && !value.is_unspecified()
                && !value.is_multicast()
                && (value.is_private() || value.is_link_local())
        }
        IpAddr::V6(value) => {
            !value.is_loopback()
                && !value.is_unspecified()
                && !value.is_multicast()
                && (value.is_unicast_link_local() || (value.segments()[0] & 0xfe00) == 0xfc00)
        }
    }
}

fn txt_contains_secret(txt: &BTreeMap<String, String>) -> bool {
    txt.keys().any(|key| {
        [
            "token",
            "secret",
            "credential",
            "membership",
            "node",
            "model",
            "intent",
            "capability",
            "topology",
            "federation",
        ]
        .iter()
        .any(|forbidden| key.contains(forbidden))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn explicit_directory_suppresses_multicast() {
        let result = resolve(ResolveRequest {
            enabled: true,
            mode: OperatingMode::Private,
            explicit_directory: Some("https://configured.example/api".into()),
            trusted_directory_did: Some("did:web:configured.example".into()),
            allow_public_fallback: false,
            collection_window_ms: 3_000,
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result.source, ResolutionSource::Explicit);
        assert_eq!(result.endpoint, "https://configured.example/api");
    }

    #[tokio::test]
    async fn local_only_rejects_before_multicast() {
        let error = resolve(ResolveRequest {
            enabled: true,
            mode: OperatingMode::LocalOnly,
            explicit_directory: None,
            trusted_directory_did: Some("did:web:local.example".into()),
            allow_public_fallback: false,
            collection_window_ms: 1_000,
        })
        .await
        .unwrap_err();
        assert!(matches!(error, LocalDirectoryError::LocalOnly));
    }

    #[test]
    fn address_scope_rejects_loopback_public_and_multicast() {
        assert!(allowed_local_address("192.168.1.2".parse().unwrap()));
        assert!(allowed_local_address("fe80::1".parse().unwrap()));
        assert!(!allowed_local_address("127.0.0.1".parse().unwrap()));
        assert!(!allowed_local_address("8.8.8.8".parse().unwrap()));
        assert!(!allowed_local_address("ff02::fb".parse().unwrap()));
    }

    #[test]
    fn secret_bearing_txt_keys_are_rejected() {
        let mut txt = BTreeMap::new();
        txt.insert("pv".into(), "0".into());
        txt.insert("membership_token".into(), "private".into());
        assert!(txt_contains_secret(&txt));
    }
}
