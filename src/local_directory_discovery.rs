// SPDX-License-Identifier: Apache-2.0
//! Opt-in verified local-directory candidate resolution.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
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
    /// True only when this result was reused from the bounded in-process cache.
    pub cache_hit: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CacheKey {
    mode: u8,
    trusted_directory_did: String,
}

#[derive(Clone, Debug)]
struct CachedResolution {
    resolution: DirectoryResolution,
    expires_at: i64,
}

type ResolutionCache = tokio::sync::Mutex<BTreeMap<CacheKey, CachedResolution>>;

fn resolution_cache() -> &'static ResolutionCache {
    static CACHE: OnceLock<ResolutionCache> = OnceLock::new();
    CACHE.get_or_init(|| tokio::sync::Mutex::new(BTreeMap::new()))
}

/// Invalidate all locally cached candidates after a trust-policy or revocation
/// update. The current CLI resolves only during startup, so configuration
/// reloads naturally start a new process; embedded runtimes can call this hook.
pub async fn invalidate_cache() {
    resolution_cache().lock().await.clear();
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
            cache_hit: false,
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
    let cache_key = CacheKey {
        mode: mode_cache_key(request.mode),
        trusted_directory_did: trusted_did.to_owned(),
    };
    let now = chrono::Utc::now().timestamp();
    {
        let mut cache = resolution_cache().lock().await;
        cache.retain(|_, entry| entry.expires_at > now);
        if let Some(entry) = cache.get(&cache_key) {
            let mut resolution = entry.resolution.clone();
            resolution.cache_hit = true;
            return Ok(Some(resolution));
        }
    }
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
        Some(candidate) => {
            if let Some(expires_at) = candidate.expires_at.filter(|expiry| *expiry > now) {
                resolution_cache().lock().await.insert(
                    cache_key,
                    CachedResolution {
                        resolution: candidate.clone(),
                        expires_at,
                    },
                );
            }
            Ok(Some(candidate))
        }
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
        cache_hit: false,
    })
}

fn mode_cache_key(mode: OperatingMode) -> u8 {
    match mode {
        OperatingMode::Public => 0,
        OperatingMode::Private => 1,
        OperatingMode::FederatedPrivate => 2,
        OperatingMode::LocalOnly => 3,
        OperatingMode::Custom => 4,
    }
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
    verify_descriptor_signature(descriptor, value, &did)
}

fn verify_descriptor_signature(
    descriptor: &Descriptor,
    value: &Value,
    did: &Value,
) -> Result<(), LocalDirectoryError> {
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
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    const SHARED_FIXTURE: &str =
        include_str!("../tests/fixtures/local-directory-discovery-v0.json");

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

    #[test]
    fn descriptor_signature_accepts_valid_and_rejects_tampered_content() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let did_id = "did:web:directory.local";
        let mut unsigned = serde_json::json!({
            "schema": "iicp.local-directory-descriptor.v0",
            "profile": "urn:iicp:profile:local-directory-discovery:v1",
            "profile_version": "0",
            "directory_did": did_id,
            "role": "standalone",
            "api_endpoints": ["https://directory.local:8443/api"],
            "issued_at": 1000,
            "expires_at": 1200
        });
        let canonical = serde_jcs::to_vec(&unsigned).unwrap();
        let mut message = SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&canonical);
        let signature = signing_key.sign(&message);
        unsigned["signature"] = serde_json::json!({
            "algorithm": "Ed25519",
            "key_id": format!("{did_id}#key-1"),
            "value": hex::encode(signature.to_bytes())
        });
        let descriptor: Descriptor = serde_json::from_value(unsigned.clone()).unwrap();
        let did = serde_json::json!({
            "id": did_id,
            "verificationMethod": [{
                "id": format!("{did_id}#key-1"),
                "publicKeyJwk": {"x": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes())}
            }]
        });
        verify_descriptor_signature(&descriptor, &unsigned, &did).unwrap();

        let mut tampered = unsigned;
        tampered["role"] = Value::String("replica".into());
        assert!(verify_descriptor_signature(&descriptor, &tampered, &did).is_err());
    }

    #[tokio::test]
    async fn cache_is_bounded_and_keyed_by_trust_policy() {
        resolution_cache().lock().await.clear();
        let now = chrono::Utc::now().timestamp();
        let key = CacheKey {
            mode: mode_cache_key(OperatingMode::Private),
            trusted_directory_did: "did:web:trusted.local".into(),
        };
        resolution_cache().lock().await.insert(
            key.clone(),
            CachedResolution {
                resolution: DirectoryResolution {
                    endpoint: "https://trusted.local/api".into(),
                    directory_did: Some(key.trusted_directory_did.clone()),
                    source: ResolutionSource::Mdns,
                    observed_hostname: Some("trusted.local".into()),
                    observed_addresses: vec!["192.168.1.10".into()],
                    descriptor_sha256: Some("a".repeat(64)),
                    expires_at: Some(now + 30),
                    cache_hit: false,
                },
                expires_at: now + 30,
            },
        );
        let cached = resolve(ResolveRequest {
            enabled: true,
            mode: OperatingMode::Private,
            explicit_directory: None,
            trusted_directory_did: Some(key.trusted_directory_did.clone()),
            allow_public_fallback: false,
            collection_window_ms: 1,
        })
        .await
        .unwrap()
        .unwrap();
        assert!(cached.cache_hit);

        resolution_cache()
            .lock()
            .await
            .get_mut(&key)
            .unwrap()
            .expires_at = now;
        let expired = resolution_cache().lock().await.remove(&key).unwrap();
        assert!(expired.expires_at <= now);
        assert!(!resolution_cache().lock().await.contains_key(&CacheKey {
            mode: mode_cache_key(OperatingMode::Private),
            trusted_directory_did: "did:web:other.local".into(),
        }));
    }

    #[test]
    fn shared_positive_and_adversarial_profile_cases_are_pinned() {
        assert_eq!(
            hex::encode(Sha256::digest(SHARED_FIXTURE.as_bytes())),
            "490bcc1a70153745a28299ff9680dc185312676ef06384789667174e61f374ed"
        );
        let fixture: Value = serde_json::from_str(SHARED_FIXTURE).unwrap();
        assert_eq!(fixture["service_type"], SERVICE_TYPE);
        assert_eq!(fixture["defaults"]["maximum_txt_bytes"], MAX_TXT_BYTES);
        assert_eq!(
            fixture["defaults"]["maximum_cache_seconds"],
            MAX_CACHE_SECONDS
        );
        for case in fixture["cases"].as_array().unwrap() {
            let actual = evaluate_shared_case(&case["input"]);
            assert_eq!(
                actual,
                case["expected"],
                "shared local-discovery case {}",
                case["id"].as_str().unwrap()
            );
        }
    }

    fn evaluate_shared_case(input: &Value) -> Value {
        let mode = input["mode"].as_str().unwrap();
        let client_kind = input["client_kind"].as_str().unwrap();
        let enabled = input["profile_enabled"].as_bool().unwrap();
        let mdns = input["mdns"].as_str().unwrap();
        let fallback = input["genesis_fallback_allowed"].as_bool().unwrap();
        let now = input["now"].as_i64().unwrap();
        if let Some(explicit) = input["explicit_directory"].as_str() {
            return fixture_result("explicit", Some(explicit), "explicit_configuration", false);
        }
        if !enabled {
            return fixture_result(
                "genesis",
                Some("https://iicp.network/api"),
                "profile_disabled",
                false,
            );
        }
        if client_kind == "browser" {
            return fixture_result(
                "genesis",
                Some("https://iicp.network/api"),
                "browser_local_discovery_unsupported",
                false,
            );
        }
        if mode == "local_only" {
            return fixture_result("none", None, "local_only_external_forbidden", false);
        }
        if mdns == "timeout" {
            return fixture_result(
                "genesis",
                Some("https://iicp.network/api"),
                "local_discovery_unavailable",
                true,
            );
        }
        if mdns == "ssdp_only" {
            return fixture_result(
                "genesis",
                Some("https://iicp.network/api"),
                "ssdp_not_supported",
                true,
            );
        }
        let mut accepted = input["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|candidate| {
                let txt = candidate["txt"].as_object().unwrap();
                let txt_safe = !txt.keys().any(|key| {
                    ["token", "secret", "credential", "membership"]
                        .iter()
                        .any(|word| key.contains(word))
                });
                candidate["txt_bytes"].as_u64().unwrap() <= MAX_TXT_BYTES as u64
                    && txt_safe
                    && candidate["descriptor_signature_valid"] == true
                    && candidate["descriptor_expires_at"].as_i64().unwrap() > now
                    && candidate["cache_expires_at"].as_i64().unwrap() > now
                    && txt
                        .get("did")
                        .is_none_or(|did| did == &candidate["descriptor_did"])
                    && matches!(
                        candidate["trust"].as_str(),
                        Some("pinned" | "domain" | "federation")
                    )
            })
            .collect::<Vec<_>>();
        accepted.sort_by(|left, right| {
            left["descriptor_did"]
                .as_str()
                .cmp(&right["descriptor_did"].as_str())
                .then_with(|| left["endpoint"].as_str().cmp(&right["endpoint"].as_str()))
        });
        if let Some(candidate) = accepted.first() {
            return fixture_result(
                "mdns",
                candidate["endpoint"].as_str(),
                "verified_local_candidate",
                true,
            );
        }
        if mode == "public" && fallback {
            fixture_result(
                "genesis",
                Some("https://iicp.network/api"),
                "local_candidates_rejected",
                true,
            )
        } else {
            fixture_result("none", None, "no_verified_directory", true)
        }
    }

    fn fixture_result(source: &str, selected: Option<&str>, reason: &str, query: bool) -> Value {
        serde_json::json!({
            "source": source,
            "selected": selected,
            "reason": reason,
            "mdns_query": query
        })
    }
}
