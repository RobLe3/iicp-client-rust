// SPDX-License-Identifier: Apache-2.0
//! Phase 2 mesh layer — peer discovery, gossip, and relay support (parity Block F, #340).
//!
//! Port of iicp-adapter `network/peer_manager.py` + `handlers/{peers,relay}.py` (ADR-009,
//! ADR-022). Bootstraps an initial peer set from the directory, gossips a random known peer
//! every 30s with an HMAC-SHA256-signed exchange (reusing the pricing HMAC key), prunes
//! peers idle for 90s, and resolves relay targets for POST /v1/relay forwarding.
//!
//! Thread-safe: the gossip task and axum handlers share the peer store via a Mutex.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};

const GOSSIP_INTERVAL: Duration = Duration::from_secs(30);
const PEER_EXPIRY: Duration = Duration::from_secs(90);
const BOOTSTRAP_LIMIT: u32 = 5;
const MAX_REPLAY_IDS: usize = 4_096;

#[derive(Debug, Clone, PartialEq)]
pub struct PeerInfo {
    pub node_id: String,
    pub endpoint: String,
    pub region: String,
    pub last_seen: String,
    pub last_contact: Instant,
    /// R3: relay election fields — advertised in gossip exchange
    pub relay_capable: bool,
    pub relay_accept_port: u16,
    pub relay_load: f64,
    /// Present only after restricted-domain admission succeeds.
    pub trust_domain_id: Option<String>,
    pub membership_generation: Option<u64>,
    pub membership_expires_at: Option<u64>,
    pub membership: Option<crate::restricted_membership::MembershipEnvelope>,
}

impl PeerInfo {
    pub fn to_response_value(&self) -> Value {
        let mut value = serde_json::json!({
            "node_id": self.node_id,
            "endpoint": self.endpoint,
            "region": self.region,
            "last_seen": self.last_seen,
        });
        if let Some(membership) = &self.membership {
            value["membership"] = serde_json::to_value(membership).unwrap_or(Value::Null);
        }
        value
    }

    pub fn to_gossip_value(&self) -> Value {
        let mut value = serde_json::json!({
            "node_id": self.node_id,
            "endpoint": self.endpoint,
            "region": self.region,
            "last_seen": self.last_seen,
            "relay_capable": self.relay_capable,
            "relay_accept_port": self.relay_accept_port,
            "relay_load": self.relay_load,
        });
        if let Some(membership) = &self.membership {
            value["membership"] = serde_json::to_value(membership).unwrap_or(Value::Null);
        }
        value
    }
}

/// R3: result of relay election — elected peer + derived relay accept address.
#[derive(Debug, Clone)]
pub struct ElectedRelay {
    pub peer: PeerInfo,
    pub relay_host: String,
    pub relay_port: u16,
}

/// Options for PeerManager constructor (R3 relay capability).
#[derive(Clone, Default)]
pub enum PeerAdmissionMode {
    #[default]
    Public,
    Restricted(Box<RestrictedPeerAdmission>),
}

#[derive(Clone)]
pub struct RestrictedLocalIdentity {
    pub membership: crate::restricted_membership::MembershipEnvelope,
    pub signing_seed: [u8; 32],
}

#[derive(Clone)]
pub struct RestrictedPeerAdmission {
    pub policy: crate::restricted_membership::MembershipPolicy,
    pub directory_membership_bearer: String,
    pub local: Option<RestrictedLocalIdentity>,
}

impl std::fmt::Debug for PeerAdmissionMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public => formatter.write_str("Public"),
            Self::Restricted(restricted) => formatter
                .debug_struct("Restricted")
                .field("policy", &restricted.policy)
                .field("local_identity_configured", &restricted.local.is_some())
                .field(
                    "directory_membership_configured",
                    &!restricted.directory_membership_bearer.is_empty(),
                )
                .finish(),
        }
    }
}

pub struct PeerManagerOpts {
    pub relay_capable: bool,
    pub relay_accept_port: u16,
    pub admission: PeerAdmissionMode,
}

impl Default for PeerManagerOpts {
    fn default() -> Self {
        Self {
            relay_capable: false,
            relay_accept_port: 9485,
            admission: PeerAdmissionMode::Public,
        }
    }
}

#[derive(Debug)]
pub struct PeerManager {
    directory_url: String,
    node_token: String,
    own_id: Mutex<String>,
    own_endpoint: Mutex<String>,
    own_relay_capable: bool,
    own_relay_accept_port: u16,
    admission: PeerAdmissionMode,
    minimum_generation: AtomicU64,
    peers: Mutex<HashMap<String, PeerInfo>>,
    replay_ids: Mutex<HashMap<String, u64>>,
    client: reqwest::Client,
}

impl PeerManager {
    pub fn new(directory_url: impl Into<String>, node_token: impl Into<String>) -> Self {
        Self::with_opts(directory_url, node_token, PeerManagerOpts::default())
    }

    pub fn with_opts(
        directory_url: impl Into<String>,
        node_token: impl Into<String>,
        opts: PeerManagerOpts,
    ) -> Self {
        let minimum_generation = match &opts.admission {
            PeerAdmissionMode::Public => 0,
            PeerAdmissionMode::Restricted(restricted) => restricted.policy.minimum_generation,
        };
        Self {
            directory_url: directory_url.into().trim_end_matches('/').to_string(),
            node_token: node_token.into(),
            own_id: Mutex::new(String::new()),
            own_endpoint: Mutex::new(String::new()),
            own_relay_capable: opts.relay_capable,
            own_relay_accept_port: opts.relay_accept_port,
            admission: opts.admission,
            minimum_generation: AtomicU64::new(minimum_generation),
            peers: Mutex::new(HashMap::new()),
            replay_ids: Mutex::new(HashMap::new()),
            client: reqwest::Client::new(),
        }
    }

    pub fn get_peers(&self) -> Vec<PeerInfo> {
        self.prune();
        self.peers
            .lock()
            .expect("peers lock")
            .values()
            .cloned()
            .collect()
    }

    pub fn relay_target(&self, node_id: &str) -> Option<PeerInfo> {
        self.prune();
        self.peers.lock().expect("peers lock").get(node_id).cloned()
    }

    /// Advance the trusted membership generation and immediately remove stale
    /// direct and relay candidates. Generations never move backwards.
    pub fn update_minimum_generation(&self, generation: u64) -> usize {
        self.minimum_generation
            .fetch_max(generation, Ordering::SeqCst);
        let minimum = self.minimum_generation.load(Ordering::SeqCst);
        let mut peers = self.peers.lock().expect("peers lock");
        let before = peers.len();
        peers.retain(|_, peer| {
            peer.membership_generation
                .is_none_or(|peer_generation| peer_generation >= minimum)
        });
        before - peers.len()
    }

    /// Merge incoming peer entries. Returns the count of newly added peers.
    pub fn merge_peers(&self, incoming: &[Value]) -> usize {
        self.merge_peers_for_scope(incoming, "peers")
    }

    fn merge_peers_for_scope(&self, incoming: &[Value], scope: &str) -> usize {
        self.merge_peers_at(incoming, scope, unix_time())
    }

    fn merge_peers_at(&self, incoming: &[Value], scope: &str, epoch: u64) -> usize {
        let own = self.own_id.lock().expect("own_id lock").clone();
        let now = Instant::now();
        let mut peers = self.peers.lock().expect("peers lock");
        let mut added = 0;
        for p in incoming {
            let nid = p.get("node_id").and_then(Value::as_str).unwrap_or("");
            if nid.is_empty() || nid == own {
                continue;
            }
            let Some(membership) = self.admitted_membership(p, nid, scope, epoch) else {
                continue;
            };
            if !peers.contains_key(nid) {
                added += 1;
            }
            peers.insert(nid.to_string(), peer_info(p, nid, membership, now));
        }
        added
    }

    fn admitted_membership(
        &self,
        peer: &Value,
        node_id: &str,
        scope: &str,
        epoch: u64,
    ) -> Option<Option<crate::restricted_membership::MembershipEnvelope>> {
        match &self.admission {
            PeerAdmissionMode::Public => Some(None),
            PeerAdmissionMode::Restricted(restricted) => self
                .verified_restricted_membership(peer, node_id, scope, epoch, restricted)
                .map(Some),
        }
    }

    fn verified_restricted_membership(
        &self,
        peer: &Value,
        node_id: &str,
        scope: &str,
        epoch: u64,
        restricted: &RestrictedPeerAdmission,
    ) -> Option<crate::restricted_membership::MembershipEnvelope> {
        if !valid_restricted_peer(peer) {
            return None;
        }
        let mut policy = restricted.policy.clone();
        policy.minimum_generation = policy
            .minimum_generation
            .max(self.minimum_generation.load(Ordering::SeqCst));
        let envelope = serde_json::from_value(peer.get("membership")?.clone()).ok()?;
        crate::restricted_membership::verify_membership(&envelope, &policy, node_id, scope, epoch)
            .ok()?;
        Some(envelope)
    }

    /// Verify one complete gossip request and return only its advertised peers.
    /// Restricted mode never falls back to the legacy HMAC or tokenless path.
    pub fn verify_and_extract_exchange(
        &self,
        body: &[u8],
        signature: Option<&str>,
    ) -> Result<Vec<Value>, &'static str> {
        match &self.admission {
            PeerAdmissionMode::Public => {
                if !self.verify_exchange(body, signature) {
                    return Err("invalid_signature");
                }
                extract_known_peers(body).ok_or("malformed_exchange")
            }
            PeerAdmissionMode::Restricted(restricted) => {
                self.verify_restricted_exchange(body, restricted)
            }
        }
    }

    fn verify_restricted_exchange(
        &self,
        body: &[u8],
        restricted: &RestrictedPeerAdmission,
    ) -> Result<Vec<Value>, &'static str> {
        let mut policy = restricted.policy.clone();
        policy.minimum_generation = policy
            .minimum_generation
            .max(self.minimum_generation.load(Ordering::SeqCst));
        let (membership, gossip, peers, payload) = parse_restricted_exchange(body)?;
        crate::restricted_membership::verify_gossip(
            &gossip,
            &membership,
            &policy,
            &payload,
            unix_time(),
            false,
        )
        .map_err(crate::restricted_membership::MembershipRefusal::code)?;
        self.record_replay(&gossip.proof.replay_id, membership.assertion.expires_at)?;
        Ok(peers)
    }

    fn record_replay(&self, replay_id: &str, expires_at: u64) -> Result<(), &'static str> {
        let now = unix_time();
        let mut replay_ids = self.replay_ids.lock().expect("replay lock");
        replay_ids.retain(|_, expiry| *expiry > now);
        if replay_ids.contains_key(replay_id) {
            return Err(crate::restricted_membership::MembershipRefusal::ReplayDetected.code());
        }
        if replay_ids.len() >= MAX_REPLAY_IDS {
            return Err(crate::restricted_membership::MembershipRefusal::ReplayCapacity.code());
        }
        replay_ids.insert(replay_id.to_string(), expires_at);
        Ok(())
    }

    /// R3: return relay-capable peers for relay election.
    pub fn get_relay_candidates(&self) -> Vec<PeerInfo> {
        self.prune();
        self.peers
            .lock()
            .expect("peers lock")
            .values()
            .filter(|p| p.relay_capable && !p.endpoint.is_empty())
            .cloned()
            .collect()
    }

    /// R3: deterministic relay election — rank by load, tiebreak by SHA-256.
    ///
    /// Scores each relay-capable peer by `(relay_load, sha256(worker_id:peer_id))`
    /// and returns the minimum, matching the Python/TypeScript algorithm.
    pub fn elect_relay(&self, worker_id: &str) -> Option<ElectedRelay> {
        let candidates = self.get_relay_candidates();
        if candidates.is_empty() {
            return None;
        }
        let score = |peer: &PeerInfo| -> (u64, String) {
            // Encode load as fixed-point to make it Ord-comparable
            let load_fp = (peer.relay_load * 1_000_000.0) as u64;
            let hash_input = format!("{}:{}", worker_id, peer.node_id);
            let mut hasher = Sha256::new();
            hasher.update(hash_input.as_bytes());
            let hash_hex = format!("{:x}", hasher.finalize());
            (load_fp, hash_hex)
        };
        let elected = candidates
            .into_iter()
            .min_by(|a, b| score(a).cmp(&score(b)))
            .expect("non-empty");
        // Derive relay host from endpoint URL (same host, relay_accept_port)
        let relay_host = Self::extract_host(&elected.endpoint);
        let relay_port = elected.relay_accept_port;
        Some(ElectedRelay {
            relay_host,
            relay_port,
            peer: elected,
        })
    }

    fn extract_host(endpoint: &str) -> String {
        // Strip scheme and path, return just the hostname.
        let without_scheme = if let Some(rest) = endpoint.strip_prefix("http://") {
            rest
        } else if let Some(rest) = endpoint.strip_prefix("https://") {
            rest
        } else {
            endpoint
        };
        // Remove any path after hostname:port
        let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
        // Remove port if present
        if let Some(h) = host_port.rsplit_once(':') {
            h.0.to_string()
        } else {
            host_port.to_string()
        }
    }

    /// Drop peers not contacted within the expiry window. Returns count pruned.
    pub fn prune(&self) -> usize {
        let now = Instant::now();
        let epoch = unix_time();
        let mut peers = self.peers.lock().expect("peers lock");
        let before = peers.len();
        peers.retain(|_, p| {
            now.duration_since(p.last_contact) < PEER_EXPIRY
                && p.membership_expires_at
                    .is_none_or(|expires| expires > epoch)
        });
        before - peers.len()
    }

    /// Verify a public-mode inbound /v1/peers HMAC signature. Restricted mode
    /// always rejects this compatibility path.
    pub fn verify_exchange(&self, body: &[u8], signature: Option<&str>) -> bool {
        if matches!(self.admission, PeerAdmissionMode::Restricted(_)) {
            return false;
        }
        if self.node_token.is_empty() {
            return true;
        }
        match signature {
            Some(sig) => crate::pricing::verify_signature(body, &self.node_token, sig),
            None => false,
        }
    }

    pub async fn start(&self, node_id: &str, own_endpoint: &str) {
        *self.own_id.lock().expect("own_id lock") = node_id.to_string();
        *self.own_endpoint.lock().expect("own_endpoint lock") = own_endpoint.to_string();
        self.bootstrap().await;
    }

    pub async fn gossip_round(&self) {
        let peers = self.get_peers();
        if peers.is_empty() {
            self.bootstrap().await;
            return;
        }
        // Cheap rotating pick without an rng dependency: oldest-contacted peer.
        let target = peers
            .into_iter()
            .min_by_key(|p| p.last_contact)
            .expect("non-empty");
        self.exchange(&target).await;
        self.prune();
    }

    pub fn gossip_interval(&self) -> Duration {
        GOSSIP_INTERVAL
    }

    async fn bootstrap(&self) {
        let url = format!("{}/v1/bootstrap", self.directory_url);
        let Some(request) = self.bootstrap_request(&url) else {
            return;
        };
        if let Ok(resp) = request.send().await {
            self.merge_bootstrap_response(resp).await;
        }
    }

    fn bootstrap_request(&self, url: &str) -> Option<reqwest::RequestBuilder> {
        let mut request = self
            .client
            .get(url)
            .query(&[("limit", BOOTSTRAP_LIMIT)])
            .timeout(Duration::from_secs(5));
        if let PeerAdmissionMode::Restricted(restricted) = &self.admission {
            let local = restricted.local.as_ref()?;
            if restricted.directory_membership_bearer.is_empty() {
                return None;
            }
            request = request
                .header("X-IICP-Membership", &restricted.directory_membership_bearer)
                .header("X-IICP-Subject-Id", &local.membership.assertion.subject.id);
        }
        Some(request)
    }

    async fn merge_bootstrap_response(&self, response: reqwest::Response) {
        if !response.status().is_success() {
            return;
        }
        if let Ok(body) = response.json::<Value>().await {
            if let Some(peers) = body.get("peers").and_then(Value::as_array) {
                self.merge_peers_for_scope(peers, "bootstrap");
            }
        }
    }

    async fn exchange(&self, target: &PeerInfo) {
        // R3: send full peer objects + own relay entry so recipients can elect us as relay.
        let own_id = self.own_id.lock().expect("own_id lock").clone();
        let own_ep = self.own_endpoint.lock().expect("own_endpoint lock").clone();
        let mut known: Vec<Value> = self
            .peers
            .lock()
            .expect("peers lock")
            .values()
            .map(PeerInfo::to_gossip_value)
            .collect();
        if let Some(own) = self.own_peer_value(own_id, own_ep) {
            known.push(own);
        }
        let payload = serde_json::json!({ "known_peers": known });
        let Some(body) = self.exchange_body(&payload) else {
            return;
        };
        let url = format!("{}/v1/peers", target.endpoint.trim_end_matches('/'));
        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(5))
            .body(body.clone());
        if !self.node_token.is_empty() {
            req = req.header(
                "X-IICP-Signature",
                crate::pricing::sign_body(&body, &self.node_token),
            );
        }
        if let Ok(response) = req.send().await {
            self.handle_exchange_response(response, &target.node_id)
                .await;
        }
    }

    async fn handle_exchange_response(&self, response: reqwest::Response, target_id: &str) {
        if !response.status().is_success() {
            return;
        }
        if let Ok(data) = response.json::<Value>().await {
            if let Some(peers) = data.get("peers").and_then(Value::as_array) {
                self.merge_peers(peers);
            }
        }
        if let Some(peer) = self.peers.lock().expect("peers lock").get_mut(target_id) {
            peer.last_contact = Instant::now();
        }
    }

    fn own_peer_value(&self, node_id: String, endpoint: String) -> Option<Value> {
        if node_id.is_empty() {
            return None;
        }
        let mut own = serde_json::json!({
            "node_id": node_id,
            "endpoint": endpoint,
            "relay_capable": self.own_relay_capable,
            "relay_accept_port": self.own_relay_accept_port,
            "relay_load": 0.0,
        });
        if let PeerAdmissionMode::Restricted(restricted) = &self.admission {
            let local = restricted.local.as_ref()?;
            own["membership"] = serde_json::to_value(&local.membership).ok()?;
        }
        Some(own)
    }

    fn exchange_body(&self, payload: &Value) -> Option<Vec<u8>> {
        let PeerAdmissionMode::Restricted(restricted) = &self.admission else {
            return serde_json::to_vec(payload).ok();
        };
        let local = restricted.local.as_ref()?;
        let canonical = serde_jcs::to_vec(payload).ok()?;
        let gossip = crate::restricted_membership::sign_gossip(
            &local.membership,
            &local.signing_seed,
            &restricted.policy.domain_id,
            &canonical,
            unix_time(),
            uuid::Uuid::new_v4().to_string(),
        )
        .ok()?;
        serde_json::to_vec(&serde_json::json!({
            "known_peers": payload["known_peers"],
            "membership": local.membership,
            "gossip": gossip,
        }))
        .ok()
    }
}

type RestrictedExchange = (
    crate::restricted_membership::MembershipEnvelope,
    crate::restricted_membership::GossipEnvelope,
    Vec<Value>,
    Vec<u8>,
);

fn parse_restricted_exchange(body: &[u8]) -> Result<RestrictedExchange, &'static str> {
    let parsed: Value = serde_json::from_slice(body).map_err(|_| "malformed_exchange")?;
    let membership =
        serde_json::from_value(parsed["membership"].clone()).map_err(|_| "membership_malformed")?;
    let gossip =
        serde_json::from_value(parsed["gossip"].clone()).map_err(|_| "gossip_malformed")?;
    let (peers, payload) = restricted_peer_payload(&parsed)?;
    Ok((membership, gossip, peers, payload))
}

fn restricted_peer_payload(parsed: &Value) -> Result<(Vec<Value>, Vec<u8>), &'static str> {
    let peers = parsed["known_peers"]
        .as_array()
        .cloned()
        .ok_or("malformed_exchange")?;
    let payload = serde_jcs::to_vec(&serde_json::json!({"known_peers": peers}))
        .map_err(|_| "malformed_exchange")?;
    Ok((peers, payload))
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn peer_info(
    peer: &Value,
    node_id: &str,
    membership: Option<crate::restricted_membership::MembershipEnvelope>,
    last_contact: Instant,
) -> PeerInfo {
    PeerInfo {
        node_id: node_id.to_string(),
        endpoint: peer["endpoint"].as_str().unwrap_or("").to_string(),
        region: peer["region"].as_str().unwrap_or("").to_string(),
        last_seen: peer["last_seen"].as_str().unwrap_or("").to_string(),
        last_contact,
        relay_capable: peer["relay_capable"].as_bool().unwrap_or(false),
        relay_accept_port: peer["relay_accept_port"].as_u64().unwrap_or(9485) as u16,
        relay_load: peer["relay_load"].as_f64().unwrap_or(0.0),
        trust_domain_id: membership
            .as_ref()
            .map(|value| value.assertion.domain_id.clone()),
        membership_generation: membership.as_ref().map(|value| value.assertion.generation),
        membership_expires_at: membership.as_ref().map(|value| value.assertion.expires_at),
        membership,
    }
}

fn extract_known_peers(body: &[u8]) -> Option<Vec<Value>> {
    serde_json::from_slice::<Value>(body)
        .ok()?
        .get("known_peers")?
        .as_array()
        .cloned()
}

fn valid_restricted_peer(peer: &Value) -> bool {
    let Some(endpoint) = peer.get("endpoint").and_then(Value::as_str) else {
        return false;
    };
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    if !valid_peer_url(&url) {
        return false;
    }
    if invalid_relay_port(peer) {
        return false;
    }
    !invalid_relay_load(peer)
}

fn invalid_relay_port(peer: &Value) -> bool {
    peer.get("relay_accept_port")
        .and_then(Value::as_u64)
        .is_some_and(|port| port == 0 || port > u16::MAX.into())
}

fn invalid_relay_load(peer: &Value) -> bool {
    peer.get("relay_load")
        .and_then(Value::as_f64)
        .is_some_and(|load| !load.is_finite() || load < 0.0)
}

fn valid_peer_url(url: &reqwest::Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && peer_url_has_no_credentials(url)
        && url.fragment().is_none()
}

fn peer_url_has_no_credentials(url: &reqwest::Url) -> bool {
    url.username().is_empty() && url.password().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn issued_membership(
        authority: &SigningKey,
        member: &SigningKey,
        node_id: &str,
        assertion_id: &str,
        now: u64,
    ) -> crate::restricted_membership::MembershipEnvelope {
        use crate::restricted_membership::{
            DetachedSignature, MembershipAssertion, MembershipEnvelope, MembershipIssuer,
            MembershipSubject, MEMBERSHIP_SCHEMA, RESTRICTED_PROFILE,
        };
        let assertion = MembershipAssertion {
            schema: MEMBERSHIP_SCHEMA.into(),
            profile: RESTRICTED_PROFILE.into(),
            assertion_id: assertion_id.into(),
            domain_id: "domain-a".into(),
            subject: MembershipSubject {
                kind: "node".into(),
                id: node_id.into(),
                key_id: format!("{node_id}#key-1"),
                public_key_ed25519: URL_SAFE_NO_PAD.encode(member.verifying_key().to_bytes()),
            },
            issuer: MembershipIssuer {
                id: "directory-a".into(),
                key_id: "directory-a#key-1".into(),
            },
            issued_at: now.saturating_sub(1),
            expires_at: now + 300,
            generation: 3,
            scopes: vec!["bootstrap".into(), "peers".into(), "relay".into()],
            audience: vec!["domain-a".into()],
        };
        let mut message = b"IICP-RTD-MEMBERSHIP-V0\n".to_vec();
        message.extend_from_slice(&serde_jcs::to_vec(&assertion).unwrap());
        MembershipEnvelope {
            assertion,
            signature: DetachedSignature {
                algorithm: "Ed25519".into(),
                key_id: None,
                value: URL_SAFE_NO_PAD.encode(authority.sign(&message).to_bytes()),
            },
        }
    }

    fn policy_for(authority: &SigningKey) -> crate::restricted_membership::MembershipPolicy {
        crate::restricted_membership::MembershipPolicy {
            domain_id: "domain-a".into(),
            authority_id: "directory-a".into(),
            authority_key_id: "directory-a#key-1".into(),
            authority_public_key_ed25519: URL_SAFE_NO_PAD
                .encode(authority.verifying_key().to_bytes()),
            minimum_generation: 3,
            maximum_clock_skew_seconds: 60,
        }
    }

    fn restricted_pm() -> PeerManager {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/restricted-trust-domain-membership-v0.json"
        ))
        .unwrap();
        let m = PeerManager::with_opts(
            "https://dir.example/api",
            "",
            PeerManagerOpts {
                relay_capable: false,
                relay_accept_port: 9485,
                admission: PeerAdmissionMode::Restricted(Box::new(RestrictedPeerAdmission {
                    policy: crate::restricted_membership::MembershipPolicy {
                        domain_id: "domain-test-a".into(),
                        authority_id: "did:iicp:test:directory-a".into(),
                        authority_key_id: "did:iicp:test:directory-a#key-1".into(),
                        authority_public_key_ed25519: fixture["authority_public_key_ed25519"]
                            .as_str()
                            .unwrap()
                            .into(),
                        minimum_generation: 7,
                        maximum_clock_skew_seconds: 60,
                    },
                    directory_membership_bearer: "test-bearer".into(),
                    local: None,
                })),
            },
        );
        *m.own_id.lock().unwrap() = "self".into();
        m
    }

    fn valid_membership() -> Value {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/restricted-trust-domain-membership-v0.json"
        ))
        .unwrap();
        fixture["vectors"][0]["envelope"].clone()
    }

    fn pm(token: &str) -> PeerManager {
        let m = PeerManager::new("https://dir.example/api", token);
        *m.own_id.lock().unwrap() = "self".into();
        m
    }

    fn pm_with_relays() -> PeerManager {
        let m = PeerManager::new("https://dir.example/api", "");
        *m.own_id.lock().unwrap() = "self".into();
        m.merge_peers(&[
            json!({"node_id": "relay-a", "endpoint": "http://relay-a:8020",
                   "relay_capable": true, "relay_accept_port": 9485, "relay_load": 0.2}),
            json!({"node_id": "relay-b", "endpoint": "http://relay-b:8020",
                   "relay_capable": true, "relay_accept_port": 9486, "relay_load": 0.1}),
            json!({"node_id": "non-relay", "endpoint": "http://nr:8020", "relay_capable": false}),
        ]);
        m
    }

    #[test]
    fn merge_adds_and_dedups_and_skips_self() {
        let m = pm("");
        assert_eq!(
            m.merge_peers(&[json!({"node_id": "a", "endpoint": "http://a"})]),
            1
        );
        // self is skipped, a is an update (not new)
        assert_eq!(
            m.merge_peers(&[
                json!({"node_id": "a", "endpoint": "http://a2"}),
                json!({"node_id": "self", "endpoint": "http://self"}),
            ]),
            0
        );
        assert_eq!(m.get_peers().len(), 1);
    }

    #[test]
    fn relay_target_lookup() {
        let m = pm("");
        m.merge_peers(&[json!({"node_id": "a", "endpoint": "http://a"})]);
        assert_eq!(m.relay_target("a").unwrap().endpoint, "http://a");
        assert!(m.relay_target("missing").is_none());
    }

    #[test]
    fn verify_exchange_token_modes() {
        let no_tok = pm("");
        assert!(no_tok.verify_exchange(b"{}", None));

        let m = pm("secret");
        let body = br#"{"known_peers":[]}"#;
        let sig = crate::pricing::sign_body(body, "secret");
        assert!(m.verify_exchange(body, Some(&sig)));
        assert!(!m.verify_exchange(body, Some("deadbeef")));
        assert!(!m.verify_exchange(body, None));
    }

    #[test]
    fn restricted_admission_requires_each_peers_own_valid_assertion() {
        let m = restricted_pm();
        assert_eq!(
            m.merge_peers_at(
                &[json!({
                    "node_id": "did:iicp:test:node-a",
                    "endpoint": "https://node-a.example",
                    "membership": valid_membership(),
                })],
                "peers",
                1_800_000_010
            ),
            1
        );
        assert_eq!(m.get_peers().len(), 1);

        assert_eq!(
            m.merge_peers(&[json!({
                "node_id": "did:iicp:test:node-x",
                "endpoint": "https://node-x.example",
            })]),
            0
        );
        assert!(m.relay_target("did:iicp:test:node-x").is_none());
    }

    #[test]
    fn restricted_mode_rejects_legacy_hmac_and_tokenless_gossip() {
        let m = restricted_pm();
        assert!(!m.verify_exchange(br#"{"known_peers":[]}"#, None));
        assert!(!m.verify_exchange(br#"{"known_peers":[]}"#, Some("legacy")));
        assert_eq!(
            m.verify_and_extract_exchange(br#"{"known_peers":[]}"#, None),
            Err("membership_malformed")
        );
    }

    #[test]
    fn revocation_generation_immediately_removes_direct_and_relay_eligibility() {
        let m = restricted_pm();
        assert_eq!(
            m.merge_peers_at(
                &[json!({
                    "node_id": "did:iicp:test:node-a",
                    "endpoint": "https://node-a.example",
                    "relay_capable": true,
                    "membership": valid_membership(),
                })],
                "peers",
                1_800_000_010,
            ),
            1
        );
        assert_eq!(m.get_relay_candidates().len(), 1);
        assert_eq!(m.update_minimum_generation(8), 1);
        assert!(m.relay_target("did:iicp:test:node-a").is_none());
        assert!(m.get_relay_candidates().is_empty());
    }

    #[test]
    fn authenticated_exchange_is_payload_bound_and_single_use() {
        let now = unix_time();
        let authority = SigningKey::from_bytes(&[7u8; 32]);
        let sender = SigningKey::from_bytes(&[8u8; 32]);
        let advertised = SigningKey::from_bytes(&[9u8; 32]);
        let sender_membership = issued_membership(
            &authority,
            &sender,
            "node-sender",
            "00000000-0000-4000-8000-000000000011",
            now,
        );
        let advertised_membership = issued_membership(
            &authority,
            &advertised,
            "node-advertised",
            "00000000-0000-4000-8000-000000000012",
            now,
        );
        let payload = json!({
            "known_peers": [{
                "node_id": "node-advertised",
                "endpoint": "https://advertised.example",
                "membership": advertised_membership,
            }]
        });
        let canonical = serde_jcs::to_vec(&payload).unwrap();
        let gossip = crate::restricted_membership::sign_gossip(
            &sender_membership,
            &[8u8; 32],
            "domain-a",
            &canonical,
            now,
            "00000000-0000-4000-8000-000000000013".into(),
        )
        .unwrap();
        let body = serde_json::to_vec(&json!({
            "known_peers": payload["known_peers"],
            "membership": sender_membership,
            "gossip": gossip,
        }))
        .unwrap();
        let manager = PeerManager::with_opts(
            "https://directory.example",
            "",
            PeerManagerOpts {
                relay_capable: false,
                relay_accept_port: 9485,
                admission: PeerAdmissionMode::Restricted(Box::new(RestrictedPeerAdmission {
                    policy: policy_for(&authority),
                    directory_membership_bearer: "bearer".into(),
                    local: None,
                })),
            },
        );
        let peers = manager
            .verify_and_extract_exchange(&body, None)
            .expect("first authenticated exchange is accepted");
        assert_eq!(manager.merge_peers(&peers), 1);
        assert_eq!(
            manager.verify_and_extract_exchange(&body, None),
            Err("gossip_replay")
        );

        let mut tampered: Value = serde_json::from_slice(&body).unwrap();
        tampered["known_peers"][0]["endpoint"] = json!("https://evil.example");
        assert_eq!(
            manager.verify_and_extract_exchange(&serde_json::to_vec(&tampered).unwrap(), None),
            Err("gossip_payload_mismatch")
        );
    }

    // ── R3: relay election tests ─────────────────────────────────────────────

    #[test]
    fn merge_stores_relay_fields() {
        let m = pm("");
        m.merge_peers(&[json!({"node_id": "r", "endpoint": "http://r:8020",
                               "relay_capable": true, "relay_accept_port": 9485})]);
        let p = m.relay_target("r").unwrap();
        assert!(p.relay_capable);
        assert_eq!(p.relay_accept_port, 9485);
    }

    #[test]
    fn get_relay_candidates_excludes_non_relay() {
        let m = pm_with_relays();
        let ids: Vec<_> = m
            .get_relay_candidates()
            .into_iter()
            .map(|p| p.node_id)
            .collect();
        assert!(!ids.contains(&"non-relay".to_string()));
        assert!(ids.contains(&"relay-a".to_string()));
        assert!(ids.contains(&"relay-b".to_string()));
    }

    #[test]
    fn elect_relay_prefers_lower_load() {
        let m = pm_with_relays();
        let elected = m.elect_relay("worker-001").expect("should elect relay");
        // relay-b load=0.1 < relay-a load=0.2 → relay-b always wins
        assert_eq!(elected.peer.node_id, "relay-b");
        assert!(elected.peer.relay_capable);
    }

    #[test]
    fn elect_relay_is_deterministic() {
        let m = pm_with_relays();
        let e1 = m.elect_relay("worker-xyz").unwrap();
        let e2 = m.elect_relay("worker-xyz").unwrap();
        assert_eq!(e1.peer.node_id, e2.peer.node_id);
    }

    #[test]
    fn elect_relay_derives_host_port() {
        let m = pm_with_relays();
        let elected = m.elect_relay("worker-001").unwrap();
        assert!(!elected.relay_host.is_empty());
        assert_eq!(elected.relay_port, elected.peer.relay_accept_port);
    }

    #[test]
    fn elect_relay_none_when_no_relays() {
        let m = pm("");
        m.merge_peers(&[
            json!({"node_id": "nr", "endpoint": "http://nr:8020", "relay_capable": false}),
        ]);
        assert!(m.elect_relay("worker").is_none());
    }

    #[test]
    fn extract_host_variants() {
        assert_eq!(PeerManager::extract_host("http://relay-a:8020"), "relay-a");
        assert_eq!(
            PeerManager::extract_host("https://relay.example.com:9485/"),
            "relay.example.com"
        );
        assert_eq!(PeerManager::extract_host("relay.host"), "relay.host");
    }
}
