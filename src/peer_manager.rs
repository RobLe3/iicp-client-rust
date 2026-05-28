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
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use serde_json::Value;

const GOSSIP_INTERVAL: Duration = Duration::from_secs(30);
const PEER_EXPIRY: Duration = Duration::from_secs(90);
const BOOTSTRAP_LIMIT: u32 = 5;

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
}

/// R3: result of relay election — elected peer + derived relay accept address.
#[derive(Debug, Clone)]
pub struct ElectedRelay {
    pub peer: PeerInfo,
    pub relay_host: String,
    pub relay_port: u16,
}

/// Options for PeerManager constructor (R3 relay capability).
pub struct PeerManagerOpts {
    pub relay_capable: bool,
    pub relay_accept_port: u16,
}

impl Default for PeerManagerOpts {
    fn default() -> Self {
        Self { relay_capable: false, relay_accept_port: 9485 }
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
    peers: Mutex<HashMap<String, PeerInfo>>,
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
        Self {
            directory_url: directory_url.into().trim_end_matches('/').to_string(),
            node_token: node_token.into(),
            own_id: Mutex::new(String::new()),
            own_endpoint: Mutex::new(String::new()),
            own_relay_capable: opts.relay_capable,
            own_relay_accept_port: opts.relay_accept_port,
            peers: Mutex::new(HashMap::new()),
            client: reqwest::Client::new(),
        }
    }

    pub fn get_peers(&self) -> Vec<PeerInfo> {
        self.peers
            .lock()
            .expect("peers lock")
            .values()
            .cloned()
            .collect()
    }

    pub fn relay_target(&self, node_id: &str) -> Option<PeerInfo> {
        self.peers.lock().expect("peers lock").get(node_id).cloned()
    }

    /// Merge incoming peer entries. Returns the count of newly added peers.
    pub fn merge_peers(&self, incoming: &[Value]) -> usize {
        let own = self.own_id.lock().expect("own_id lock").clone();
        let now = Instant::now();
        let mut peers = self.peers.lock().expect("peers lock");
        let mut added = 0;
        for p in incoming {
            let nid = p.get("node_id").and_then(Value::as_str).unwrap_or("");
            if nid.is_empty() || nid == own {
                continue;
            }
            if !peers.contains_key(nid) {
                added += 1;
            }
            peers.insert(
                nid.to_string(),
                PeerInfo {
                    node_id: nid.to_string(),
                    endpoint: p
                        .get("endpoint")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    region: p
                        .get("region")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    last_seen: p
                        .get("last_seen")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    last_contact: now,
                    relay_capable: p
                        .get("relay_capable")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    relay_accept_port: p
                        .get("relay_accept_port")
                        .and_then(Value::as_u64)
                        .unwrap_or(9485) as u16,
                    relay_load: p
                        .get("relay_load")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0),
                },
            );
        }
        added
    }

    /// R3: return relay-capable peers for relay election.
    pub fn get_relay_candidates(&self) -> Vec<PeerInfo> {
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
        Some(ElectedRelay { relay_host, relay_port, peer: elected })
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
        let mut peers = self.peers.lock().expect("peers lock");
        let before = peers.len();
        peers.retain(|_, p| now.duration_since(p.last_contact) < PEER_EXPIRY);
        before - peers.len()
    }

    /// Verify an inbound /v1/peers HMAC signature. No token configured → accept.
    pub fn verify_exchange(&self, body: &[u8], signature: Option<&str>) -> bool {
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
        if let Ok(resp) = self
            .client
            .get(&url)
            .query(&[("limit", BOOTSTRAP_LIMIT)])
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<Value>().await {
                    if let Some(arr) = body.get("peers").and_then(Value::as_array) {
                        self.merge_peers(arr);
                    }
                }
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
            .map(|p| serde_json::json!({
                "node_id": p.node_id,
                "endpoint": p.endpoint,
                "region": p.region,
                "relay_capable": p.relay_capable,
                "relay_accept_port": p.relay_accept_port,
                "relay_load": p.relay_load,
            }))
            .collect();
        if !own_id.is_empty() {
            known.push(serde_json::json!({
                "node_id": own_id,
                "endpoint": own_ep,
                "relay_capable": self.own_relay_capable,
                "relay_accept_port": self.own_relay_accept_port,
                "relay_load": 0.0,
            }));
        }
        let body =
            serde_json::to_vec(&serde_json::json!({ "known_peers": known })).unwrap_or_default();
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
        if let Ok(resp) = req.send().await {
            if resp.status().is_success() {
                if let Ok(data) = resp.json::<Value>().await {
                    if let Some(arr) = data.get("peers").and_then(Value::as_array) {
                        self.merge_peers(arr);
                    }
                }
                if let Some(p) = self
                    .peers
                    .lock()
                    .expect("peers lock")
                    .get_mut(&target.node_id)
                {
                    p.last_contact = Instant::now();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        let ids: Vec<_> = m.get_relay_candidates().into_iter().map(|p| p.node_id).collect();
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
        m.merge_peers(&[json!({"node_id": "nr", "endpoint": "http://nr:8020", "relay_capable": false})]);
        assert!(m.elect_relay("worker").is_none());
    }

    #[test]
    fn extract_host_variants() {
        assert_eq!(PeerManager::extract_host("http://relay-a:8020"), "relay-a");
        assert_eq!(PeerManager::extract_host("https://relay.example.com:9485/"), "relay.example.com");
        assert_eq!(PeerManager::extract_host("relay.host"), "relay.host");
    }
}
