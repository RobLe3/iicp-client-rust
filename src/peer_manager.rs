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
}

#[derive(Debug)]
pub struct PeerManager {
    directory_url: String,
    node_token: String,
    own_id: Mutex<String>,
    peers: Mutex<HashMap<String, PeerInfo>>,
    client: reqwest::Client,
}

impl PeerManager {
    pub fn new(directory_url: impl Into<String>, node_token: impl Into<String>) -> Self {
        Self {
            directory_url: directory_url.into().trim_end_matches('/').to_string(),
            node_token: node_token.into(),
            own_id: Mutex::new(String::new()),
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
                },
            );
        }
        added
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

    pub async fn start(&self, node_id: &str) {
        *self.own_id.lock().expect("own_id lock") = node_id.to_string();
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
        let known: Vec<String> = self
            .peers
            .lock()
            .expect("peers lock")
            .keys()
            .cloned()
            .collect();
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
}
