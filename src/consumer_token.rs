// SPDX-License-Identifier: Apache-2.0
//! Directory-issued consumer token acquisition for Phase-2 task auth (#496).
//!
//! Spec: spec/iicp-dir.md §3.10

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;

const EXPIRY_BUFFER_S: u64 = 30;

/// Cache key: (caller_node_token, target_node_id, intent).
type CacheKey = (String, String, String);
/// Cached value: (token, exp_unix).
type CachedToken = (String, u64);

/// Thread-safe consumer token cache.
pub struct ConsumerTokenCache {
    inner: Mutex<HashMap<CacheKey, CachedToken>>,
}

impl ConsumerTokenCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Return a cached token if it has more than EXPIRY_BUFFER_S remaining.
    fn get(&self, key: &(String, String, String)) -> Option<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.get(key).and_then(|(tok, exp)| {
            if now + EXPIRY_BUFFER_S < *exp {
                Some(tok.clone())
            } else {
                None
            }
        })
    }

    pub fn set(&self, key: (String, String, String), token: String, exp: u64) {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.insert(key, (token, exp));
    }
}

impl Default for ConsumerTokenCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Acquire a consumer token from the directory.
///
/// Returns `None` on any failure — callers should fall back to no-auth gracefully.
pub async fn acquire_consumer_token(
    cache: &ConsumerTokenCache,
    http: &Client,
    directory_url: &str,
    node_token: &str,
    target_node_id: &str,
    intent: &str,
    timeout_s: f64,
) -> Option<String> {
    let key = (
        node_token.to_owned(),
        target_node_id.to_owned(),
        intent.to_owned(),
    );
    if let Some(tok) = cache.get(&key) {
        return Some(tok);
    }

    let base = directory_url.trim_end_matches("/api").trim_end_matches('/');
    let url = format!("{base}/api/v1/consumer-token");

    let body = serde_json::json!({
        "target_node_id": target_node_id,
        "intent": intent,
    });

    let result = tokio::time::timeout(
        Duration::from_secs_f64(timeout_s),
        http.post(&url).bearer_auth(node_token).json(&body).send(),
    )
    .await;

    let resp = match result {
        Ok(Ok(r)) => r,
        _ => return None,
    };

    if resp.status().as_u16() != 201 {
        return None;
    }

    let data: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return None,
    };

    let token = data["token"].as_str()?.to_owned();
    let exp = data["expires_at"].as_u64().unwrap_or(0);
    cache.set(key, token.clone(), exp);
    Some(token)
}
