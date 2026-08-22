// SPDX-License-Identifier: Apache-2.0
//! Directory-issued consumer token acquisition for Phase-2 task auth (#496).
//!
//! Spec: spec/iicp-dir.md §3.10

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;

use crate::errors::{IicpError, Result};
use crate::types::RestrictedDirectoryContext;

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

/// Restricted-domain variant. Unlike the compatibility helper, failures are
/// returned so callers cannot silently downgrade to unauthenticated dispatch.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn acquire_restricted_consumer_token(
    cache: &ConsumerTokenCache,
    http: &crate::http::HttpClient,
    directory_url: &str,
    node_token: &str,
    target_node_id: &str,
    intent: &str,
    context: &RestrictedDirectoryContext,
) -> Result<Option<String>> {
    let key = (
        node_token.to_owned(),
        target_node_id.to_owned(),
        intent.to_owned(),
    );
    if let Some(token) = cache.get(&key) {
        return Ok(Some(token));
    }
    let membership =
        crate::secret_store::resolve(&context.membership_credential, None).map_err(|_| {
            IicpError::PolicyRefused {
                code: "restricted_membership_unavailable".into(),
                message: "restricted directory membership credential is unavailable".into(),
            }
        })?;
    let base = directory_url.trim_end_matches("/api").trim_end_matches('/');
    let url = format!("{base}/api/v1/consumer-token");
    let body = serde_json::json!({"target_node_id": target_node_id, "intent": intent});
    let (status, data) = http
        .post_restricted_json(
            &url,
            &body,
            membership.expose(),
            &context.subject_id,
            Some(node_token),
            None,
        )
        .await?;
    if status != 201 {
        return Err(IicpError::Protocol {
            code: data["error"]["code"].as_str().unwrap_or("unknown").into(),
            message: data["error"]["message"].as_str().unwrap_or("").into(),
            status,
        });
    }
    crate::restricted_directory::validate_decision(&data, context, "consumer_token")?;
    let token = data["token"]
        .as_str()
        .ok_or_else(|| IicpError::PolicyRefused {
            code: "restricted_consumer_token_malformed".into(),
            message: "restricted consumer-token response is malformed".into(),
        })?
        .to_owned();
    let exp = data["expires_at"].as_u64().unwrap_or(0);
    cache.set(key, token.clone(), exp);
    Ok(Some(token))
}

#[cfg(test)]
mod restricted_tests {
    use super::*;
    use crate::runtime_config::SecretRef;
    use mockito::{Matcher, ServerOpts};

    fn context(path: &std::path::Path) -> RestrictedDirectoryContext {
        RestrictedDirectoryContext {
            domain_id: "domain-a".into(),
            authority_id: "did:iicp:test:directory-a".into(),
            subject_id: "client-a".into(),
            subject_kind: "client".into(),
            minimum_membership_generation: 7,
            membership_credential: SecretRef::File {
                path: path.display().to_string(),
            },
        }
    }

    fn secret_file() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("iicp-ct-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, "member-token").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    #[tokio::test]
    async fn restricted_token_requires_matching_directory_decision() {
        let path = secret_file();
        let mut server = mockito::Server::new_with_opts_async(ServerOpts::default()).await;
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        let response = serde_json::json!({
            "token":"consumer.sig", "expires_at": expiry,
            "restricted_domain_decision": {
                "schema":"iicp.restricted-trust-domain.directory-decision.v0",
                "profile":"urn:iicp:profile:restricted-trust-domain:v1",
                "decision":"eligible", "operation":"consumer_token",
                "domain_id":"domain-a", "authority_id":"did:iicp:test:directory-a",
                "subject_kind":"client", "membership_generation":7,
                "membership_expires_at": expiry
            }
        });
        let mock = server
            .mock("POST", "/api/v1/consumer-token")
            .match_header("authorization", "Bearer node-token")
            .match_header("x-iicp-membership", "member-token")
            .match_header("x-iicp-subject-id", "client-a")
            .match_body(Matcher::PartialJson(serde_json::json!({
                "target_node_id":"node-a", "intent":"urn:iicp:intent:llm:chat:v1"
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(response.to_string())
            .create_async()
            .await;
        let http = crate::http::HttpClient::new(5_000, None).unwrap();
        let token = acquire_restricted_consumer_token(
            &ConsumerTokenCache::new(),
            &http,
            &server.url(),
            "node-token",
            "node-a",
            "urn:iicp:intent:llm:chat:v1",
            &context(&path),
        )
        .await
        .unwrap();
        assert_eq!(token.as_deref(), Some("consumer.sig"));
        mock.assert_async().await;
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn restricted_token_rejects_missing_decision() {
        let path = secret_file();
        let mut server = mockito::Server::new_with_opts_async(ServerOpts::default()).await;
        let mock = server
            .mock("POST", "/api/v1/consumer-token")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"token":"consumer.sig","expires_at":9999999999}"#)
            .create_async()
            .await;
        let http = crate::http::HttpClient::new(5_000, None).unwrap();
        assert!(acquire_restricted_consumer_token(
            &ConsumerTokenCache::new(),
            &http,
            &server.url(),
            "node-token",
            "node-a",
            "urn:iicp:intent:llm:chat:v1",
            &context(&path),
        )
        .await
        .is_err());
        mock.assert_async().await;
        let _ = std::fs::remove_file(path);
    }
}
