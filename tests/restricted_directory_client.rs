// SPDX-License-Identifier: Apache-2.0

use axum::{extract::State, http::HeaderMap, routing::get, Json, Router};
use iicp_client::{
    runtime_config::SecretRef, ClientConfig, IicpClient, ProfileRequest, RestrictedDirectoryContext,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

type ObservedHeaders = Arc<Mutex<Option<(String, String)>>>;

fn protected_secret_file() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("iicp-membership-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, b"membership-token").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

fn config(url: String, secret: &std::path::Path) -> ClientConfig {
    ClientConfig {
        directory_url: url,
        profile_request: Some(ProfileRequest {
            profile_id: "urn:iicp:profile:restricted-trust-domain:v1".into(),
            profile_version: "0.1.0-draft".into(),
            profile_fixture_sha256: "a".repeat(64),
            required: true,
        }),
        restricted_directory: Some(RestrictedDirectoryContext {
            domain_id: "domain-a".into(),
            authority_id: "did:iicp:test:directory-a".into(),
            subject_id: "client-a".into(),
            subject_kind: "client".into(),
            minimum_membership_generation: 7,
            membership_credential: SecretRef::File {
                path: secret.display().to_string(),
            },
        }),
        ..ClientConfig::default()
    }
}

#[tokio::test]
async fn authenticated_discovery_marks_candidates_with_validated_provenance() {
    let observed = Arc::new(Mutex::new(None));
    let state = Arc::clone(&observed);
    let app = Router::new()
        .route(
            "/v1/discover",
            get(|State(state): State<ObservedHeaders>, headers: HeaderMap| async move {
                *state.lock().unwrap() = Some((
                    headers["x-iicp-membership"].to_str().unwrap().into(),
                    headers["x-iicp-subject-id"].to_str().unwrap().into(),
                ));
                Json(json!({
                    "nodes": [{"node_id":"n1","endpoint":"https://node.example/task","score":0.8,"available":true,"region":"eu"}],
                    "count": 1,
                    "profile_negotiation": {"requested":true,"status":"compatible","dispatch_allowed":true},
                    "restricted_domain_decision": {
                        "schema":"iicp.restricted-trust-domain.directory-decision.v0",
                        "profile":"urn:iicp:profile:restricted-trust-domain:v1",
                        "decision":"eligible","operation":"discovery","domain_id":"domain-a",
                        "authority_id":"did:iicp:test:directory-a","subject_kind":"client",
                        "membership_generation":8,"membership_expires_at":u64::MAX
                    }
                }))
            }),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let secret = protected_secret_file();
    let client = IicpClient::new(config(format!("http://{address}"), &secret)).unwrap();

    let result = client
        .discover("urn:iicp:intent:llm:chat:v1", None, None)
        .await
        .unwrap();
    assert_eq!(
        observed.lock().unwrap().clone(),
        Some(("membership-token".into(), "client-a".into()))
    );
    assert_eq!(
        result.restricted_eligibility.unwrap().membership_generation,
        8
    );
    assert!(result.nodes[0].restricted_eligibility.is_some());
    server.abort();
}

#[tokio::test]
async fn missing_decision_fails_closed_without_retry_or_public_fallback() {
    let calls = Arc::new(Mutex::new(0_u32));
    let state = Arc::clone(&calls);
    let app = Router::new()
        .route(
            "/v1/discover",
            get(|State(calls): State<Arc<Mutex<u32>>>| async move {
                *calls.lock().unwrap() += 1;
                Json::<Value>(json!({"nodes":[],"count":0,"profile_negotiation":{"requested":true,"status":"compatible","dispatch_allowed":true}}))
            }),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let secret = protected_secret_file();
    let client = IicpClient::new(config(format!("http://{address}"), &secret)).unwrap();

    assert!(client
        .discover("urn:iicp:intent:llm:chat:v1", None, None)
        .await
        .is_err());
    assert_eq!(*calls.lock().unwrap(), 1);
    server.abort();
}

#[test]
fn unavailable_secret_fails_at_construction_before_network_use() {
    let secret = protected_secret_file();
    let mut cfg = config("http://127.0.0.1:1".into(), &secret);
    cfg.restricted_directory
        .as_mut()
        .unwrap()
        .membership_credential = SecretRef::File {
        path: "/definitely/missing/iicp-membership".into(),
    };
    assert!(IicpClient::new(cfg).is_err());
}
