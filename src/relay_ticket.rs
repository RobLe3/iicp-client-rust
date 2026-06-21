//! Directory-signed relay bind ticket helpers (#510 / DIR-RELAY-03).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"iicp:relay-bind-ticket:v1\n";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayBindTicketClaims {
    pub v: u8,
    pub typ: String,
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
}

pub fn verify_relay_bind_ticket(
    token: &str,
    public_key_hex: &str,
    worker_id: &str,
    relay_audience: &str,
    now_s: i64,
) -> Option<RelayBindTicketClaims> {
    let (payload_b64, sig_hex) = token.split_once('.')?;
    if sig_hex.len() != 128 {
        return None;
    }
    let pub_bytes: [u8; 32] = hex::decode(public_key_hex).ok()?.try_into().ok()?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex).ok()?.try_into().ok()?;
    let key = VerifyingKey::from_bytes(&pub_bytes).ok()?;
    let sig = Signature::from_bytes(&sig_bytes);
    let mut msg = DOMAIN.to_vec();
    msg.extend_from_slice(payload_b64.as_bytes());
    key.verify(&msg, &sig).ok()?;
    let payload_json = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let claims: RelayBindTicketClaims = serde_json::from_slice(&payload_json).ok()?;
    if claims.typ != "relay-bind-ticket" || claims.sub != worker_id || claims.exp <= now_s {
        return None;
    }
    if claims.aud != "*" && claims.aud != relay_audience {
        return None;
    }
    Some(claims)
}

pub async fn fetch_relay_bind_ticket(
    directory_url: &str,
    node_token: &str,
    worker_id: &str,
    relay_node_id: Option<&str>,
) -> Option<String> {
    let url = format!("{}/v1/relay/ticket", directory_url.trim_end_matches('/'));
    let body = match relay_node_id {
        Some(id) => serde_json::json!({ "relay_node_id": id }),
        None => serde_json::json!({}),
    };
    let resp = reqwest::Client::new()
        .post(url)
        .bearer_auth(node_token)
        .header("X-Node-Id", worker_id)
        .json(&body)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let data: serde_json::Value = resp.json().await.ok()?;
    data.get("ticket")?.as_str().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_ticket(worker_id: &str, relay_id: &str) -> (String, String) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let payload = serde_json::json!({
            "v": 1, "typ": "relay-bind-ticket", "iss": "test",
            "sub": worker_id, "aud": relay_id, "iat": 1, "exp": 999999
        })
        .to_string();
        let b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let mut msg = DOMAIN.to_vec();
        msg.extend_from_slice(b64.as_bytes());
        let sig = sk.sign(&msg);
        (
            format!("{}.{}", b64, hex::encode(sig.to_bytes())),
            hex::encode(sk.verifying_key().to_bytes()),
        )
    }

    #[test]
    fn verifies_valid_ticket_and_rejects_wrong_claims() {
        let (token, pub_hex) = signed_ticket("worker-1", "relay-1");
        assert!(verify_relay_bind_ticket(&token, &pub_hex, "worker-1", "relay-1", 100).is_some());
        assert!(verify_relay_bind_ticket(&token, &pub_hex, "attacker", "relay-1", 100).is_none());
        assert!(verify_relay_bind_ticket(&token, &pub_hex, "worker-1", "relay-2", 100).is_none());
        assert!(
            verify_relay_bind_ticket(&token, &pub_hex, "worker-1", "relay-1", 1_000_000).is_none()
        );
    }
}
