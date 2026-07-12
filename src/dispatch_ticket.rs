use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
const DOMAIN: &[u8] = b"iicp:dispatch-route-ticket:v1\n";
const AUDIENCE: &str = "iicp.directory.dispatch";
#[derive(Debug, Clone, Deserialize)]
pub struct DispatchRouteTicketClaims {
    pub v: u8,
    pub typ: String,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub node_id: String,
    pub intent: String,
    pub iat: i64,
    pub exp: i64,
}
pub fn verify_dispatch_route_ticket(
    token: &str,
    public_key_hex: &str,
    issuer: &str,
    node_id: &str,
    intent: &str,
    now_s: i64,
) -> Option<DispatchRouteTicketClaims> {
    let (payload, sig_hex) = token.split_once('.')?;
    if sig_hex.len() != 128 {
        return None;
    };
    let key = VerifyingKey::from_bytes(&hex::decode(public_key_hex).ok()?.try_into().ok()?).ok()?;
    let signature = Signature::from_bytes(&hex::decode(sig_hex).ok()?.try_into().ok()?);
    key.verify(&[DOMAIN, payload.as_bytes()].concat(), &signature)
        .ok()?;
    let claims: DispatchRouteTicketClaims =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    (claims.v == 1
        && claims.typ == "dispatch-route-ticket"
        && claims.iss == issuer
        && claims.aud == AUDIENCE
        && claims.node_id == node_id
        && claims.intent == intent
        && claims.exp > now_s
        && claims.jti.len() == 24
        && claims
            .jti
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
    .then_some(claims)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixture_verifies() {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../parity/dispatch-route-ticket-v1.json")).unwrap();
        let c = &f["valid"]["claims"];
        assert!(verify_dispatch_route_ticket(
            f["valid"]["token"].as_str().unwrap(),
            f["public_key_hex"].as_str().unwrap(),
            c["iss"].as_str().unwrap(),
            c["node_id"].as_str().unwrap(),
            c["intent"].as_str().unwrap(),
            1_800_000_000
        )
        .is_some());
    }
}

    #[test]
    fn canonical_fixture_vectors_fail_closed() {
        let f: serde_json::Value = serde_json::from_str(include_str!("../parity/dispatch-route-ticket-v1.json")).unwrap();
        for vector in f["validation_vectors"].as_array().unwrap() {
            let token = match vector["token"].as_str().unwrap() {
                "valid" => f["valid"]["token"].as_str().unwrap().to_string(),
                "valid+0" => format!("{}0", f["valid"]["token"].as_str().unwrap()),
                "wrong_audience" => f["wrong_audience"]["token"].as_str().unwrap().to_string(),
                other => other.to_string(),
            };
            let result = verify_dispatch_route_ticket(&token, f["public_key_hex"].as_str().unwrap(), vector["issuer"].as_str().unwrap(), vector["node_id"].as_str().unwrap(), vector["intent"].as_str().unwrap(), vector["now_s"].as_i64().unwrap());
            assert_eq!(result.is_some(), vector["expected"] == "valid", "{}", vector["name"].as_str().unwrap());
        }
    }
