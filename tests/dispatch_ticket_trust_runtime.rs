use iicp_client::dispatch_ticket_trust::{
    verify_dispatch_ticket_v2, DispatchTicketBindings, DispatchTrustBundle,
    LocalDispatchReplayCache,
};
use serde_json::Value;

#[test]
fn runtime_verifier_consumes_portable_vectors() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../parity/dispatch-ticket-trust-v2-crypto.json"
    ))
    .unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let keys = fixture["keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|key| {
                vector["trust_bundle_key_ids"]
                    .as_array()
                    .unwrap()
                    .contains(&key["key_id"])
            })
            .cloned()
            .collect::<Vec<_>>();
        let bundle: DispatchTrustBundle =
            serde_json::from_value(serde_json::json!({"bundle_version": 4, "keys": keys})).unwrap();
        let claims = &vector["claims"];
        let bindings = DispatchTicketBindings {
            issuer: claims["issuer"].as_str().unwrap().into(),
            provider_id: claims["provider_id"].as_str().unwrap().into(),
            intent: claims["intent"].as_str().unwrap().into(),
            constraints_digest: claims["constraints_digest"].as_str().unwrap().into(),
            audience: None,
        };
        let mut replay = LocalDispatchReplayCache::default();
        if vector["jti_seen"].as_bool().unwrap() {
            replay.remember(
                claims["jti"].as_str().unwrap(),
                claims["expires_at"].as_u64().unwrap(),
            );
        }
        let result = verify_dispatch_ticket_v2(
            claims,
            vector["signature_b64url"].as_str().unwrap(),
            &bundle,
            &bindings,
            vector["now"].as_u64().unwrap(),
            4,
            Some(&mut replay),
        );
        assert_eq!(
            result.code,
            vector["expected"].as_str().unwrap(),
            "{}",
            vector["id"]
        );
    }
}

#[test]
fn bundle_rollback_and_binding_mismatch_fail_closed() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../parity/dispatch-ticket-trust-v2-crypto.json"
    ))
    .unwrap();
    let vector = &fixture["vectors"][0];
    let mut bundle: DispatchTrustBundle = serde_json::from_value(
        serde_json::json!({"bundle_version": 3, "keys": [fixture["keys"][0].clone()]}),
    )
    .unwrap();
    let bindings = DispatchTicketBindings {
        issuer: vector["claims"]["issuer"].as_str().unwrap().into(),
        provider_id: "wrong-provider".into(),
        intent: vector["claims"]["intent"].as_str().unwrap().into(),
        constraints_digest: vector["claims"]["constraints_digest"]
            .as_str()
            .unwrap()
            .into(),
        audience: None,
    };
    assert_eq!(
        verify_dispatch_ticket_v2(
            &vector["claims"],
            vector["signature_b64url"].as_str().unwrap(),
            &bundle,
            &bindings,
            vector["now"].as_u64().unwrap(),
            4,
            None
        )
        .code,
        "reject_bundle_rollback"
    );
    bundle.bundle_version = 4;
    assert_eq!(
        verify_dispatch_ticket_v2(
            &vector["claims"],
            vector["signature_b64url"].as_str().unwrap(),
            &bundle,
            &bindings,
            vector["now"].as_u64().unwrap(),
            0,
            None
        )
        .code,
        "reject_claim_mismatch"
    );
}
