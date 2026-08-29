use std::fs;

#[test]
fn stable_task_contracts_do_not_import_tcp_stream_state() {
    for path in [
        "src/client.rs",
        "src/types.rs",
        "src/routing_policy.rs",
        "src/service_lifecycle.rs",
        "src/native_call_identity.rs",
        "src/native_response_sequence.rs",
    ] {
        let source = fs::read_to_string(path).unwrap();
        assert!(
            !source.contains("tokio::net::TcpStream"),
            "{path} leaked TCP stream state into a transport-neutral contract"
        );
    }
}

#[test]
fn native_identity_and_response_lifecycle_remain_available_without_tcp_module_gating() {
    let library = fs::read_to_string("src/lib.rs").unwrap();
    assert!(library.contains("#[cfg(feature = \"iicp-tcp\")]\npub mod iicp_tcp;"));
    assert!(library.contains("pub mod native_call_identity;"));
    assert!(library.contains("pub mod native_response_sequence;"));
    assert!(!library.contains("#[cfg(feature = \"iicp-tcp\")]\npub mod native_call_identity;"));
    assert!(!library.contains("#[cfg(feature = \"iicp-tcp\")]\npub mod native_response_sequence;"));
}

#[test]
fn documented_boundary_does_not_claim_quic_or_featureless_cli_support() {
    let documentation = fs::read_to_string("docs/TRANSPORT_SEPARATION.md").unwrap();
    assert!(documentation.contains("QUIC remains post-1.0 research"));
    assert!(documentation.contains("--no-default-features --lib"));
    assert!(documentation.contains("featureless binary"));
}
