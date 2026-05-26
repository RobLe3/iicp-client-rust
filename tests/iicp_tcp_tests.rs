// SPDX-License-Identifier: Apache-2.0
//! IicpTcpServer integration tests — Rust port of the Python/TypeScript test
//! matrix. Boots a server on a free local port and runs each handler exactly
//! once. Verifies the iter-1410 framing fix is correctly applied (the
//! payload_bearing_frame_does_not_close_session test sends INIT + PING in
//! a single TCP write).
//!
//! All tests behind `--features iicp-tcp` so the SDK still builds for
//! HTTP-only consumers without ciborium pulled in.

#![cfg(feature = "iicp-tcp")]

use std::sync::Arc;
use std::time::Duration;

use ciborium::value::Value as CborValue;
use iicp_client::iicp_tcp::{
    decode_cbor, encode_frame, IicpTcpClient, IicpTcpClientError, IicpTcpServer, MsgType,
    FRAMING_VERSION, FRAME_HEADER_LEN, IICP_MAGIC,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(5);

fn cbor_encode(value: &CborValue) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).unwrap();
    out
}

async fn read_frame(sock: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut head = [0u8; FRAME_HEADER_LEN];
    timeout(TIMEOUT, sock.read_exact(&mut head)).await??;
    assert_eq!(&head[0..4], IICP_MAGIC);
    let mt = head[5];
    let payload_len = u32::from_be_bytes(head[8..12].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        timeout(TIMEOUT, sock.read_exact(&mut payload)).await??;
    }
    Ok((mt, payload))
}

/// Start a server in a background task; return the bound port.
async fn start_server() -> u16 {
    let server = IicpTcpServer::new("127.0.0.1", 0)
        .with_node_id("test-node-id")
        .with_handler(Arc::new(|task| {
            Box::pin(async move {
                // Echo handler: return the payload back under "echo" key
                serde_json::json!({ "result": { "echo": task.payload } })
            })
        }))
        .with_discover_lookup(Arc::new(|intent| {
            Box::pin(async move {
                vec![
                    CborValue::Map(vec![
                        (
                            CborValue::Text("node_id".into()),
                            CborValue::Text("fake-1".into()),
                        ),
                        (
                            CborValue::Text("endpoint".into()),
                            CborValue::Text("http://fake.example:8080".into()),
                        ),
                        (CborValue::Text("intent".into()), CborValue::Text(intent.clone())),
                    ]),
                    CborValue::Map(vec![
                        (
                            CborValue::Text("node_id".into()),
                            CborValue::Text("fake-2".into()),
                        ),
                        (
                            CborValue::Text("endpoint".into()),
                            CborValue::Text("http://fake.example:8080".into()),
                        ),
                        (CborValue::Text("intent".into()), CborValue::Text(intent)),
                    ]),
                ]
            })
        }));
    let listener = server.bind().await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = server.serve_on(listener).await;
    });
    // Tiny settle delay to let the accept loop be ready before tests connect.
    tokio::time::sleep(Duration::from_millis(20)).await;
    port
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_init_returns_ack_with_node_id() {
    let port = start_server().await;
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    let init_payload = cbor_encode(&CborValue::Map(vec![(
        CborValue::Integer(1.into()),
        CborValue::Integer((FRAMING_VERSION as i64).into()),
    )]));
    let frame = encode_frame(MsgType::Init as u8, &init_payload, 0);
    sock.write_all(&frame).await.unwrap();

    let (mt, payload) = read_frame(&mut sock).await.unwrap();
    assert_eq!(mt, MsgType::Ack as u8);
    let body = decode_cbor(&payload).unwrap();
    // Verify framing_version (key 1) and node_id (key 2) present
    if let CborValue::Map(entries) = &body {
        let key_1 = CborValue::Integer(1.into());
        let key_2 = CborValue::Integer(2.into());
        let v1 = entries.iter().find(|(k, _)| k == &key_1).map(|(_, v)| v);
        let v2 = entries.iter().find(|(k, _)| k == &key_2).map(|(_, v)| v);
        assert!(matches!(v1, Some(CborValue::Integer(_))));
        assert_eq!(v2, Some(&CborValue::Text("test-node-id".into())));
    } else {
        panic!("ACK payload not a map");
    }
}

#[tokio::test]
async fn test_ping_with_echo_round_trips() {
    let port = start_server().await;
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    // INIT → ACK
    let init = encode_frame(
        MsgType::Init as u8,
        &cbor_encode(&CborValue::Map(vec![(
            CborValue::Integer(1.into()),
            CborValue::Integer((FRAMING_VERSION as i64).into()),
        )])),
        0,
    );
    sock.write_all(&init).await.unwrap();
    read_frame(&mut sock).await.unwrap();

    // PING with echo
    let echo = b"rust-tcp-roundtrip-2026".to_vec();
    let ping_payload = cbor_encode(&CborValue::Map(vec![(
        CborValue::Integer(1.into()),
        CborValue::Bytes(echo.clone()),
    )]));
    let frame = encode_frame(MsgType::Ping as u8, &ping_payload, 0);
    sock.write_all(&frame).await.unwrap();
    let (mt, payload) = read_frame(&mut sock).await.unwrap();
    assert_eq!(mt, MsgType::Pong as u8);
    let body = decode_cbor(&payload).unwrap();
    if let CborValue::Map(entries) = &body {
        let key_1 = CborValue::Integer(1.into());
        for (k, v) in entries {
            if k == &key_1 {
                assert_eq!(v, &CborValue::Bytes(echo));
                return;
            }
        }
    }
    panic!("echo not in PONG body");
}

#[tokio::test]
async fn test_discover_returns_lookup_result() {
    let port = start_server().await;
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let init = encode_frame(
        MsgType::Init as u8,
        &cbor_encode(&CborValue::Map(vec![(
            CborValue::Integer(1.into()),
            CborValue::Integer((FRAMING_VERSION as i64).into()),
        )])),
        0,
    );
    sock.write_all(&init).await.unwrap();
    read_frame(&mut sock).await.unwrap();

    let intent = "urn:iicp:intent:llm:chat:v1";
    let discover_payload = cbor_encode(&CborValue::Map(vec![
        (CborValue::Integer(2.into()), CborValue::Text("sess-d1".into())),
        (CborValue::Integer(3.into()), CborValue::Text(intent.into())),
    ]));
    sock.write_all(&encode_frame(MsgType::Discover as u8, &discover_payload, 0))
        .await
        .unwrap();
    let (mt, payload) = read_frame(&mut sock).await.unwrap();
    assert_eq!(mt, MsgType::Response as u8);
    let body = decode_cbor(&payload).unwrap();
    // body[20] should be a CBOR Array of 2 nodes
    if let CborValue::Map(entries) = body {
        for (k, v) in entries {
            if k == CborValue::Integer(20.into()) {
                if let CborValue::Array(items) = v {
                    assert_eq!(items.len(), 2);
                    return;
                }
            }
        }
    }
    panic!("nodes array (key 20) not in discover response");
}

#[tokio::test]
async fn test_call_invokes_handler() {
    let port = start_server().await;
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let init = encode_frame(
        MsgType::Init as u8,
        &cbor_encode(&CborValue::Map(vec![(
            CborValue::Integer(1.into()),
            CborValue::Integer((FRAMING_VERSION as i64).into()),
        )])),
        0,
    );
    sock.write_all(&init).await.unwrap();
    read_frame(&mut sock).await.unwrap();

    let json_body = serde_json::json!({"messages": [{"role": "user", "content": "hi"}]});
    let json_bytes = serde_json::to_vec(&json_body).unwrap();
    let call_payload = cbor_encode(&CborValue::Map(vec![
        (CborValue::Integer(2.into()), CborValue::Text("sess-c1".into())),
        (
            CborValue::Integer(3.into()),
            CborValue::Text("urn:iicp:intent:llm:chat:v1".into()),
        ),
        (CborValue::Integer(15.into()), CborValue::Text("call-0001".into())),
        (CborValue::Integer(5.into()), CborValue::Bytes(json_bytes)),
    ]));
    sock.write_all(&encode_frame(MsgType::Call as u8, &call_payload, 0))
        .await
        .unwrap();
    let (mt, payload) = read_frame(&mut sock).await.unwrap();
    assert_eq!(mt, MsgType::Response as u8);
    let body = decode_cbor(&payload).unwrap();
    // body[100] (error_code) MUST be absent
    if let CborValue::Map(entries) = &body {
        for (k, _v) in entries {
            if *k == CborValue::Integer(100.into()) {
                panic!("unexpected error_code in CALL response");
            }
        }
        // body[5] is the CBOR-encoded handler result (bytes)
        for (k, v) in entries {
            if *k == CborValue::Integer(5.into()) {
                if let CborValue::Bytes(b) = v {
                    let inner = decode_cbor(b).unwrap();
                    // Inner should have an "echo" key
                    if let CborValue::Map(m2) = inner {
                        for (k2, _) in &m2 {
                            if k2 == &CborValue::Text("echo".to_string()) {
                                return;
                            }
                        }
                    }
                    panic!("CALL result missing 'echo' key");
                }
            }
        }
    }
    panic!("CALL response missing result (key 5)");
}

#[tokio::test]
async fn test_close_results_in_clean_hangup() {
    let port = start_server().await;
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let init = encode_frame(
        MsgType::Init as u8,
        &cbor_encode(&CborValue::Map(vec![(
            CborValue::Integer(1.into()),
            CborValue::Integer((FRAMING_VERSION as i64).into()),
        )])),
        0,
    );
    sock.write_all(&init).await.unwrap();
    read_frame(&mut sock).await.unwrap();

    sock.write_all(&encode_frame(MsgType::Close as u8, &[], 0)).await.unwrap();
    // Server should close — read returns 0
    let mut buf = [0u8; 8];
    let n = timeout(TIMEOUT, sock.read(&mut buf)).await.unwrap().unwrap();
    assert_eq!(n, 0, "expected EOF after CLOSE, got {n} bytes: {buf:?}");
}

#[tokio::test]
async fn test_bad_magic_closes_connection() {
    let port = start_server().await;
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut garbage = vec![b'X', b'X', b'X', b'X'];
    garbage.extend_from_slice(&[0u8; FRAME_HEADER_LEN - 4]);
    sock.write_all(&garbage).await.unwrap();
    let mut buf = [0u8; 8];
    let n = timeout(TIMEOUT, sock.read(&mut buf)).await.unwrap().unwrap();
    assert_eq!(n, 0, "server should close on bad magic");
}

#[tokio::test]
async fn test_payload_bearing_frame_does_not_close_session() {
    // iter-1410 regression guard: send INIT + PING back-to-back as a single TCP
    // write. Pre-fix the session loop closed after INIT because decode() raised
    // on the missing payload bytes that were still sitting in the kernel buffer.
    let port = start_server().await;
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let init = encode_frame(
        MsgType::Init as u8,
        &cbor_encode(&CborValue::Map(vec![(
            CborValue::Integer(1.into()),
            CborValue::Integer((FRAMING_VERSION as i64).into()),
        )])),
        0,
    );
    let ping = encode_frame(
        MsgType::Ping as u8,
        &cbor_encode(&CborValue::Map(vec![(
            CborValue::Integer(1.into()),
            CborValue::Bytes(b"x".to_vec()),
        )])),
        0,
    );
    let mut combined = Vec::with_capacity(init.len() + ping.len());
    combined.extend_from_slice(&init);
    combined.extend_from_slice(&ping);
    sock.write_all(&combined).await.unwrap();

    let (mt1, _) = read_frame(&mut sock).await.unwrap();
    let (mt2, _) = read_frame(&mut sock).await.unwrap();
    assert_eq!(mt1, MsgType::Ack as u8);
    assert_eq!(mt2, MsgType::Pong as u8);
}

// ── IicpTcpClient round-trip tests against the server fixture ───────────────

#[tokio::test]
async fn test_client_handshake_populates_peer_node_id() {
    let port = start_server().await;
    let mut client = IicpTcpClient::connect("127.0.0.1", port).await.unwrap();
    client.handshake().await.unwrap();
    assert_eq!(client.framing_version, Some(FRAMING_VERSION));
    assert_eq!(client.peer_node_id.as_deref(), Some("test-node-id"));
}

#[tokio::test]
async fn test_client_ping_with_echo() {
    let port = start_server().await;
    let mut client = IicpTcpClient::connect("127.0.0.1", port).await.unwrap();
    client.handshake().await.unwrap();
    let echo = b"rust-client-ping-2026";
    let got = client.ping(Some(echo)).await.unwrap();
    assert_eq!(got.as_deref(), Some(&echo[..]));
}

#[tokio::test]
async fn test_client_ping_empty_returns_none() {
    let port = start_server().await;
    let mut client = IicpTcpClient::connect("127.0.0.1", port).await.unwrap();
    client.handshake().await.unwrap();
    let got = client.ping(None).await.unwrap();
    assert_eq!(got, None);
}

#[tokio::test]
async fn test_client_discover_returns_nodes() {
    let port = start_server().await;
    let mut client = IicpTcpClient::connect("127.0.0.1", port).await.unwrap();
    client.handshake().await.unwrap();
    let nodes = client.discover("urn:iicp:intent:llm:chat:v1").await.unwrap();
    assert_eq!(nodes.len(), 2);
}

#[tokio::test]
async fn test_client_call_returns_handler_result() {
    let port = start_server().await;
    let mut client = IicpTcpClient::connect("127.0.0.1", port).await.unwrap();
    client.handshake().await.unwrap();
    let payload = serde_json::json!({"messages": [{"role":"user","content":"hi from rust client"}]});
    let result = client
        .call("urn:iicp:intent:llm:chat:v1", payload.clone(), Some("call-rust-1"))
        .await
        .unwrap();
    // The server-side handler returns { "result": { "echo": <payload> } }; the
    // server then sends only the inner result (the "result" wrapper is stripped),
    // so the client sees { "echo": <payload> } directly.
    let echo = result.get("echo").expect("echo missing");
    assert_eq!(echo, &payload);
}

#[tokio::test]
async fn test_client_call_raises_on_server_error() {
    // Server with no handler returns error_code 503.
    let server = IicpTcpServer::new("127.0.0.1", 0).with_node_id("no-handler");
    let listener = server.bind().await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { let _ = server.serve_on(listener).await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut client = IicpTcpClient::connect("127.0.0.1", port).await.unwrap();
    client.handshake().await.unwrap();
    match client.call("urn:iicp:intent:llm:chat:v1", serde_json::json!({}), None).await {
        Err(IicpTcpClientError::Server { code, .. }) => {
            assert_eq!(code, 503);
        }
        other => panic!("expected Server error, got {other:?}"),
    }
}

#[tokio::test]
async fn test_client_full_session_init_ping_discover_call_close() {
    let port = start_server().await;
    let mut client = IicpTcpClient::connect("127.0.0.1", port).await.unwrap();
    client.handshake().await.unwrap();
    assert_eq!(client.ping(Some(b"x")).await.unwrap().as_deref(), Some(&b"x"[..]));
    let nodes = client.discover("urn:iicp:intent:llm:chat:v1").await.unwrap();
    assert_eq!(nodes.len(), 2);
    let result = client
        .call(
            "urn:iicp:intent:llm:chat:v1",
            serde_json::json!({"k": "v"}),
            Some("c1"),
        )
        .await
        .unwrap();
    assert_eq!(result.get("echo").and_then(|e| e.get("k")), Some(&serde_json::json!("v")));
    client.close().await.unwrap();
}
