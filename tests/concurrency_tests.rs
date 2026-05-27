// SPDX-License-Identifier: Apache-2.0
//! Unit tests for ConcurrencyGate + its IicpTcpServer integration.
//! Rust port of the Python/TS test matrix.

#![cfg(feature = "iicp-tcp")]

use std::sync::Arc;
use std::time::Duration;

use ciborium::value::Value as CborValue;
use iicp_client::concurrency::{CapacityExceededError, ConcurrencyGate};
use iicp_client::iicp_tcp::{
    decode_cbor, encode_frame, IicpTcpServer, MsgType, FRAMING_VERSION, FRAME_HEADER_LEN,
    IICP_MAGIC,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::time::timeout;

const T: Duration = Duration::from_secs(5);

fn cbor_encode(v: &CborValue) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).unwrap();
    out
}

async fn read_frame(sock: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut head = [0u8; FRAME_HEADER_LEN];
    timeout(T, sock.read_exact(&mut head)).await??;
    assert_eq!(&head[0..4], IICP_MAGIC);
    let mt = head[5];
    let payload_len = u32::from_be_bytes(head[8..12].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        timeout(T, sock.read_exact(&mut payload)).await??;
    }
    Ok((mt, payload))
}

// ── Primitive tests ─────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "max_concurrent must be >= 1")]
fn test_new_zero_panics() {
    let _ = ConcurrencyGate::new(0);
}

#[test]
fn test_active_jobs_and_load_track_acquisitions() {
    let g = ConcurrencyGate::new(2);
    assert_eq!(g.active_jobs(), 0);
    assert_eq!(g.load(), 0.0);
    g.acquire().unwrap();
    assert_eq!(g.active_jobs(), 1);
    assert!((g.load() - 0.5).abs() < 1e-9);
    g.acquire().unwrap();
    assert_eq!(g.active_jobs(), 2);
    assert_eq!(g.load(), 1.0);
    g.release();
    assert_eq!(g.active_jobs(), 1);
    g.release();
    assert_eq!(g.active_jobs(), 0);
}

#[test]
fn test_acquire_returns_error_when_full() {
    let g = ConcurrencyGate::new(2);
    g.acquire().unwrap();
    g.acquire().unwrap();
    match g.acquire() {
        Err(CapacityExceededError { max_concurrent }) => assert_eq!(max_concurrent, 2),
        Ok(()) => panic!("third acquire should have failed"),
    }
}

#[tokio::test]
async fn test_run_helper_releases_on_success() {
    let g = ConcurrencyGate::new(1);
    let result: Result<i32, _> = g.run(async { 42 }).await;
    assert_eq!(result.unwrap(), 42);
    assert_eq!(g.active_jobs(), 0);
}

#[tokio::test]
async fn test_run_helper_releases_on_panic_via_drop_guard() {
    let g = Arc::new(ConcurrencyGate::new(1));
    let g2 = g.clone();
    let handle = tokio::spawn(async move {
        let _: Result<(), _> = g2.run::<_, ()>(async { panic!("boom") }).await;
    });
    // Wait for the spawned task to finish (it'll panic, but we don't care)
    let _ = handle.await;
    assert_eq!(g.active_jobs(), 0, "slot must be released even on panic");
}

// ── IicpTcpServer integration ──────────────────────────────────────────────

async fn start_server_with_gate(gate: Arc<ConcurrencyGate>, hold: Arc<Notify>) -> u16 {
    let hold_inner = hold.clone();
    let server = IicpTcpServer::new("127.0.0.1", 0)
        .with_node_id("gated")
        .with_handler(Arc::new(move |_task| {
            let h = hold_inner.clone();
            Box::pin(async move {
                h.notified().await;
                serde_json::json!({ "result": { "ok": true } })
            })
        }))
        .with_concurrency_gate(gate);
    let listener = server.bind().await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { let _ = server.serve_on(listener).await; });
    tokio::time::sleep(Duration::from_millis(20)).await;
    port
}

async fn do_call(port: u16, call_id: &str) -> std::io::Result<(u8, Vec<u8>)> {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await?;
    let init = encode_frame(
        MsgType::Init as u8,
        &cbor_encode(&CborValue::Map(vec![(
            CborValue::Integer(1.into()),
            CborValue::Integer((FRAMING_VERSION as i64).into()),
        )])),
        0,
    );
    sock.write_all(&init).await?;
    read_frame(&mut sock).await?; // consume ACK

    let call_payload = cbor_encode(&CborValue::Map(vec![
        (CborValue::Integer(2.into()), CborValue::Text("sess".into())),
        (
            CborValue::Integer(3.into()),
            CborValue::Text("urn:iicp:intent:llm:chat:v1".into()),
        ),
        (CborValue::Integer(15.into()), CborValue::Text(call_id.into())),
        (
            CborValue::Integer(5.into()),
            CborValue::Bytes(serde_json::to_vec(&serde_json::json!({})).unwrap()),
        ),
    ]));
    sock.write_all(&encode_frame(MsgType::Call as u8, &call_payload, 0))
        .await?;
    read_frame(&mut sock).await
}

#[tokio::test]
async fn test_under_capacity_call_passes_through() {
    let gate = Arc::new(ConcurrencyGate::new(2));
    let hold = Arc::new(Notify::new());
    hold.notify_one();  // pre-release so handler returns immediately
    let port = start_server_with_gate(gate.clone(), hold).await;
    let (mt, payload) = do_call(port, "c1").await.unwrap();
    assert_eq!(mt, MsgType::Response as u8);
    let body = decode_cbor(&payload).unwrap();
    // No error_code key → handler ran successfully
    if let CborValue::Map(entries) = body {
        for (k, _) in &entries {
            if let CborValue::Integer(i) = k {
                let n: i128 = i.clone().into();
                assert!(n != 100, "unexpected error_code present");
            }
        }
    }
}

#[tokio::test]
async fn test_at_capacity_call_returns_429_iicp_e021() {
    let gate = Arc::new(ConcurrencyGate::new(2));
    let hold = Arc::new(Notify::new());
    let port = start_server_with_gate(gate.clone(), hold.clone()).await;

    // Fire two long-running CALLs to occupy the gate
    let p1 = port;
    let c1 = tokio::spawn(async move { do_call(p1, "c1").await });
    let c2 = tokio::spawn(async move { do_call(p1, "c2").await });
    // Wait until both slots are taken
    for _ in 0..50 {
        if gate.active_jobs() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(gate.active_jobs(), 2, "expected gate full before third call");

    // Third CALL hits the gate
    let (mt, payload) = do_call(port, "c3").await.unwrap();
    assert_eq!(mt, MsgType::Response as u8);
    let body = decode_cbor(&payload).unwrap();
    let mut found_code = None;
    let mut found_msg = None;
    if let CborValue::Map(entries) = body {
        for (k, v) in entries {
            if let CborValue::Integer(i) = &k {
                let n: i128 = i.clone().into();
                if n == 100 {
                    if let CborValue::Integer(j) = v {
                        let nn: i128 = j.into();
                        found_code = Some(nn);
                    }
                } else if n == 101 {
                    if let CborValue::Text(s) = v {
                        found_msg = Some(s);
                    }
                }
            }
        }
    }
    assert_eq!(found_code, Some(429), "expected error_code=429");
    assert!(
        found_msg.as_deref().unwrap_or("").contains("IICP-E021"),
        "expected IICP-E021 in error_message, got {found_msg:?}"
    );

    // Cleanup: release the handlers
    hold.notify_waiters();
    let _ = c1.await;
    let _ = c2.await;
}
