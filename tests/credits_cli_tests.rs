// SPDX-License-Identifier: Apache-2.0
//! 2026-06-11 — `iicp-node credits` resilience behavior tests.
//!
//! 1. Transient 5xx gets ONE retry (deploy windows / shared-hosting blips must
//!    not surface as one-shot CLI errors). Fails if the retry is removed.
//! 2. Definitive 4xx is NOT retried.
//! 3. With no --node, one node's persistent failure must not hide the others:
//!    every node is shown, exit is non-zero. Fails if the loop aborts early.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const OK_BODY: &str = r#"{"node_id":"n1","total_earned":5.0,"total_spent":0.0,"balance":5.0,"tx_count":1,"reconciles":true,"unit":"credit","tokens_per_credit":1000}"#;
const ERR_BODY: &str =
    r#"{"error":{"code":"server_error","message":"An internal error occurred"}}"#;

/// Serve raw HTTP responses sequentially on a free port; the last response
/// repeats for any further requests. Returns (port, hit_counter).
fn serve_sequence(responses: Vec<(u16, &'static str)>) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_bg = Arc::clone(&hits);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let idx = hits_bg.fetch_add(1, Ordering::SeqCst);
            let (status, body) = responses[idx.min(responses.len() - 1)];
            // Drain the request head so the client doesn't see a reset.
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let reason = if status == 200 { "OK" } else { "Error" };
            let resp = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    (port, hits)
}

#[test]
fn credits_retries_once_on_transient_500() {
    let (port, hits) = serve_sequence(vec![(500, ERR_BODY), (200, OK_BODY)]);

    let out = Command::new(env!("CARGO_BIN_EXE_iicp-node"))
        .args([
            "credits",
            "--node-id",
            "n1",
            "--token",
            "t",
            "--directory-url",
            &format!("http://127.0.0.1:{port}"),
            "--json",
        ])
        .output()
        .expect("run iicp-node");

    assert!(
        out.status.success(),
        "transient 500 then 200 must succeed via retry; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2, "expected exactly one retry");
    assert!(String::from_utf8_lossy(&out.stdout).contains("\"balance\""));
}

#[test]
fn credits_does_not_retry_definitive_4xx() {
    let (port, hits) = serve_sequence(vec![(
        401,
        r#"{"error":{"code":"unauthorized","message":"invalid node_token"}}"#,
    )]);

    let out = Command::new(env!("CARGO_BIN_EXE_iicp-node"))
        .args([
            "credits",
            "--node-id",
            "n1",
            "--token",
            "bad",
            "--directory-url",
            &format!("http://127.0.0.1:{port}"),
        ])
        .output()
        .expect("run iicp-node");

    assert!(!out.status.success(), "401 must fail");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "definitive 4xx must not be retried"
    );
}

#[test]
fn credits_all_nodes_continues_past_failing_node() {
    let (bad_port, _bad_hits) = serve_sequence(vec![(500, ERR_BODY)]);
    let (good_port, _good_hits) = serve_sequence(vec![(200, OK_BODY)]);

    let home = std::env::temp_dir().join(format!("iicp-credits-cli-{}", std::process::id()));
    let nodes_dir = home.join("nodes");
    std::fs::create_dir_all(&nodes_dir).expect("mkdir");
    // 'default' with no cached token + ≥2 nodes with tokens → all-nodes path.
    std::fs::write(
        nodes_dir.join("default.json"),
        r#"{"node_id":"n-def","operator_id":"op","name":"default","backend_url":"http://b","model":"m","created_at":"2026-01-01T00:00:00Z"}"#,
    )
    .unwrap();
    std::fs::write(
        nodes_dir.join("aaa-bad.json"),
        format!(
            r#"{{"node_id":"n-bad","operator_id":"op","name":"aaa-bad","backend_url":"http://b","model":"m","directory_url":"http://127.0.0.1:{bad_port}","node_token":"t1","created_at":"2026-01-01T00:00:00Z"}}"#
        ),
    )
    .unwrap();
    std::fs::write(
        nodes_dir.join("zzz-good.json"),
        format!(
            r#"{{"node_id":"n-good","operator_id":"op","name":"zzz-good","backend_url":"http://b","model":"m","directory_url":"http://127.0.0.1:{good_port}","node_token":"t2","created_at":"2026-01-01T00:00:00Z"}}"#
        ),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_iicp-node"))
        .args(["credits"])
        .env("IICP_HOME", &home)
        .output()
        .expect("run iicp-node");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("zzz-good"),
        "the healthy node must still be displayed; stdout: {stdout}; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "exit must be non-zero when any node failed"
    );

    let _ = std::fs::remove_dir_all(&home);
}
