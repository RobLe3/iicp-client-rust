// SPDX-License-Identifier: Apache-2.0
//! Relay-as-last-resort — ADR-041 tier-3, Part 3 R1 (#341).
//!
//! Workers behind CGNAT hold an outbound IICP-TCP connection here.
//! The relay pushes CALL frames down and routes RESPONSE frames back
//! to waiting HTTP handlers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ciborium::value::Value as CborVal;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

const IICP_MAGIC: &[u8] = b"IICP";
const FRAMING_VERSION: u8 = 0x01;
const FRAME_HEADER_LEN: usize = 12;

const MT_INIT: u8 = 0x01;
const MT_ACK: u8 = 0x02;
const MT_CLOSE: u8 = 0x07;
const MT_PING: u8 = 0x09;
const MT_PONG: u8 = 0x0a;
const MT_RELAY_BIND: u8 = 0x0b;
const MT_RELAY_ACK: u8 = 0x0c;
const MT_CALL: u8 = 0x05;
const MT_RESPONSE: u8 = 0x06;

fn make_frame(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    buf.extend_from_slice(IICP_MAGIC);
    buf.push(FRAMING_VERSION);
    buf.push(msg_type);
    buf.push(0); // flags
    buf.push(0); // reserved
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Encode a CBOR map with integer keys (IICP framing spec requirement).
fn cbor_encode_int_map(entries: &[(i64, CborVal)]) -> Vec<u8> {
    let map = CborVal::Map(
        entries
            .iter()
            .map(|(k, v)| (CborVal::Integer((*k).into()), v.clone()))
            .collect(),
    );
    let mut buf = Vec::new();
    let _ = ciborium::ser::into_writer(&map, &mut buf);
    buf
}

/// Decode a CBOR map to `HashMap<integer_key, CborVal>`.
fn cbor_decode_int_map(data: &[u8]) -> Option<HashMap<i64, CborVal>> {
    let v: CborVal = ciborium::de::from_reader(data).ok()?;
    let map = match v {
        CborVal::Map(m) => m,
        _ => return None,
    };
    let mut out = HashMap::new();
    for (k, val) in map {
        if let CborVal::Integer(n) = k {
            if let Ok(key_i) = i64::try_from(n) {
                out.insert(key_i, val);
            }
        }
    }
    Some(out)
}

fn cbor_text_or_bytes(v: Option<&CborVal>) -> Option<String> {
    match v? {
        CborVal::Text(s) => Some(s.clone()),
        CborVal::Bytes(b) => String::from_utf8(b.clone()).ok(),
        _ => None,
    }
}

fn cbor_bytes(v: Option<&CborVal>) -> Option<Vec<u8>> {
    match v? {
        CborVal::Bytes(b) => Some(b.clone()),
        CborVal::Text(s) => Some(s.as_bytes().to_vec()),
        _ => None,
    }
}

// Reserved for RELAY_BIND model-list decoding (parity with Python/TS relay session).
#[allow(dead_code)]
fn cbor_list_of_strings(v: Option<&CborVal>) -> Vec<String> {
    match v {
        Some(CborVal::Array(arr)) => arr
            .iter()
            .filter_map(|x| {
                if let CborVal::Text(s) = x {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect(),
        _ => vec![],
    }
}

// ── RelayWorkerSession ────────────────────────────────────────────────────────

/// Cloneable handle to a bound relay-worker session.
#[derive(Clone)]
pub struct RelayWorkerSession {
    pub worker_id: String,
    /// Channel to the write task; send a frame → it gets written to the TCP socket.
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Pending request map: call_id → oneshot sender.
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<Value>>>>,
}

impl RelayWorkerSession {
    fn new(worker_id: String, write_tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self {
            worker_id,
            write_tx,
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Push a task CALL to the bound worker and await the RESPONSE.
    pub async fn forward_task(&self, task: &Value, timeout_secs: u64) -> Result<Value, String> {
        let call_id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel::<Value>();
        self.pending.lock().unwrap().insert(call_id.clone(), tx);

        let payload_json = serde_json::to_string(task).unwrap_or_default();
        // Integer CBOR keys (spec): 15 = call_id, 5 = task payload bytes
        let cbor = cbor_encode_int_map(&[
            (15, CborVal::Text(call_id.clone())),
            (5, CborVal::Bytes(payload_json.into_bytes())),
        ]);
        let frame = make_frame(MT_CALL, &cbor);

        if self.write_tx.send(frame).is_err() {
            self.pending.lock().unwrap().remove(&call_id);
            return Err("relay session write channel closed".into());
        }

        match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err("relay session closed".into()),
            Err(_) => {
                self.pending.lock().unwrap().remove(&call_id);
                Err(format!(
                    "relay forward timeout ({timeout_secs}s) for call {call_id}"
                ))
            }
        }
    }

    fn send_raw(&self, frame: Vec<u8>) -> Result<(), String> {
        self.write_tx
            .send(frame)
            .map_err(|_| "relay write channel closed".into())
    }

    /// Whether the underlying worker socket is still alive/writable.
    ///
    /// #510 interim hardening: an alive bound session must not be displaced
    /// by a new RELAY_BIND for the same worker_id (unauthenticated bind).
    pub fn is_alive(&self) -> bool {
        !self.write_tx.is_closed()
    }

    pub fn on_response(&self, call_id: &str, result: Value) {
        if let Some(tx) = self.pending.lock().unwrap().remove(call_id) {
            let _ = tx.send(result);
        }
    }
}

// ── RelaySessionRegistry ─────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct RelaySessionRegistry {
    sessions: Arc<Mutex<HashMap<String, RelayWorkerSession>>>,
}

impl RelaySessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind(&self, worker_id: String, session: RelayWorkerSession) {
        self.sessions.lock().unwrap().insert(worker_id, session);
    }

    pub fn unbind(&self, worker_id: &str) {
        self.sessions.lock().unwrap().remove(worker_id);
    }

    /// Remove the entry for `worker_id` only if it is still `session`.
    ///
    /// #510: a legitimate reconnect may already have bound a newer session for
    /// this worker_id — the ending session must not displace it on teardown.
    pub fn unbind_session(&self, worker_id: &str, session: &RelayWorkerSession) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(existing) = sessions.get(worker_id) {
            if Arc::ptr_eq(&existing.pending, &session.pending) {
                sessions.remove(worker_id);
            }
        }
    }

    pub fn get(&self, worker_id: &str) -> Option<RelayWorkerSession> {
        self.sessions.lock().unwrap().get(worker_id).cloned()
    }

    pub fn is_bound(&self, worker_id: &str) -> bool {
        self.sessions.lock().unwrap().contains_key(worker_id)
    }

    pub fn bound_worker_ids(&self) -> Vec<String> {
        self.sessions.lock().unwrap().keys().cloned().collect()
    }
}

// ── RelayAcceptServer ─────────────────────────────────────────────────────────

pub struct RelayAcceptServer {
    pub registry: RelaySessionRegistry,
    pub host: String,
    pub port: u16,
}

impl RelayAcceptServer {
    pub fn new(registry: RelaySessionRegistry, host: impl Into<String>, port: u16) -> Self {
        Self {
            registry,
            host: host.into(),
            port,
        }
    }

    pub async fn serve(self: Arc<Self>) -> Result<(), String> {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("relay accept bind {addr}: {e}"))?;
        tracing::info!("Relay accept server listening on {}", addr);
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    tracing::debug!("Relay accept: connection from {peer}");
                    let reg = self.registry.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_relay_connection(stream, reg).await {
                            tracing::warn!("Relay session error from {peer}: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("Relay accept error: {e}");
                }
            }
        }
    }
}

async fn read_frame(reader: &mut (impl AsyncReadExt + Unpin)) -> Result<(u8, Vec<u8>), String> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|e| e.to_string())?;
    if &header[..4] != IICP_MAGIC {
        return Err(format!("bad magic {:?}", &header[..4]));
    }
    let msg_type = header[5];
    let payload_len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    if payload_len > 16 * 1024 * 1024 {
        return Err(format!("payload too large: {payload_len}"));
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader
            .read_exact(&mut payload)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok((msg_type, payload))
}

async fn handle_relay_connection(
    stream: TcpStream,
    registry: RelaySessionRegistry,
) -> Result<(), String> {
    let peer = stream
        .peer_addr()
        .map(|p| p.to_string())
        .unwrap_or_else(|_| "?".into());
    let (mut reader, mut writer) = stream.into_split();

    // Step 1: INIT/ACK
    let (mt, _) = read_frame(&mut reader).await?;
    if mt != MT_INIT {
        return Err(format!("expected INIT, got 0x{mt:02x}"));
    }
    let ack_payload =
        cbor_encode_int_map(&[(1, CborVal::Integer((FRAMING_VERSION as i64).into()))]);
    writer
        .write_all(&make_frame(MT_ACK, &ack_payload))
        .await
        .map_err(|e| e.to_string())?;

    // Step 2: RELAY_BIND
    let (mt, payload) = read_frame(&mut reader).await?;
    if mt != MT_RELAY_BIND {
        return Err(format!("expected RELAY_BIND, got 0x{mt:02x}"));
    }
    let body = cbor_decode_int_map(&payload).ok_or("RELAY_BIND decode failed")?;
    let worker_id = cbor_text_or_bytes(body.get(&1)).unwrap_or_default();
    let intent = cbor_text_or_bytes(body.get(&2)).unwrap_or_default();
    if worker_id.is_empty() {
        return Err("RELAY_BIND missing worker_id".into());
    }

    // #510 interim hardening: RELAY_BIND is unauthenticated, so refuse to
    // displace an existing session whose socket is still alive (mid-session
    // hijack). Rebind after socket death (legitimate reconnect) still works.
    if let Some(existing) = registry.get(&worker_id) {
        if existing.is_alive() {
            tracing::warn!(
                "Relay: rejected RELAY_BIND for worker={} from {}: \
                 worker_id already bound to an alive session (#510)",
                worker_id,
                peer
            );
            let nack = cbor_encode_int_map(&[
                (1, CborVal::Text("error".into())),
                (2, CborVal::Text(worker_id.clone())),
                (
                    3,
                    CborVal::Text("worker_id already bound to an alive session".into()),
                ),
            ]);
            writer
                .write_all(&make_frame(MT_RELAY_ACK, &nack))
                .await
                .map_err(|e| e.to_string())?;
            return Ok(());
        }
    }

    // Spawn writer task — receives frames from an unbounded channel and writes to socket.
    let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(frame) = write_rx.recv().await {
            if writer.write_all(&frame).await.is_err() {
                break;
            }
        }
    });

    let session = RelayWorkerSession::new(worker_id.clone(), write_tx);
    registry.bind(worker_id.clone(), session.clone());
    tracing::info!("Relay: worker={} bound (intent={})", worker_id, intent);

    let relay_ack = cbor_encode_int_map(&[
        (1, CborVal::Text("ok".into())),
        (2, CborVal::Text(worker_id.clone())),
    ]);
    session.send_raw(make_frame(MT_RELAY_ACK, &relay_ack))?;

    // Step 3: relay-worker frame loop (read only; writes go through the channel)
    let result = relay_worker_loop(&mut reader, &session).await;
    // Only remove the registry entry if it is still ours — a legitimate
    // reconnect may already have bound a newer session for this worker_id.
    registry.unbind_session(&worker_id, &session);
    tracing::info!("Relay: session ended for worker={}", worker_id);
    result
}

async fn relay_worker_loop(
    reader: &mut (impl AsyncReadExt + Unpin),
    session: &RelayWorkerSession,
) -> Result<(), String> {
    loop {
        let (mt, payload) = match read_frame(reader).await {
            Ok(f) => f,
            Err(_) => return Ok(()),
        };
        match mt {
            MT_PING => {
                let echo = cbor_decode_int_map(&payload)
                    .and_then(|b| cbor_bytes(b.get(&1)))
                    .unwrap_or_default();
                let pong = cbor_encode_int_map(&[(1, CborVal::Bytes(echo))]);
                session.send_raw(make_frame(MT_PONG, &pong))?;
            }
            MT_RESPONSE => {
                if let Some(body) = cbor_decode_int_map(&payload) {
                    let call_id = cbor_text_or_bytes(body.get(&15)).unwrap_or_default();
                    let result: Value = match cbor_bytes(body.get(&5)) {
                        Some(bytes) => serde_json::from_slice(&bytes).unwrap_or(Value::Null),
                        None => Value::Null,
                    };
                    if !call_id.is_empty() {
                        session.on_response(&call_id, result);
                    }
                }
            }
            MT_CLOSE => return Ok(()),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[cfg(feature = "iicp-tcp")]
    #[test]
    fn relay_msg_types() {
        use crate::iicp_tcp::MsgType;
        assert_eq!(MsgType::RelayBind as u8, 0x0b);
        assert_eq!(MsgType::RelayAck as u8, 0x0c);
    }

    #[test]
    fn registry_bind_get_unbind() {
        let reg = RelaySessionRegistry::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        let session = RelayWorkerSession::new("w-001".into(), tx);
        assert!(!reg.is_bound("w-001"));
        reg.bind("w-001".into(), session);
        assert!(reg.is_bound("w-001"));
        assert!(reg.get("w-001").is_some());
        reg.unbind("w-001");
        assert!(!reg.is_bound("w-001"));
        assert!(reg.get("w-001").is_none());
    }

    #[test]
    fn on_response_resolves_pending() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let session = RelayWorkerSession::new("w-001".into(), tx);
        let (otx, mut orx) = oneshot::channel::<Value>();
        session
            .pending
            .lock()
            .unwrap()
            .insert("call-abc".into(), otx);
        session.on_response("call-abc", json!({ "result": "ok" }));
        let val = orx.try_recv().expect("should be resolved");
        assert_eq!(val["result"], "ok");
    }

    #[test]
    fn on_response_ignores_unknown() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let session = RelayWorkerSession::new("w-001".into(), tx);
        session.on_response("unknown", json!({})); // must not panic
    }

    #[test]
    fn bound_worker_ids() {
        let reg = RelaySessionRegistry::new();
        let mk = |id: &str| {
            let (tx, _rx) = mpsc::unbounded_channel();
            RelayWorkerSession::new(id.into(), tx)
        };
        reg.bind("a".into(), mk("a"));
        reg.bind("b".into(), mk("b"));
        let mut ids = reg.bound_worker_ids();
        ids.sort();
        assert_eq!(ids, vec!["a", "b"]);
    }

    // ── RelayAcceptServer bind hardening (#510) ──────────────────────────────
    // Behavior tests: these fail if the alive-session rebind rejection is
    // reverted.

    /// Spawn an accept loop on an ephemeral port; returns the bound port.
    async fn start_test_relay(registry: RelaySessionRegistry) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, _peer)) = listener.accept().await {
                    let reg = registry.clone();
                    tokio::spawn(async move {
                        let _ = handle_relay_connection(stream, reg).await;
                    });
                }
            }
        });
        port
    }

    /// Wire-level worker: INIT/ACK + RELAY_BIND; returns the RELAY_ACK body.
    async fn wire_bind(stream: &mut TcpStream, worker_id: &str) -> HashMap<i64, CborVal> {
        let init = cbor_encode_int_map(&[(1, CborVal::Integer(1i64.into()))]);
        stream.write_all(&make_frame(MT_INIT, &init)).await.unwrap();
        let (mt, _payload) = read_frame(stream).await.unwrap();
        assert_eq!(mt, MT_ACK, "expected ACK after INIT");
        let bind = cbor_encode_int_map(&[
            (1, CborVal::Text(worker_id.into())),
            (2, CborVal::Text("urn:iicp:intent:llm:chat:v1".into())),
            (3, CborVal::Array(vec![])),
        ]);
        stream
            .write_all(&make_frame(MT_RELAY_BIND, &bind))
            .await
            .unwrap();
        let (mt, payload) = read_frame(stream).await.unwrap();
        assert_eq!(mt, MT_RELAY_ACK, "expected RELAY_ACK after RELAY_BIND");
        cbor_decode_int_map(&payload).unwrap()
    }

    fn ack_status(ack: &HashMap<i64, CborVal>) -> String {
        cbor_text_or_bytes(ack.get(&1)).unwrap_or_default()
    }

    #[tokio::test]
    async fn hijack_bind_of_alive_session_is_rejected() {
        let reg = RelaySessionRegistry::new();
        let port = start_test_relay(reg.clone()).await;

        let mut worker_a = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let ack_a = wire_bind(&mut worker_a, "w-hijack").await;
        assert_eq!(ack_status(&ack_a), "ok");
        let session_a = reg.get("w-hijack").expect("worker A must be bound");

        // Attacker on socket B binds the same worker_id while A is alive.
        let mut worker_b = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let ack_b = wire_bind(&mut worker_b, "w-hijack").await;
        assert_eq!(
            ack_status(&ack_b),
            "error",
            "second bind of an alive worker must be rejected"
        );

        // A's session remains installed and still receives dispatches.
        let still = reg.get("w-hijack").expect("registry entry must remain");
        assert!(
            Arc::ptr_eq(&still.pending, &session_a.pending),
            "registry entry must not be replaced"
        );
        assert!(still.is_alive());

        let sess = still.clone();
        let dispatch =
            tokio::spawn(async move { sess.forward_task(&json!({ "ping": 1 }), 5).await });
        let (mt, payload) = read_frame(&mut worker_a).await.unwrap();
        assert_eq!(mt, MT_CALL, "dispatch must arrive on worker A's socket");
        let body = cbor_decode_int_map(&payload).unwrap();
        let call_id = cbor_text_or_bytes(body.get(&15)).unwrap();
        let resp = cbor_encode_int_map(&[
            (15, CborVal::Text(call_id)),
            (5, CborVal::Bytes(br#"{"pong":true}"#.to_vec())),
        ]);
        worker_a
            .write_all(&make_frame(MT_RESPONSE, &resp))
            .await
            .unwrap();
        let result = dispatch.await.unwrap().expect("forward_task must succeed");
        assert_eq!(result["pong"], true);
    }

    #[tokio::test]
    async fn rebind_after_socket_death_succeeds() {
        let reg = RelaySessionRegistry::new();
        let port = start_test_relay(reg.clone()).await;

        let mut worker_a = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let ack_a = wire_bind(&mut worker_a, "w-reconnect").await;
        assert_eq!(ack_status(&ack_a), "ok");

        drop(worker_a); // socket death
                        // Wait until the relay observes the dead socket (unbound, or
                        // bound-but-dead).
        for _ in 0..200 {
            match reg.get("w-reconnect") {
                None => break,
                Some(s) if !s.is_alive() => break,
                Some(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        }

        let mut worker_b = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let ack_b = wire_bind(&mut worker_b, "w-reconnect").await;
        assert_eq!(
            ack_status(&ack_b),
            "ok",
            "rebind after socket death must succeed"
        );
        assert!(reg.is_bound("w-reconnect"));
    }
}
