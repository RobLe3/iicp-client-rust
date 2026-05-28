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
    registry.unbind(&worker_id);
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
}
