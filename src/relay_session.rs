// SPDX-License-Identifier: Apache-2.0
//! Relay-as-last-resort — ADR-041 tier-3, Part 3 R1 (#341).
//!
//! Workers behind CGNAT hold an outbound IICP-TCP connection here.
//! The relay pushes CALL frames down and routes RESPONSE frames back
//! to waiting HTTP handlers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ciborium::value::Value as CborVal;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::relay_ticket::{
    consume_relay_bind_ticket, verify_relay_bind_ticket, RelayBindTicketClaims,
};

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

// ── HttpPollWorkerSession (#450 browser workers) ─────────────────────────────

/// One bound HTTP long-poll relay-worker session.
///
/// Same forward/respond semantics as [`RelayWorkerSession`] — the registry
/// stores both behind [`RelaySession`] so relay handlers treat the transports
/// identically. Instead of pushing CALL frames down a TCP socket,
/// `forward_task()` queues the call for the worker's `GET /v1/relay/pull`
/// long-poll; the worker posts the result via `POST /v1/relay/result`.
///
/// Auth: `session_token` is issued at bind and presented as a Bearer token on
/// pull/result/unbind — stronger than the unauthenticated TCP RELAY_BIND
/// (#510), applied to the new transport from day one.
///
/// Liveness = the worker pulled within `liveness_window`. A dead session is
/// displaceable by a fresh bind (#510 interim-C: an ALIVE session never is).
#[derive(Clone)]
pub struct HttpPollWorkerSession {
    pub worker_id: String,
    pub intent: String,
    pub models: Vec<String>,
    pub session_token: String,
    call_tx: mpsc::UnboundedSender<Value>,
    call_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Value>>>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<Value>>>>,
    last_pull: Arc<Mutex<std::time::Instant>>,
    liveness_window: std::time::Duration,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl HttpPollWorkerSession {
    pub fn new(worker_id: String, intent: String, models: Vec<String>) -> Self {
        Self::with_liveness_window(
            worker_id,
            intent,
            models,
            std::time::Duration::from_secs(90),
        )
    }

    pub fn with_liveness_window(
        worker_id: String,
        intent: String,
        models: Vec<String>,
        liveness_window: std::time::Duration,
    ) -> Self {
        let (call_tx, call_rx) = mpsc::unbounded_channel();
        Self {
            worker_id,
            intent,
            models,
            session_token: Uuid::new_v4().simple().to_string(),
            call_tx,
            call_rx: Arc::new(tokio::sync::Mutex::new(call_rx)),
            pending: Arc::new(Mutex::new(HashMap::new())),
            last_pull: Arc::new(Mutex::new(std::time::Instant::now())),
            liveness_window,
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Queue a CALL for the polling worker and await its RESPONSE.
    pub async fn forward_task(&self, task: &Value, timeout_secs: u64) -> Result<Value, String> {
        let call_id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel::<Value>();
        self.pending.lock().unwrap().insert(call_id.clone(), tx);
        let call = serde_json::json!({ "call_id": call_id, "task": task });
        if self.call_tx.send(call).is_err() {
            self.pending.lock().unwrap().remove(&call_id);
            return Err("relay poll session closed".into());
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

    /// Long-poll: next queued CALL, or `None` when the window elapses.
    pub async fn next_call(&self, timeout: std::time::Duration) -> Option<Value> {
        *self.last_pull.lock().unwrap() = std::time::Instant::now();
        let mut rx = self.call_rx.lock().await;
        let out = tokio::time::timeout(timeout, rx.recv())
            .await
            .ok()
            .flatten();
        *self.last_pull.lock().unwrap() = std::time::Instant::now();
        out
    }

    pub fn is_alive(&self) -> bool {
        !self.closed.load(std::sync::atomic::Ordering::Relaxed)
            && self.last_pull.lock().unwrap().elapsed() < self.liveness_window
    }

    pub fn on_response(&self, call_id: &str, result: Value) {
        if let Some(tx) = self.pending.lock().unwrap().remove(call_id) {
            let _ = tx.send(result);
        }
    }

    pub fn close(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

// ── RelaySession (transport-agnostic handle) ─────────────────────────────────

/// A bound relay-worker session over either transport (TCP frames or HTTP
/// long-poll). Relay handlers forward through this without caring which.
#[derive(Clone)]
pub enum RelaySession {
    Tcp(RelayWorkerSession),
    HttpPoll(HttpPollWorkerSession),
}

impl RelaySession {
    pub async fn forward_task(&self, task: &Value, timeout_secs: u64) -> Result<Value, String> {
        match self {
            RelaySession::Tcp(s) => s.forward_task(task, timeout_secs).await,
            RelaySession::HttpPoll(s) => s.forward_task(task, timeout_secs).await,
        }
    }

    pub fn is_alive(&self) -> bool {
        match self {
            RelaySession::Tcp(s) => s.is_alive(),
            RelaySession::HttpPoll(s) => s.is_alive(),
        }
    }

    pub fn on_response(&self, call_id: &str, result: Value) {
        match self {
            RelaySession::Tcp(s) => s.on_response(call_id, result),
            RelaySession::HttpPoll(s) => s.on_response(call_id, result),
        }
    }

    pub fn models(&self) -> Vec<String> {
        match self {
            RelaySession::Tcp(_) => vec![],
            RelaySession::HttpPoll(s) => s.models.clone(),
        }
    }
}

// ── RelaySessionRegistry ─────────────────────────────────────────────────────

/// Red-team F5 (2026-06-12): cap concurrent relay sessions so a bind-flood
/// can't exhaust relay memory / starve legitimate workers.
pub const MAX_RELAY_SESSIONS: usize = 256;

#[derive(Clone, Default)]
pub struct RelaySessionRegistry {
    sessions: Arc<Mutex<HashMap<String, RelaySession>>>,
}

impl RelaySessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// True if a NEW worker_id can't be admitted (cap reached). A rebind of an
    /// already-bound worker_id is always allowed (F5).
    pub fn at_capacity(&self, worker_id: &str) -> bool {
        let sessions = self.sessions.lock().unwrap();
        !sessions.contains_key(worker_id) && sessions.len() >= MAX_RELAY_SESSIONS
    }

    pub fn count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    pub fn bind(&self, worker_id: String, session: RelaySession) {
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
        if let Some(RelaySession::Tcp(existing)) = sessions.get(worker_id) {
            if Arc::ptr_eq(&existing.pending, &session.pending) {
                sessions.remove(worker_id);
            }
        }
    }

    pub fn get(&self, worker_id: &str) -> Option<RelaySession> {
        self.sessions.lock().unwrap().get(worker_id).cloned()
    }

    /// Find an HTTP-poll session by its bearer token (pull/result auth, #450).
    pub fn get_by_token(&self, token: &str) -> Option<HttpPollWorkerSession> {
        if token.is_empty() {
            return None;
        }
        self.sessions
            .lock()
            .unwrap()
            .values()
            .find_map(|s| match s {
                RelaySession::HttpPoll(p) if p.session_token == token => Some(p.clone()),
                _ => None,
            })
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
    /// The relay's public HTTP task port — advertised in RELAY_ACK (field 4)
    /// so workers can register {relay}:{http_port}/v1/relay-for/<wid> (#450).
    pub http_port: u16,
    pub require_bind_ticket: bool,
    pub bind_ticket_public_key_hex: Option<String>,
    pub relay_node_id: String,
}

impl RelayAcceptServer {
    pub fn new(registry: RelaySessionRegistry, host: impl Into<String>, port: u16) -> Self {
        Self::with_http_port(registry, host, port, 9484)
    }

    pub fn with_http_port(
        registry: RelaySessionRegistry,
        host: impl Into<String>,
        port: u16,
        http_port: u16,
    ) -> Self {
        Self {
            registry,
            host: host.into(),
            port,
            http_port,
            require_bind_ticket: std::env::var("IICP_RELAY_REQUIRE_BIND_TICKET")
                .ok()
                .as_deref()
                == Some("1"),
            bind_ticket_public_key_hex: std::env::var("IICP_RELAY_BIND_TICKET_PUBLIC_KEY").ok(),
            relay_node_id: std::env::var("IICP_NODE_ID").unwrap_or_else(|_| "*".to_string()),
        }
    }

    pub fn with_bind_ticket_auth(
        mut self,
        require: bool,
        public_key_hex: Option<String>,
        relay_node_id: impl Into<String>,
    ) -> Self {
        self.require_bind_ticket = require;
        self.bind_ticket_public_key_hex = public_key_hex;
        self.relay_node_id = relay_node_id.into();
        self
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
                    let http_port = self.http_port;
                    let require_bind_ticket = self.require_bind_ticket;
                    let bind_ticket_public_key_hex = self.bind_ticket_public_key_hex.clone();
                    let relay_node_id = self.relay_node_id.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_relay_connection(
                            stream,
                            reg,
                            http_port,
                            require_bind_ticket,
                            bind_ticket_public_key_hex,
                            relay_node_id,
                        )
                        .await
                        {
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
    http_port: u16,
    require_bind_ticket: bool,
    bind_ticket_public_key_hex: Option<String>,
    relay_node_id: String,
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
    let bind_ticket = cbor_text_or_bytes(body.get(&4)).unwrap_or_default();
    if worker_id.is_empty() {
        return Err("RELAY_BIND missing worker_id".into());
    }

    let mut ticket_claims: Option<RelayBindTicketClaims> = None;
    if !bind_ticket.is_empty() {
        if let Some(pub_hex) = &bind_ticket_public_key_hex {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            ticket_claims =
                verify_relay_bind_ticket(&bind_ticket, pub_hex, &worker_id, &relay_node_id, now);
            if ticket_claims.is_none() {
                let nack = cbor_encode_int_map(&[
                    (1, CborVal::Text("error".into())),
                    (2, CborVal::Text(worker_id.clone())),
                    (3, CborVal::Text("relay bind ticket invalid".into())),
                ]);
                writer
                    .write_all(&make_frame(MT_RELAY_ACK, &nack))
                    .await
                    .map_err(|e| e.to_string())?;
                return Ok(());
            }
        }
    } else if require_bind_ticket {
        let nack = cbor_encode_int_map(&[
            (1, CborVal::Text("error".into())),
            (2, CborVal::Text(worker_id.clone())),
            (3, CborVal::Text("relay bind ticket required".into())),
        ]);
        writer
            .write_all(&make_frame(MT_RELAY_ACK, &nack))
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    } else {
        tracing::warn!(
            "Relay: unsigned RELAY_BIND for worker={} — #510 ticket auth not yet enforced",
            worker_id
        );
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

    // Red-team F5: cap concurrent sessions (bind-flood DoS). Rebind exempt.
    if registry.at_capacity(&worker_id) {
        tracing::warn!(
            "Relay: at session capacity — rejecting bind for {}",
            worker_id
        );
        let nack = cbor_encode_int_map(&[
            (1, CborVal::Text("error".into())),
            (2, CborVal::Text(worker_id.clone())),
            (3, CborVal::Text("relay at session capacity".into())),
        ]);
        writer
            .write_all(&make_frame(MT_RELAY_ACK, &nack))
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    }

    if let Some(claims) = &ticket_claims {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if !consume_relay_bind_ticket(claims, now) {
            let nack = cbor_encode_int_map(&[
                (1, CborVal::Text("error".into())),
                (2, CborVal::Text(worker_id.clone())),
                (3, CborVal::Text("relay bind ticket replayed".into())),
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
    registry.bind(worker_id.clone(), RelaySession::Tcp(session.clone()));
    tracing::info!("Relay: worker={} bound (intent={})", worker_id, intent);

    // Field 4 (additive, #450): the relay's HTTP task port, so the worker can
    // register {relay_host}:{http_port}/v1/relay-for/{worker_id} with the
    // directory. Old workers ignore unknown CBOR keys.
    let relay_ack = cbor_encode_int_map(&[
        (1, CborVal::Text("ok".into())),
        (2, CborVal::Text(worker_id.clone())),
        (4, CborVal::Integer(i64::from(http_port).into())),
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
        reg.bind("w-001".into(), RelaySession::Tcp(session));
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
        reg.bind("a".into(), RelaySession::Tcp(mk("a")));
        reg.bind("b".into(), RelaySession::Tcp(mk("b")));
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
                        let _ = handle_relay_connection(stream, reg, 9484, false, None, "*".into())
                            .await;
                    });
                }
            }
        });
        port
    }

    /// Wire-level worker: INIT/ACK + RELAY_BIND; returns the RELAY_ACK body.
    async fn wire_bind(stream: &mut TcpStream, worker_id: &str) -> HashMap<i64, CborVal> {
        wire_bind_with_ticket(stream, worker_id, None).await
    }

    async fn wire_bind_with_ticket(
        stream: &mut TcpStream,
        worker_id: &str,
        bind_ticket: Option<String>,
    ) -> HashMap<i64, CborVal> {
        let init = cbor_encode_int_map(&[(1, CborVal::Integer(1i64.into()))]);
        stream.write_all(&make_frame(MT_INIT, &init)).await.unwrap();
        let (mt, _payload) = read_frame(stream).await.unwrap();
        assert_eq!(mt, MT_ACK, "expected ACK after INIT");
        let mut fields = vec![
            (1, CborVal::Text(worker_id.into())),
            (2, CborVal::Text("urn:iicp:intent:llm:chat:v1".into())),
            (3, CborVal::Array(vec![])),
        ];
        if let Some(ticket) = bind_ticket {
            fields.push((4, CborVal::Text(ticket)));
        }
        let bind = cbor_encode_int_map(&fields);
        stream
            .write_all(&make_frame(MT_RELAY_BIND, &bind))
            .await
            .unwrap();
        let (mt, payload) = read_frame(stream).await.unwrap();
        assert_eq!(mt, MT_RELAY_ACK, "expected RELAY_ACK after RELAY_BIND");
        cbor_decode_int_map(&payload).unwrap()
    }

    fn signed_ticket(worker_id: &str, relay_id: &str) -> (String, String) {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let payload = serde_json::json!({
            "v": 1, "typ": "relay-bind-ticket", "jti": "02020202020202020202020202020202", "iss": "test",
            "sub": worker_id, "aud": relay_id, "iat": 1, "exp": 9999999999i64
        })
        .to_string();
        let b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let mut msg = b"iicp:relay-bind-ticket:v1\n".to_vec();
        msg.extend_from_slice(b64.as_bytes());
        let sig = sk.sign(&msg);
        (
            format!("{}.{}", b64, hex::encode(sig.to_bytes())),
            hex::encode(sk.verifying_key().to_bytes()),
        )
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
        let tcp_pending = |s: &RelaySession| match s {
            RelaySession::Tcp(t) => Arc::clone(&t.pending),
            RelaySession::HttpPoll(_) => panic!("expected TCP session"),
        };
        assert!(
            Arc::ptr_eq(&tcp_pending(&still), &tcp_pending(&session_a)),
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

    #[tokio::test]
    async fn strict_bind_ticket_accepts_valid_and_rejects_wrong_worker() {
        let reg = RelaySessionRegistry::new();
        let (good_ticket, pub_hex) = signed_ticket("w-ticket", "relay-test");
        let (bad_ticket, _) = signed_ticket("attacker", "relay-test");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let reg_clone = reg.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, _peer)) = listener.accept().await {
                    let reg = reg_clone.clone();
                    let pub_hex = pub_hex.clone();
                    tokio::spawn(async move {
                        let _ = handle_relay_connection(
                            stream,
                            reg,
                            9484,
                            true,
                            Some(pub_hex),
                            "relay-test".into(),
                        )
                        .await;
                    });
                }
            }
        });

        let mut worker_a = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let ack_a = wire_bind_with_ticket(&mut worker_a, "w-ticket", Some(good_ticket)).await;
        assert_eq!(ack_status(&ack_a), "ok");
        drop(worker_a);
        for _ in 0..200 {
            match reg.get("w-ticket") {
                None => break,
                Some(s) if !s.is_alive() => break,
                Some(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        }

        let mut worker_b = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let ack_b = wire_bind_with_ticket(&mut worker_b, "w-ticket", Some(bad_ticket)).await;
        assert_eq!(ack_status(&ack_b), "error");
        assert_eq!(
            cbor_text_or_bytes(ack_b.get(&3)).unwrap_or_default(),
            "relay bind ticket invalid"
        );
    }
}
