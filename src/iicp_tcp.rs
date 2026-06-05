// SPDX-License-Identifier: Apache-2.0
//! Native IICP binary transport (port 9484) — server + framing + cbor payloads.
//!
//! Rust port of iicp-client-python iicp_tcp.py (iter-1414) and
//! iicp-client-typescript iicp_tcp.ts (iter-1415). Wire-compatible with
//! adapter nodes and REACH FRAME-PING-01 / FRAME-INIT-01 conformance probes.
//!
//! Enabled via the `iicp-tcp` feature flag — ciborium is added as an opt-in
//! dependency because HTTP-only nodes don't need it.
//!
//! Implements the iter-1410 framing fixes from the start:
//! - Session loop reads the announced payload BEFORE decoding (pre-fix the
//!   adapter version closed on every payload-bearing frame because the loop
//!   only waited for the 12-byte header and called decode() immediately).
//! - CALL handler decodes key-5 JSON dict before invoking the user handler
//!   (mirrors the adapter call_pipeline fix).
//!
//! Spec: iicp.network/spec/iicp-framing.md, ADR-040.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Arc;

use ciborium::value::Value as CborValue;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

// ── Constants ─────────────────────────────────────────────────────────────────

pub const IICP_MAGIC: &[u8; 4] = b"IICP"; // 0x49 0x49 0x43 0x50
pub const FRAMING_VERSION: u8 = 0x01;
pub const FRAME_HEADER_LEN: usize = 12;
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// IICP message type codes (spec/iicp-framing.md §3, 0x01–0x0E).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    Init = 0x01,
    Ack = 0x02,
    Discover = 0x03,
    SubProtocol = 0x04,
    Call = 0x05,
    Response = 0x06,
    Close = 0x07,
    Feedback = 0x08,
    Ping = 0x09,
    Pong = 0x0a,
    /// R1 relay-as-last-resort: worker binds outbound session to relay (#341).
    RelayBind = 0x0b,
    RelayAck = 0x0c,
}

impl MsgType {
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => MsgType::Init,
            0x02 => MsgType::Ack,
            0x03 => MsgType::Discover,
            0x04 => MsgType::SubProtocol,
            0x05 => MsgType::Call,
            0x06 => MsgType::Response,
            0x07 => MsgType::Close,
            0x08 => MsgType::Feedback,
            0x09 => MsgType::Ping,
            0x0a => MsgType::Pong,
            0x0b => MsgType::RelayBind,
            0x0c => MsgType::RelayAck,
            _ => return None,
        })
    }
}

// ── Frame ─────────────────────────────────────────────────────────────────────

/// A parsed IICP binary frame.
#[derive(Debug, Clone)]
pub struct IicpFrame {
    pub version: u8,
    pub msg_type: u8,
    pub flags: u8,
    pub payload: Vec<u8>,
}

pub fn encode_frame(msg_type: u8, payload: &[u8], flags: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.extend_from_slice(IICP_MAGIC);
    out.push(FRAMING_VERSION);
    out.push(msg_type);
    out.push(flags);
    out.push(0); // reserved
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decode one frame from `data`; return (frame, bytes_consumed).
pub fn decode_frame(data: &[u8]) -> Result<(IicpFrame, usize), String> {
    if data.len() < FRAME_HEADER_LEN {
        return Err(format!(
            "IICP frame too short: {} < {FRAME_HEADER_LEN}",
            data.len()
        ));
    }
    if &data[0..4] != IICP_MAGIC {
        return Err(format!("Invalid IICP magic: {:?}", &data[0..4]));
    }
    let version = data[4];
    let msg_type = data[5];
    let flags = data[6];
    let payload_len = u32::from_be_bytes(data[8..12].try_into().unwrap()) as usize;
    let total = FRAME_HEADER_LEN + payload_len;
    if data.len() < total {
        return Err(format!(
            "IICP payload truncated: need {total}, have {}",
            data.len()
        ));
    }
    Ok((
        IicpFrame {
            version,
            msg_type,
            flags,
            payload: data[FRAME_HEADER_LEN..total].to_vec(),
        },
        total,
    ))
}

// ── CBOR payload helpers ─────────────────────────────────────────────────────

pub fn encode_cbor(value: &CborValue) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("cbor encode");
    out
}

pub fn decode_cbor(data: &[u8]) -> Result<CborValue, String> {
    ciborium::de::from_reader(data).map_err(|e| format!("cbor decode: {e}"))
}

/// Build the CBOR payload for an ACK message (`{1: framing_version, 2: node_id?}`).
pub fn encode_ack(framing_version: u8, node_id: Option<&str>) -> Vec<u8> {
    let mut entries: Vec<(CborValue, CborValue)> = vec![(
        CborValue::Integer(1.into()),
        CborValue::Integer((framing_version as i64).into()),
    )];
    if let Some(id) = node_id {
        entries.push((
            CborValue::Integer(2.into()),
            CborValue::Text(id.to_string()),
        ));
    }
    encode_cbor(&CborValue::Map(entries))
}

pub fn encode_pong(echo: Option<&[u8]>) -> Vec<u8> {
    let mut entries: Vec<(CborValue, CborValue)> = Vec::new();
    if let Some(b) = echo {
        entries.push((CborValue::Integer(1.into()), CborValue::Bytes(b.to_vec())));
    }
    encode_cbor(&CborValue::Map(entries))
}

pub fn encode_response(
    session_id: &str,
    call_id: Option<&str>,
    result: Option<&[u8]>,
    error_code: Option<i64>,
    error_message: Option<&str>,
) -> Vec<u8> {
    let mut entries: Vec<(CborValue, CborValue)> = vec![(
        CborValue::Integer(2.into()),
        CborValue::Text(session_id.to_string()),
    )];
    if let Some(cid) = call_id {
        entries.push((
            CborValue::Integer(15.into()),
            CborValue::Text(cid.to_string()),
        ));
    }
    if let Some(r) = result {
        entries.push((CborValue::Integer(5.into()), CborValue::Bytes(r.to_vec())));
    }
    if let Some(ec) = error_code {
        entries.push((
            CborValue::Integer(100.into()),
            CborValue::Integer(ec.into()),
        ));
    }
    if let Some(em) = error_message {
        entries.push((
            CborValue::Integer(101.into()),
            CborValue::Text(em.to_string()),
        ));
    }
    encode_cbor(&CborValue::Map(entries))
}

pub fn encode_discover_response(session_id: &str, intent: &str, nodes: &[CborValue]) -> Vec<u8> {
    encode_cbor(&CborValue::Map(vec![
        (
            CborValue::Integer(2.into()),
            CborValue::Text(session_id.to_string()),
        ),
        (
            CborValue::Integer(3.into()),
            CborValue::Text(intent.to_string()),
        ),
        (
            CborValue::Integer(20.into()),
            CborValue::Array(nodes.to_vec()),
        ),
    ]))
}

// Pull an integer key out of a CBOR map. Returns None if not a map or key absent.
fn cbor_map_get(map: &CborValue, key: i64) -> Option<&CborValue> {
    if let CborValue::Map(entries) = map {
        for (k, v) in entries {
            if let CborValue::Integer(i) = k {
                let n: i128 = (*i).into();
                if n == key as i128 {
                    return Some(v);
                }
            }
        }
    }
    None
}

fn cbor_to_str(v: &CborValue) -> Option<String> {
    match v {
        CborValue::Text(s) => Some(s.clone()),
        _ => None,
    }
}

fn cbor_to_bytes(v: &CborValue) -> Option<Vec<u8>> {
    match v {
        CborValue::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

// ── Server ────────────────────────────────────────────────────────────────────

/// Task body delivered to the user handler — JSON-decoded from CBOR key 5.
#[derive(Debug, Clone)]
pub struct TcpTask {
    pub task_id: String,
    pub intent: String,
    pub payload: serde_json::Value,
}

/// User-supplied task handler — returns either `(result, None, None)` for
/// success (result is encoded as CBOR for transport) or
/// `(None, Some(code), Some(msg))` for error.
pub type TcpTaskHandler = Arc<
    dyn Fn(TcpTask) -> Pin<Box<dyn std::future::Future<Output = serde_json::Value> + Send>>
        + Send
        + Sync,
>;

/// Discover lookup callback — given an intent URN, return a CBOR Array of node
/// descriptors. Typically delegated to the IicpClient's discover() call.
pub type DiscoverLookup = Arc<
    dyn Fn(String) -> Pin<Box<dyn std::future::Future<Output = Vec<CborValue>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct IicpTcpServer {
    host: String,
    port: u16,
    node_id: Option<String>,
    handler: Option<TcpTaskHandler>,
    discover_lookup: Option<DiscoverLookup>,
    /// Optional ConcurrencyGate; when set, every CALL acquires a slot
    /// first. CapacityExceededError → RESPONSE error_code=429 IICP-E021.
    concurrency_gate: Option<std::sync::Arc<crate::concurrency::ConcurrencyGate>>,
}

impl IicpTcpServer {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            node_id: None,
            handler: None,
            discover_lookup: None,
            concurrency_gate: None,
        }
    }

    pub fn with_node_id(mut self, id: impl Into<String>) -> Self {
        self.node_id = Some(id.into());
        self
    }

    pub fn with_handler(mut self, h: TcpTaskHandler) -> Self {
        self.handler = Some(h);
        self
    }

    pub fn with_discover_lookup(mut self, d: DiscoverLookup) -> Self {
        self.discover_lookup = Some(d);
        self
    }

    pub fn with_concurrency_gate(
        mut self,
        gate: std::sync::Arc<crate::concurrency::ConcurrencyGate>,
    ) -> Self {
        self.concurrency_gate = Some(gate);
        self
    }

    /// Bind and accept connections forever. Returns an error if bind fails.
    pub async fn serve_forever(self) -> std::io::Result<()> {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr).await?;
        tracing::info!("IICP TCP server listening on {addr}");

        loop {
            let (socket, peer) = listener.accept().await?;
            let server = self.clone();
            tokio::spawn(async move {
                debug!("IICP TCP connection from {peer}");
                if let Err(e) = server.handle_connection(socket).await {
                    warn!("IICP TCP session error from {peer}: {e}");
                }
            });
        }
    }

    /// Bind and return a TcpListener bound to the configured address.
    /// Useful for tests that need to know the bound port before serving.
    pub async fn bind(&self) -> std::io::Result<TcpListener> {
        TcpListener::bind(format!("{}:{}", self.host, self.port)).await
    }

    /// Run the accept loop against a pre-bound listener (test helper).
    pub async fn serve_on(self, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (socket, peer) = listener.accept().await?;
            let server = self.clone();
            tokio::spawn(async move {
                debug!("IICP TCP connection from {peer}");
                if let Err(e) = server.handle_connection(socket).await {
                    warn!("IICP TCP session error from {peer}: {e}");
                }
            });
        }
    }

    /// Handle one already-accepted socket as a native IICP connection (#457). Public so a
    /// single-port multiplexer in `IicpNode::serve` can route native connections here
    /// (the HTTP control plane and native transport share one port via first-byte detection).
    pub async fn handle_connection(&self, mut socket: TcpStream) -> std::io::Result<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(4096);

        // Stage 1 + magic byte validation. Read until we have the 12-byte header.
        // First check magic byte once we have at least 4 bytes.
        let mut read_chunk = [0u8; 4096];
        loop {
            if buf.len() >= 4 {
                if &buf[0..4] != IICP_MAGIC {
                    warn!("Invalid IICP magic from client — closing");
                    return Ok(());
                }
                break;
            }
            let n = socket.read(&mut read_chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&read_chunk[..n]);
        }
        while buf.len() < FRAME_HEADER_LEN {
            let n = socket.read(&mut read_chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&read_chunk[..n]);
        }

        loop {
            // Stage 2: peek payload_len, wait for full frame BEFORE decoding.
            // This is the iter-1410 framing fix — pre-fix the adapter loop only
            // waited for the header and called decode() immediately, which
            // raises "payload truncated" the moment any frame with a non-empty
            // CBOR payload arrives across two TCP reads.
            while buf.len() < FRAME_HEADER_LEN {
                let n = socket.read(&mut read_chunk).await?;
                if n == 0 {
                    return Ok(());
                }
                buf.extend_from_slice(&read_chunk[..n]);
            }
            if &buf[0..4] != IICP_MAGIC {
                warn!("Mid-stream magic drift — closing");
                return Ok(());
            }
            let payload_len = u32::from_be_bytes(buf[8..12].try_into().unwrap()) as usize;
            if payload_len + FRAME_HEADER_LEN > MAX_PAYLOAD {
                warn!("IICP frame payload exceeds limit — closing");
                return Ok(());
            }
            let total_len = FRAME_HEADER_LEN + payload_len;
            while buf.len() < total_len {
                let n = socket.read(&mut read_chunk).await?;
                if n == 0 {
                    return Ok(());
                }
                buf.extend_from_slice(&read_chunk[..n]);
            }

            let (frame, consumed) = match decode_frame(&buf) {
                Ok(t) => t,
                Err(e) => {
                    warn!("Frame decode error: {e}");
                    return Ok(());
                }
            };
            buf.drain(..consumed);

            let keep_open = self.dispatch(frame, &mut socket).await?;
            if !keep_open {
                return Ok(());
            }
        }
    }

    async fn dispatch(&self, frame: IicpFrame, socket: &mut TcpStream) -> std::io::Result<bool> {
        match MsgType::from_u8(frame.msg_type) {
            Some(MsgType::Init) => self.on_init(socket).await,
            Some(MsgType::Ping) => self.on_ping(&frame, socket).await,
            Some(MsgType::Discover) => self.on_discover(&frame, socket).await,
            Some(MsgType::Call) => self.on_call(&frame, socket).await,
            Some(MsgType::Close) => Ok(false), // graceful shutdown
            Some(MsgType::Feedback) => Ok(true),
            _ => Ok(true), // ignore unknown msg types
        }
    }

    async fn on_init(&self, socket: &mut TcpStream) -> std::io::Result<bool> {
        let ack = encode_ack(FRAMING_VERSION, self.node_id.as_deref());
        let frame = encode_frame(MsgType::Ack as u8, &ack, 0);
        socket.write_all(&frame).await?;
        Ok(true)
    }

    async fn on_ping(&self, frame: &IicpFrame, socket: &mut TcpStream) -> std::io::Result<bool> {
        let mut echo: Option<Vec<u8>> = None;
        if !frame.payload.is_empty() {
            if let Ok(body) = decode_cbor(&frame.payload) {
                if let Some(v) = cbor_map_get(&body, 1) {
                    echo = cbor_to_bytes(v);
                }
            }
        }
        let pong = encode_pong(echo.as_deref());
        let out = encode_frame(MsgType::Pong as u8, &pong, 0);
        socket.write_all(&out).await?;
        Ok(true)
    }

    async fn on_discover(
        &self,
        frame: &IicpFrame,
        socket: &mut TcpStream,
    ) -> std::io::Result<bool> {
        let mut session_id = "unknown".to_string();
        let mut intent = String::new();
        if let Ok(body) = decode_cbor(&frame.payload) {
            if let Some(v) = cbor_map_get(&body, 2) {
                if let Some(s) = cbor_to_str(v) {
                    session_id = s;
                }
            }
            if let Some(v) = cbor_map_get(&body, 3) {
                if let Some(s) = cbor_to_str(v) {
                    intent = s;
                }
            }
        }

        let nodes: Vec<CborValue> =
            if let (Some(lookup), false) = (&self.discover_lookup, intent.is_empty()) {
                lookup(intent.clone()).await
            } else {
                Vec::new()
            };

        let resp = encode_discover_response(&session_id, &intent, &nodes);
        let out = encode_frame(MsgType::Response as u8, &resp, 0);
        socket.write_all(&out).await?;
        Ok(true)
    }

    async fn on_call(&self, frame: &IicpFrame, socket: &mut TcpStream) -> std::io::Result<bool> {
        let mut session_id = "unknown".to_string();
        let mut call_id: Option<String> = None;
        let mut intent = String::new();
        let mut payload_json = serde_json::Value::Object(Default::default());

        if let Ok(body) = decode_cbor(&frame.payload) {
            if let Some(v) = cbor_map_get(&body, 2) {
                if let Some(s) = cbor_to_str(v) {
                    session_id = s;
                }
            }
            if let Some(v) = cbor_map_get(&body, 3) {
                if let Some(s) = cbor_to_str(v) {
                    intent = s;
                }
            }
            if let Some(v) = cbor_map_get(&body, 15) {
                if let Some(s) = cbor_to_str(v) {
                    call_id = Some(s);
                }
            }
            if let Some(v) = cbor_map_get(&body, 5) {
                // Mirror the call_pipeline contract: key 5 is the task body as
                // either a CBOR Map OR a UTF-8 JSON byte string. Try byte
                // string first because that's the common SDK shape.
                if let CborValue::Bytes(bytes) = v {
                    if let Ok(s) = std::str::from_utf8(bytes) {
                        if let Ok(decoded) = serde_json::from_str(s) {
                            payload_json = decoded;
                        }
                    }
                } else if let CborValue::Map(entries) = v {
                    // Convert CBOR map to BTreeMap<String, JSON>
                    let mut obj = serde_json::Map::new();
                    for (k, vv) in entries {
                        if let CborValue::Text(key) = k {
                            // Convert value to JSON via roundtrip
                            let bytes = encode_cbor(vv);
                            if let Ok(jv) =
                                ciborium::de::from_reader::<serde_json::Value, _>(&bytes[..])
                            {
                                obj.insert(key.clone(), jv);
                            }
                        }
                    }
                    payload_json = serde_json::Value::Object(obj);
                }
            }
        }

        let mut result_bytes: Option<Vec<u8>> = None;
        let mut error_code: Option<i64> = None;
        let mut error_message: Option<String> = None;

        if let Some(handler) = &self.handler {
            let task = TcpTask {
                task_id: call_id.clone().unwrap_or_else(|| session_id.clone()),
                intent: intent.clone(),
                payload: payload_json,
            };

            // Tier 2 Item 5: optional ConcurrencyGate. CapacityExceededError →
            // RESPONSE error_code=429 IICP-E021 so the directory's NodeScorer
            // sees back-pressure consistently across HTTP and native IICP.
            let gate = self.concurrency_gate.clone();
            let run_handler = async {
                let user_result = handler(task).await;
                if let serde_json::Value::Object(map) = &user_result {
                    if let Some(ec) = map.get("error_code").and_then(|v| v.as_i64()) {
                        return Err((
                            ec,
                            map.get("error_message")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "handler error".to_string()),
                        ));
                    }
                    let inner = map.get("result").unwrap_or(&user_result);
                    Ok(encode_cbor(&json_to_cbor(inner)))
                } else {
                    Ok(encode_cbor(&json_to_cbor(&user_result)))
                }
            };

            if let Some(g) = gate {
                match g.acquire() {
                    Ok(()) => {
                        let outcome = run_handler.await;
                        g.release();
                        match outcome {
                            Ok(bytes) => result_bytes = Some(bytes),
                            Err((code, msg)) => {
                                error_code = Some(code);
                                error_message = Some(msg);
                            }
                        }
                    }
                    Err(e) => {
                        error_code = Some(429);
                        error_message = Some(format!(
                            "IICP-E021: max_concurrent={} reached",
                            e.max_concurrent
                        ));
                    }
                }
            } else {
                match run_handler.await {
                    Ok(bytes) => result_bytes = Some(bytes),
                    Err((code, msg)) => {
                        error_code = Some(code);
                        error_message = Some(msg);
                    }
                }
            }
        } else {
            error_code = Some(503);
            error_message = Some("no handler configured".to_string());
        }

        let resp = encode_response(
            &session_id,
            call_id.as_deref(),
            result_bytes.as_deref(),
            error_code,
            error_message.as_deref(),
        );
        let out = encode_frame(MsgType::Response as u8, &resp, 0);
        socket.write_all(&out).await?;
        Ok(true)
    }
}

/// Convert serde_json Value → ciborium Value for transport encoding.
fn json_to_cbor(v: &serde_json::Value) -> CborValue {
    match v {
        serde_json::Value::Null => CborValue::Null,
        serde_json::Value::Bool(b) => CborValue::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                CborValue::Integer(i.into())
            } else if let Some(u) = n.as_u64() {
                CborValue::Integer((u as i128).try_into().unwrap_or(0.into()))
            } else if let Some(f) = n.as_f64() {
                CborValue::Float(f)
            } else {
                CborValue::Null
            }
        }
        serde_json::Value::String(s) => CborValue::Text(s.clone()),
        serde_json::Value::Array(items) => {
            CborValue::Array(items.iter().map(json_to_cbor).collect())
        }
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(CborValue, CborValue)> = Vec::with_capacity(map.len());
            // Use BTreeMap to get deterministic ordering
            let sorted: BTreeMap<&String, &serde_json::Value> = map.iter().collect();
            for (k, v) in sorted {
                entries.push((CborValue::Text(k.clone()), json_to_cbor(v)));
            }
            CborValue::Map(entries)
        }
    }
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Error returned by IicpTcpClient RPC methods.
#[derive(Debug, thiserror::Error)]
pub enum IicpTcpClientError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("server error {code}: {message}")]
    Server { code: i64, message: String },
    #[error("operation timed out after {ms}ms")]
    Timeout { ms: u64 },
}

/// Native IICP TCP client (consumer side). Symmetric counterpart to
/// IicpTcpServer: connect, handshake, then issue PING/DISCOVER/CALL requests.
///
/// # Example
///
/// ```rust,ignore
/// use iicp_client::iicp_tcp::IicpTcpClient;
/// let mut client = IicpTcpClient::connect("203.0.113.5", 9484).await?;
/// client.handshake().await?;
/// let nodes = client.discover("urn:iicp:intent:llm:chat:v1").await?;
/// let result = client.call(
///     "urn:iicp:intent:llm:chat:v1",
///     serde_json::json!({"messages": [{"role":"user","content":"hi"}]}),
///     None,
/// ).await?;
/// client.close().await?;
/// ```
pub struct IicpTcpClient {
    sock: TcpStream,
    timeout: std::time::Duration,
    /// node_id from the server's ACK (populated by handshake).
    pub peer_node_id: Option<String>,
    /// framing_version negotiated in INIT/ACK (populated by handshake).
    pub framing_version: Option<u8>,
}

impl IicpTcpClient {
    /// Connect to host:port. Default 10s timeout for connect + each subsequent RPC.
    pub async fn connect(host: &str, port: u16) -> Result<Self, IicpTcpClientError> {
        Self::connect_with_timeout(host, port, std::time::Duration::from_secs(10)).await
    }

    pub async fn connect_with_timeout(
        host: &str,
        port: u16,
        timeout: std::time::Duration,
    ) -> Result<Self, IicpTcpClientError> {
        let addr = format!("{host}:{port}");
        let sock = tokio::time::timeout(timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| IicpTcpClientError::Timeout {
                ms: timeout.as_millis() as u64,
            })??;
        Ok(Self {
            sock,
            timeout,
            peer_node_id: None,
            framing_version: None,
        })
    }

    /// Send INIT, await ACK, populate peer_node_id + framing_version.
    pub async fn handshake(&mut self) -> Result<(), IicpTcpClientError> {
        let init_payload = encode_cbor(&CborValue::Map(vec![(
            CborValue::Integer(1.into()),
            CborValue::Integer((FRAMING_VERSION as i64).into()),
        )]));
        let frame = encode_frame(MsgType::Init as u8, &init_payload, 0);
        self.write_all(&frame).await?;
        let (mt, payload) = self.read_frame().await?;
        if mt != MsgType::Ack as u8 {
            return Err(IicpTcpClientError::Protocol(format!(
                "expected ACK (0x02), got 0x{mt:02x}"
            )));
        }
        if let Ok(body) = decode_cbor(&payload) {
            if let Some(CborValue::Integer(i)) = cbor_map_get(&body, 1) {
                let n: i128 = (*i).into();
                self.framing_version = Some(n as u8);
            }
            if let Some(v) = cbor_map_get(&body, 2) {
                self.peer_node_id = cbor_to_str(v);
            }
        }
        Ok(())
    }

    /// Send PING; return echoed bytes from PONG (or None if not echoed).
    pub async fn ping(
        &mut self,
        echo: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, IicpTcpClientError> {
        let body = if let Some(b) = echo {
            CborValue::Map(vec![(
                CborValue::Integer(1.into()),
                CborValue::Bytes(b.to_vec()),
            )])
        } else {
            CborValue::Map(vec![])
        };
        let frame = encode_frame(MsgType::Ping as u8, &encode_cbor(&body), 0);
        self.write_all(&frame).await?;
        let (mt, payload) = self.read_frame().await?;
        if mt != MsgType::Pong as u8 {
            return Err(IicpTcpClientError::Protocol(format!(
                "expected PONG (0x0a), got 0x{mt:02x}"
            )));
        }
        if payload.is_empty() {
            return Ok(None);
        }
        if let Ok(body) = decode_cbor(&payload) {
            if let Some(v) = cbor_map_get(&body, 1) {
                return Ok(cbor_to_bytes(v));
            }
        }
        Ok(None)
    }

    /// Send DISCOVER for `intent`; return the nodes list as CBOR Values.
    pub async fn discover(&mut self, intent: &str) -> Result<Vec<CborValue>, IicpTcpClientError> {
        self.discover_with_session(intent, "discover-1").await
    }

    pub async fn discover_with_session(
        &mut self,
        intent: &str,
        session_id: &str,
    ) -> Result<Vec<CborValue>, IicpTcpClientError> {
        let payload = encode_cbor(&CborValue::Map(vec![
            (
                CborValue::Integer(2.into()),
                CborValue::Text(session_id.into()),
            ),
            (CborValue::Integer(3.into()), CborValue::Text(intent.into())),
        ]));
        let frame = encode_frame(MsgType::Discover as u8, &payload, 0);
        self.write_all(&frame).await?;
        let (mt, body_bytes) = self.read_frame().await?;
        if mt != MsgType::Response as u8 {
            return Err(IicpTcpClientError::Protocol(format!(
                "expected RESPONSE (0x06), got 0x{mt:02x}"
            )));
        }
        let body = decode_cbor(&body_bytes).map_err(IicpTcpClientError::Protocol)?;
        if let Some(CborValue::Array(items)) = cbor_map_get(&body, 20) {
            return Ok(items.clone());
        }
        Ok(Vec::new())
    }

    /// Send CALL with JSON payload; return the CBOR-decoded result as serde_json::Value.
    /// Returns IicpTcpClientError::Server when the server includes error_code (key 100).
    pub async fn call(
        &mut self,
        intent: &str,
        payload: serde_json::Value,
        call_id: Option<&str>,
    ) -> Result<serde_json::Value, IicpTcpClientError> {
        self.call_with_session(intent, payload, call_id, "call-1")
            .await
    }

    pub async fn call_with_session(
        &mut self,
        intent: &str,
        payload: serde_json::Value,
        call_id: Option<&str>,
        session_id: &str,
    ) -> Result<serde_json::Value, IicpTcpClientError> {
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| IicpTcpClientError::Protocol(format!("JSON encode: {e}")))?;
        let mut entries: Vec<(CborValue, CborValue)> = vec![
            (
                CborValue::Integer(2.into()),
                CborValue::Text(session_id.into()),
            ),
            (CborValue::Integer(3.into()), CborValue::Text(intent.into())),
            (
                CborValue::Integer(5.into()),
                CborValue::Bytes(payload_bytes),
            ),
        ];
        if let Some(cid) = call_id {
            entries.push((CborValue::Integer(15.into()), CborValue::Text(cid.into())));
        }
        let frame = encode_frame(
            MsgType::Call as u8,
            &encode_cbor(&CborValue::Map(entries)),
            0,
        );
        self.write_all(&frame).await?;
        let (mt, body_bytes) = self.read_frame().await?;
        if mt != MsgType::Response as u8 {
            return Err(IicpTcpClientError::Protocol(format!(
                "expected RESPONSE (0x06), got 0x{mt:02x}"
            )));
        }
        let body = decode_cbor(&body_bytes).map_err(IicpTcpClientError::Protocol)?;
        if let Some(CborValue::Integer(i)) = cbor_map_get(&body, 100) {
            let code: i128 = (*i).into();
            let message = cbor_map_get(&body, 101)
                .and_then(cbor_to_str)
                .unwrap_or_default();
            return Err(IicpTcpClientError::Server {
                code: code as i64,
                message,
            });
        }
        let result_v = cbor_map_get(&body, 5);
        match result_v {
            Some(CborValue::Bytes(bytes)) => {
                // Result body is CBOR-encoded server-side. Decode and convert
                // to serde_json::Value via roundtrip.
                let inner = decode_cbor(bytes).map_err(IicpTcpClientError::Protocol)?;
                Ok(cbor_to_json(&inner))
            }
            Some(other) => Ok(cbor_to_json(other)),
            None => Ok(serde_json::Value::Object(Default::default())),
        }
    }

    /// Send CLOSE — server hangs up cleanly. Subsequent RPCs on this client will fail.
    pub async fn close(&mut self) -> Result<(), IicpTcpClientError> {
        let frame = encode_frame(MsgType::Close as u8, &[], 0);
        self.write_all(&frame).await?;
        Ok(())
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    async fn write_all(&mut self, data: &[u8]) -> Result<(), IicpTcpClientError> {
        tokio::time::timeout(self.timeout, self.sock.write_all(data))
            .await
            .map_err(|_| IicpTcpClientError::Timeout {
                ms: self.timeout.as_millis() as u64,
            })??;
        Ok(())
    }

    async fn read_frame(&mut self) -> Result<(u8, Vec<u8>), IicpTcpClientError> {
        let mut head = [0u8; FRAME_HEADER_LEN];
        tokio::time::timeout(self.timeout, self.sock.read_exact(&mut head))
            .await
            .map_err(|_| IicpTcpClientError::Timeout {
                ms: self.timeout.as_millis() as u64,
            })??;
        if &head[0..4] != IICP_MAGIC {
            return Err(IicpTcpClientError::Protocol(format!(
                "bad magic in response: {:?}",
                &head[0..4]
            )));
        }
        let mt = head[5];
        let payload_len = u32::from_be_bytes(head[8..12].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            tokio::time::timeout(self.timeout, self.sock.read_exact(&mut payload))
                .await
                .map_err(|_| IicpTcpClientError::Timeout {
                    ms: self.timeout.as_millis() as u64,
                })??;
        }
        Ok((mt, payload))
    }
}

/// Reverse of json_to_cbor — convert a ciborium Value into serde_json::Value
/// for ergonomic return types on the client side.
fn cbor_to_json(v: &CborValue) -> serde_json::Value {
    match v {
        CborValue::Null => serde_json::Value::Null,
        CborValue::Bool(b) => serde_json::Value::Bool(*b),
        CborValue::Integer(i) => {
            let n: i128 = (*i).into();
            if let Ok(j) = i64::try_from(n) {
                serde_json::Value::Number(j.into())
            } else {
                serde_json::Value::String(n.to_string())
            }
        }
        CborValue::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        CborValue::Text(s) => serde_json::Value::String(s.clone()),
        CborValue::Bytes(b) => serde_json::Value::String(base64_encode(b)),
        CborValue::Array(items) => {
            serde_json::Value::Array(items.iter().map(cbor_to_json).collect())
        }
        CborValue::Map(entries) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in entries {
                let key = match k {
                    CborValue::Text(s) => s.clone(),
                    CborValue::Integer(i) => {
                        let n: i128 = (*i).into();
                        n.to_string()
                    }
                    _ => continue,
                };
                obj.insert(key, cbor_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
        _ => serde_json::Value::Null,
    }
}

/// Minimal base64 encode for byte values in JSON output (avoid adding a base64 dep).
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut chunks = bytes.chunks_exact(3);
    for chunk in &mut chunks {
        let v = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        out.push(ALPHA[(v >> 18 & 0x3f) as usize] as char);
        out.push(ALPHA[(v >> 12 & 0x3f) as usize] as char);
        out.push(ALPHA[(v >> 6 & 0x3f) as usize] as char);
        out.push(ALPHA[(v & 0x3f) as usize] as char);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let v = match rem.len() {
            1 => (rem[0] as u32) << 16,
            2 => ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8),
            _ => 0,
        };
        out.push(ALPHA[(v >> 18 & 0x3f) as usize] as char);
        out.push(ALPHA[(v >> 12 & 0x3f) as usize] as char);
        if rem.len() == 2 {
            out.push(ALPHA[(v >> 6 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        out.push('=');
    }
    out
}
