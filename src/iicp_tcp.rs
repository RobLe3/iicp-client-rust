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
        return Err(format!("IICP frame too short: {} < {FRAME_HEADER_LEN}", data.len()));
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
        return Err(format!("IICP payload truncated: need {total}, have {}", data.len()));
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
    let mut entries: Vec<(CborValue, CborValue)> = vec![
        (CborValue::Integer(1.into()), CborValue::Integer((framing_version as i64).into())),
    ];
    if let Some(id) = node_id {
        entries.push((CborValue::Integer(2.into()), CborValue::Text(id.to_string())));
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
    let mut entries: Vec<(CborValue, CborValue)> = vec![
        (CborValue::Integer(2.into()), CborValue::Text(session_id.to_string())),
    ];
    if let Some(cid) = call_id {
        entries.push((CborValue::Integer(15.into()), CborValue::Text(cid.to_string())));
    }
    if let Some(r) = result {
        entries.push((CborValue::Integer(5.into()), CborValue::Bytes(r.to_vec())));
    }
    if let Some(ec) = error_code {
        entries.push((CborValue::Integer(100.into()), CborValue::Integer(ec.into())));
    }
    if let Some(em) = error_message {
        entries.push((CborValue::Integer(101.into()), CborValue::Text(em.to_string())));
    }
    encode_cbor(&CborValue::Map(entries))
}

pub fn encode_discover_response(session_id: &str, intent: &str, nodes: &[CborValue]) -> Vec<u8> {
    encode_cbor(&CborValue::Map(vec![
        (CborValue::Integer(2.into()), CborValue::Text(session_id.to_string())),
        (CborValue::Integer(3.into()), CborValue::Text(intent.to_string())),
        (CborValue::Integer(20.into()), CborValue::Array(nodes.to_vec())),
    ]))
}

// Pull an integer key out of a CBOR map. Returns None if not a map or key absent.
fn cbor_map_get<'a>(map: &'a CborValue, key: i64) -> Option<&'a CborValue> {
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
    dyn Fn(
            TcpTask,
        ) -> Pin<
            Box<dyn std::future::Future<Output = serde_json::Value> + Send>,
        > + Send
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
}

impl IicpTcpServer {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            node_id: None,
            handler: None,
            discover_lookup: None,
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

    async fn handle_connection(&self, mut socket: TcpStream) -> std::io::Result<()> {
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

    async fn on_discover(&self, frame: &IicpFrame, socket: &mut TcpStream) -> std::io::Result<bool> {
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

        let nodes: Vec<CborValue> = if let (Some(lookup), false) =
            (&self.discover_lookup, intent.is_empty())
        {
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
                            if let Ok(jv) = ciborium::de::from_reader::<serde_json::Value, _>(&bytes[..]) {
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
            let user_result = handler(task).await;
            // Handler may return {"error_code": N, "error_message": "..."} or the
            // result body directly. Inspect for error_code key.
            if let serde_json::Value::Object(map) = &user_result {
                if let Some(ec) = map.get("error_code").and_then(|v| v.as_i64()) {
                    error_code = Some(ec);
                    error_message = map
                        .get("error_message")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .or(Some("handler error".to_string()));
                } else {
                    // CBOR-encode the result for transport. If the handler
                    // returned a {"result": ...} wrapper, unwrap it.
                    let inner = map.get("result").unwrap_or(&user_result);
                    let cbor_value = json_to_cbor(inner);
                    result_bytes = Some(encode_cbor(&cbor_value));
                }
            } else {
                let cbor_value = json_to_cbor(&user_result);
                result_bytes = Some(encode_cbor(&cbor_value));
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
        serde_json::Value::Array(items) => CborValue::Array(items.iter().map(json_to_cbor).collect()),
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
