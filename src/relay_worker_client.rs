// SPDX-License-Identifier: Apache-2.0
// Only compiled when the iicp-tcp feature is enabled (requires ciborium).
#![cfg(feature = "iicp-tcp")]
//! Relay worker client — ADR-041 tier-3, Part 3 R2 (#341).
//!
//! Rust port of `relay_worker_client.py` / `relay_worker_client.ts`.
//! Connects outbound to a relay node, performs the INIT/RELAY_BIND handshake,
//! handles incoming CALL frames, and auto-reconnects with exponential backoff.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use ciborium::value::Value as CborVal;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const IICP_MAGIC: &[u8] = b"IICP";
const FRAMING_VERSION: u8 = 0x01;
const FRAME_HEADER_LEN: usize = 12;
const PING_INTERVAL_SECS: u64 = 30;
const MAX_RECONNECT_DELAY_SECS: u64 = 60;

const MT_INIT: u8 = 0x01;
const MT_ACK: u8 = 0x02;
const MT_CALL: u8 = 0x05;
const MT_RESPONSE: u8 = 0x06;
const MT_PING: u8 = 0x09;
const MT_PONG: u8 = 0x0a;
const MT_RELAY_BIND: u8 = 0x0b;
const MT_RELAY_ACK: u8 = 0x0c;

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

fn cbor_encode_int_map(entries: &[(i64, CborVal)]) -> Vec<u8> {
    let map = CborVal::Map(
        entries.iter().map(|(k, v)| (CborVal::Integer((*k).into()), v.clone())).collect(),
    );
    let mut buf = Vec::new();
    let _ = ciborium::ser::into_writer(&map, &mut buf);
    buf
}

fn cbor_decode_int_map(data: &[u8]) -> Option<std::collections::HashMap<i64, CborVal>> {
    let v: CborVal = ciborium::de::from_reader(data).ok()?;
    let map = match v { CborVal::Map(m) => m, _ => return None };
    let mut out = std::collections::HashMap::new();
    for (k, val) in map {
        if let CborVal::Integer(n) = k {
            if let Ok(key) = i64::try_from(n) { out.insert(key, val); }
        }
    }
    Some(out)
}

fn cbor_bytes(v: Option<&CborVal>) -> Vec<u8> {
    match v {
        Some(CborVal::Bytes(b)) => b.clone(),
        Some(CborVal::Text(s)) => s.as_bytes().to_vec(),
        _ => vec![],
    }
}

fn cbor_text(v: Option<&CborVal>) -> String {
    match v {
        Some(CborVal::Text(s)) => s.clone(),
        Some(CborVal::Bytes(b)) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    }
}

async fn read_frame(reader: &mut (impl AsyncReadExt + Unpin)) -> Option<(u8, Vec<u8>)> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await.ok()?;
    if &header[..4] != IICP_MAGIC { return None; }
    let msg_type = header[5];
    let payload_len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    if payload_len > 16 * 1024 * 1024 { return None; }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 { reader.read_exact(&mut payload).await.ok()?; }
    Some((msg_type, payload))
}

/// Handler type for relay worker CALL frames.
pub type RelayHandlerFn =
    Arc<dyn Fn(Value) -> std::pin::Pin<Box<dyn Future<Output = Value> + Send>> + Send + Sync>;

/// Callback invoked after a successful RELAY_ACK — use to re-register with the directory (#358).
pub type OnBindFn = Arc<
    dyn Fn(String, u16, String) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// Relay worker client — connects outbound to a relay, handles CALL frames.
pub struct RelayWorkerClient {
    worker_id: String,
    intent: String,
    relay_host: String,
    relay_port: u16,
    handler: RelayHandlerFn,
    models: Vec<String>,
    on_bind: Option<OnBindFn>,
}

impl RelayWorkerClient {
    pub fn new(
        worker_id: impl Into<String>,
        intent: impl Into<String>,
        relay_host: impl Into<String>,
        relay_port: u16,
        handler: RelayHandlerFn,
        models: Vec<String>,
    ) -> Self {
        Self {
            worker_id: worker_id.into(),
            intent: intent.into(),
            relay_host: relay_host.into(),
            relay_port,
            handler,
            models,
            on_bind: None,
        }
    }

    pub fn with_on_bind(mut self, cb: OnBindFn) -> Self {
        self.on_bind = Some(cb);
        self
    }

    /// Connect-and-run loop with exponential backoff reconnect. Runs until cancelled.
    pub async fn run(self: Arc<Self>) {
        let mut delay = Duration::from_secs(2);
        loop {
            match self.session().await {
                Ok(()) => { delay = Duration::from_secs(2); }
                Err(e) => {
                    tracing::warn!(
                        "Relay worker {}: session error: {e} — reconnecting in {:?}",
                        self.worker_id, delay,
                    );
                }
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(MAX_RECONNECT_DELAY_SECS));
        }
    }

    async fn session(&self) -> Result<(), String> {
        let stream = TcpStream::connect(format!("{}:{}", self.relay_host, self.relay_port))
            .await
            .map_err(|e| e.to_string())?;
        tracing::debug!(
            "Relay worker {}: connected to {}:{}",
            self.worker_id, self.relay_host, self.relay_port
        );
        let (mut reader, mut writer) = stream.into_split();

        // Step 1: INIT → ACK
        let init = cbor_encode_int_map(&[(1, CborVal::Integer((FRAMING_VERSION as i64).into()))]);
        writer.write_all(&make_frame(MT_INIT, &init)).await.map_err(|e| e.to_string())?;
        let (mt, _) = read_frame(&mut reader).await.ok_or("EOF after INIT")?;
        if mt != MT_ACK { return Err(format!("expected ACK, got 0x{mt:02x}")); }

        // Step 2: RELAY_BIND → RELAY_ACK
        let bind = cbor_encode_int_map(&[
            (1, CborVal::Text(self.worker_id.clone())),
            (2, CborVal::Text(self.intent.clone())),
            (3, CborVal::Array(self.models.iter().map(|m| CborVal::Text(m.clone())).collect())),
        ]);
        writer.write_all(&make_frame(MT_RELAY_BIND, &bind)).await.map_err(|e| e.to_string())?;
        let (mt, payload) = read_frame(&mut reader).await.ok_or("EOF after RELAY_BIND")?;
        if mt != MT_RELAY_ACK { return Err(format!("expected RELAY_ACK, got 0x{mt:02x}")); }
        let ack_body = cbor_decode_int_map(&payload).ok_or("RELAY_ACK decode failed")?;
        if cbor_text(ack_body.get(&1)) != "ok" {
            return Err(format!("RELAY_ACK not ok: {:?}", ack_body.get(&1)));
        }

        tracing::info!(
            "Relay worker {}: bound to relay {}:{}",
            self.worker_id, self.relay_host, self.relay_port
        );
        if let Some(cb) = &self.on_bind {
            cb(self.relay_host.clone(), self.relay_port, self.worker_id.clone()).await;
        }

        // Step 3: session loop
        let handler = Arc::clone(&self.handler);
        let worker_id = self.worker_id.clone();
        let writer = Arc::new(tokio::sync::Mutex::new(writer));
        let writer_ping = Arc::clone(&writer);

        // PING keepalive task
        let ping_task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(PING_INTERVAL_SECS)).await;
                let pong = cbor_encode_int_map(&[(1, CborVal::Bytes(vec![]))]);
                let frame = make_frame(MT_PING, &pong);
                let mut w = writer_ping.lock().await;
                if w.write_all(&frame).await.is_err() { break; }
            }
        });

        loop {
            match read_frame(&mut reader).await {
                None => break,
                Some((MT_CALL, payload)) => {
                    let handler = Arc::clone(&handler);
                    let writer = Arc::clone(&writer);
                    let wid = worker_id.clone();
                    tokio::spawn(async move {
                        let body = cbor_decode_int_map(&payload);
                        let call_id = body.as_ref()
                            .map(|b| cbor_text(b.get(&15)))
                            .unwrap_or_default();
                        let raw5 = body.as_ref().map(|b| cbor_bytes(b.get(&5))).unwrap_or_default();
                        let task: Value = serde_json::from_slice(&raw5).unwrap_or(Value::Null);
                        let result = handler(task).await;
                        let resp_body = serde_json::to_string(&result).unwrap_or_default();
                        let resp_payload = cbor_encode_int_map(&[
                            (15, CborVal::Text(call_id.clone())),
                            (5, CborVal::Bytes(resp_body.into_bytes())),
                        ]);
                        let mut w = writer.lock().await;
                        if let Err(e) = w.write_all(&make_frame(MT_RESPONSE, &resp_payload)).await {
                            tracing::warn!("Relay worker {wid}: RESPONSE write error: {e}");
                        }
                    });
                }
                Some((MT_PONG, _)) => {}
                Some((0x07, _)) => break, // CLOSE
                Some((mt, _)) => {
                    tracing::debug!("Relay worker {worker_id}: unhandled frame 0x{mt:02x}");
                }
            }
        }

        ping_task.abort();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn make_frame_has_correct_magic() {
        let frame = make_frame(0x09, b"payload");
        assert_eq!(&frame[..4], b"IICP");
        assert_eq!(frame[5], 0x09);
        assert_eq!(u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]), 7);
    }

    #[test]
    fn cbor_int_map_roundtrip() {
        let encoded = cbor_encode_int_map(&[
            (15, CborVal::Text("call-abc".into())),
            (5, CborVal::Bytes(b"hello".to_vec())),
        ]);
        let decoded = cbor_decode_int_map(&encoded).unwrap();
        assert_eq!(cbor_text(decoded.get(&15)), "call-abc");
        assert_eq!(cbor_bytes(decoded.get(&5)), b"hello");
    }

    #[test]
    fn relay_worker_client_constructs() {
        let handler: RelayHandlerFn = Arc::new(|v| Box::pin(async move { v }));
        let _ = RelayWorkerClient::new(
            "w-001",
            "urn:iicp:intent:llm:chat:v1",
            "relay.example.com",
            9485,
            handler,
            vec!["qwen2.5:0.5b".into()],
        );
    }
}
