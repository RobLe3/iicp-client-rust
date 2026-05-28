# iicp-client · Rust SDK

[![CI](https://github.com/RobLe3/iicp-client-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/RobLe3/iicp-client-rust/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/IICP-v1.7-indigo.svg)](https://iicp.network/spec)
[![crates.io](https://img.shields.io/badge/crates.io-iicp--client-orange?logo=rust)](https://crates.io/crates/iicp-client)

Official Rust client library for the [IICP protocol](https://iicp.network) — route AI agent tasks by intent across a self-organising mesh of provider nodes. No central broker. No hardcoded endpoints.

```
urn:iicp:intent:llm:chat:v1  →  discover  →  select  →  submit
```

## Add to Cargo.toml

```toml
[dependencies]
iicp-client = "0.2"
```

Or for the latest unreleased code:

```toml
[dependencies]
iicp-client = { git = "https://github.com/RobLe3/iicp-client-rust" }
```

---

## Quickstart

```rust
use iicp_client::{ChatMessage, ChatOptions, ClientConfig, IicpClient};

#[tokio::main]
async fn main() -> iicp_client::Result<()> {
    let client = IicpClient::new(ClientConfig::default())?;

    let nodes = client.discover("urn:iicp:intent:llm:chat:v1", None).await?;
    let node  = nodes.nodes.into_iter().next().expect("no nodes available");

    let reply = client.chat(
        &node,
        vec![
            ChatMessage { role: "system".into(), content: "You are a helpful assistant.".into() },
            ChatMessage { role: "user".into(),   content: "What is IICP?".into() },
        ],
        Some(ChatOptions { timeout_ms: Some(30_000), ..Default::default() }),
    ).await?;

    println!("{}", reply.choices[0].message.content);
    Ok(())
}
```

---

## Configuration

```rust
use iicp_client::ClientConfig;

let config = ClientConfig {
    directory_url : "https://iicp.network/api".into(),  // IICP directory
    timeout_ms    : 30_000,                              // max 120 000 (SDK-04)
    region        : Some("eu-central".into()),           // prefer nodes in region
    node_token    : None,                                // optional auth token
};
```

| Field | Default | Description |
|-------|---------|-------------|
| `directory_url` | `"https://iicp.network/api"` | IICP directory endpoint |
| `timeout_ms` | `30000` | Request timeout — max 120 000 ms |
| `region` | `None` | Preferred node region |
| `node_token` | `None` | Bearer token for authenticated nodes |

---

## Discover options

```rust
use iicp_client::DiscoverOptions;

let nodes = client.discover(
    "urn:iicp:intent:llm:chat:v1",
    Some(DiscoverOptions {
        region        : Some("eu-central".into()),
        model         : Some("phi3:mini".into()),
        min_reputation: Some(0.7),
        limit         : Some(5),
    }),
).await?;
```

---

## Error handling

```rust
use iicp_client::IicpError;

match client.submit(&node, request).await {
    Ok(resp) => println!("{:?}", resp),
    Err(IicpError::Protocol { code, message, status }) =>
        eprintln!("[{code}] {message}  (HTTP {status})"),
    Err(e) => eprintln!("Error: {e}"),
}
```

Error codes match the [IICP error reference](https://iicp.network/docs/error-reference).

---

## Serving as a node — handler contract

When you run a serving node (`IicpNode::serve`), your handler returns the **inner result
value**; `serve()` wraps it in the `TaskResponse.result` envelope for you. Do **not** return
an already-wrapped `{"result": ...}` value — that double-nests the response and breaks
cross-flavour interop with the Python/TS SDKs (response shape must be `{"result": {...}}`).

The `backends::invoke_backend` / `openai_compat::invoke` helpers return a
`{"result": ...}` consumer envelope, so when using them as a serve handler, unwrap the
inner value first:

```rust
let v = iicp_client::backends::invoke_backend("openai_compat", &opts, &req.intent, &req.payload)
    .await
    .unwrap_or_else(|e| serde_json::json!({"error_code": 500, "error_message": e}));
// serve() re-wraps in TaskResponse.result — return the inner value to stay single-level.
Ok(v.get("result").cloned().unwrap_or(v))
```

---

## NAT traversal — automatic (v0.7.3+)

Since v0.7.3, NAT detection runs automatically on every `iicp-node serve` startup — no flags
needed. Requires the `nat` feature (UPnP detection):

```toml
[dependencies]
iicp-client = { version = "0.7", features = ["nat"] }
# For relay substrate (CGNAT fallback): add "iicp-tcp"
iicp-client = { version = "0.7", features = ["nat", "iicp-tcp"] }
```

| Tier | When | What happens |
|------|------|-------------|
| **0** | VPS/cloud (public IP on NIC) or `IICP_PUBLIC_ENDPOINT` set | Registers directly |
| **1a** | Home router with UPnP, no CGNAT | Port-forward via UPnP → register WAN IP |
| **1b** | CGNAT + IPv6 + AddPinhole works | Registers IPv6 with firewall rule |
| **1c** | CGNAT + IPv6 + AddPinhole fails (FRITZ!Box error 606) | Registers IPv6 + logs guidance |
| **3** | CGNAT + no usable IPv6 | Auto-elects relay from directory |
| **4** | Nothing worked | Serves locally with operator guidance |

### Environment-specific behaviour

**Docker bridge (`-p 8020:8020`)** — UPnP is skipped (reaches Docker NAT, not home router).
Set `IICP_PUBLIC_ENDPOINT`:
```bash
docker run -e IICP_PUBLIC_ENDPOINT=http://your-host:8020 \
           -e IICP_BACKEND_URL=http://host.docker.internal:11434 \
           -p 8020:8020 my-iicp-node
```

**CGNAT + no IPv6 → automatic relay:**
```
[iicp-node] NAT tier=3: auto-electing relay from directory...
[iicp-node] auto-elected relay: relay.example.com:9485
```

### Running a relay-capable node (relay operator)

```rust
use iicp_client::{IicpNode, NodeConfig};

let node = IicpNode::new(NodeConfig {
    endpoint         : "http://relay.example.com:8020".into(),
    intent           : "urn:iicp:intent:llm:chat:v1".into(),
    relay_capable    : true,   // accept RELAY_BIND on TCP 9485 (requires iicp-tcp)
    relay_accept_port: 9485,
    enable_mesh      : true,   // advertise relay_capable=true in gossip
    ..Default::default()
});
```

### Opt-out / override

```bash
IICP_AUTO_DETECT_NAT=false              # disable detection entirely
IICP_PUBLIC_ENDPOINT=http://x.x.x.x:8020  # trust this endpoint
IICP_RELAY_WORKER_ENDPOINT=host:9485    # specific relay instead of auto-elect
```

---

## SDK conformance

| Rule | Description | Status |
|------|-------------|--------|
| SDK-01 | discover → select → submit pipeline | ✓ |
| SDK-02 | `task_id` auto-generated (UUID v4) | ✓ |
| SDK-03 | Intent URN pattern validation (regex) | ✓ |
| SDK-04 | `timeout_ms` capped at 120 000 ms | ✓ |
| SDK-05 | Retry on 429 / 503 | planned |
| SDK-06 | W3C `traceparent` propagation | planned |

Conformance tier: `iicp:sdk:v1` (spec S.14) · [Request a badge](https://iicp.network/conformance)

---

## Development

```bash
cargo test          # 109 tests
cargo clippy        # lint
cargo build --release
cargo run --example quickstart
```

---

## Links

- [Protocol spec](https://iicp.network/spec) — full IICP specification
- [Node setup guide](https://iicp.network/docs/node-setup) — run your own node
- [Error reference](https://iicp.network/docs/error-reference) — all error codes
- [iicp-client-python](https://github.com/RobLe3/iicp-client-python) — Python SDK
- [iicp-client-typescript](https://github.com/RobLe3/iicp-client-typescript) — TypeScript SDK

---

Apache 2.0 · [iicp.network](https://iicp.network)
