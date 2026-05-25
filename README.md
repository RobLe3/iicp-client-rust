# iicp-client · Rust SDK

[![CI](https://github.com/RobLe3/iicp-client-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/RobLe3/iicp-client-rust/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/IICP-v1.5-indigo.svg)](https://iicp.network/spec)
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
cargo test          # 19 tests + 1 doc-test
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
