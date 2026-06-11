# iicp-client · Rust SDK

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/IICP-v1.7-indigo.svg)](https://iicp.network/spec)
[![crates.io](https://img.shields.io/badge/crates.io-iicp--client-orange?logo=rust)](https://crates.io/crates/iicp-client)

Official Rust client library for the [IICP protocol](https://iicp.network) — route AI agent tasks by intent across a self-organising mesh of provider nodes. No central broker. No hardcoded endpoints.

```
urn:iicp:intent:llm:chat:v1  →  discover  →  select  →  submit
```

## Install

```bash
cargo add iicp-client
```

Or add to `Cargo.toml` directly:

```toml
[dependencies]
iicp-client = "0.7.54"
```

To run a provider node from the command line, install the `iicp-node` binary:

```bash
cargo install iicp-client
```

Or for the latest unreleased code:

```toml
[dependencies]
iicp-client = { git = "https://github.com/RobLe3/iicp-client-rust" }
```

---

## Architecture — consumer or provider?

This SDK covers **both** sides of the IICP protocol:

| Role | What you do | Type |
|------|-------------|------|
| **Consumer** | Send AI tasks to the mesh; discover and submit | `IicpClient` |
| **Provider** | Run a node, register with the directory, serve tasks | `IicpNode` |

Consumer and provider can run in the same process. For production provider nodes backed by Ollama/vLLM, see [iicp.network/docs/node-setup](https://iicp.network/docs/node-setup).

---

## Quickstart

`chat()` discovers the best node and submits the task internally (SDK-01) — no
manual node selection needed.

```rust
use iicp_client::{ChatMessage, ChatOptions, ClientConfig, IicpClient};

#[tokio::main]
async fn main() -> iicp_client::Result<()> {
    let client = IicpClient::new(ClientConfig::default())?;

    let reply = client.chat(
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

Need the discovered nodes directly? Call `discover` yourself — the third
argument is an optional W3C `traceparent` for trace propagation:

```rust
let nodes = client.discover("urn:iicp:intent:llm:chat:v1", None, None).await?;
let node  = nodes.nodes.into_iter().next().expect("no nodes available");
```

---

## Use as a local API proxy (OpenAI / Ollama / Anthropic compat)

Run a local gateway that speaks the OpenAI, Ollama, and Anthropic HTTP APIs and routes
every request across the IICP mesh — point any tool you already use at it, no code changes.

```bash
cargo install iicp-client --features proxy
iicp-node proxy                       # → http://127.0.0.1:9483

export OPENAI_BASE_URL=http://127.0.0.1:9483/v1   # OpenAI SDK / LangChain / Cursor / liteLLM
export OLLAMA_HOST=http://127.0.0.1:9483          # Open WebUI / Continue.dev / aider / Jan
```

Loopback-only consumer (never registers with the directory). The proxy is behind the
`proxy` Cargo feature (kept out of `default` so library builds stay lean). Override the
port with `--port` / `IICP_PROXY_PORT`; co-host next to a node with
`iicp-node serve --with-proxy`. Every response carries `Server: iicp-proxy`. Full guide:
<https://iicp.network/docs/proxy>

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
| `routing_epsilon` | `0.05` | ε-greedy exploration probability — with this probability a random node is selected instead of the top-ranked one, promoting discovery of new providers; `0.0` disables; override with `IICP_ROUTING_EPSILON` |

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
    None, // optional W3C traceparent
).await?;
```

---

## Error handling

```rust
use iicp_client::IicpError;

match client.submit(request).await {
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

### Backends — pick an inference engine

`iicp-node serve` (and the `backends::invoke_backend` dispatch) supports four
backend engines, selected with `--backend-type` / `IICP_BACKEND_TYPE`
(default `openai_compat`):

| `--backend-type` | Speaks | Typical backend |
|------------------|--------|-----------------|
| `openai_compat` | OpenAI `/v1/*` | Ollama, LM Studio, any OpenAI-compatible server |
| `vllm` | OpenAI `/v1/*` | vLLM OpenAI server (default port 8000) |
| `llamacpp` | OpenAI `/v1/*` | llama.cpp `llama-server` (default port 8080) |
| `anthropic` | Anthropic Messages API (`POST /v1/messages`) | Anthropic API → first-class Claude |

The `anthropic` backend translates the IICP `llm:chat:v1` task into an Anthropic
Messages request and translates the reply back to the OpenAI chat-completion
shape — so a Claude-backed node looks identical to any other node to IICP
clients. It hoists system-role messages into the top-level `system` param, sends
`x-api-key` + `anthropic-version` headers, and defaults `max_tokens` (Anthropic
requires it). With no `--backend-url` override it targets `https://api.anthropic.com/v1`.

```bash
# Serve Claude as an IICP node
iicp-node serve \
  --backend-type anthropic \
  --model claude-opus-4-8 \
  --backend-api-key "$ANTHROPIC_API_KEY"
# or set IICP_BACKEND_TYPE / IICP_BACKEND_API_KEY in the environment
```

The API key comes from `--backend-api-key` (env `IICP_BACKEND_API_KEY`). For the
OpenAI-compatible backends this is sent as a Bearer token; for `anthropic` it is
sent as the `x-api-key` header.

### Input modalities — text, image, audio

A node advertises the input modalities each model accepts under
`capabilities[].input_modalities`, detected from the model name (conservative
name-pattern matching, ADR-046 / #408 / #414):

| Model name contains | Advertised modalities |
|---------------------|-----------------------|
| `vl` / `vision` / `llava` | `["text", "image"]` |
| `audio` / `voxtral` | `["text", "audio"]` |
| `omni` | `["text", "image", "audio"]` |
| anything else | `["text"]` |

Each modality is a modality of chat, not a separate intent. A single node hosting
several models advertises one capability object per `(intent, input_modalities)`
group, so a text model and a vision model on the same node surface as distinct
capabilities. Image and audio are passed through OpenAI-style content parts
(`text` and `image_url` blocks); the `anthropic` backend maps `image_url` parts
(data-URL or remote URL) into native Anthropic image content blocks.

### Listen port — default 9484, auto-increment (v0.7.5+)

The official IICP port **9484** is the default listen port (`IICP_PORT`, `--port`).
The `iicp-node` binary auto-increments to the next free port when 9484 is already
in use, so several nodes on one host don't need hand-picked ports — first binds
9484, second 9485, third 9486, etc. Each node gets its own port (hence its own NAT
pinhole); multiple models on one node share that single port. Auto-increment is
skipped when you pass an explicit `--public-endpoint`.

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

## Operator identity

Your **operator identity** is an ed25519 keypair — its public key *is* your `operator_id` (the
directory stores it as `operator_pubkey`). One identity spans every node you run: it binds them to
you (nodes show **`Operated by <your name>` ✓**), earns a
[founder ordinal](https://iicp.network/founders), and rolls each node's credits into one operator
wallet. Your `display_name` is the public, mutable handle; your contact stays local.

```bash
iicp-node init                       # create your key-backed identity (~/.iicp/operator.json)
iicp-node serve --node mynode        # signs an operator→node delegation; binds the node to you
iicp-node operator rename "NewName"  # change your public display_name (signed)
iicp-node operator encrypt           # password-encrypt the secret at rest ($IICP_OPERATOR_PASSPHRASE)
iicp-node operator decrypt           # remove at-rest encryption
```

**The key is the identity** — whoever holds `~/.iicp/operator.json` controls it (its nodes, ordinal,
and wallet); there is no central recovery. Back it up (encrypted), never commit or share it; lose it
and the identity, with its founder ordinal, is gone.

Full guide: **[iicp.network/docs/operator-identity](https://iicp.network/docs/operator-identity)**

---

## SDK conformance

| Rule | Description | Status |
|------|-------------|--------|
| SDK-01 | discover → select → submit pipeline | ✓ |
| SDK-02 | `task_id` auto-generated (UUID v4) | ✓ |
| SDK-03 | Intent URN pattern validation (regex) | ✓ |
| SDK-04 | `timeout_ms` capped at 120 000 ms | ✓ |
| SDK-05 | Retry on transient errors (429 / 502 / 503 / 504) | ✓ |
| SDK-06 | W3C `traceparent` propagation (shared across discover + submit) | ✓ |

Conformance tier: `iicp:sdk:v1` (spec S.14) · [Request a badge](https://iicp.network/conformance)

---

## Development

```bash
cargo test          # run the unit suite
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
