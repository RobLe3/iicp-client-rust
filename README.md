# iicp-client — Rust SDK

Official Rust client library for the [IICP protocol](https://iicp.network) (Intent-based Inter-agent Communication Protocol).

> **Status: deferred** — Rust SDK development is on hold until the Python and TypeScript SDKs reach stable v1.0. The scaffolding is complete; implementation will follow when the protocol spec is frozen.

Implements **ADR-016 §1** — SDK conformance rules SDK-01 through SDK-06.

---

## Planned quickstart

```rust
use iicp_client::{IicpClient, ClientConfig, DiscoverOptions};

#[tokio::main]
async fn main() -> iicp_client::Result<()> {
    let client = IicpClient::new(ClientConfig::default())?;

    let nodes = client.discover("urn:iicp:intent:llm:chat:v1", None).await?;
    println!("Found {} nodes", nodes.nodes.len());

    let response = client.chat(
        &nodes.nodes[0],
        vec![serde_json::json!({"role": "user", "content": "Hello!"})
            .try_into()
            .unwrap()],
        None,
    ).await?;
    println!("{}", response.choices[0].message.content);
    Ok(())
}
```

---

## Links

- Protocol spec: [iicp.network/spec](https://iicp.network/spec)
- Python SDK: [github.com/RobLe3/iicp-client-python](https://github.com/RobLe3/iicp-client-python)
- TypeScript SDK: [github.com/RobLe3/iicp-client-typescript](https://github.com/RobLe3/iicp-client-typescript)
- Conformance: [iicp.network/conformance](https://iicp.network/conformance)

---

**License**: Apache 2.0 · © IICP Working Group
