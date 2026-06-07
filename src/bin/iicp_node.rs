//! iicp-node — turn iicp-client into a runnable IICP provider node.
//!
//! ```text
//! cargo install iicp-client
//! iicp-node init                                # interactive wizard
//! iicp-node list                                # list saved node configs
//! iicp-node serve --node <name>                 # serve a persisted node
//! iicp-node serve --model qwen2.5:0.5b --backend-url http://localhost:11434
//! ```
//!
//! All flags are also accepted as env vars (IICP_BACKEND_URL,
//! IICP_BACKEND_MODEL, IICP_PUBLIC_ENDPOINT, IICP_DIRECTORY_URL,
//! IICP_REGION, IICP_MAX_CONCURRENT, IICP_NODE_ID, IICP_INTENT,
//! IICP_PORT, IICP_HOST, IICP_SKIP_REGISTRATION, IICP_NODE_NAME,
//! IICP_AUTO_DETECT_NAT, IICP_EXTERNAL_IP_PROBE_URL).
//!
//! Mirrors the Python (`iicp_client.cli`) and TypeScript (`@iicp/client/cli`)
//! entry points so operators choosing Rust get the same one-liner setup.

use std::env;
use std::io::{self, BufRead, Write};
use std::process;
use std::time::Duration;

use iicp_client::backends::invoke_backend;
use iicp_client::backends::openai_compat::OpenAiCompatOptions;
use iicp_client::backends::BACKEND_TYPES;
use iicp_client::identity::{
    config_dir, generate_node, list_nodes, load_node, load_operator, save_node, save_operator,
    NodeIdentity, OperatorIdentity,
};
use iicp_client::node::{IicpNode, NodeConfig};
use iicp_client::{ClientConfig, IicpClient, TaskRequest};

fn env_or(name: &str, fallback: Option<&str>) -> Option<String> {
    env::var(name)
        .ok()
        .or_else(|| fallback.map(|s| s.to_string()))
}

fn env_int(name: &str, fallback: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

fn env_bool(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(false)
}

/// Return the first bindable TCP port >= `start` on `host`.
///
/// The official IICP port 9484 is the starting point; when running multiple
/// nodes on one host (each model on its own port → its own pinhole) the second
/// node auto-increments to 9485, the third to 9486, and so on. Probes by
/// attempting a real bind so the chosen port is genuinely free before NAT
/// detection opens a pinhole and the directory registration advertises it.
fn find_available_port(host: &str, start: u16, max_tries: u16) -> u16 {
    for offset in 0..max_tries {
        let candidate = start.saturating_add(offset);
        let addr_str = fmt_bind_addr(host, candidate);
        if addr_str
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|a| std::net::TcpListener::bind(a).is_ok())
        {
            return candidate;
        }
    }
    start // exhausted — let serve() surface the real bind error
}

/// Format a bind address string, wrapping IPv6 host in brackets.
fn fmt_bind_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[derive(Default)]
struct ServeOpts {
    node: String,
    backend_url: String,
    backend_type: String,
    model: String,
    public_endpoint: String,
    directory_url: String,
    region: String,
    intent: String,
    max_concurrent: usize,
    node_id: String,
    port: u16,
    host: String,
    skip_registration: bool,
    auto_detect_nat: bool,
    /// True when `--no-auto-detect-nat` was passed — suppresses the saved-config re-enable.
    no_auto_detect_nat: bool,
    external_ip_probe_url: String,
    relay_worker_endpoint: String,
    log_dir: Option<String>,
    /// #405 — take over the per-node_id single-instance lock if another process holds it.
    force: bool,
    /// #5 — Bearer key for an auth-requiring OpenAI-compat backend (LM Studio, hosted). Empty = none.
    backend_api_key: String,
    /// ADR-050 2-C — also run the compat proxy gateway (loopback 9483) in this process.
    with_proxy: bool,
}

fn print_help() {
    print!(
        "usage: iicp-node <command> [options]\n\n\
         Commands:\n\
         \x20 init                       Interactive wizard — set up operator + first node\n\
         \x20 list                       List node configs saved under ~/.iicp/nodes/\n\
         \x20 serve                      Register and serve a node\n\
         \x20 query <prompt>             Discover mesh nodes and submit a chat task\n\
         \x20 credits                    Show this node's earned / spent / balance credits\n\
         \x20 operator rename <name>     Change your public display_name (signed by your operator key)\n\
         \x20 operator encrypt           Password-encrypt the operator secret at rest ($IICP_OPERATOR_PASSPHRASE)\n\
         \x20 operator decrypt           Remove at-rest encryption of the operator secret\n\
         \x20 proxy                      Run the local OpenAI/Ollama/Anthropic compat gateway (loopback)\n\
         \x20 help                       Print this help\n\n\
         Global flags:\n\
         \x20 --version, -V              Print version and exit\n\
         \x20 --help, -h                 Print this help\n\n\
         serve required (flag or env):\n\
         \x20 --model NAME               IICP_BACKEND_MODEL (e.g. qwen2.5:0.5b)\n\
         \x20 (or --node NAME            load from ~/.iicp/nodes/<NAME>.json after `iicp-node init`)\n\n\
         serve optional:\n\
         \x20 --backend-url URL          IICP_BACKEND_URL (default http://localhost:11434 — local Ollama)\n\
         \x20 --backend-type TYPE        IICP_BACKEND_TYPE — openai_compat | vllm | llamacpp | anthropic (default openai_compat)\n\
         \x20 --public-endpoint URL      IICP_PUBLIC_ENDPOINT — externally reachable URL\n\
         \x20 --directory-url URL        IICP_DIRECTORY_URL (default https://iicp.network/api)\n\
         \x20 --region REGION            IICP_REGION (e.g. us-east; unknown if unset)\n\
         \x20 --intent URN               IICP_INTENT (default urn:iicp:intent:llm:chat:v1)\n\
         \x20 --max-concurrent N         IICP_MAX_CONCURRENT (default 4)\n\
         \x20 --node-id ID               IICP_NODE_ID (auto-generated if absent)\n\
         \x20 --port N                   IICP_PORT (default 9484)\n\
         \x20 --host HOST                IICP_HOST (default :: — dual-stack IPv4+IPv6)\n\
         \x20 --skip-registration        IICP_SKIP_REGISTRATION — dev mode\n\
         \x20 --force                    IICP_FORCE — take over the single-instance lock for this node_id\n\
         \x20 --backend-api-key KEY      IICP_BACKEND_API_KEY — Bearer key for an auth'd backend (LM Studio, hosted)\n\
         \x20 --auto-detect-nat          IICP_AUTO_DETECT_NAT — run NAT detection at startup (default on)\n\
         \x20 --no-auto-detect-nat       disable NAT detection (overrides IICP_AUTO_DETECT_NAT)\n\
         \x20 --external-ip-probe-url U  IICP_EXTERNAL_IP_PROBE_URL — fallback IPv4 probe\n\
         \x20 --relay-worker-endpoint EP IICP_RELAY_WORKER_ENDPOINT — relay host:port for CGNAT nodes\n\
         \x20 --with-proxy               IICP_WITH_PROXY — also run the compat proxy gateway (loopback 9483)\n\
         \x20 --log-dir DIR              IICP_LOG_DIR (default ~/.iicp/logs/)\n\n\
         query optional:\n\
         \x20 --directory-url URL        IICP_DIRECTORY_URL (default https://iicp.network/api)\n\
         \x20 --intent URN               IICP_INTENT (default urn:iicp:intent:llm:chat:v1)\n\
         \x20 --model NAME               Pin to a specific model on the remote node\n\
         \x20 --max-tokens N             Limit response length\n\
         \x20 --timeout-ms N             Request timeout (default 60000)\n\n\
         credits optional:\n\
         \x20 --node NAME                Load saved node config (~/.iicp/nodes/<NAME>.json)\n\
         \x20 --node-id ID               Node id to query (alternative to --node)\n\
         \x20 --token T                  Node token (default $IICP_NODE_TOKEN or cached)\n\
         \x20 --directory-url URL        IICP_DIRECTORY_URL (default https://iicp.network/api)\n\
         \x20 --json                     Emit the raw summary JSON\n\
         \x20 --verify                   Cryptographically audit awards against the signed log\n\n\
         proxy optional:\n\
         \x20 --host HOST                IICP_PROXY_HOST (default 127.0.0.1)\n\
         \x20 --port N                   IICP_PROXY_PORT (default 9483)\n\
         \x20 --directory-url URL        IICP_DIRECTORY_URL\n\
         \x20 --region REGION            IICP_PROXY_PREFERRED_REGION\n"
    );
}

/// True when any arg is `-h`/`--help`. Per-subcommand handlers call this at the TOP,
/// before their parse loop, so `--help` prints usage + exits 0 instead of erroring as
/// an "unknown flag" (mirrors the `serve`/parse_args `--help` short-circuit).
fn wants_help(args: &[String]) -> bool {
    args.iter().any(|a| a == "-h" || a == "--help")
}

fn print_query_help() {
    print!(
        "usage: iicp-node query <prompt> [options]\n\n\
         Discover mesh nodes for an intent and submit a chat task.\n\n\
         Options:\n\
         \x20 --directory-url URL   IICP_DIRECTORY_URL (default https://iicp.network/api)\n\
         \x20 --intent URN          IICP_INTENT (default urn:iicp:intent:llm:chat:v1)\n\
         \x20 --model NAME          Pin to a specific model on the remote node\n\
         \x20 --max-tokens N        Limit response length\n\
         \x20 --timeout-ms N        Request timeout (default 60000)\n\
         \x20 -h, --help            Print this help\n"
    );
}

fn print_credits_help() {
    print!(
        "usage: iicp-node credits [options]\n\n\
         Show this node's earned / spent / balance from the directory's reconcile-checked\n\
         summary. With no --node/--node-id, a single saved node (or `default`) is used.\n\n\
         Options:\n\
         \x20 --node NAME           Load saved node config (~/.iicp/nodes/<NAME>.json)\n\
         \x20 --node-id ID          Node id to query (alternative to --node)\n\
         \x20 --token T             Node token (default $IICP_NODE_TOKEN or cached)\n\
         \x20 --directory-url URL   IICP_DIRECTORY_URL (default https://iicp.network/api)\n\
         \x20 --json                Emit the raw summary JSON\n\
         \x20 --verify              Cryptographically audit awards against the signed log\n\
         \x20 -h, --help            Print this help\n"
    );
}

fn print_operator_help() {
    print!(
        "usage: iicp-node operator <subcommand> [options]\n\n\
         Subcommands:\n\
         \x20 rename <name>   Change your public display_name (signed by your operator key)\n\
         \x20 encrypt         Password-encrypt the operator secret at rest ($IICP_OPERATOR_PASSPHRASE)\n\
         \x20 decrypt         Remove at-rest encryption of the operator secret\n\n\
         rename options:\n\
         \x20 --directory-url URL   IICP_DIRECTORY_URL (default https://iicp.network/api)\n\
         \x20 -h, --help            Print this help\n"
    );
}

fn print_proxy_help() {
    print!(
        "usage: iicp-node proxy [options]\n\n\
         Run the local OpenAI/Ollama/Anthropic compat gateway on loopback. Consumer-side,\n\
         no directory registration.\n\n\
         Options:\n\
         \x20 --host HOST           IICP_PROXY_HOST (default 127.0.0.1)\n\
         \x20 --port N              IICP_PROXY_PORT (default 9483)\n\
         \x20 --directory-url URL   IICP_DIRECTORY_URL\n\
         \x20 --region REGION       IICP_PROXY_PREFERRED_REGION\n\
         \x20 -h, --help            Print this help\n"
    );
}

fn print_init_help() {
    print!(
        "usage: iicp-node init\n\n\
         Interactive wizard — set up an operator identity and your first node config under\n\
         ~/.iicp/. Takes no flags; run with no arguments to start the wizard.\n\n\
         Options:\n\
         \x20 -h, --help   Print this help (does NOT start the wizard)\n"
    );
}

async fn run_query(args: &[String]) -> Result<(), String> {
    if wants_help(args) {
        print_query_help();
        return Ok(());
    }
    // Collect positional args and flags
    let mut prompt = String::new();
    let mut directory_url =
        env::var("IICP_DIRECTORY_URL").unwrap_or_else(|_| "https://iicp.network/api".to_string());
    let mut intent =
        env::var("IICP_INTENT").unwrap_or_else(|_| "urn:iicp:intent:llm:chat:v1".to_string());
    let mut model: Option<String> = None;
    let mut max_tokens: Option<u32> = None;
    let mut timeout_ms: u64 = 60_000;

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with('-') {
            if i + 1 >= args.len() {
                return Err(format!("flag {a} needs a value"));
            }
            let v = args[i + 1].clone();
            match a.as_str() {
                "--directory-url" => directory_url = v,
                "--intent" => intent = v,
                "--model" => model = Some(v),
                "--max-tokens" => {
                    max_tokens = Some(v.parse().map_err(|e| format!("--max-tokens: {e}"))?)
                }
                "--timeout-ms" => {
                    timeout_ms = v.parse().map_err(|e| format!("--timeout-ms: {e}"))?
                }
                _ => return Err(format!("unknown flag: {a}")),
            }
            i += 2;
        } else {
            if !prompt.is_empty() {
                prompt.push(' ');
            }
            prompt.push_str(a);
            i += 1;
        }
    }

    if prompt.is_empty() {
        return Err("Usage: iicp-node query <prompt> [flags]".to_string());
    }

    let config = ClientConfig {
        directory_url,
        timeout_ms,
        ..Default::default()
    };
    let client = IicpClient::new(config).map_err(|e| format!("client init: {e}"))?;

    let request = TaskRequest {
        task_id: uuid::Uuid::new_v4().to_string(),
        intent: intent.clone(),
        payload: serde_json::json!({
            "messages": [{"role": "user", "content": prompt}]
        }),
        constraints: if model.is_some() || max_tokens.is_some() {
            Some(iicp_client::TaskConstraints {
                timeout_ms: None,
                max_tokens,
                model,
            })
        } else {
            None
        },
        auth: None,
    };

    eprintln!("[iicp-node] Discovering nodes for {}...", intent);
    let resp = client.submit(request).await.map_err(|e| format!("{e}"))?;

    // Spec iicp-dir.md §task response: terminal success status is "success" (was "completed";
    // the node + adapter emit "success"). Accept both so the CLI doesn't reject a successful task.
    if resp.status == "success" || resp.status == "completed" {
        let content = resp
            .result
            .as_ref()
            .and_then(|r| r.get("content").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                serde_json::to_string_pretty(
                    resp.result.as_ref().unwrap_or(&serde_json::Value::Null),
                )
                .unwrap_or_default()
            });
        println!("{content}");
        if let Some(m) = &resp.metrics {
            if let Some(node_id) = &m.node_id {
                eprintln!(
                    "[iicp-node] routed to node {}",
                    &node_id[..8.min(node_id.len())]
                );
            }
            if let Some(ms) = m.latency_ms {
                eprintln!("[iicp-node] latency {ms:.0}ms");
            }
        }
    } else {
        eprintln!("[iicp-node] task status: {}", resp.status);
        return Err(format!("task did not complete (status={})", resp.status));
    }
    Ok(())
}

/// Recursive canonical JSON — byte-identical to the directory's signing form
/// (iicp-directory-rs federation.rs `canonical_json`: recursive key-sort, no whitespace,
/// scalars via serde_json's compact repr which leaves `/` and unicode unescaped). This MUST
/// match exactly or every signature verification fails. (#456 --verify)
fn canonical_json(v: &serde_json::Value) -> String {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(&map[*k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(arr) => {
            format!(
                "[{}]",
                arr.iter().map(canonical_json).collect::<Vec<_>>().join(",")
            )
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// #456 `--verify`: cryptographically confirm this node's CREDIT_AWARD income against the
/// directory's **signed event log** — defends against a lying directory, on top of the
/// tampered-local-file defense the base command already provides. Resolves the directory's
/// Ed25519 key from `/.well-known/did.json`, fetches the signed CREDIT_AWARD events, and
/// re-derives + verifies each signature. Returns `(verified_sum, verified_count, failed_count)`.
async fn verify_credit_awards(
    directory_url: &str,
    node_id: &str,
) -> Result<(f64, u64, u64), String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use sha2::{Digest, Sha256};

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| format!("client: {e}"))?;

    // 1. Resolve the directory signing key from /.well-known/did.json at the ORIGIN
    //    (did.json sits at the host root, not under any /api path).
    let origin = reqwest::Url::parse(directory_url)
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| {
                let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
                format!("{}://{}{}", u.scheme(), h, port)
            })
        })
        .unwrap_or_else(|| {
            directory_url
                .trim_end_matches("/api")
                .trim_end_matches('/')
                .to_string()
        });
    let did: serde_json::Value = client
        .get(format!("{origin}/.well-known/did.json"))
        .send()
        .await
        .map_err(|e| format!("did.json fetch: {e}"))?
        .json()
        .await
        .map_err(|e| format!("did.json parse: {e}"))?;
    let x = did
        .get("verificationMethod")
        .and_then(|v| v.get(0))
        .and_then(|m| m.get("publicKeyJwk"))
        .and_then(|j| j.get("x"))
        .and_then(|s| s.as_str())
        .ok_or("directory did.json has no Ed25519 verification key (publicKeyJwk.x)")?;
    let pub_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| "bad did.json key (base64url)")?;
    let pub_arr: [u8; 32] = pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "did.json key is not 32 bytes")?;
    let vk = VerifyingKey::from_bytes(&pub_arr).map_err(|_| "bad Ed25519 verifying key")?;

    // 2. Fetch + verify the signed CREDIT_AWARD events for this node (paginated by seq).
    let (mut verified_sum, mut verified, mut failed) = (0.0_f64, 0u64, 0u64);
    let mut since: u64 = 0;
    loop {
        let url = format!(
            "{}/v1/events?event_types=CREDIT_AWARD&since_seq={}&limit=500",
            directory_url.trim_end_matches('/'),
            since
        );
        let body: serde_json::Value = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("events fetch: {e}"))?
            .json()
            .await
            .map_err(|e| format!("events parse: {e}"))?;
        let events = body
            .get("events")
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default();
        if events.is_empty() {
            break;
        }
        let mut max_seq = since;
        for e in &events {
            let seq = e.get("seq").and_then(|v| v.as_i64()).unwrap_or(0);
            if seq as u64 > max_seq {
                max_seq = seq as u64;
            }
            if e.get("event_type").and_then(|v| v.as_str()) != Some("CREDIT_AWARD") {
                continue;
            }
            if e.get("node_id").and_then(|v| v.as_str()) != Some(node_id) {
                continue;
            }
            let Some(sig_hex) = e.get("sig").and_then(|v| v.as_str()) else {
                continue;
            };
            let event_id = e.get("event_id").and_then(|v| v.as_str()).unwrap_or("");
            let ts_ms = e.get("ts_ms").and_then(|v| v.as_i64()).unwrap_or(0);
            let payload = e.get("payload").cloned().unwrap_or(serde_json::Value::Null);
            // #458 hash-chain genesis root: SHA256_hex("iicp:dir:event-log:genesis:v1"). The
            // directory serves prev_hash per event; default to this for a genesis/legacy event.
            let prev_hash = e
                .get("prev_hash")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("c44802bedf3e63b5a3f1634c5d19263634f92f26dd15401b09b06dd53a80cf9d");
            // Re-derive the directory's signing message (§3.4 / federation.rs event_message):
            //   sha256( event_id:event_type:seq:ts_ms : sha256_hex(canonical_json(payload)) : prev_hash )
            let payload_hash = hex::encode(Sha256::digest(canonical_json(&payload).as_bytes()));
            let input = format!("{event_id}:CREDIT_AWARD:{seq}:{ts_ms}:{payload_hash}:{prev_hash}");
            let msg = Sha256::digest(input.as_bytes());
            let sig_ok = hex::decode(sig_hex)
                .ok()
                .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
                .map(|arr| {
                    vk.verify(msg.as_slice(), &Signature::from_bytes(&arr))
                        .is_ok()
                })
                .unwrap_or(false);
            if sig_ok {
                verified += 1;
                verified_sum += payload
                    .get("amount")
                    .and_then(|a| a.as_f64())
                    .unwrap_or(0.0);
            } else {
                failed += 1;
            }
        }
        if events.len() < 500 || max_seq <= since {
            break;
        }
        since = max_seq;
    }
    Ok((verified_sum, verified, failed))
}

/// `iicp-node credits [--node NAME] [--token T] [--directory-url U] [--json] [--verify]`
/// — show this node's lifetime earned / spent / balance from the directory's
/// reconcile-checked GET /v1/credits/summary (#456). The displayed figures come from the
/// directory (not the local file), so editing the saved config cannot inflate them; the
/// `reconciles` flag flags a ledger that doesn't add up. `--verify` cryptographically audits
/// each award against the directory's signed CREDIT_AWARD log.
async fn run_credits(args: &[String]) -> Result<(), String> {
    if wants_help(args) {
        print_credits_help();
        return Ok(());
    }
    let mut node_name: Option<String> = None;
    let mut directory_url: Option<String> = None;
    let mut token: Option<String> = env::var("IICP_NODE_TOKEN").ok();
    let mut node_id: Option<String> = None;
    let mut as_json = false;
    let mut verify = false;

    // Value-taking flags — anything else with a leading `-` is an unknown flag (not a
    // "needs a value" error). This keeps `--bogus` honest (item 8).
    const VALUE_FLAGS: &[&str] = &["--node", "--token", "--directory-url", "--node-id"];

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--json" => {
                as_json = true;
                i += 1;
            }
            "--verify" => {
                verify = true;
                i += 1;
            }
            _ if a.starts_with('-') => {
                if !VALUE_FLAGS.contains(&a.as_str()) {
                    return Err(format!("unknown flag: {a}"));
                }
                if i + 1 >= args.len() {
                    return Err(format!("flag {a} needs a value"));
                }
                let v = args[i + 1].clone();
                match a.as_str() {
                    "--node" => node_name = Some(v),
                    "--token" => token = Some(v),
                    "--directory-url" => directory_url = Some(v),
                    "--node-id" => node_id = Some(v),
                    _ => unreachable!("VALUE_FLAGS guard above is exhaustive"),
                }
                i += 2;
            }
            _ => return Err(format!("unexpected argument: {a}")),
        }
    }

    // No-arg UX (item 7): when neither --node nor --node-id was given, fall back to a
    // single saved node (or one named `default`) so a bare `iicp-node credits` works.
    if node_name.is_none() && node_id.is_none() {
        let saved = list_nodes().unwrap_or_default();
        let pick = if saved.len() == 1 {
            Some(saved[0].name.clone())
        } else {
            saved
                .iter()
                .find(|n| n.name == "default")
                .map(|n| n.name.clone())
        };
        match pick {
            Some(name) => {
                eprintln!("[iicp-node] no --node/--node-id given — using saved node '{name}'");
                node_name = Some(name);
            }
            None if !saved.is_empty() => {
                let names: Vec<&str> = saved.iter().map(|n| n.name.as_str()).collect();
                return Err(format!(
                    "node required: pass --node NAME or --node-id ID. Saved nodes: {}",
                    names.join(", ")
                ));
            }
            None => {} // no saved nodes — fall through to the node_id-required error below
        }
    }

    if let Some(ref name) = node_name {
        match load_node(name) {
            Ok(Some(ni)) => {
                directory_url.get_or_insert(ni.directory_url.clone());
                node_id.get_or_insert(ni.node_id.clone());
                if token.is_none() {
                    token = ni.node_token.clone();
                }
            }
            Ok(None) => {
                return Err(format!(
                    "no saved config at ~/.iicp/nodes/{name}.json — run `iicp-node init` / `serve` first"
                ))
            }
            Err(e) => return Err(format!("load node {name}: {e}")),
        }
    }

    let directory_url = directory_url.unwrap_or_else(|| {
        env::var("IICP_DIRECTORY_URL").unwrap_or_else(|_| "https://iicp.network/api".to_string())
    });
    let node_id = node_id.ok_or("node_id required (use --node NAME or --node-id ID)")?;
    let token = token.ok_or(
        "no node_token — run `iicp-node serve` once (it caches the token), or pass --token / $IICP_NODE_TOKEN",
    )?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("client: {e}"))?;

    let url = format!("{}/v1/credits/summary", directory_url.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Node-Id", &node_id)
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("bad response: {e}"))?;

    if !status.is_success() {
        let msg = body
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("request rejected");
        return Err(format!("HTTP {status}: {msg}"));
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&body).unwrap_or_default()
        );
        return Ok(());
    }

    let num = |k: &str| body.get(k).and_then(|v| v.as_f64()).unwrap_or(0.0);
    let earned = num("total_earned");
    let spent = num("total_spent");
    let balance = num("balance");
    let tx = body.get("tx_count").and_then(|v| v.as_u64()).unwrap_or(0);
    let reconciles = body
        .get("reconciles")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let tpc = body
        .get("tokens_per_credit")
        .and_then(|v| v.as_u64())
        .unwrap_or(1000);

    println!(
        "IICP credits — {}",
        node_name.as_deref().unwrap_or(&node_id)
    );
    println!("  Earned (income)   {earned:>12.3}");
    println!("  Spent             {spent:>12.3}");
    println!("  ─────────────────────────────");
    let check = if reconciles {
        "✓ reconciles"
    } else {
        "✗ DOES NOT RECONCILE"
    };
    println!(
        "  Balance           {balance:>12.3}   {check}   (≈ {} tokens)",
        (balance * tpc as f64) as i64
    );
    println!("  {tx} transactions · `iicp-node credits --json` for raw");
    if !reconciles {
        eprintln!(
            "[iicp-node] WARNING: balance != earned − spent — the ledger does not reconcile; do not trust these figures."
        );
    }
    if verify {
        let (vsum, vcount, vfailed) = verify_credit_awards(&directory_url, &node_id).await?;
        println!("  ── cryptographic verification (signed CREDIT_AWARD log) ──");
        if vfailed > 0 {
            eprintln!(
                "[iicp-node] ✗ {vfailed} award event(s) FAILED Ed25519 verification — tampered or \
                 inconsistent event log. Do NOT trust these figures."
            );
            return Err(format!(
                "{vfailed} CREDIT_AWARD signature(s) failed verification"
            ));
        }
        println!(
            "  ✓ {vcount} award(s) cryptographically verified · {vsum:.3} credits (Ed25519, signed by the directory)"
        );
        let free_tier = earned - vsum;
        if free_tier > 0.0001 {
            println!(
                "  · {free_tier:.3} credits are free-tier allocation (directory-granted, not signed task awards)"
            );
        } else if vsum > earned + 0.0001 {
            eprintln!(
                "[iicp-node] WARNING: verified awards ({vsum:.3}) exceed the summary's total_earned ({earned:.3}) — inconsistent; investigate."
            );
        }
    }

    Ok(())
}

fn parse_args(args: &[String]) -> Result<ServeOpts, String> {
    let mut opts = ServeOpts {
        node: env_or("IICP_NODE_NAME", None).unwrap_or_default(),
        // #410 — default EMPTY here so saved-node config (--node) can supply backend_url.
        // The Ollama localhost:11434 fallback is applied AFTER apply_saved_node, giving the
        // correct precedence: flag > env > saved-config > built-in default.
        backend_url: env_or("IICP_BACKEND_URL", None).unwrap_or_default(),
        backend_type: env_or("IICP_BACKEND_TYPE", Some("openai_compat")).unwrap(),
        model: env_or("IICP_BACKEND_MODEL", None).unwrap_or_default(),
        public_endpoint: env_or("IICP_PUBLIC_ENDPOINT", None).unwrap_or_default(),
        directory_url: env_or("IICP_DIRECTORY_URL", Some("https://iicp.network/api")).unwrap(),
        region: env_or("IICP_REGION", Some("")).unwrap(),
        intent: env_or("IICP_INTENT", Some("urn:iicp:intent:llm:chat:v1")).unwrap(),
        max_concurrent: env_int("IICP_MAX_CONCURRENT", 4) as usize,
        node_id: env_or("IICP_NODE_ID", None).unwrap_or_default(),
        port: env_int("IICP_PORT", 9484) as u16,
        host: env_or("IICP_HOST", Some("::")).unwrap(),
        skip_registration: env_bool("IICP_SKIP_REGISTRATION"),
        // Default ON — opt out with IICP_AUTO_DETECT_NAT=false.
        auto_detect_nat: std::env::var("IICP_AUTO_DETECT_NAT")
            .map(|v| v.to_lowercase() != "false" && v.to_lowercase() != "0")
            .unwrap_or(true),
        no_auto_detect_nat: false,
        // Default to api.ipify.org so FRITZ!Box/CGNAT detection works out of the box.
        external_ip_probe_url: env_or("IICP_EXTERNAL_IP_PROBE_URL", None)
            .unwrap_or_else(|| "https://api.ipify.org".to_string()),
        relay_worker_endpoint: env_or("IICP_RELAY_WORKER_ENDPOINT", None).unwrap_or_default(),
        log_dir: env_or("IICP_LOG_DIR", None),
        force: env_bool("IICP_FORCE"),
        backend_api_key: env_or("IICP_BACKEND_API_KEY", Some("")).unwrap(),
        with_proxy: env_bool("IICP_WITH_PROXY"),
    };

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--help" | "-h" => return Err("HELP".into()),
            "--skip-registration" => {
                opts.skip_registration = true;
                i += 1;
            }
            "--force" => {
                opts.force = true;
                i += 1;
            }
            "--with-proxy" => {
                opts.with_proxy = true;
                i += 1;
            }
            "--auto-detect-nat" => {
                opts.auto_detect_nat = true;
                i += 1;
            }
            // Explicit off-switch (parity with Python `--no-auto-detect-nat`). Overrides the
            // env default; also prevents apply_saved_node from re-enabling it (see node_supplied).
            "--no-auto-detect-nat" => {
                opts.auto_detect_nat = false;
                opts.no_auto_detect_nat = true;
                i += 1;
            }
            _ => {
                if i + 1 >= args.len() {
                    return Err(format!("flag {arg} needs a value"));
                }
                let v = args[i + 1].clone();
                match arg.as_str() {
                    "--node" => opts.node = v,
                    "--backend-url" => opts.backend_url = v,
                    "--backend-type" => opts.backend_type = v,
                    "--backend-api-key" => opts.backend_api_key = v,
                    "--model" => opts.model = v,
                    "--public-endpoint" => opts.public_endpoint = v,
                    "--directory-url" => opts.directory_url = v,
                    "--region" => opts.region = v,
                    "--intent" => opts.intent = v,
                    "--max-concurrent" => {
                        opts.max_concurrent =
                            v.parse().map_err(|e| format!("--max-concurrent: {e}"))?;
                    }
                    "--node-id" => opts.node_id = v,
                    "--port" => opts.port = v.parse().map_err(|e| format!("--port: {e}"))?,
                    "--host" => opts.host = v,
                    "--external-ip-probe-url" => opts.external_ip_probe_url = v,
                    "--relay-worker-endpoint" => opts.relay_worker_endpoint = v,
                    "--log-dir" => opts.log_dir = Some(v),
                    _ => return Err(format!("unknown flag: {arg}")),
                }
                i += 2;
            }
        }
    }
    Ok(opts)
}

fn apply_saved_node(opts: &mut ServeOpts, saved: &NodeIdentity) {
    if opts.backend_url.is_empty() {
        opts.backend_url = saved.backend_url.clone();
    }
    if opts.model.is_empty() {
        opts.model = saved.model.clone();
    }
    if opts.public_endpoint.is_empty() {
        opts.public_endpoint = saved.public_endpoint.clone();
    }
    if opts.directory_url == "https://iicp.network/api" {
        opts.directory_url = saved.directory_url.clone();
    }
    if opts.region.is_empty() {
        opts.region = saved.region.clone();
    }
    if opts.intent == "urn:iicp:intent:llm:chat:v1" {
        opts.intent = saved.intent.clone();
    }
    if opts.node_id.is_empty() {
        opts.node_id = saved.node_id.clone();
    }
    if opts.max_concurrent == 4 {
        opts.max_concurrent = saved.max_concurrent as usize;
    }
    if opts.port == 9484 {
        opts.port = saved.port;
    }
    if opts.host == "::" || opts.host == "0.0.0.0" {
        // Both are "default" / all-interfaces — let the saved config win
        if !saved.host.is_empty() && saved.host != "::" && saved.host != "0.0.0.0" {
            opts.host = saved.host.clone();
        }
    }
    // Saved-config may re-enable NAT detection only if the user did not explicitly disable it.
    if !opts.auto_detect_nat && !opts.no_auto_detect_nat {
        opts.auto_detect_nat = saved.auto_detect_nat;
    }
    if opts.external_ip_probe_url.is_empty() {
        opts.external_ip_probe_url = saved.external_ip_probe_url.clone();
    }
}

// ── GAP-6 — probe backend for all available models ─────────────────────────
/// Best-effort: returns all model names from Ollama `/api/tags` or OpenAI `/v1/models`.
/// Empty vec on any error — caller falls back to the single configured model.
async fn probe_backend_models(backend_url: &str, api_key: &str) -> Vec<String> {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    // #409/#5 — an auth-requiring backend (LM Studio, hosted) returns 401 on
    // /v1/models without the Bearer key; attach it so GAP-6 model discovery
    // (and thus multi-intent advertising) works against auth'd backends.
    let auth = |req: reqwest::RequestBuilder| {
        if api_key.is_empty() {
            req
        } else {
            req.bearer_auth(api_key)
        }
    };
    // #409 — strip a trailing `/v1` so both probe URLs are well-formed whether the
    // operator passed `http://host:11434` (Ollama) or `http://host:1234/v1` (LM Studio /
    // OpenAI-compat). Without this, a /v1 backend_url produced `…/v1/api/tags` and
    // `…/v1/v1/models` — both 404 — so no models were discovered and multi-intent (#409)
    // never fired for OpenAI-compat backends.
    let base = backend_url.trim_end_matches('/');
    let root = base.strip_suffix("/v1").unwrap_or(base);
    // Try Ollama /api/tags first
    if let Ok(resp) = auth(client.get(format!("{root}/api/tags"))).send().await {
        if resp.status().is_success() {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                let models: Vec<String> = data["models"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|m| m["name"].as_str().map(str::to_string))
                    .collect();
                if !models.is_empty() {
                    return models;
                }
            }
        }
    }
    // Fallback: OpenAI-compat /v1/models
    if let Ok(resp) = auth(client.get(format!("{root}/v1/models"))).send().await {
        if resp.status().is_success() {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                let models: Vec<String> = data["data"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|m| m["id"].as_str().map(str::to_string))
                    .collect();
                return models;
            }
        }
    }
    vec![]
}

/// Detect the backend server flavor for the `backend` node-detail field:
/// `ollama` / `lmstudio` / `vllm` / `llamacpp` / `anthropic` / `custom`. For the
/// non-OpenAI dialects the configured `backend_type` is authoritative; for
/// `openai_compat` it probes distinguishing endpoints/headers (best-effort —
/// Ollama's proprietary `/api/version`, then `/v1/models` Server / X-Powered-By),
/// defaulting to `custom` for an unrecognised OpenAI-compatible server.
async fn detect_backend_flavor(backend_url: &str, api_key: &str, backend_type: &str) -> String {
    match backend_type {
        "anthropic" => return "anthropic".into(),
        "vllm" => return "vllm".into(),
        "llamacpp" => return "llamacpp".into(),
        _ => {}
    }
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return "custom".into(),
    };
    let auth = |req: reqwest::RequestBuilder| {
        if api_key.is_empty() {
            req
        } else {
            req.bearer_auth(api_key)
        }
    };
    let base = backend_url.trim_end_matches('/');
    let root = base.strip_suffix("/v1").unwrap_or(base);
    // Fingerprint by /v1/models response headers FIRST. Order matters: LM Studio
    // also implements Ollama-compatible /api/version + /api/tags, so /api/version
    // is NOT an Ollama discriminator — but LM Studio always stamps
    // `X-Powered-By: Express`, which Ollama never sets.
    if let Ok(r) = auth(client.get(format!("{root}/v1/models"))).send().await {
        if r.status().is_success() {
            let h = r.headers();
            let server = h
                .get("server")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();
            let powered = h
                .get("x-powered-by")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();
            if powered.contains("express") {
                return "lmstudio".into(); // LM Studio serves via Express
            }
            if server.contains("vllm") || server.contains("uvicorn") {
                return "vllm".into(); // vLLM runs on uvicorn
            }
            if server.contains("llama.cpp") || server.contains("llama-server") {
                return "llamacpp".into();
            }
            // No Express / uvicorn / llama header → real Ollama exposes /api/version.
            if let Ok(rv) = auth(client.get(format!("{root}/api/version"))).send().await {
                if rv.status().is_success() {
                    return "ollama".into();
                }
            }
            return "custom".into();
        }
    }
    // No /v1/models (older Ollama) — fall back to the proprietary endpoint.
    if let Ok(rv) = auth(client.get(format!("{root}/api/version"))).send().await {
        if rv.status().is_success() {
            return "ollama".into();
        }
    }
    "custom".into()
}

// ── #346 — dependency checker (no auto-install on Rust — cargo would need a rebuild) ─

struct DepIssue {
    name: String,
    // "ok"       — present / compiled in
    // "optional" — opt-in capability not compiled; node runs fine without it
    // "warn"     — degraded runtime state (backend unreachable, no IPv6)
    // "missing"  — required dependency absent
    severity: &'static str,
    message: String,
}

async fn check_dependencies(backend_url: &str) -> Vec<DepIssue> {
    let mut out: Vec<DepIssue> = Vec::new();

    // Backend reachability
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            out.push(DepIssue {
                name: "backend".into(),
                severity: "warn",
                message: "could not build HTTP client".into(),
            });
            return out;
        }
    };
    let probe_url = format!("{}/api/tags", backend_url.trim_end_matches('/'));
    match client.get(&probe_url).send().await {
        Ok(r) if r.status().is_success() => out.push(DepIssue {
            name: "backend".into(),
            severity: "ok",
            message: format!("reachable at {backend_url}"),
        }),
        Ok(r) => out.push(DepIssue {
            name: "backend".into(),
            severity: "warn",
            message: format!("backend HTTP {}", r.status()),
        }),
        Err(e) => out.push(DepIssue {
            name: "backend".into(),
            severity: "warn",
            message: format!("{backend_url} unreachable: {e}"),
        }),
    }

    // Feature flag advisory — Rust deps are compile-time, so "ok" means "feature compiled in".
    #[cfg(feature = "nat")]
    out.push(DepIssue {
        name: "nat".into(),
        severity: "ok",
        message: "feature nat compiled in (UPnP + IPv6 pinhole)".into(),
    });
    #[cfg(not(feature = "nat"))]
    out.push(DepIssue {
        name: "nat".into(),
        severity: "optional",
        message: "UPnP/IPv6 NAT detection off (optional — set a public endpoint manually, or enable with --features nat)".into(),
    });

    #[cfg(feature = "iicp-tcp")]
    out.push(DepIssue {
        name: "iicp-tcp".into(),
        severity: "ok",
        message: "feature iicp-tcp compiled in (native TCP transport)".into(),
    });
    #[cfg(not(feature = "iicp-tcp"))]
    out.push(DepIssue {
        name: "iicp-tcp".into(),
        severity: "optional",
        message: "native IICP-TCP transport off (optional — HTTP transport active; enable with --features iicp-tcp)".into(),
    });

    #[cfg(feature = "metrics")]
    out.push(DepIssue {
        name: "metrics".into(),
        severity: "ok",
        message: "feature metrics compiled in (/metrics endpoint)".into(),
    });
    #[cfg(not(feature = "metrics"))]
    out.push(DepIssue {
        name: "metrics".into(),
        severity: "optional",
        message: "Prometheus /metrics endpoint off (optional — enable with --features metrics)"
            .into(),
    });

    // IPv6 routing surface (advisory)
    #[cfg(feature = "nat")]
    {
        let v6 = iicp_client::nat_detection::detect_ipv6(0, Duration::from_millis(1500)).await;
        if v6.global_v6_available {
            let mut msg = format!("{} global IPv6 address(es)", v6.addresses.len());
            if v6.external_v6_reachable {
                msg.push_str("; outbound v6 reachable");
            }
            out.push(DepIssue {
                name: "ipv6".into(),
                severity: "ok",
                message: msg,
            });
        } else {
            out.push(DepIssue {
                name: "ipv6".into(),
                severity: "warn",
                message: "no global IPv6 — direct hosting will require IPv4 + tunnel".into(),
            });
        }
    }

    out
}

fn print_dep_status(issues: &[DepIssue]) {
    for i in issues {
        let glyph = match i.severity {
            "ok" => "  ✓",
            "optional" => "  ○",
            "warn" => "  !",
            "missing" => "  ✗",
            _ => "  ?",
        };
        println!("{glyph} {:<18}  {}", i.name, i.message);
    }
}

fn ask(prompt: &str, fallback: &str) -> String {
    let suffix = if fallback.is_empty() {
        String::new()
    } else {
        format!(" [{fallback}]")
    };
    print!("{prompt}{suffix}: ");
    let _ = io::stdout().flush();
    let stdin = io::stdin();
    let line = stdin.lock().lines().next();
    match line {
        Some(Ok(s)) => {
            let t = s.trim();
            if t.is_empty() {
                fallback.to_string()
            } else {
                t.to_string()
            }
        }
        _ => fallback.to_string(),
    }
}

async fn run_init(args: &[String]) -> Result<(), String> {
    // Short-circuit `-h`/`--help` BEFORE touching ~/.iicp or prompting — otherwise
    // `iicp-node init --help` would launch the wizard and prompt to overwrite configs.
    if wants_help(args) {
        print_init_help();
        return Ok(());
    }
    println!("iicp-node init — IICP Rust SDK");
    let dir = config_dir().map_err(|e| e.to_string())?;
    println!("Config dir: {}", dir.display());
    println!();

    // Operator
    let op = match load_operator().map_err(|e| e.to_string())? {
        Some(existing) => {
            println!(
                "Found existing operator: {} (created {})",
                existing.operator_id, existing.created_at
            );
            existing
        }
        None => {
            println!("No operator identity yet — creating one.");
            let display = ask("Display name (optional)", "");
            let contact = ask("Contact email or @handle (optional)", "");
            let op = OperatorIdentity::generate(&display, &contact);
            let p = save_operator(&op).map_err(|e| e.to_string())?;
            println!("  ✓ saved {}", p.display());
            op
        }
    };
    println!();

    // Node
    let name = ask("Node name (used as filename stem, lowercase)", "default");
    if let Ok(Some(_)) = load_node(&name) {
        print!("  ! ~/.iicp/nodes/{name}.json already exists. ");
        let yn = ask("Overwrite? [y/N]", "n").to_lowercase();
        if yn != "y" && yn != "yes" {
            return Ok(());
        }
    }
    let backend = ask(
        "Backend URL (Ollama / vLLM / LM Studio)",
        "http://localhost:11434",
    );
    let model = ask("Backend model", "qwen2.5:0.5b");
    let directory = ask("IICP directory URL", "https://iicp.network/api");
    let region = ask("Region tag (e.g. us-east; blank = unknown)", "unknown");
    let intent = ask("Intent URN", "urn:iicp:intent:llm:chat:v1");
    let port_s = ask("Listen port", "9484");
    let port: u16 = port_s.parse().unwrap_or(9484);
    let host = ask("Bind host", "0.0.0.0");
    let public_endpoint = ask("Public endpoint URL (blank = dev mode)", "");
    let auto_detect_nat = matches!(
        ask("Auto-detect NAT via UPnP/STUN? [y/N]", "n")
            .to_lowercase()
            .as_str(),
        "y" | "yes"
    );
    let external_ip_probe_url = if auto_detect_nat {
        ask(
            "External IPv4 probe URL (optional fallback)",
            "https://api.ipify.org",
        )
    } else {
        String::new()
    };

    let node = generate_node(
        &op.operator_id,
        &name,
        &backend,
        &model,
        &intent,
        &region,
        &directory,
        port,
        &host,
        &public_endpoint,
        auto_detect_nat,
        &external_ip_probe_url,
    )
    .map_err(|e| e.to_string())?;
    let p = save_node(&node).map_err(|e| e.to_string())?;
    println!();
    println!("  ✓ saved {}  (node_id={})", p.display(), node.node_id);
    println!();

    // Dependency check (#346 parity — Rust prints status; no in-place install)
    println!("Checking dependencies …");
    let issues = check_dependencies(&backend).await;
    print_dep_status(&issues);
    let required_missing = issues.iter().any(|i| i.severity == "missing");
    let optional_off = issues.iter().any(|i| i.severity == "optional");
    if required_missing {
        println!();
        println!("  ✗ a required dependency is missing — see above before serving.");
    } else if optional_off {
        println!();
        println!("  ○ optional features above are off — your node runs fine without them.");
        println!("    To enable all of them, reinstall with:");
        println!("    cargo install iicp-client --features \"nat iicp-tcp metrics\"");
    }

    println!();
    println!("Documentation:");
    println!("  Docs:       https://iicp.network/docs/sdk-quickstart-docker");
    println!("  Reference:  iicp-node --help");
    println!("  Spec:       https://iicp.network/spec");
    println!();
    println!("Run: iicp-node serve --node {name}");
    Ok(())
}

fn run_list() -> Result<(), String> {
    let nodes = list_nodes().map_err(|e| e.to_string())?;
    if nodes.is_empty() {
        println!("No saved node configs. Run `iicp-node init` first.");
        return Ok(());
    }
    let dir = config_dir().map_err(|e| e.to_string())?;
    println!("Saved nodes ({}/nodes):", dir.display());
    for n in &nodes {
        let endpoint = if n.public_endpoint.is_empty() {
            "(dev)".to_string()
        } else {
            n.public_endpoint.clone()
        };
        println!("  - {:<20}  {:<24}  {}", n.name, n.model, endpoint);
    }
    Ok(())
}

async fn run_serve(mut opts: ServeOpts) -> Result<(), String> {
    // CIP toggle via env var — safe-off default; operators advertise as a
    // CIP worker by setting IICP_CIP_ALLOW_WORKER=true. Matches the same
    // env hook in the Python + TypeScript SDKs.
    if env_bool("IICP_CIP_ALLOW_WORKER") {
        use iicp_client::cip_policy::{configure_cip_policy, CooperativeInferencePolicyOptions};
        configure_cip_policy(CooperativeInferencePolicyOptions {
            enabled: true,
            allow_worker: true,
            allow_coordinator: true,
            ..Default::default()
        });
    }

    // ADR-050 2-C: co-host the compat proxy on loopback alongside the node, supervised
    // so a proxy failure logs but never drops the network-facing node. Forced to 127.0.0.1.
    if opts.with_proxy {
        #[cfg(feature = "proxy")]
        {
            let pport: u16 = std::env::var("IICP_PROXY_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(9483);
            let dir = opts.directory_url.clone();
            let region = if opts.region.is_empty() {
                None
            } else {
                Some(opts.region.clone())
            };
            println!("co-hosted proxy → http://127.0.0.1:{pport} (OpenAI/Ollama/Anthropic compat)");
            tokio::spawn(async move {
                if let Err(e) = iicp_client::proxy::run_proxy(iicp_client::proxy::ProxyConfig {
                    host: "127.0.0.1".to_string(),
                    port: pport,
                    directory_url: Some(dir),
                    region,
                })
                .await
                {
                    eprintln!("[iicp-node] co-hosted proxy error (node continues): {e}");
                }
            });
        }
        #[cfg(not(feature = "proxy"))]
        eprintln!(
            "[iicp-node] --with-proxy ignored: built without the proxy gateway. \
             Reinstall with: cargo install iicp-client --features proxy"
        );
    }

    // Did the operator name a saved node? (--node, or IICP_NODE_NAME env). Captured before
    // apply_saved_node so the model-required guard below can tell "load from disk" apart from
    // "serve a one-off node from flags".
    let node_supplied = !opts.node.is_empty();

    // Load persisted node config if --node was provided.
    if node_supplied {
        match load_node(&opts.node).map_err(|e| e.to_string())? {
            Some(saved) => apply_saved_node(&mut opts, &saved),
            None => {
                return Err(format!(
                    "no saved config at ~/.iicp/nodes/{}.json. Run `iicp-node init` first.",
                    opts.node
                ));
            }
        }
    }

    // #410 — built-in fallback applied LAST (after flag/env/saved-config), so the default
    // never shadows a saved-node backend_url. #414/C1 (parity with Python) — an `anthropic`
    // backend defaults to the Anthropic API, not localhost Ollama.
    if opts.backend_url.is_empty() {
        opts.backend_url = if opts.backend_type == "anthropic" {
            "https://api.anthropic.com".to_string()
        } else {
            "http://localhost:11434".to_string()
        };
    }

    // Onboarding: if no --model given, auto-select the first model the backend advertises
    // (Ollama /api/tags or OpenAI /v1/models) so a bare `iicp-node serve` just works.
    if opts.model.is_empty() && !opts.backend_url.is_empty() {
        let models = probe_backend_models(&opts.backend_url, &opts.backend_api_key).await;
        if let Some(first) = models.first() {
            eprintln!(
                "[iicp-node] no --model given — auto-selected '{first}' from backend {}",
                opts.backend_url
            );
            opts.model = first.clone();
        }
    }
    // A node MUST serve a concrete model. If we still have none and the operator didn't load
    // a saved node, fail with a clear, actionable message rather than serving an empty model.
    if opts.model.is_empty() {
        if node_supplied {
            return Err(format!(
                "saved node '{}' has no model set, and the backend {} advertised none. Set --model NAME or re-run `iicp-node init`.",
                opts.node, opts.backend_url
            ));
        }
        return Err(format!(
            "--model NAME or --node NAME required: no model given and backend {} advertised none. \
             Pass --model NAME, load a saved node with --node NAME, or check the backend is running \
             (e.g. `ollama pull qwen2.5:0.5b`).",
            opts.backend_url
        ));
    }
    if opts.backend_url.is_empty() {
        return Err("backend URL is empty — pass --backend-url URL or $IICP_BACKEND_URL".into());
    }
    if !BACKEND_TYPES.contains(&opts.backend_type.as_str()) {
        return Err(format!("--backend-type must be one of {BACKEND_TYPES:?}"));
    }

    if opts.node_id.is_empty() {
        opts.node_id = uuid::Uuid::new_v4().to_string();
    }
    // Directory column is CHAR(36) — truncate custom names to 36 chars.
    opts.node_id.truncate(36);

    // #405 — single-instance lock: refuse a second LIVE process for this node_id
    // (the token-rotation war). Distinct node_ids are unaffected. Held for the
    // serve lifetime; the pidfile is removed on shutdown (Drop). Fails open.
    let _instance_lock =
        match iicp_client::instance_lock::InstanceLock::acquire(&opts.node_id, opts.force) {
            Ok(lock) => lock,
            Err(e) => {
                eprintln!("[iicp-node] {e}");
                return Err(e);
            }
        };

    // Resolve the actual listen port before NAT detection: start at the
    // requested port (default 9484, the official IICP port) and auto-increment
    // to the next free port. Keeps one port per node (multiple models share it)
    // while N nodes on one host each get a distinct port → distinct pinhole.
    // Skipped when the operator supplies an explicit --public-endpoint.
    if opts.public_endpoint.is_empty() {
        let resolved_port = find_available_port(&opts.host, opts.port, 64);
        if resolved_port != opts.port {
            eprintln!(
                "[iicp-node] port {} in use — auto-incremented to first free port {}.",
                opts.port, resolved_port
            );
            opts.port = resolved_port;
        }
        opts.public_endpoint = format!("http://localhost:{}", opts.port);
    }

    // ADR-043 §5 / #343 — Tier-0 IPv6 pinhole attempt. Runs unconditionally
    // when the operator's public_endpoint is bracketed-IPv6 (even without
    // --auto-detect-nat). Mirrors Python + TS cli paths.
    #[cfg(feature = "nat")]
    let tier0_pinhole = if !opts.auto_detect_nat && opts.public_endpoint.contains('[') {
        let r = iicp_client::nat_detection::try_open_v6_pinhole_for_endpoint(
            &opts.public_endpoint,
            opts.port,
        )
        .await;
        for line in &r.detection_log {
            eprintln!("[iicp-node] v6: {line}");
        }
        if let Some(new_ep) = &r.rewritten_endpoint {
            opts.public_endpoint = new_ep.clone();
        }
        Some(r)
    } else {
        None
    };
    #[cfg(not(feature = "nat"))]
    let _tier0_pinhole: Option<()> = None;

    // GAP-6: probe backend for all available models so the directory registration
    // advertises the full model list — not just the single configured model.
    let discovered_models = probe_backend_models(&opts.backend_url, &opts.backend_api_key).await;

    let mut cfg = NodeConfig::new(&opts.node_id, &opts.public_endpoint, &opts.intent);
    cfg.model = Some(opts.model.clone());
    // Detect the backend server flavor (ollama/lmstudio/vllm/llamacpp/anthropic/custom)
    // so it surfaces in the directory node detail.
    let backend_flavor =
        detect_backend_flavor(&opts.backend_url, &opts.backend_api_key, &opts.backend_type).await;
    eprintln!("[iicp-node] backend detected: {backend_flavor}");
    cfg.backend = Some(backend_flavor);
    cfg.region = if opts.region.is_empty() {
        None
    } else {
        Some(opts.region.clone())
    };
    cfg.directory_url = opts.directory_url.clone();
    cfg.max_concurrent = opts.max_concurrent;
    if !opts.relay_worker_endpoint.is_empty() {
        cfg.relay_worker_endpoint = Some(opts.relay_worker_endpoint.clone());
    }
    // #463/#464 — bind the operator identity: issue a delegation FROM the (key-backed) operator
    // identity for this node and advertise the public display_name. The directory verifies the
    // delegation (operator_pub == operator_id) and records the operator. Never sends secret/contact.
    if let Ok(Some(op)) = load_operator() {
        if op.is_key_backed() {
            if let Ok(sk) = op.signing_key() {
                let token = iicp_client::delegation::issue_delegation(&sk, &opts.node_id, 3600);
                cfg.operator_delegation = serde_json::to_value(&token).ok();
                cfg.operator_display_name = if op.display_name.is_empty() {
                    None
                } else {
                    Some(op.display_name.clone())
                };
                cfg.operator_created_at = Some(op.created_at.clone());
                cfg.operator_integrity_hash = if op.operator_integrity_hash.is_empty() {
                    None
                } else {
                    Some(op.operator_integrity_hash.clone())
                };
            }
        }
    }
    // Resolve log directory: CLI flag > IICP_LOG_DIR > ~/.iicp/logs/
    cfg.log_dir = Some({
        let raw = opts.log_dir.clone().unwrap_or_else(|| {
            config_dir()
                .map(|d| d.join("logs").to_string_lossy().into_owned())
                .unwrap_or_else(|_| ".iicp/logs".to_string())
        });
        std::path::PathBuf::from(raw)
    });
    // Populate additional models; register() merges capabilities into models array.
    cfg.capabilities = discovered_models
        .into_iter()
        .filter(|m| m != &opts.model)
        .collect();
    if !cfg.capabilities.is_empty() {
        eprintln!(
            "[iicp-node] GAP-6: advertising {} additional model(s): {:?}",
            cfg.capabilities.len(),
            &cfg.capabilities[..cfg.capabilities.len().min(6)],
        );
    }
    // Surface Tier-0 declaration so the directory accepts public_reachable=true
    // without dial-back. Mirrors the apply_nat_profile path used after
    // detect_nat — but without running the full v4 UPnP escalation.
    #[cfg(feature = "nat")]
    if tier0_pinhole.is_some() && !opts.auto_detect_nat {
        cfg.transport_method = Some("direct".to_string());
        cfg.nat_type = Some("unknown".to_string());
        cfg.transport_metadata = Some(serde_json::json!({
            "tier": 0,
            "detection_log_tail": tier0_pinhole
                .as_ref()
                .and_then(|p| p.detection_log.last())
                .cloned(),
        }));
    }
    // Capture before cfg is consumed by IicpNode::new.
    let resolved_log_dir = cfg.log_dir.clone();
    #[cfg_attr(not(feature = "nat"), allow(unused_mut))]
    let mut node = IicpNode::new(cfg);

    // Open node log (best-effort — log failure never blocks serve).
    let node_log: Option<std::sync::Arc<iicp_client::node_log::NodeLog>> =
        resolved_log_dir.as_deref().and_then(|d| {
            iicp_client::node_log::NodeLog::open(d, &opts.node_id)
                .map(std::sync::Arc::new)
                .ok()
        });

    // If a v6 pinhole was opened, register the UID with the node so
    // graceful shutdown revokes it.
    #[cfg(feature = "nat")]
    if let Some(r) = &tier0_pinhole {
        if r.pinhole_active {
            // Synthesize a minimal NatProfile so apply_nat_profile picks up
            // the pinhole UID into IicpNode::pinhole_uid.
            let mut synth = iicp_client::nat_detection::NatProfile {
                tier: 0,
                transport_method: iicp_client::nat_detection::TransportMethod::Direct,
                public_endpoint: Some(opts.public_endpoint.clone()),
                transport_endpoint: None,
                internal_endpoint: None,
                operator_guidance: None,
                detection_log: r.detection_log.clone(),
                ipv6: Some(iicp_client::nat_detection::Ipv6Profile {
                    pinhole_active: true,
                    pinhole_unique_id: r.pinhole_unique_id,
                    pinhole_lease_seconds: r.pinhole_lease_seconds,
                    pinhole_inbound_allowed: r.pinhole_inbound_allowed,
                    ..Default::default()
                }),
            };
            // apply_nat_profile expects a full profile; we don't want it to
            // overwrite transport_method already set above. Patch only the
            // pinhole UID tracking path.
            node.apply_nat_profile(&synth);
            let _ = &mut synth;
        }
    }

    // ADR-041 / #343 — optional NAT auto-detection prior to register.
    // When tier≥3 (CGNAT + no IPv6 path) and no relay configured, auto-elect
    // a relay from the directory so the node can register via relay.
    #[cfg(not(feature = "nat"))]
    if opts.auto_detect_nat {
        eprintln!(
            "[iicp-node] WARNING: --auto-detect-nat requested but this binary was compiled \
             without the 'nat' feature (UPnP/IPv6 pinhole support).\n\
             Reinstall with: cargo install iicp-client --features nat\n\
             NAT detection will be skipped."
        );
    }
    #[cfg(feature = "nat")]
    if opts.auto_detect_nat {
        let detect_opts = iicp_client::nat_detection::DetectNatOptions {
            bind_host: opts.host.clone(),
            bind_port: opts.port,
            operator_public_endpoint: if opts.public_endpoint.is_empty() {
                None
            } else {
                Some(opts.public_endpoint.clone())
            },
            external_ip_probe_url: if opts.external_ip_probe_url.is_empty() {
                None
            } else {
                Some(opts.external_ip_probe_url.clone())
            },
            ..Default::default()
        };
        let profile = iicp_client::nat_detection::detect_nat(detect_opts).await;
        let v6_pin = profile
            .ipv6
            .as_ref()
            .map(|v| v.pinhole_active)
            .unwrap_or(false);
        eprintln!(
            "[iicp-node] NAT auto-detect: tier={} method={:?} public={} ipv6_pinhole={}",
            profile.tier,
            profile.transport_method,
            profile.public_endpoint.as_deref().unwrap_or("<none>"),
            v6_pin
        );
        if profile.tier >= 3 && !profile.detection_log.is_empty() {
            eprintln!("[iicp-node] NAT detection log:");
            for line in &profile.detection_log {
                eprintln!("[iicp-node]   {line}");
            }
        }
        if let Some(guidance) = &profile.operator_guidance {
            eprintln!("[iicp-node] NAT guidance: {guidance}");
        }
        node.apply_nat_profile(&profile);

        // Propagate detected public endpoint back to opts so the NAT-4 guard
        // (which checks opts.public_endpoint) sees the real reachable URL.
        if let Some(ep) = &profile.public_endpoint {
            opts.public_endpoint = ep.clone();
        }

        // Tier ≥ 3 (CGNAT + no usable IPv6 path) and no relay configured:
        // auto-elect relay from the directory.
        if profile.tier >= 3 && opts.relay_worker_endpoint.is_empty() {
            eprintln!(
                "[iicp-node] NAT tier={}: auto-electing relay from directory…",
                profile.tier
            );
            if let Some((relay_host, relay_port)) =
                auto_elect_relay(&opts.directory_url, &opts.intent, &opts.node_id).await
            {
                opts.relay_worker_endpoint = format!("{relay_host}:{relay_port}");
                node.set_relay_worker_endpoint(opts.relay_worker_endpoint.clone());
                eprintln!(
                    "[iicp-node] auto-elected relay: {}:{}",
                    relay_host, relay_port
                );
            } else {
                eprintln!(
                    "[iicp-node] NAT tier={}: no relay-capable peers in directory. \
                     Set IICP_RELAY_WORKER_ENDPOINT=<host>:<port> to specify a relay manually.",
                    profile.tier
                );
            }
        }
    }

    let backend_url = opts.backend_url.clone();
    let model = opts.model.clone();
    // Normalize to the OpenAI-dialect root: the handler appends /chat/completions,
    // so base_url MUST end in /v1 (Ollama serves the OpenAI dialect at /v1). An
    // operator naturally passes --backend-url http://host:11434 (matching the
    // /api/tags probe URL), so append /v1 if absent. Mirrors the Python CLI; the
    // raw backend_url is kept for probe_backend_models (which queries /api/tags).
    let base_url = {
        let t = backend_url.trim_end_matches('/');
        if t.ends_with("/v1") {
            t.to_string()
        } else {
            format!("{t}/v1")
        }
    };
    let openai_opts = OpenAiCompatOptions {
        base_url,
        model: Some(model.clone()),
        // #5 — backend auth: LM Studio / hosted OpenAI-compat endpoints require a
        // Bearer key. Empty → no Authorization header (local Ollama/vLLM).
        api_key: Some(opts.backend_api_key.clone()).filter(|k| !k.is_empty()),
        timeout: Duration::from_secs(60),
    };

    // NAT-4 guard: if the endpoint is non-routable (localhost/private) and no relay
    // is configured, registration will always fail with 422. Skip it early and print
    // a clear diagnostic instead of a confusing "422 Unprocessable Entity" error.
    let endpoint_is_local = {
        let ep = opts.public_endpoint.to_lowercase();
        ep.contains("localhost")
            || ep.contains("127.")
            || ep.contains("0.0.0.0")
            || ep.contains("192.168.")
            || ep.contains("10.")
    };
    if endpoint_is_local && opts.relay_worker_endpoint.is_empty() && !opts.skip_registration {
        eprintln!(
            "[iicp-node] no routable endpoint detected and no relay configured — \
             skipping directory registration. This node will accept direct connections \
             on {}:{} but will not appear in discover results. \
             To register: set IICP_PUBLIC_ENDPOINT=<your-public-url> or \
             IICP_RELAY_WORKER_ENDPOINT=<relay-host>:<port>.",
            opts.host, opts.port
        );
        opts.skip_registration = true;
    }

    // BUG-6 fix: probe-bind the port before registering so a port conflict fails
    // immediately without leaving a stale directory registration.
    // The probe listener is dropped right away; serve() re-binds milliseconds later.
    if !opts.skip_registration {
        let probe_addr = fmt_bind_addr(&opts.host, opts.port)
            .parse::<std::net::SocketAddr>()
            .map_err(|e| format!("invalid listen address: {e}"))?;
        std::net::TcpListener::bind(probe_addr).map_err(|e| {
            format!(
                "cannot bind {}:{} — {e}  \
                 (fix: choose a free port with --port N or free the occupied port first)",
                opts.host, opts.port
            )
        })?;
        // probe listener dropped here; port is immediately available for serve()
    }

    // #457 / ADR-040 — advertise the native IICP binary transport. serve() multiplexes it
    // onto the SAME socket as HTTP (first-byte detection), so transport_endpoint shares the
    // endpoint's host:port with the iicp:// scheme. Derived from the FINAL endpoint (after NAT
    // detection); only sent when registering (skip_registration gates the non-routable case)
    // → advertise-when-reachable. Opt out with IICP_DISABLE_NATIVE_TRANSPORT=1.
    if !opts.skip_registration
        && std::env::var("IICP_DISABLE_NATIVE_TRANSPORT").as_deref() != Ok("1")
    {
        if let Some(tep) = iicp_client::node::derive_native_endpoint(&opts.public_endpoint) {
            node.set_transport_endpoint(tep);
        }
    }

    // #404 — register with bounded backoff retry. On persistent failure, still
    // start the heartbeat loop with an empty token: its first heartbeat 401s and
    // the #399 re-register path recovers once the directory is reachable. This is
    // the self-healing watchdog — the node never ends up running un-registered
    // with no heartbeat (the old "continuing without heartbeat" dead end).
    let token = if opts.skip_registration {
        None
    } else {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match node.register().await {
                Ok(t) => {
                    eprintln!(
                        "[iicp-node] registered as {} (token={}…)",
                        opts.node_id,
                        t.chars().take(8).collect::<String>()
                    );
                    if let Some(ref log) = node_log {
                        log.write(
                            "register_ok",
                            &opts.node_id,
                            &format!("endpoint={}", opts.public_endpoint),
                        );
                    }
                    // #456 — cache the token in the saved config so `iicp-node credits`
                    // can authenticate later without re-registering (best-effort).
                    if !opts.node.is_empty() {
                        if let Ok(Some(mut ni)) = load_node(&opts.node) {
                            ni.node_token = Some(t.clone());
                            let _ = save_node(&ni);
                        }
                    }
                    break Some(t);
                }
                Err(e) if attempt >= 3 => {
                    eprintln!(
                        "[iicp-node] registration failed after {attempt} attempts: {e} — \
                         starting heartbeat loop anyway; it will re-register on the first 401"
                    );
                    if let Some(ref log) = node_log {
                        log.write(
                            "register_fail",
                            &opts.node_id,
                            &format!("error={e} attempts={attempt}"),
                        );
                    }
                    break Some(String::new()); // empty token → #399 re-register self-heals
                }
                Err(e) => {
                    let backoff = std::time::Duration::from_secs(2u64.pow(attempt));
                    eprintln!(
                        "[iicp-node] registration attempt {attempt} failed: {e} — retrying in {}s",
                        backoff.as_secs()
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    };

    eprintln!(
        "[iicp-node] serving {} on {}:{} — backend {} (model={}, max_concurrent={})",
        opts.intent, opts.host, opts.port, opts.backend_url, opts.model, opts.max_concurrent
    );
    if let Some(ref log) = node_log {
        log.write(
            "serve_start",
            &opts.node_id,
            &format!(
                "port={} model={} intent={}",
                opts.port, opts.model, opts.intent
            ),
        );
    }

    let opts_handler = openai_opts.clone();
    let backend_type = opts.backend_type.clone();
    let bind = fmt_bind_addr(&opts.host, opts.port);
    let token_for_serve = token.clone();
    let serve_result = tokio::select! {
        r = node.serve(
            move |req| {
                let opts_handler = opts_handler.clone();
                let backend_type = backend_type.clone();
                async move {
                    // backend_type is validated before serve(); fall back to the
                    // openai_compat result shape if it were ever unknown.
                    let v = invoke_backend(&backend_type, &opts_handler, &req.intent, &req.payload)
                        .await
                        .unwrap_or_else(|e| serde_json::json!({
                            "error_code": 500,
                            "error_message": e,
                        }));
                    // Unwrap the backend's {"result": ...} envelope: serve() re-wraps the
                    // handler's value in TaskResponse.result, so returning the inner value
                    // keeps the serve response single-level — matching the Python/TS SDKs
                    // (cross-flavour interop). Error envelopes pass through unchanged.
                    Ok(v.get("result").cloned().unwrap_or(v))
                }
            },
            &bind,
            token_for_serve,
        ) => r.map_err(|e| e.to_string()),
        _ = tokio::signal::ctrl_c() => {
            eprintln!("[iicp-node] SIGINT received — shutting down");
            Ok(())
        }
    };

    // #343 — revoke pinhole + deregister on the way out, best-effort.
    #[cfg(feature = "nat")]
    {
        let _ = node.revoke_pinhole().await;
    }
    if let Some(t) = &token {
        match node.deregister(Some(t)).await {
            Ok(()) => {
                if let Some(ref log) = node_log {
                    log.write("deregister_ok", &opts.node_id, "");
                }
            }
            Err(e) => {
                eprintln!("[iicp-node] deregister failed: {e}");
                if let Some(ref log) = node_log {
                    log.write("deregister_fail", &opts.node_id, &format!("error={e}"));
                }
            }
        }
    }

    serve_result
}

/// Query the directory for relay-capable peers and elect one deterministically.
/// Used when NAT detection returns tier≥3 (CGNAT + no usable IPv6 path).
/// Returns (relay_host, relay_port) or None if no relay-capable peer is found.
/// Only called from the nat-gated tier≥3 path, so gate the definition too —
/// otherwise it is dead code in default-feature builds (CI clippy -D warnings).
#[cfg(feature = "nat")]
async fn auto_elect_relay(
    directory_url: &str,
    intent: &str,
    node_id: &str,
) -> Option<(String, u16)> {
    use sha2::{Digest, Sha256};
    let url = format!(
        "{}/v1/discover?intent={}&relay_capable=true",
        directory_url.trim_end_matches('/'),
        urlencoding_simple(intent)
    );
    let client = reqwest::Client::new();
    let Ok(resp) = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    else {
        return None;
    };
    if !resp.status().is_success() {
        return None;
    }
    let Ok(data) = resp.json::<serde_json::Value>().await else {
        return None;
    };
    let candidates: Vec<&serde_json::Value> = data
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|n| {
                    n.get("relay_capable")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                        && n.get("endpoint")
                            .and_then(|v| v.as_str())
                            .is_some_and(|s| !s.is_empty())
                })
                .collect()
        })
        .unwrap_or_default();
    if candidates.is_empty() {
        return None;
    }
    let score = |node: &&serde_json::Value| -> (u64, String) {
        let load = node.get("load").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let nid = node.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
        let hash_input = format!("{node_id}:{nid}");
        let mut hasher = Sha256::new();
        hasher.update(hash_input.as_bytes());
        let hash_hex = format!("{:x}", hasher.finalize());
        ((load * 1_000_000.0) as u64, hash_hex)
    };
    let elected = candidates.iter().min_by(|a, b| score(a).cmp(&score(b)))?;
    let endpoint = elected
        .get("endpoint")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim_end_matches('/');
    // Extract host from endpoint URL
    let relay_host = if let Some(rest) = endpoint.strip_prefix("http://") {
        rest.split('/')
            .next()
            .unwrap_or("")
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(rest)
    } else if let Some(rest) = endpoint.strip_prefix("https://") {
        rest.split('/')
            .next()
            .unwrap_or("")
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(rest)
    } else {
        endpoint.split('/').next().unwrap_or("")
    };
    if relay_host.is_empty() {
        return None;
    }
    let relay_port = elected
        .get("relay_accept_port")
        .and_then(|v| v.as_u64())
        .unwrap_or(9485) as u16;
    Some((relay_host.to_string(), relay_port))
}

#[cfg(feature = "nat")]
fn urlencoding_simple(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' | ':' | '/' => {
                vec![c]
            }
            _ => format!("%{:02X}", c as u8).chars().collect::<Vec<_>>(),
        })
        .collect()
}

/// `iicp-node operator rename <name>` (#460) — change the public, mutable display_name over
/// the immutable operator_id. The operator signs the canonical rename bytes with their own
/// key, so the directory authenticates the change by signature alone (no node token); one
/// signed call updates the single operator record, reflected on every node + the leaderboard.
/// Updates the local operator.json on success. Never sends the secret/contact.
/// Resolve a passphrase: $IICP_OPERATOR_PASSPHRASE if set (headless/CI), else an interactive
/// prompt (this command is operator-run, so a prompt is fine here — only `serve` stays
/// non-interactive). NOTE: the prompt echoes (no `rpassword` dep, to avoid a TC-11 gate).
fn operator_passphrase(prompt: &str, confirm: bool) -> Result<String, String> {
    if let Some(pw) = iicp_client::operator_crypto::passphrase_from_env() {
        return Ok(pw);
    }
    let pw = ask(prompt, "");
    if pw.is_empty() {
        return Err("a passphrase is required".into());
    }
    if confirm && pw != ask("Confirm passphrase", "") {
        return Err("passphrases do not match".into());
    }
    Ok(pw)
}

/// `iicp-node operator encrypt` (#460) — seal the operator secret at rest under a passphrase.
fn run_operator_encrypt() -> Result<(), String> {
    let op = load_operator()
        .map_err(|e| e.to_string())?
        .ok_or("no operator identity — run `iicp-node init` first")?;
    if op.is_encrypted() {
        println!("Operator secret is already encrypted at rest.");
        return Ok(());
    }
    if !op.is_key_backed() {
        return Err("legacy keyless operator identity has nothing to encrypt (#464)".into());
    }
    let pw = operator_passphrase("New operator passphrase", true)?;
    save_operator(&op.encrypt_at_rest(&pw)?).map_err(|e| e.to_string())?;
    println!(
        "Operator secret encrypted at rest (AES-256-GCM / PBKDF2). Set $IICP_OPERATOR_PASSPHRASE \
         to unlock it headlessly during `serve`."
    );
    Ok(())
}

/// `iicp-node operator decrypt` (#460) — restore the plaintext secret at rest.
fn run_operator_decrypt() -> Result<(), String> {
    let op = load_operator()
        .map_err(|e| e.to_string())?
        .ok_or("no operator identity — run `iicp-node init` first")?;
    if !op.is_encrypted() {
        println!("Operator secret is already stored in plaintext.");
        return Ok(());
    }
    let pw = operator_passphrase("Operator passphrase", false)?;
    save_operator(&op.decrypt_at_rest(&pw)?).map_err(|e| e.to_string())?;
    println!("Operator secret decrypted (now stored in plaintext at rest).");
    Ok(())
}

async fn run_operator(args: &[String]) -> Result<(), String> {
    // `-h`/`--help` anywhere prints usage + exits 0 (covers the sub-dispatch too).
    if wants_help(args) {
        print_operator_help();
        return Ok(());
    }
    let sub = args.first().map(String::as_str).unwrap_or("");
    if sub == "encrypt" {
        return run_operator_encrypt();
    }
    if sub == "decrypt" {
        return run_operator_decrypt();
    }
    if sub.is_empty() {
        // No subcommand — print usage rather than "unknown operator subcommand: " (item 8).
        print_operator_help();
        return Ok(());
    }
    if sub != "rename" {
        return Err(format!("unknown operator subcommand: {sub}"));
    }
    let mut name: Option<String> = None;
    let mut directory_url: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if a == "--directory-url" {
            i += 1;
            directory_url = args.get(i).cloned();
        } else if let Some(v) = a.strip_prefix("--directory-url=") {
            directory_url = Some(v.to_string());
        } else if !a.starts_with("--") && name.is_none() {
            name = Some(a.clone());
        }
        i += 1;
    }
    let name = name.ok_or("usage: iicp-node operator rename <name>")?;
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err("display name must be 1-64 chars with no control characters".into());
    }

    let mut op = load_operator()
        .map_err(|e| e.to_string())?
        .ok_or("no operator identity — run `iicp-node init` first")?;
    if !op.is_key_backed() {
        return Err(
            "legacy keyless operator identity (operator_id is a UUID, not a key) — \
                    cannot sign a rename. Regenerate with a key-backed identity (#464)"
                .into(),
        );
    }

    let directory_url = directory_url.unwrap_or_else(|| {
        env::var("IICP_DIRECTORY_URL").unwrap_or_else(|_| "https://iicp.network/api".to_string())
    });
    let sk = op.signing_key()?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let sig = iicp_client::delegation::sign_rename(&sk, &name, &op.operator_id, ts);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("client: {e}"))?;
    let url = format!("{}/v1/operator/rename", directory_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "operator_pub": op.operator_id.clone(),
            "display_name": name.clone(),
            "ts": ts,
            "sig": sig,
        }))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    if !status.is_success() {
        let msg = body
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("request rejected");
        return Err(format!("HTTP {status}: {msg}"));
    }

    // Persist the new name locally so the next `serve` re-asserts it at register.
    op.display_name = body
        .get("display_name")
        .and_then(|v| v.as_str())
        .unwrap_or(&name)
        .to_string();
    save_operator(&op).map_err(|e| e.to_string())?;
    println!("Renamed operator display_name to {:?}.", op.display_name);
    Ok(())
}

// ── proxy (ADR-050) — local compat gateway; consumer, loopback, no registration ──
#[cfg(feature = "proxy")]
async fn run_proxy_cmd(args: &[String]) -> Result<(), String> {
    if wants_help(args) {
        print_proxy_help();
        return Ok(());
    }
    let mut host = env::var("IICP_PROXY_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let mut port: u16 = env::var("IICP_PROXY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9483);
    let mut directory_url = env::var("IICP_DIRECTORY_URL").ok();
    let mut region = env::var("IICP_PROXY_PREFERRED_REGION").ok();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                i += 1;
                host = args.get(i).cloned().ok_or("--host needs a value")?;
            }
            "--port" => {
                i += 1;
                port = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .ok_or("--port needs a number")?;
            }
            "--directory-url" => {
                i += 1;
                directory_url = args.get(i).cloned();
            }
            "--region" => {
                i += 1;
                region = args.get(i).cloned();
            }
            other => return Err(format!("unknown proxy flag: {other}")),
        }
        i += 1;
    }
    iicp_client::proxy::run_proxy(iicp_client::proxy::ProxyConfig {
        host,
        port,
        directory_url,
        region,
    })
    .await
    .map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" || args[1] == "help" {
        print_help();
        // No args at all → usage error (exit 2). Explicit help request → success (exit 0).
        process::exit(if args.len() < 2 { 2 } else { 0 });
    }
    if args[1] == "--version" || args[1] == "-V" {
        println!("iicp-node {}", env!("CARGO_PKG_VERSION"));
        process::exit(0);
    }
    let cmd = &args[1];
    if cmd == "init" {
        if let Err(e) = run_init(&args[2..]).await {
            eprintln!("ERROR: {e}");
            process::exit(1);
        }
        return;
    }
    if cmd == "list" {
        if let Err(e) = run_list() {
            eprintln!("ERROR: {e}");
            process::exit(1);
        }
        return;
    }
    if cmd == "query" {
        if let Err(e) = run_query(&args[2..]).await {
            eprintln!("ERROR: {e}");
            process::exit(1);
        }
        return;
    }
    if cmd == "credits" {
        if let Err(e) = run_credits(&args[2..]).await {
            eprintln!("ERROR: {e}");
            process::exit(1);
        }
        return;
    }
    if cmd == "operator" {
        if let Err(e) = run_operator(&args[2..]).await {
            eprintln!("ERROR: {e}");
            process::exit(1);
        }
        return;
    }
    if cmd == "proxy" {
        #[cfg(feature = "proxy")]
        {
            if let Err(e) = run_proxy_cmd(&args[2..]).await {
                eprintln!("ERROR: {e}");
                process::exit(1);
            }
            return;
        }
        #[cfg(not(feature = "proxy"))]
        {
            eprintln!(
                "iicp-node was built without the proxy gateway. \
                 Reinstall with: cargo install iicp-client --features proxy"
            );
            process::exit(2);
        }
    }
    if cmd != "serve" {
        eprintln!("unknown command: {cmd}");
        print_help();
        process::exit(2);
    }
    let opts = match parse_args(&args[2..]) {
        Ok(o) => o,
        Err(e) if e == "HELP" => {
            print_help();
            process::exit(0);
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            process::exit(2);
        }
    };
    if let Err(e) = run_serve(opts).await {
        eprintln!("ERROR: {e}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #410 — saved-node backend_url must be applied when no flag/env supplied it.
    // Regression: ServeOpts.backend_url used to default to the non-empty Ollama
    // literal, so apply_saved_node's `is_empty()` guard never fired and the saved
    // config's backend_url was silently ignored (node served the wrong backend).
    #[test]
    fn saved_backend_url_applies_when_unset() {
        let mut opts = ServeOpts::default(); // backend_url == "" (the #410 fix)
        let saved = NodeIdentity {
            backend_url: "http://localhost:1234/v1".to_string(),
            model: "qwen2.5-coder-14b-instruct-mlx".to_string(),
            ..Default::default()
        };
        apply_saved_node(&mut opts, &saved);
        assert_eq!(opts.backend_url, "http://localhost:1234/v1");
        assert_eq!(opts.model, "qwen2.5-coder-14b-instruct-mlx");
    }

    // region: an unset region (empty after parse) must restore the saved region and never
    // silently register as "eu-central". Regression for the first external operator (@shaal:
    // set us-east, the directory showed eu-central — --region defaulted to the truthy
    // "eu-central", which both mislabeled non-EU operators and shadowed this restore). See #484.
    #[test]
    fn saved_region_applies_when_unset() {
        let mut opts = ServeOpts::default(); // region == "" (the fix; parse default was "eu-central")
        let saved = NodeIdentity {
            region: "us-east".to_string(),
            ..Default::default()
        };
        apply_saved_node(&mut opts, &saved);
        assert_eq!(
            opts.region, "us-east",
            "saved region must be restored when --region is unset"
        );
    }

    // An explicit --region/IICP_REGION value must win over a saved region.
    #[test]
    fn explicit_region_overrides_saved() {
        let mut opts = ServeOpts {
            region: "us-west".to_string(),
            ..Default::default()
        };
        let saved = NodeIdentity {
            region: "us-east".to_string(),
            ..Default::default()
        };
        apply_saved_node(&mut opts, &saved);
        assert_eq!(opts.region, "us-west");
    }

    // CLI-friction fixes — every command's `-h`/`--help` is detected before its parse loop.
    #[test]
    fn wants_help_detects_short_and_long() {
        assert!(wants_help(&["-h".to_string()]));
        assert!(wants_help(&["foo".to_string(), "--help".to_string()]));
        assert!(!wants_help(&["foo".to_string(), "--bar".to_string()]));
        assert!(!wants_help(&[]));
    }

    // --no-auto-detect-nat is parsed as an off-switch (parity with Python) and flips the
    // env-default ON value to OFF, recording the explicit-disable marker.
    #[test]
    fn no_auto_detect_nat_flag_disables_and_marks() {
        let opts = parse_args(&["--no-auto-detect-nat".to_string()]).unwrap();
        assert!(!opts.auto_detect_nat);
        assert!(opts.no_auto_detect_nat);
    }

    // A saved-node with auto_detect_nat=true must NOT re-enable detection once the operator
    // explicitly passed --no-auto-detect-nat (the off-switch wins over saved config).
    #[test]
    fn explicit_no_auto_detect_nat_survives_saved_node() {
        let mut opts = ServeOpts {
            no_auto_detect_nat: true,
            auto_detect_nat: false,
            ..Default::default()
        };
        let saved = NodeIdentity {
            auto_detect_nat: true,
            ..Default::default()
        };
        apply_saved_node(&mut opts, &saved);
        assert!(
            !opts.auto_detect_nat,
            "explicit --no-auto-detect-nat must win over saved config"
        );
    }

    // Without the off-switch, a saved-node CAN re-enable NAT detection (unchanged behavior).
    #[test]
    fn saved_node_reenables_auto_detect_nat_without_off_switch() {
        let mut opts = ServeOpts {
            no_auto_detect_nat: false,
            auto_detect_nat: false,
            ..Default::default()
        };
        let saved = NodeIdentity {
            auto_detect_nat: true,
            ..Default::default()
        };
        apply_saved_node(&mut opts, &saved);
        assert!(opts.auto_detect_nat);
    }

    // An explicit flag/env value (non-empty before apply_saved_node) must win.
    #[test]
    fn explicit_backend_url_overrides_saved() {
        let mut opts = ServeOpts {
            backend_url: "http://flag:9999/v1".to_string(),
            ..Default::default()
        };
        let saved = NodeIdentity {
            backend_url: "http://localhost:1234/v1".to_string(),
            ..Default::default()
        };
        apply_saved_node(&mut opts, &saved);
        assert_eq!(opts.backend_url, "http://flag:9999/v1");
    }

    /// Single-shot mock of GET /v1/credits/summary — std-only, no test deps.
    fn spawn_mock_summary(status_line: &'static str, body: &'static str) -> u16 {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut b = [0u8; 2048];
                let _ = s.read(&mut b);
                let resp = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        port
    }

    /// #456 — `iicp-node credits` renders a 200 summary and, crucially, ERRORS on 401:
    /// a wrong/forged token cannot produce credit figures (the amounts come authenticated
    /// from the directory, not from the local config). Fails without the run_credits command.
    #[tokio::test]
    async fn credits_renders_on_200_and_errs_on_401() {
        let ok_body = r#"{"node_id":"n1","total_earned":142.5,"total_spent":38.25,"balance":104.25,"tx_count":2,"reconciles":true,"unit":"credit","tokens_per_credit":1000}"#;
        let port = spawn_mock_summary("200 OK", ok_body);
        let ok_args: Vec<String> = vec![
            "--node-id".into(),
            "n1".into(),
            "--token".into(),
            "t".into(),
            "--directory-url".into(),
            format!("http://127.0.0.1:{port}"),
            "--json".into(),
        ];
        assert!(
            run_credits(&ok_args).await.is_ok(),
            "valid 200 summary must render"
        );

        let port2 = spawn_mock_summary(
            "401 Unauthorized",
            r#"{"error":{"code":"unauthorized","message":"invalid node_token"}}"#,
        );
        let bad_args: Vec<String> = vec![
            "--node-id".into(),
            "n1".into(),
            "--token".into(),
            "forged".into(),
            "--directory-url".into(),
            format!("http://127.0.0.1:{port2}"),
        ];
        assert!(
            run_credits(&bad_args).await.is_err(),
            "a forged/wrong token must be rejected — local config cannot fabricate credits"
        );
    }

    /// 2-path mock: serves /.well-known/did.json (with `did_x` as the Ed25519 JWK x) and
    /// /v1/events (with `events_body`). Handles several requests on a daemon thread.
    fn spawn_verify_mock(did_x: String, events_body: String) -> u16 {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let did_body = format!(
                r#"{{"verificationMethod":[{{"publicKeyJwk":{{"kty":"OKP","crv":"Ed25519","x":"{did_x}"}}}}]}}"#
            );
            for _ in 0..8 {
                let Ok((mut s, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 1024];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let body = if req.contains("did.json") {
                    &did_body
                } else {
                    &events_body
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        port
    }

    /// #456 --verify: a properly-signed CREDIT_AWARD verifies; a tampered `amount` (same sig)
    /// MUST fail verification — the heart of "you can't fake earnings." Fails without the
    /// canonical_json + Ed25519 verify in verify_credit_awards (#404).
    #[tokio::test]
    async fn verify_accepts_valid_award_and_rejects_tampered_amount() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};

        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey_b64 = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let event_id = "11111111-1111-1111-1111-111111111111";
        let seq = 2i64;
        let ts_ms = 1_700_000_000_000i64;
        let payload = serde_json::json!({"amount": 5.0, "new_balance": 5.0, "task_id": "t1"});
        // #458: genesis-case hash-chain link, bound into the signing input.
        let prev_hash = "c44802bedf3e63b5a3f1634c5d19263634f92f26dd15401b09b06dd53a80cf9d";
        // Sign exactly as the directory does (§3.4 / federation.rs event_message).
        let payload_hash = hex::encode(Sha256::digest(canonical_json(&payload).as_bytes()));
        let input = format!("{event_id}:CREDIT_AWARD:{seq}:{ts_ms}:{payload_hash}:{prev_hash}");
        let msg = Sha256::digest(input.as_bytes());
        let sig_hex = hex::encode(sk.sign(msg.as_slice()).to_bytes());
        let mk_events = |pl: &serde_json::Value| {
            serde_json::json!({"events":[{
                "event_id": event_id, "event_type": "CREDIT_AWARD", "seq": seq, "ts_ms": ts_ms,
                "node_id": "n1", "payload": pl, "prev_hash": prev_hash, "sig": sig_hex,
            }]})
            .to_string()
        };

        // Valid → verifies.
        let port = spawn_verify_mock(pubkey_b64.clone(), mk_events(&payload));
        let (sum, ok, failed) = verify_credit_awards(&format!("http://127.0.0.1:{port}"), "n1")
            .await
            .unwrap();
        assert_eq!(
            (sum, ok, failed),
            (5.0, 1, 0),
            "valid signed award must verify"
        );

        // Tampered amount (same sig over the original payload) → MUST fail.
        let tampered = serde_json::json!({"amount": 9999.0, "new_balance": 5.0, "task_id": "t1"});
        let port2 = spawn_verify_mock(pubkey_b64, mk_events(&tampered));
        let (_s, ok2, failed2) = verify_credit_awards(&format!("http://127.0.0.1:{port2}"), "n1")
            .await
            .unwrap();
        assert_eq!(ok2, 0, "a tampered amount must NOT verify");
        assert!(
            failed2 >= 1,
            "a tampered amount must count as a failed signature"
        );
    }
}
