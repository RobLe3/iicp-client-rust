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
    external_ip_probe_url: String,
    relay_worker_endpoint: String,
    log_dir: Option<String>,
}

fn print_help() {
    print!(
        "usage: iicp-node <command> [options]\n\n\
         Commands:\n\
         \x20 init                       Interactive wizard — set up operator + first node\n\
         \x20 list                       List node configs saved under ~/.iicp/nodes/\n\
         \x20 serve                      Register and serve a node\n\
         \x20 query <prompt>             Discover mesh nodes and submit a chat task\n\n\
         Global flags:\n\
         \x20 --version, -V              Print version and exit\n\
         \x20 --help, -h                 Print this help\n\n\
         serve required (flag or env):\n\
         \x20 --model NAME               IICP_BACKEND_MODEL (e.g. qwen2.5:0.5b)\n\
         \x20 (or --node NAME            load from ~/.iicp/nodes/<NAME>.json after `iicp-node init`)\n\n\
         serve optional:\n\
         \x20 --backend-url URL          IICP_BACKEND_URL (default http://localhost:11434 — local Ollama)\n\
         \x20 --backend-type TYPE        IICP_BACKEND_TYPE — openai_compat | vllm | llamacpp (default openai_compat)\n\
         \x20 --public-endpoint URL      IICP_PUBLIC_ENDPOINT — externally reachable URL\n\
         \x20 --directory-url URL        IICP_DIRECTORY_URL (default https://iicp.network/api)\n\
         \x20 --region REGION            IICP_REGION (default eu-central)\n\
         \x20 --intent URN               IICP_INTENT (default urn:iicp:intent:llm:chat:v1)\n\
         \x20 --max-concurrent N         IICP_MAX_CONCURRENT (default 4)\n\
         \x20 --node-id ID               IICP_NODE_ID (auto-generated if absent)\n\
         \x20 --port N                   IICP_PORT (default 9484)\n\
         \x20 --host HOST                IICP_HOST (default :: — dual-stack IPv4+IPv6)\n\
         \x20 --skip-registration        IICP_SKIP_REGISTRATION — dev mode\n\
         \x20 --auto-detect-nat          IICP_AUTO_DETECT_NAT — run NAT detection at startup\n\
         \x20 --external-ip-probe-url U  IICP_EXTERNAL_IP_PROBE_URL — fallback IPv4 probe\n\
         \x20 --log-dir DIR              IICP_LOG_DIR (default ~/.iicp/logs/)\n\n\
         query optional:\n\
         \x20 --directory-url URL        IICP_DIRECTORY_URL (default https://iicp.network/api)\n\
         \x20 --intent URN               IICP_INTENT (default urn:iicp:intent:llm:chat:v1)\n\
         \x20 --model NAME               Pin to a specific model on the remote node\n\
         \x20 --max-tokens N             Limit response length\n\
         \x20 --timeout-ms N             Request timeout (default 60000)\n"
    );
}

async fn run_query(args: &[String]) -> Result<(), String> {
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

    if resp.status == "completed" {
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

fn parse_args(args: &[String]) -> Result<ServeOpts, String> {
    let mut opts = ServeOpts {
        node: env_or("IICP_NODE_NAME", None).unwrap_or_default(),
        // Onboarding: default to Ollama's well-known local port so `iicp-node serve --model X`
        // works with no --backend-url for the overwhelmingly common local-Ollama case.
        backend_url: env_or("IICP_BACKEND_URL", Some("http://localhost:11434")).unwrap(),
        backend_type: env_or("IICP_BACKEND_TYPE", Some("openai_compat")).unwrap(),
        model: env_or("IICP_BACKEND_MODEL", None).unwrap_or_default(),
        public_endpoint: env_or("IICP_PUBLIC_ENDPOINT", None).unwrap_or_default(),
        directory_url: env_or("IICP_DIRECTORY_URL", Some("https://iicp.network/api")).unwrap(),
        region: env_or("IICP_REGION", Some("eu-central")).unwrap(),
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
        // Default to api.ipify.org so FRITZ!Box/CGNAT detection works out of the box.
        external_ip_probe_url: env_or("IICP_EXTERNAL_IP_PROBE_URL", None)
            .unwrap_or_else(|| "https://api.ipify.org".to_string()),
        relay_worker_endpoint: env_or("IICP_RELAY_WORKER_ENDPOINT", None).unwrap_or_default(),
        log_dir: env_or("IICP_LOG_DIR", None),
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
            "--auto-detect-nat" => {
                opts.auto_detect_nat = true;
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
    if opts.region == "eu-central" {
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
    if !opts.auto_detect_nat {
        opts.auto_detect_nat = saved.auto_detect_nat;
    }
    if opts.external_ip_probe_url.is_empty() {
        opts.external_ip_probe_url = saved.external_ip_probe_url.clone();
    }
}

// ── GAP-6 — probe backend for all available models ─────────────────────────
/// Best-effort: returns all model names from Ollama `/api/tags` or OpenAI `/v1/models`.
/// Empty vec on any error — caller falls back to the single configured model.
async fn probe_backend_models(backend_url: &str) -> Vec<String> {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let base = backend_url.trim_end_matches('/');
    // Try Ollama /api/tags first
    if let Ok(resp) = client.get(format!("{base}/api/tags")).send().await {
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
    if let Ok(resp) = client.get(format!("{base}/v1/models")).send().await {
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

async fn run_init() -> Result<(), String> {
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
    let region = ask("Region tag", "eu-central");
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

    // Load persisted node config if --node was provided.
    if !opts.node.is_empty() {
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

    // Onboarding: if no --model given, auto-select the first model the backend advertises
    // (Ollama /api/tags or OpenAI /v1/models) so a bare `iicp-node serve` just works.
    if opts.model.is_empty() && !opts.backend_url.is_empty() {
        let models = probe_backend_models(&opts.backend_url).await;
        if let Some(first) = models.first() {
            eprintln!(
                "[iicp-node] no --model given — auto-selected '{first}' from backend {}",
                opts.backend_url
            );
            opts.model = first.clone();
        }
    }
    if opts.backend_url.is_empty() || opts.model.is_empty() {
        return Err(format!(
            "no --model given and backend {} advertised no models. Pass --model NAME, or check the backend is running (e.g. `ollama pull qwen2.5:0.5b`).",
            opts.backend_url
        ));
    }
    if !BACKEND_TYPES.contains(&opts.backend_type.as_str()) {
        return Err(format!("--backend-type must be one of {BACKEND_TYPES:?}"));
    }

    if opts.node_id.is_empty() {
        opts.node_id = uuid::Uuid::new_v4().to_string();
    }
    // Directory column is CHAR(36) — truncate custom names to 36 chars.
    opts.node_id.truncate(36);

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
    let discovered_models = probe_backend_models(&opts.backend_url).await;

    let mut cfg = NodeConfig::new(&opts.node_id, &opts.public_endpoint, &opts.intent);
    cfg.model = Some(opts.model.clone());
    cfg.region = Some(opts.region.clone());
    cfg.directory_url = opts.directory_url.clone();
    cfg.max_concurrent = opts.max_concurrent;
    if !opts.relay_worker_endpoint.is_empty() {
        cfg.relay_worker_endpoint = Some(opts.relay_worker_endpoint.clone());
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
        api_key: None,
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

    let token = if opts.skip_registration {
        None
    } else {
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
                Some(t)
            }
            Err(e) => {
                eprintln!("[iicp-node] registration failed: {e} — continuing without heartbeat");
                if let Some(ref log) = node_log {
                    log.write("register_fail", &opts.node_id, &format!("error={e}"));
                }
                None
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

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_help();
        process::exit(if args.len() < 2 { 2 } else { 0 });
    }
    if args[1] == "--version" || args[1] == "-V" {
        println!("iicp-node {}", env!("CARGO_PKG_VERSION"));
        process::exit(0);
    }
    let cmd = &args[1];
    if cmd == "init" {
        if let Err(e) = run_init().await {
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
