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

use iicp_client::backends::openai_compat::{invoke, OpenAiCompatOptions};
use iicp_client::identity::{
    config_dir, generate_node, list_nodes, load_node, load_operator, save_node, save_operator,
    NodeIdentity, OperatorIdentity,
};
use iicp_client::node::{IicpNode, NodeConfig};

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

struct ServeOpts {
    node: String,
    backend_url: String,
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
}

fn print_help() {
    print!(
        "usage: iicp-node <command> [options]\n\n\
         Commands:\n\
         \x20 init                       Interactive wizard — set up operator + first node\n\
         \x20 list                       List node configs saved under ~/.iicp/nodes/\n\
         \x20 serve                      Register and serve a node\n\n\
         serve required (flag or env):\n\
         \x20 --backend-url URL          IICP_BACKEND_URL\n\
         \x20 --model NAME               IICP_BACKEND_MODEL (e.g. qwen2.5:0.5b)\n\
         \x20 (or --node NAME            load from ~/.iicp/nodes/<NAME>.json after `iicp-node init`)\n\n\
         serve optional:\n\
         \x20 --public-endpoint URL      IICP_PUBLIC_ENDPOINT — externally reachable URL\n\
         \x20 --directory-url URL        IICP_DIRECTORY_URL (default https://iicp.network/api)\n\
         \x20 --region REGION            IICP_REGION (default eu-central)\n\
         \x20 --intent URN               IICP_INTENT (default urn:iicp:intent:llm:chat:v1)\n\
         \x20 --max-concurrent N         IICP_MAX_CONCURRENT (default 4)\n\
         \x20 --node-id ID               IICP_NODE_ID (auto-generated if absent)\n\
         \x20 --port N                   IICP_PORT (default 8020)\n\
         \x20 --host HOST                IICP_HOST (default 0.0.0.0)\n\
         \x20 --skip-registration        IICP_SKIP_REGISTRATION — dev mode\n\
         \x20 --auto-detect-nat          IICP_AUTO_DETECT_NAT — run NAT detection at startup\n\
         \x20 --external-ip-probe-url U  IICP_EXTERNAL_IP_PROBE_URL — fallback IPv4 probe\n"
    );
}

fn parse_args(args: &[String]) -> Result<ServeOpts, String> {
    let mut opts = ServeOpts {
        node: env_or("IICP_NODE_NAME", None).unwrap_or_default(),
        backend_url: env_or("IICP_BACKEND_URL", None).unwrap_or_default(),
        model: env_or("IICP_BACKEND_MODEL", None).unwrap_or_default(),
        public_endpoint: env_or("IICP_PUBLIC_ENDPOINT", None).unwrap_or_default(),
        directory_url: env_or("IICP_DIRECTORY_URL", Some("https://iicp.network/api")).unwrap(),
        region: env_or("IICP_REGION", Some("eu-central")).unwrap(),
        intent: env_or("IICP_INTENT", Some("urn:iicp:intent:llm:chat:v1")).unwrap(),
        max_concurrent: env_int("IICP_MAX_CONCURRENT", 4) as usize,
        node_id: env_or("IICP_NODE_ID", None).unwrap_or_default(),
        port: env_int("IICP_PORT", 8020) as u16,
        host: env_or("IICP_HOST", Some("0.0.0.0")).unwrap(),
        skip_registration: env_bool("IICP_SKIP_REGISTRATION"),
        auto_detect_nat: env_bool("IICP_AUTO_DETECT_NAT"),
        external_ip_probe_url: env_or("IICP_EXTERNAL_IP_PROBE_URL", None).unwrap_or_default(),
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
    if opts.port == 8020 {
        opts.port = saved.port;
    }
    if opts.host == "0.0.0.0" {
        opts.host = saved.host.clone();
    }
    if !opts.auto_detect_nat {
        opts.auto_detect_nat = saved.auto_detect_nat;
    }
    if opts.external_ip_probe_url.is_empty() {
        opts.external_ip_probe_url = saved.external_ip_probe_url.clone();
    }
}

// ── #346 — dependency checker (no auto-install on Rust — cargo would need a rebuild) ─

struct DepIssue {
    name: String,
    severity: &'static str, // "ok" | "warn" | "missing"
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
        severity: "missing",
        message:
            "feature nat not compiled — rebuild with `cargo install iicp-client --features nat`"
                .into(),
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
        severity: "warn",
        message: "feature iicp-tcp not compiled — rebuild with --features iicp-tcp".into(),
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
        severity: "warn",
        message: "feature metrics not compiled — rebuild with --features metrics".into(),
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
    let port_s = ask("Listen port", "8020");
    let port: u16 = port_s.parse().unwrap_or(8020);
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
    let missing = issues.iter().any(|i| i.severity == "missing");
    if missing {
        println!();
        println!("  ! some features are not compiled. Rebuild with the right --features set:");
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

    if opts.backend_url.is_empty() || opts.model.is_empty() {
        return Err(
            "--backend-url and --model are required (or IICP_BACKEND_URL / IICP_BACKEND_MODEL, or --node NAME)"
                .into(),
        );
    }

    if opts.node_id.is_empty() {
        let suffix: String = uuid::Uuid::new_v4().simple().to_string()[..8].into();
        opts.node_id = format!("sdk-{}-{suffix}", opts.model.replace(':', "-"));
    }
    if opts.public_endpoint.is_empty() {
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
    let tier0_pinhole: Option<()> = None;

    let mut cfg = NodeConfig::new(&opts.node_id, &opts.public_endpoint, &opts.intent);
    cfg.model = Some(opts.model.clone());
    cfg.region = Some(opts.region.clone());
    cfg.directory_url = opts.directory_url.clone();
    cfg.max_concurrent = opts.max_concurrent;
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
    #[cfg_attr(not(feature = "nat"), allow(unused_mut))]
    let mut node = IicpNode::new(cfg);

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
        node.apply_nat_profile(&profile);
    }

    let backend_url = opts.backend_url.clone();
    let model = opts.model.clone();
    let openai_opts = OpenAiCompatOptions {
        base_url: backend_url.clone(),
        model: Some(model.clone()),
        api_key: None,
        timeout: Duration::from_secs(60),
    };

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
                Some(t)
            }
            Err(e) => {
                eprintln!("[iicp-node] registration failed: {e} — continuing without heartbeat");
                None
            }
        }
    };

    eprintln!(
        "[iicp-node] serving {} on {}:{} — backend {} (model={}, max_concurrent={})",
        opts.intent, opts.host, opts.port, opts.backend_url, opts.model, opts.max_concurrent
    );

    let opts_handler = openai_opts.clone();
    let bind = format!("{}:{}", opts.host, opts.port);
    let token_for_serve = token.clone();
    let serve_result = tokio::select! {
        r = node.serve(
            move |req| {
                let opts_handler = opts_handler.clone();
                async move { Ok(invoke(&opts_handler, &req.intent, &req.payload).await) }
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
        if let Err(e) = node.deregister(t).await {
            eprintln!("[iicp-node] deregister failed: {e}");
        }
    }

    serve_result
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_help();
        process::exit(if args.len() < 2 { 2 } else { 0 });
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
