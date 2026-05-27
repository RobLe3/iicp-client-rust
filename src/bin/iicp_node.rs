//! iicp-node — turn iicp-client into a runnable IICP provider node.
//!
//! ```text
//! cargo install iicp-client
//! iicp-node serve --model qwen2.5:0.5b --backend-url http://localhost:11434
//! ```
//!
//! All flags are also accepted as env vars (IICP_BACKEND_URL,
//! IICP_BACKEND_MODEL, IICP_PUBLIC_ENDPOINT, IICP_DIRECTORY_URL,
//! IICP_REGION, IICP_MAX_CONCURRENT, IICP_NODE_ID, IICP_INTENT,
//! IICP_PORT, IICP_HOST, IICP_SKIP_REGISTRATION).
//!
//! Mirrors the Python (`iicp_client.cli`) and TypeScript (`@iicp/client/cli`)
//! entry points so operators choosing Rust get the same one-liner setup.

use std::env;
use std::process;
use std::time::Duration;

use iicp_client::backends::openai_compat::{invoke, OpenAiCompatOptions};
use iicp_client::node::{IicpNode, NodeConfig};

fn env_or(name: &str, fallback: Option<&str>) -> Option<String> {
    env::var(name).ok().or_else(|| fallback.map(|s| s.to_string()))
}

fn env_int(name: &str, fallback: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

struct ServeOpts {
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
}

fn print_help() {
    print!(
        "usage: iicp-node serve [options]\n\n\
         Run an IICP provider node backed by an OpenAI-compatible server.\n\n\
         Required (flag or env):\n\
         \x20 --backend-url URL         IICP_BACKEND_URL\n\
         \x20 --model NAME              IICP_BACKEND_MODEL (e.g. qwen2.5:0.5b)\n\n\
         Optional:\n\
         \x20 --public-endpoint URL     IICP_PUBLIC_ENDPOINT — externally reachable URL of this node\n\
         \x20 --directory-url URL       IICP_DIRECTORY_URL (default https://iicp.network/api)\n\
         \x20 --region REGION           IICP_REGION (default eu-central)\n\
         \x20 --intent URN              IICP_INTENT (default urn:iicp:intent:llm:chat:v1)\n\
         \x20 --max-concurrent N        IICP_MAX_CONCURRENT (default 4)\n\
         \x20 --node-id ID              IICP_NODE_ID (auto-generated if absent)\n\
         \x20 --port N                  IICP_PORT (default 8020)\n\
         \x20 --host HOST               IICP_HOST (default 0.0.0.0)\n\
         \x20 --skip-registration       IICP_SKIP_REGISTRATION — dev mode\n"
    );
}

fn parse_args(args: &[String]) -> Result<ServeOpts, String> {
    let mut opts = ServeOpts {
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
        skip_registration: env_or("IICP_SKIP_REGISTRATION", Some("false"))
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false),
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
            _ => {
                if i + 1 >= args.len() {
                    return Err(format!("flag {arg} needs a value"));
                }
                let v = args[i + 1].clone();
                match arg.as_str() {
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
                    _ => return Err(format!("unknown flag: {arg}")),
                }
                i += 2;
            }
        }
    }
    Ok(opts)
}

async fn run_serve(mut opts: ServeOpts) -> Result<(), String> {
    if opts.backend_url.is_empty() || opts.model.is_empty() {
        return Err(
            "--backend-url and --model are required (or IICP_BACKEND_URL / IICP_BACKEND_MODEL)"
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

    let mut cfg = NodeConfig::new(&opts.node_id, &opts.public_endpoint, &opts.intent);
    cfg.model = Some(opts.model.clone());
    cfg.region = Some(opts.region.clone());
    cfg.directory_url = opts.directory_url.clone();
    cfg.max_concurrent = opts.max_concurrent;
    let node = IicpNode::new(cfg);

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
                eprintln!(
                    "[iicp-node] registration failed: {e} — continuing without heartbeat"
                );
                None
            }
        }
    };

    eprintln!(
        "[iicp-node] serving {} on {}:{} — backend {} (model={}, max_concurrent={})",
        opts.intent, opts.host, opts.port, opts.backend_url, opts.model, opts.max_concurrent
    );

    let opts_handler = openai_opts.clone();
    node.serve(
        move |req| {
            let opts_handler = opts_handler.clone();
            async move { Ok(invoke(&opts_handler, &req.intent, &req.payload).await) }
        },
        &format!("{}:{}", opts.host, opts.port),
        token,
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_help();
        process::exit(if args.len() < 2 { 2 } else { 0 });
    }
    if args[1] != "serve" {
        eprintln!("unknown command: {}", args[1]);
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
