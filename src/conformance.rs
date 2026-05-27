// SPDX-License-Identifier: Apache-2.0
//! Self-conformance probes — operator-side health verification.
//!
//! Rust port of iicp-client-python's `conformance.py` (iter-1435) and
//! iicp-client-typescript's `conformance.ts` (iter-1436). Tier 2 Item 4
//! of #340 closing across all 3 hybrid SDKs.
//!
//! Four probes mirror the adapter set:
//!
//!   CONF-REG-01    — node_id + node_token are set
//!   CONF-HEALTH-01 — local /iicp/health returns 200 with required schema
//!   CONF-REACH-01  — directory /v1/probe confirms internet reachability
//!   CONF-DISC-01   — own node_id appears in /v1/discover NODELIST

use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::node::IicpNode;

const REQUIRED_HEALTH_FIELDS: &[&str] = &["status", "node_id", "region", "load", "models"];
const NON_ROUTABLE: &[&str] = &["localhost", "127.0.0.1", "::1", "example.com", "0.0.0.0"];
const DISCOVER_INTENT: &str = "urn:iicp:intent:llm:chat:v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub test_id: String,
    pub passed: bool,
    pub message: String,
    pub latency_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub pass_count: usize,
    pub fail_count: usize,
    pub last_run_at: String,
    pub tests: Vec<ProbeResult>,
}

// ── Probes ────────────────────────────────────────────────────────────────

async fn check_registered(node_id: &str, node_token: Option<&str>) -> ProbeResult {
    if !node_id.is_empty() && node_token.is_some_and(|t| !t.is_empty()) {
        let short = if node_id.len() > 8 {
            format!("{}…", &node_id[..8])
        } else {
            node_id.to_string()
        };
        return ProbeResult {
            test_id: "CONF-REG-01".into(),
            passed: true,
            message: format!("Registered ({short})"),
            latency_ms: None,
        };
    }
    if !node_id.is_empty() {
        return ProbeResult {
            test_id: "CONF-REG-01".into(),
            passed: true,
            message: format!(
                "node_id set ({}…); token not tracked by SDK",
                &node_id[..node_id.len().min(8)]
            ),
            latency_ms: None,
        };
    }
    ProbeResult {
        test_id: "CONF-REG-01".into(),
        passed: false,
        message: "node_id empty — register() not yet called".into(),
        latency_ms: None,
    }
}

async fn check_health_schema(local_port: u16) -> ProbeResult {
    let url = format!("http://127.0.0.1:{local_port}/iicp/health");
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return ProbeResult {
                test_id: "CONF-HEALTH-01".into(),
                passed: false,
                message: format!("Error: {e}"),
                latency_ms: None,
            };
        }
    };
    let t0 = std::time::Instant::now();
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return ProbeResult {
                test_id: "CONF-HEALTH-01".into(),
                passed: false,
                message: format!("Error: {e}"),
                latency_ms: None,
            };
        }
    };
    let latency_ms = t0.elapsed().as_secs_f64() * 1000.0;
    if !resp.status().is_success() {
        return ProbeResult {
            test_id: "CONF-HEALTH-01".into(),
            passed: false,
            message: format!("HTTP {}", resp.status().as_u16()),
            latency_ms: Some(latency_ms),
        };
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            return ProbeResult {
                test_id: "CONF-HEALTH-01".into(),
                passed: false,
                message: format!("Body parse error: {e}"),
                latency_ms: Some(latency_ms),
            };
        }
    };
    let present: HashSet<&str> = body
        .as_object()
        .map(|m| m.keys().map(|k| k.as_str()).collect())
        .unwrap_or_default();
    let mut missing: Vec<&str> = REQUIRED_HEALTH_FIELDS
        .iter()
        .copied()
        .filter(|f| !present.contains(f))
        .collect();
    if !missing.is_empty() {
        missing.sort();
        return ProbeResult {
            test_id: "CONF-HEALTH-01".into(),
            passed: false,
            message: format!("Missing fields: {missing:?}"),
            latency_ms: Some(latency_ms),
        };
    }
    ProbeResult {
        test_id: "CONF-HEALTH-01".into(),
        passed: true,
        message: format!("OK ({latency_ms:.0}ms)"),
        latency_ms: Some(latency_ms),
    }
}

fn parse_host_port(endpoint: &str) -> (String, u16) {
    let mut s = endpoint;
    for scheme in ["https://", "http://"] {
        if let Some(rest) = endpoint.strip_prefix(scheme) {
            s = rest;
            break;
        }
    }
    let authority = s.split('/').next().unwrap_or(s);
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let port = port_str.parse::<u16>().unwrap_or(443);
        (host.to_string(), port)
    } else {
        let port = if endpoint.starts_with("https://") { 443 } else { 80 };
        (authority.to_string(), port)
    }
}

fn directory_base(directory_url: &str) -> String {
    let trimmed = directory_url.trim_end_matches('/');
    if trimmed.ends_with("/api") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/api")
    }
}

async fn check_reachability(endpoint: &str, directory_url: &str) -> ProbeResult {
    let ep = endpoint.trim_end_matches('/');
    if ep.is_empty() || NON_ROUTABLE.iter().any(|p| ep.contains(p)) {
        return ProbeResult {
            test_id: "CONF-REACH-01".into(),
            passed: false,
            message: "endpoint is non-routable — external check skipped; \
                      see https://iicp.network/docs/port-forwarding"
                .into(),
            latency_ms: None,
        };
    }
    let (host, port) = parse_host_port(ep);
    let url = format!(
        "{}/v1/probe?host={}&port={}",
        directory_base(directory_url),
        urlencoding(&host),
        port
    );
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return ProbeResult {
                test_id: "CONF-REACH-01".into(),
                passed: false,
                message: format!("Client build: {e}"),
                latency_ms: None,
            };
        }
    };
    let t0 = std::time::Instant::now();
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return ProbeResult {
                test_id: "CONF-REACH-01".into(),
                passed: false,
                message: format!("Probe unavailable: {e}"),
                latency_ms: None,
            };
        }
    };
    let latency_ms = t0.elapsed().as_secs_f64() * 1000.0;
    if !resp.status().is_success() {
        return ProbeResult {
            test_id: "CONF-REACH-01".into(),
            passed: false,
            message: format!("HTTP {}", resp.status().as_u16()),
            latency_ms: Some(latency_ms),
        };
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            return ProbeResult {
                test_id: "CONF-REACH-01".into(),
                passed: false,
                message: format!("Body parse error: {e}"),
                latency_ms: Some(latency_ms),
            };
        }
    };
    if body.get("reachable").and_then(|v| v.as_bool()) == Some(true) {
        return ProbeResult {
            test_id: "CONF-REACH-01".into(),
            passed: true,
            message: format!("Reachable ({latency_ms:.0}ms)"),
            latency_ms: Some(latency_ms),
        };
    }
    let err = body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("not reachable");
    ProbeResult {
        test_id: "CONF-REACH-01".into(),
        passed: false,
        message: err.to_string(),
        latency_ms: Some(latency_ms),
    }
}

async fn check_discover_self(node_id: &str, directory_url: &str) -> ProbeResult {
    if node_id.is_empty() {
        return ProbeResult {
            test_id: "CONF-DISC-01".into(),
            passed: false,
            message: "No node_id — register() not yet called".into(),
            latency_ms: None,
        };
    }
    let url = format!(
        "{}/v1/discover?intent={}",
        directory_base(directory_url),
        urlencoding(DISCOVER_INTENT)
    );
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return ProbeResult {
                test_id: "CONF-DISC-01".into(),
                passed: false,
                message: format!("Client build: {e}"),
                latency_ms: None,
            };
        }
    };
    let t0 = std::time::Instant::now();
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return ProbeResult {
                test_id: "CONF-DISC-01".into(),
                passed: false,
                message: format!("Discover error: {e}"),
                latency_ms: None,
            };
        }
    };
    let latency_ms = t0.elapsed().as_secs_f64() * 1000.0;
    if !resp.status().is_success() {
        return ProbeResult {
            test_id: "CONF-DISC-01".into(),
            passed: false,
            message: format!("HTTP {}", resp.status().as_u16()),
            latency_ms: Some(latency_ms),
        };
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            return ProbeResult {
                test_id: "CONF-DISC-01".into(),
                passed: false,
                message: format!("Body parse error: {e}"),
                latency_ms: Some(latency_ms),
            };
        }
    };
    let nodes = body
        .get("nodes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let found = nodes
        .iter()
        .any(|n| n.get("node_id").and_then(|v| v.as_str()) == Some(node_id));
    if found {
        ProbeResult {
            test_id: "CONF-DISC-01".into(),
            passed: true,
            message: format!("Found in NODELIST ({} nodes)", nodes.len()),
            latency_ms: Some(latency_ms),
        }
    } else {
        ProbeResult {
            test_id: "CONF-DISC-01".into(),
            passed: false,
            message: format!(
                "node_id absent from NODELIST (got {} nodes)",
                nodes.len()
            ),
            latency_ms: Some(latency_ms),
        }
    }
}

/// Minimal URL-percent-encoder for the host/intent we pass as query strings.
/// Reserved chars are encoded; ASCII unreserved (RFC 3986) pass through.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ── Public entry point ────────────────────────────────────────────────────

/// Run the four conformance probes concurrently and return a report. Pass
/// `node_token` to make CONF-REG-01 verify the token in addition to node_id.
pub async fn run_conformance_checks(
    node: &IicpNode,
    local_port: u16,
    node_token: Option<&str>,
) -> ConformanceReport {
    let cfg = node.cfg();
    let (a, b, c, d) = tokio::join!(
        check_registered(&cfg.node_id, node_token),
        check_health_schema(local_port),
        check_reachability(&cfg.endpoint, &cfg.directory_url),
        check_discover_self(&cfg.node_id, &cfg.directory_url),
    );
    let results = vec![a, b, c, d];
    let pass_count = results.iter().filter(|r| r.passed).count();
    let fail_count = results.iter().filter(|r| !r.passed).count();
    ConformanceReport {
        pass_count,
        fail_count,
        last_run_at: rfc3339_now(),
        tests: results,
    }
}

fn rfc3339_now() -> String {
    // tokio's ::time has no formatter; use std::time + manual ISO format.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Hand-format YYYY-MM-DDTHH:MM:SSZ from UNIX seconds (UTC). Sufficient
    // for the probe report; if operators need richer formatting they can
    // re-serialize via their preferred datetime crate.
    let days_since_epoch = secs / 86400;
    let secs_of_day = secs % 86400;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    let (year, month, day) = days_to_ymd(days_since_epoch as i64);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert days-since-1970-01-01 → (year, month, day). Civil-date algorithm
/// from Howard Hinnant's date utilities, public domain.
fn days_to_ymd(z: i64) -> (i64, u8, u8) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
