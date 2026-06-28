// SPDX-License-Identifier: Apache-2.0
//! Quick-Tunnel escalation — #520 rung 5 of the NAT ladder.
//! Rust port of iicp-client-python/tunnel.py (0f97ca1) and
//! iicp-client-typescript/src/tunnel.ts (36456f2).
//!
//! When every NAT variant fails (no direct endpoint, no UPnP pinhole, no IPv6
//! GUA, no relay-capable peer in the directory), the node can still become
//! publicly reachable with ZERO account, domain, or router changes: spawn
//! `cloudflared tunnel --url http://127.0.0.1:<port>` and register the issued
//! `https://*.trycloudflare.com` URL as the endpoint.
//!
//! Lifecycle is fully automatic: setup (binary detection — never
//! auto-installed), initiation (spawn + URL parse ≤20 s), supervision
//! (bounded respawn; URL rotates → caller re-registers), teardown
//! (`close()` idempotent; Drop kills the child so a normal exit never
//! orphans it).

use std::collections::VecDeque;
use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// cloudflared usually prints the URL within ~5 s; 20 s covers slow first runs.
pub const TUNNEL_START_TIMEOUT: Duration = Duration::from_secs(20);
/// Bounded self-healing: this many CONSECUTIVE failed respawns (without the tunnel
/// recovering to a healthy state in between) → give up. The counter resets to 0 once
/// a respawned tunnel passes a health check, so a long-running relay that sees many
/// edge-drops over its lifetime keeps healing indefinitely — the cap only catches a
/// truly broken cloudflared that never comes back. (#538)
pub const MAX_RESPAWNS: u32 = 3;
/// Active liveness check of the tunnel's OWN public URL — catches the failure mode the
/// process-exit watcher misses: cloudflared still running but the edge connection
/// dropped, so the URL is unreachable while the node looks healthy (the recurring
/// dead-endpoint bug, #538). Probe every interval; after this many consecutive
/// failures, force a tunnel restart (kill → respawn → new URL → re-register).
pub const TUNNEL_HEALTH_INTERVAL: Duration = Duration::from_secs(30);
pub const TUNNEL_HEALTH_MAX_FAILS: u32 = 2;
pub const TUNNEL_VERIFY_TIMEOUT: Duration = Duration::from_secs(30);
pub const TUNNEL_DOH_TIMEOUT: Duration = Duration::from_secs(5);
pub const TUNNEL_RATE_LIMIT_COOLDOWN: Duration = Duration::from_secs(15 * 60);
/// Host-wide spacing between accountless Quick Tunnel creation attempts. Cloudflare
/// does not guarantee Quick Tunnel availability for production use; multiple local
/// IICP services must therefore avoid a create/verify/kill thundering herd.
pub const TUNNEL_CREATE_MIN_INTERVAL: Duration = Duration::from_secs(120);
pub const TUNNEL_CREATE_LEASE: Duration = Duration::from_secs(45);

static QUICK_TUNNEL_RATE_LIMIT_UNTIL: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    Ready,
    Twilight,
    Recovering,
    Dead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelDeadDecision {
    Stop,
    RetryAfter(Duration),
}

fn trycloudflare_host(url: &str) -> Option<&str> {
    let rest = url.trim_start().strip_prefix("https://")?;
    let host = rest.split('/').next().unwrap_or(rest);
    if host.ends_with(".trycloudflare.com")
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        Some(host)
    } else {
        None
    }
}

fn is_likely_dns_error(err: &reqwest::Error) -> bool {
    error_message_is_likely_dns(&err.to_string())
}

fn error_message_is_likely_dns(message: &str) -> bool {
    let msg = message.to_ascii_lowercase();
    msg.contains("dns")
        || msg.contains("failed to lookup address")
        || msg.contains("nodename nor servname")
        || msg.contains("name or service not known")
        || msg.contains("temporary failure in name resolution")
}

fn quick_tunnel_rate_limit_store() -> &'static Mutex<Option<Instant>> {
    QUICK_TUNNEL_RATE_LIMIT_UNTIL.get_or_init(|| Mutex::new(None))
}

fn quick_tunnel_rate_limit_cooldown() -> Duration {
    std::env::var("IICP_TUNNEL_RATE_LIMIT_COOLDOWN_S")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .map(Duration::from_secs)
        .unwrap_or(TUNNEL_RATE_LIMIT_COOLDOWN)
}

fn epoch_seconds_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default()
}

fn iicp_home() -> PathBuf {
    std::env::var_os("IICP_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".iicp")))
        .unwrap_or_else(|| PathBuf::from(".iicp"))
}

fn quick_tunnel_rate_limit_state_path() -> PathBuf {
    std::env::var_os("IICP_TUNNEL_RATE_LIMIT_STATE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            iicp_home()
                .join("state")
                .join("quick_tunnel_rate_limit.json")
        })
}

fn quick_tunnel_create_state_path() -> PathBuf {
    std::env::var_os("IICP_TUNNEL_CREATE_STATE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            iicp_home()
                .join("state")
                .join("quick_tunnel_create_gate.json")
        })
}

fn quick_tunnel_create_lock_path() -> PathBuf {
    std::env::var_os("IICP_TUNNEL_CREATE_LOCK_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| iicp_home().join("state").join("quick_tunnel_create.lock"))
}

fn read_persistent_rate_limit_until() -> Option<f64> {
    let path = quick_tunnel_rate_limit_state_path();
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => {
            eprintln!(
                "[quick-tunnel] ignoring unreadable cooldown state {}: {err}",
                path.display()
            );
            return None;
        }
    };
    let value: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(err) => {
            eprintln!(
                "[quick-tunnel] ignoring invalid cooldown state {}: {err}",
                path.display()
            );
            return None;
        }
    };
    value
        .get("quick_tunnel_rate_limited_until")
        .and_then(|v| v.as_f64())
        .filter(|until| *until > 0.0)
}

fn read_json_field_f64(path: &Path, field: &str) -> Option<f64> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => {
            eprintln!(
                "[quick-tunnel] ignoring unreadable state {}: {err}",
                path.display()
            );
            return None;
        }
    };
    let value: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(err) => {
            eprintln!(
                "[quick-tunnel] ignoring invalid state {}: {err}",
                path.display()
            );
            return None;
        }
    };
    value
        .get(field)
        .and_then(|v| v.as_f64())
        .filter(|v| *v > 0.0)
}

fn duration_until_epoch(until_epoch_seconds: f64) -> Option<Duration> {
    let remaining = until_epoch_seconds - epoch_seconds_now();
    (remaining > 0.0).then(|| Duration::from_secs_f64(remaining))
}

fn quick_tunnel_create_min_interval() -> Duration {
    std::env::var("IICP_TUNNEL_CREATE_MIN_INTERVAL_S")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(TUNNEL_CREATE_MIN_INTERVAL)
}

fn quick_tunnel_create_lease_duration() -> Duration {
    std::env::var("IICP_TUNNEL_CREATE_LEASE_S")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .map(Duration::from_secs)
        .unwrap_or(TUNNEL_CREATE_LEASE)
}

fn clear_create_gate_if_safe() {
    let path = quick_tunnel_create_state_path();
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => eprintln!(
            "[quick-tunnel] could not clear expired create-gate state {}: {err}",
            path.display()
        ),
    }
}

fn quick_tunnel_create_gate_remaining() -> Option<Duration> {
    let path = quick_tunnel_create_state_path();
    let until = read_json_field_f64(&path, "quick_tunnel_create_not_before")?;
    match duration_until_epoch(until) {
        Some(remaining) => Some(remaining),
        None => {
            clear_create_gate_if_safe();
            None
        }
    }
}

fn mark_quick_tunnel_create_attempt() {
    let interval = quick_tunnel_create_min_interval();
    if interval.is_zero() {
        clear_create_gate_if_safe();
        return;
    }
    let path = quick_tunnel_create_state_path();
    let payload = serde_json::json!({
        "quick_tunnel_create_not_before": epoch_seconds_now() + interval.as_secs_f64(),
        "interval_s": interval.as_secs_f64(),
        "pid": std::process::id(),
        "reason": "host_wide_quick_tunnel_creation_pacing",
    });
    let result = (|| -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_file_name(format!(
            "{}.tmp.{}",
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("quick_tunnel_create_gate.json"),
            std::process::id()
        ));
        let bytes = serde_json::to_vec_pretty(&payload).map_err(std::io::Error::other)?;
        fs::write(&tmp, bytes)?;
        fs::rename(tmp, &path)?;
        Ok(())
    })();
    if let Err(err) = result {
        eprintln!(
            "[quick-tunnel] could not persist create-gate state {}: {err}",
            path.display()
        );
    }
}

#[derive(Debug)]
struct QuickTunnelCreateLease {
    path: PathBuf,
}

impl Drop for QuickTunnelCreateLease {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn acquire_quick_tunnel_create_lease() -> Result<QuickTunnelCreateLease, Duration> {
    let path = quick_tunnel_create_lock_path();
    let lease = quick_tunnel_create_lease_duration();
    let now = epoch_seconds_now();
    if let Some(parent) = path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            eprintln!(
                "[quick-tunnel] could not create lock dir {}: {err}; continuing without lock",
                parent.display()
            );
            return Ok(QuickTunnelCreateLease {
                path: PathBuf::new(),
            });
        }
    }

    for _ in 0..2 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write;
                let payload = serde_json::json!({
                    "pid": std::process::id(),
                    "expires_at": now + lease.as_secs_f64(),
                    "lease_s": lease.as_secs_f64(),
                    "reason": "host_wide_quick_tunnel_creation_lock",
                });
                let bytes = serde_json::to_vec_pretty(&payload)
                    .map_err(|_| lease)
                    .unwrap_or_default();
                let _ = file.write_all(&bytes);
                return Ok(QuickTunnelCreateLease { path });
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                let expires = read_json_field_f64(&path, "expires_at").unwrap_or(0.0);
                if let Some(remaining) = duration_until_epoch(expires) {
                    return Err(remaining);
                }
                let _ = fs::remove_file(&path);
                continue;
            }
            Err(err) => {
                eprintln!(
                    "[quick-tunnel] could not acquire create lock {}: {err}; continuing without lock",
                    path.display()
                );
                return Ok(QuickTunnelCreateLease {
                    path: PathBuf::new(),
                });
            }
        }
    }

    Err(lease)
}

fn clear_persistent_rate_limit_if_safe() {
    let path = quick_tunnel_rate_limit_state_path();
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => eprintln!(
            "[quick-tunnel] could not clear expired cooldown state {}: {err}",
            path.display()
        ),
    }
}

fn persistent_rate_limit_remaining() -> Option<Duration> {
    let until = read_persistent_rate_limit_until()?;
    match duration_until_epoch(until) {
        Some(remaining) => Some(remaining),
        None => {
            clear_persistent_rate_limit_if_safe();
            None
        }
    }
}

fn persist_rate_limit_until(until_epoch_seconds: f64, cooldown: Duration) {
    let path = quick_tunnel_rate_limit_state_path();
    let payload = serde_json::json!({
        "quick_tunnel_rate_limited_until": until_epoch_seconds,
        "cooldown_s": cooldown.as_secs_f64(),
        "reason": "cloudflare_quick_tunnel_rate_limit",
    });
    let result = (|| -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_file_name(format!(
            "{}.tmp",
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("quick_tunnel_rate_limit.json")
        ));
        let bytes = serde_json::to_vec_pretty(&payload).map_err(std::io::Error::other)?;
        fs::write(&tmp, bytes)?;
        fs::rename(tmp, &path)?;
        Ok(())
    })();
    if let Err(err) = result {
        eprintln!(
            "[quick-tunnel] could not persist cooldown state {}: {err}",
            path.display()
        );
    }
}

fn quick_tunnel_rate_limit_remaining() -> Option<Duration> {
    let process_remaining = {
        let guard = quick_tunnel_rate_limit_store().lock().unwrap();
        (*guard).and_then(|until| {
            let remaining = until.saturating_duration_since(Instant::now());
            (!remaining.is_zero()).then_some(remaining)
        })
    };
    [process_remaining, persistent_rate_limit_remaining()]
        .into_iter()
        .flatten()
        .max()
}

fn mark_quick_tunnel_rate_limited() -> Duration {
    let cooldown = quick_tunnel_rate_limit_cooldown();
    *quick_tunnel_rate_limit_store().lock().unwrap() = Some(Instant::now() + cooldown);
    persist_rate_limit_until(epoch_seconds_now() + cooldown.as_secs_f64(), cooldown);
    cooldown
}

fn rate_limit_pause_from_error(error: &str) -> Option<Duration> {
    for marker in [
        "paused for ",
        "paced for ",
        "held by another local IICP node for ",
    ] {
        let Some(after) = error.split(marker).nth(1) else {
            continue;
        };
        let seconds = after
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse::<u64>()
            .ok()?;
        if seconds > 0 {
            return Some(Duration::from_secs(seconds));
        }
    }
    None
}

fn extend_retry_for_spawn_error(decision: TunnelDeadDecision, error: &str) -> TunnelDeadDecision {
    match (decision, rate_limit_pause_from_error(error)) {
        (TunnelDeadDecision::RetryAfter(delay), Some(rate_limit_delay)) => {
            TunnelDeadDecision::RetryAfter(delay.max(rate_limit_delay))
        }
        (decision, _) => decision,
    }
}

fn cloudflared_output_is_rate_limited(lines: &VecDeque<String>) -> bool {
    let joined = lines
        .iter()
        .map(|line| line.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    joined.contains("429")
        || joined.contains("too many requests")
        || joined.contains("error code: 1015")
        || joined.contains("rate limit")
}

async fn doh_has_answer(client: &reqwest::Client, host: &str, record_type: &str) -> bool {
    let url = format!("https://cloudflare-dns.com/dns-query?name={host}&type={record_type}");
    let resp = match client
        .get(url)
        .header("accept", "application/dns-json")
        .timeout(TUNNEL_DOH_TIMEOUT)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(_) => return false,
    };
    if !resp.status().is_success() {
        return false;
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(body) => body,
        Err(_) => return false,
    };
    body.get("Status").and_then(|v| v.as_u64()) == Some(0)
        && body
            .get("Answer")
            .and_then(|v| v.as_array())
            .is_some_and(|answers| !answers.is_empty())
}

async fn trycloudflare_published_via_doh(client: &reqwest::Client, url: &str) -> bool {
    let Some(host) = trycloudflare_host(url) else {
        return false;
    };
    doh_has_answer(client, host, "A").await || doh_has_answer(client, host, "AAAA").await
}

/// GET `<url>/iicp/health` round-trips through the Cloudflare edge back to the local
/// node — the same path a browser consumer takes — so it detects an edge-drop, not
/// just a local-process death. Build error → treat as healthy (never self-restart on
/// our own client error). For accountless Quick Tunnels, local macOS DNS can lag
/// Cloudflare's authoritative publication by long enough to create a destructive
/// create→verify→kill loop. If local resolution fails but Cloudflare DoH already
/// returns an A/AAAA answer, keep the tunnel and publish it: external resolvers can
/// reach it even while this host's resolver cache is stale. Used by the watchdog from
/// its own (non-tokio) thread.
async fn tunnel_url_reachable(url: &str) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(_) => return true,
    };
    let probe = format!("{}/iicp/health", url.trim_end_matches('/'));
    match client.get(&probe).send().await {
        Ok(r) => r.status().is_success(),
        Err(err) if is_likely_dns_error(&err) => {
            if trycloudflare_published_via_doh(&client, url).await {
                eprintln!(
                    "[quick-tunnel] local DNS has not resolved {url} yet, but Cloudflare DoH \
                     already publishes it — keeping tunnel alive."
                );
                true
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

fn tunnel_url_reachable_sync(url: &str) -> bool {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map(|rt| rt.block_on(tunnel_url_reachable(url)))
        .unwrap_or(true)
}

fn wait_until_reachable(
    url: &str,
    probe: &(dyn Fn(&str) -> bool + Send + Sync),
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if probe(url) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn sleep_until_closed(closed: &AtomicBool, delay: Duration) -> bool {
    let deadline = Instant::now() + delay;
    loop {
        if closed.load(Ordering::Relaxed) {
            return true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        std::thread::sleep(remaining.min(Duration::from_millis(200)));
    }
}

pub const INSTALL_HINT: &str = "cloudflared not found — install it to become reachable \
without router changes (zero-account Quick Tunnel): macOS `brew install cloudflared` · \
Linux: https://pkg.cloudflare.com · Windows `winget install Cloudflare.cloudflared`";

/// Locate the cloudflared binary on PATH, or None (we never auto-install it).
pub fn cloudflared_path() -> Option<std::path::PathBuf> {
    let exts: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ""]
    } else {
        &[""]
    };
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate = dir.join(format!("cloudflared{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn extract_url(line: &str) -> Option<String> {
    let start = line.find("https://")?;
    let rest = &line[start..];
    let end = rest
        .find(|c: char| {
            !(c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == ':' || c == '/')
        })
        .unwrap_or(rest.len());
    let url = &rest[..end];
    if url.ends_with(".trycloudflare.com") {
        Some(url.to_string())
    } else {
        None
    }
}

/// A running Quick Tunnel: public `url` → `http://127.0.0.1:<local_port>`.
pub struct QuickTunnel {
    child: Arc<Mutex<Child>>,
    pub url: String,
    pub local_port: u16,
    binary: std::path::PathBuf,
    closed: Arc<AtomicBool>,
    respawns: Arc<AtomicU32>,
}

impl QuickTunnel {
    pub fn respawns(&self) -> u32 {
        self.respawns.load(Ordering::Relaxed)
    }

    /// True while the child has not exited.
    pub fn is_running(&self) -> bool {
        matches!(self.child.lock().unwrap().try_wait(), Ok(None))
    }

    /// Start the watchdog: on unexpected exit, respawn (bounded) and call
    /// `on_new_url(new_url)` — Quick Tunnel URLs rotate per process, so the
    /// caller MUST re-register. After [`MAX_RESPAWNS`], `on_dead()` fires once.
    ///
    /// Callbacks run on the watchdog thread; marshal to your runtime if needed.
    pub fn watch(
        &self,
        initial_url: String,
        on_new_url: impl Fn(String) + Send + 'static,
        on_dead: impl FnOnce() + Send + 'static,
    ) {
        let child = Arc::clone(&self.child);
        let closed = Arc::clone(&self.closed);
        let respawns = Arc::clone(&self.respawns);
        let binary = self.binary.clone();
        let local_port = self.local_port;
        std::thread::Builder::new()
            .name("quick-tunnel-watchdog".into())
            .spawn(move || {
                // Current-thread runtime for the periodic health probe. Safe to block_on
                // here — this is a plain std thread, not a tokio worker.
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .ok();
                let mut current_url = initial_url;
                let mut health_fails: u32 = 0;
                let mut last_health = Instant::now();
                loop {
                    // Wait until the process exits OR the tunnel URL goes unreachable
                    // (edge-drop) for too long. Poll, not blocking wait(): close() and
                    // the health-kill both need the child lock too.
                    loop {
                        {
                            let mut guard = child.lock().unwrap();
                            if let Ok(Some(_)) = guard.try_wait() {
                                break; // process exited — crash or our health-triggered kill
                            }
                        }
                        if closed.load(Ordering::Relaxed) {
                            return;
                        }
                        // #538 — edge-drop detection: cloudflared can stay alive while its
                        // tunnel becomes unreachable. Probe the public URL; restart on a
                        // sustained failure so the dead endpoint can't persist.
                        if last_health.elapsed() >= TUNNEL_HEALTH_INTERVAL {
                            last_health = Instant::now();
                            let healthy = rt
                                .as_ref()
                                .map(|r| r.block_on(tunnel_url_reachable(&current_url)))
                                .unwrap_or(true);
                            if healthy {
                                health_fails = 0;
                                // Recovered/steady → forget prior respawns so a relay's
                                // lifetime edge-drops never exhaust MAX_RESPAWNS.
                                respawns.store(0, Ordering::Relaxed);
                            } else {
                                health_fails += 1;
                                if health_fails >= TUNNEL_HEALTH_MAX_FAILS {
                                    eprintln!(
                                        "[quick-tunnel] {current_url} unreachable {health_fails}× \
                                         while cloudflared is up (edge dropped) — restarting tunnel."
                                    );
                                    let _ = child.lock().unwrap().kill();
                                    health_fails = 0;
                                    // try_wait() sees the exit on the next poll → respawn arm.
                                }
                            }
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    if closed.load(Ordering::Relaxed) {
                        return;
                    }
                    let n = respawns.fetch_add(1, Ordering::Relaxed) + 1;
                    if n > MAX_RESPAWNS {
                        eprintln!(
                            "[quick-tunnel] {} consecutive respawns failed to recover a healthy \
                             tunnel — giving up. Node is no longer publicly reachable; restart \
                             `iicp-node serve`.",
                            n - 1
                        );
                        on_dead();
                        return;
                    }
                    eprintln!("[quick-tunnel] tunnel down — respawning ({n}/{MAX_RESPAWNS})…");
                    match spawn_and_parse(local_port, TUNNEL_START_TIMEOUT, &binary) {
                        Ok((fresh_child, url)) => {
                            *child.lock().unwrap() = fresh_child;
                            current_url = url.clone();
                            health_fails = 0;
                            last_health = Instant::now();
                            eprintln!("[quick-tunnel] back up at {url} — re-registering.");
                            on_new_url(url);
                        }
                        Err(e) => {
                            eprintln!("[quick-tunnel] respawn failed: {e}");
                            on_dead();
                            return;
                        }
                    }
                }
            })
            .expect("spawn watchdog thread");
    }

    /// Elastic watchdog: public-URL keepalive + twilight/recovery states.
    ///
    /// Unlike [`Self::watch`], this callback does not publish a rotated URL until the
    /// new public URL has passed `/iicp/health`. This lets callers heartbeat
    /// `available:false` while a tunnel is stale/recovering and only re-register once
    /// the tunnel is publicly usable again.
    pub fn watch_elastic(
        &self,
        initial_url: String,
        on_new_url: impl Fn(String) + Send + 'static,
        on_state: impl Fn(TunnelState) + Send + 'static,
        on_dead: impl FnOnce() + Send + 'static,
    ) {
        self.watch_elastic_with_probe(
            initial_url,
            on_new_url,
            on_state,
            on_dead,
            Arc::new(tunnel_url_reachable_sync),
            TUNNEL_HEALTH_INTERVAL,
            TUNNEL_VERIFY_TIMEOUT,
        );
    }

    /// Elastic watchdog variant for supervised CLIs. The caller can decide
    /// whether a confirmed Dead state should stop the watchdog or retry later.
    pub fn watch_elastic_managed(
        &self,
        initial_url: String,
        on_new_url: impl Fn(String) + Send + 'static,
        on_state: impl Fn(TunnelState) + Send + 'static,
        on_dead: impl FnMut() -> TunnelDeadDecision + Send + 'static,
    ) {
        self.watch_elastic_with_probe_and_dead_policy(
            initial_url,
            on_new_url,
            on_state,
            on_dead,
            Arc::new(tunnel_url_reachable_sync),
            TUNNEL_HEALTH_INTERVAL,
            TUNNEL_VERIFY_TIMEOUT,
        );
    }

    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn watch_elastic_with_probe(
        &self,
        initial_url: String,
        on_new_url: impl Fn(String) + Send + 'static,
        on_state: impl Fn(TunnelState) + Send + 'static,
        on_dead: impl FnOnce() + Send + 'static,
        probe: Arc<dyn Fn(&str) -> bool + Send + Sync + 'static>,
        health_interval: Duration,
        verify_timeout: Duration,
    ) {
        let mut on_dead_once = Some(on_dead);
        self.watch_elastic_with_probe_and_dead_policy(
            initial_url,
            on_new_url,
            on_state,
            move || {
                if let Some(on_dead) = on_dead_once.take() {
                    on_dead();
                }
                TunnelDeadDecision::Stop
            },
            probe,
            health_interval,
            verify_timeout,
        );
    }

    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn watch_elastic_with_probe_and_dead_policy(
        &self,
        initial_url: String,
        on_new_url: impl Fn(String) + Send + 'static,
        on_state: impl Fn(TunnelState) + Send + 'static,
        mut on_dead: impl FnMut() -> TunnelDeadDecision + Send + 'static,
        probe: Arc<dyn Fn(&str) -> bool + Send + Sync + 'static>,
        health_interval: Duration,
        verify_timeout: Duration,
    ) {
        let child = Arc::clone(&self.child);
        let closed = Arc::clone(&self.closed);
        let respawns = Arc::clone(&self.respawns);
        let binary = self.binary.clone();
        let local_port = self.local_port;
        std::thread::Builder::new()
            .name("quick-tunnel-elastic-watchdog".into())
            .spawn(move || {
                let mut current_url = initial_url;
                let mut health_fails: u32 = 0;
                let mut state = TunnelState::Ready;
                on_state(state);
                let mut last_health = Instant::now();

                let set_state = |state_ref: &mut TunnelState, next: TunnelState| {
                    if *state_ref != next {
                        *state_ref = next;
                        on_state(next);
                    }
                };

                loop {
                    loop {
                        {
                            let mut guard = child.lock().unwrap();
                            if let Ok(Some(_)) = guard.try_wait() {
                                break;
                            }
                        }
                        if closed.load(Ordering::Relaxed) {
                            return;
                        }
                        if last_health.elapsed() >= health_interval {
                            last_health = Instant::now();
                            if probe(&current_url) {
                                health_fails = 0;
                                respawns.store(0, Ordering::Relaxed);
                                set_state(&mut state, TunnelState::Ready);
                            } else {
                                health_fails += 1;
                                set_state(&mut state, TunnelState::Twilight);
                                if health_fails >= TUNNEL_HEALTH_MAX_FAILS {
                                    eprintln!(
                                        "[quick-tunnel] {current_url} unreachable {health_fails}× \
                                         while cloudflared is up (twilight) — rebuilding tunnel."
                                    );
                                    set_state(&mut state, TunnelState::Recovering);
                                    let _ = child.lock().unwrap().kill();
                                    health_fails = 0;
                                }
                            }
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    if closed.load(Ordering::Relaxed) {
                        return;
                    }
                    set_state(&mut state, TunnelState::Recovering);
                    let n = respawns.fetch_add(1, Ordering::Relaxed) + 1;
                    if n > MAX_RESPAWNS {
                        eprintln!(
                            "[quick-tunnel] {} consecutive respawns failed to recover a healthy \
                             tunnel — giving up. Node is no longer publicly reachable; restart \
                             `iicp-node serve`.",
                            n - 1
                        );
                        set_state(&mut state, TunnelState::Dead);
                        match on_dead() {
                            TunnelDeadDecision::Stop => return,
                            TunnelDeadDecision::RetryAfter(delay) => {
                                eprintln!(
                                    "[quick-tunnel] dead-state retry policy active — retrying in {}s.",
                                    delay.as_secs()
                                );
                                if sleep_until_closed(closed.as_ref(), delay) {
                                    return;
                                }
                                respawns.store(0, Ordering::Relaxed);
                                health_fails = 0;
                                set_state(&mut state, TunnelState::Recovering);
                                continue;
                            }
                        }
                    }
                    eprintln!("[quick-tunnel] tunnel down — respawning ({n}/{MAX_RESPAWNS})…");
                    match spawn_and_parse(local_port, TUNNEL_START_TIMEOUT, &binary) {
                        Ok((fresh_child, url)) => {
                            *child.lock().unwrap() = fresh_child;
                            current_url = url.clone();
                            health_fails = 0;
                            eprintln!(
                                "[quick-tunnel] candidate tunnel up at {url}; verifying public health…"
                            );
                            if wait_until_reachable(&url, probe.as_ref(), verify_timeout) {
                                last_health = Instant::now();
                                respawns.store(0, Ordering::Relaxed);
                                set_state(&mut state, TunnelState::Ready);
                                eprintln!("[quick-tunnel] verified at {url} — re-registering.");
                                on_new_url(url);
                            } else {
                                eprintln!(
                                    "[quick-tunnel] candidate {url} did not become reachable; rebuilding."
                                );
                                let _ = child.lock().unwrap().kill();
                            }
                        }
                        Err(e) => {
                            eprintln!("[quick-tunnel] respawn failed: {e}");
                            set_state(&mut state, TunnelState::Dead);
                            match extend_retry_for_spawn_error(on_dead(), &e) {
                                TunnelDeadDecision::Stop => return,
                                TunnelDeadDecision::RetryAfter(delay) => {
                                    eprintln!(
                                        "[quick-tunnel] dead-state retry policy active — retrying in {}s.",
                                        delay.as_secs()
                                    );
                                    if sleep_until_closed(closed.as_ref(), delay) {
                                        return;
                                    }
                                    respawns.store(0, Ordering::Relaxed);
                                    health_fails = 0;
                                    set_state(&mut state, TunnelState::Recovering);
                                    continue;
                                }
                            }
                        }
                    }
                }
            })
            .expect("spawn elastic watchdog thread");
    }

    /// Terminate the tunnel child. Idempotent; also runs on Drop.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        let mut guard = self.child.lock().unwrap();
        if matches!(guard.try_wait(), Ok(None)) {
            let _ = guard.kill();
            let _ = guard.wait();
        }
        eprintln!("[quick-tunnel] closed.");
    }
}

impl Drop for QuickTunnel {
    fn drop(&mut self) {
        self.close();
    }
}

/// Spawn cloudflared and return the running tunnel with its public URL.
pub fn open_quick_tunnel(local_port: u16, timeout: Duration) -> Result<QuickTunnel, String> {
    let binary = cloudflared_path().ok_or_else(|| INSTALL_HINT.to_string())?;
    open_quick_tunnel_with(local_port, timeout, &binary)
}

/// Like [`open_quick_tunnel`] but with an explicit binary (tests use a fake).
pub fn open_quick_tunnel_with(
    local_port: u16,
    timeout: Duration,
    binary: &Path,
) -> Result<QuickTunnel, String> {
    let (child, url) = spawn_and_parse(local_port, timeout, binary)?;
    Ok(QuickTunnel {
        child: Arc::new(Mutex::new(child)),
        url,
        local_port,
        binary: binary.to_path_buf(),
        closed: Arc::new(AtomicBool::new(false)),
        respawns: Arc::new(AtomicU32::new(0)),
    })
}

/// Spawn cloudflared and block until its public URL appears (or timeout).
fn spawn_and_parse(
    local_port: u16,
    timeout: Duration,
    binary: &Path,
) -> Result<(Child, String), String> {
    if let Some(remaining) = quick_tunnel_rate_limit_remaining() {
        return Err(format!(
            "accountless Quick Tunnel creation paused for {}s after Cloudflare rate limiting; \
             retry later or configure a named tunnel / IICP_PUBLIC_ENDPOINT",
            remaining.as_secs().max(1)
        ));
    }
    if let Some(remaining) = quick_tunnel_create_gate_remaining() {
        return Err(format!(
            "accountless Quick Tunnel creation paced for {}s to avoid Cloudflare rate limits; \
             falling back to the previous reachability method while the tunnel budget recovers",
            remaining.as_secs().max(1)
        ));
    }
    let _create_lease = acquire_quick_tunnel_create_lease().map_err(|remaining| {
        format!(
            "accountless Quick Tunnel creation held by another local IICP node for {}s; \
             falling back to the previous reachability method",
            remaining.as_secs().max(1)
        )
    })?;
    // Record the attempt before spawning cloudflared. This intentionally spaces
    // both successful and failed creations across local nodes; otherwise a restart
    // storm can hit Cloudflare before a 429/1015 cooldown marker exists.
    mark_quick_tunnel_create_attempt();

    let mut child = Command::new(binary)
        .args(["tunnel", "--url", &format!("http://127.0.0.1:{local_port}")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn cloudflared: {e}"))?;

    // cloudflared logs to stderr; read both to be version-proof. Reader
    // threads keep the pipes drained for the child's whole lifetime so it
    // never blocks on a full pipe.
    let (tx, rx) = mpsc::channel::<String>();
    for reader in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let tx = tx.clone();
        std::thread::Builder::new()
            .name("quick-tunnel-read".into())
            .spawn(move || {
                for line in std::io::BufReader::new(reader)
                    .lines()
                    .map_while(Result::ok)
                {
                    let _ = tx.send(line); // receiver may be gone after URL found — fine
                }
            })
            .expect("spawn reader thread");
    }
    drop(tx);

    let deadline = Instant::now() + timeout;
    let mut last_lines: VecDeque<String> = VecDeque::with_capacity(6);
    let error_with_output = |reason: &str, last_lines: &VecDeque<String>| {
        let mut out = if last_lines.is_empty() {
            reason.to_string()
        } else {
            format!(
                "{reason}; last cloudflared output: {}",
                last_lines
                    .iter()
                    .map(|line| line.trim())
                    .collect::<Vec<_>>()
                    .join(" | ")
            )
        };
        if cloudflared_output_is_rate_limited(last_lines) {
            let cooldown = mark_quick_tunnel_rate_limited();
            out.push_str(&format!(
                "; accountless Quick Tunnel rate limit detected — pausing tunnel creation for {}s",
                cooldown.as_secs()
            ));
        }
        out
    };
    let url = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let _ = child.kill();
            return Err(error_with_output(
                &format!(
                    "cloudflared produced no tunnel URL within {}s",
                    timeout.as_secs()
                ),
                &last_lines,
            ));
        }
        match rx.recv_timeout(remaining) {
            Ok(line) => {
                if last_lines.len() == 6 {
                    last_lines.pop_front();
                }
                last_lines.push_back(line.clone());
                if let Some(u) = extract_url(&line) {
                    break u;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                return Err(error_with_output(
                    &format!(
                        "cloudflared produced no tunnel URL within {}s",
                        timeout.as_secs()
                    ),
                    &last_lines,
                ));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = child.kill();
                return Err(error_with_output(
                    "cloudflared exited before printing a tunnel URL",
                    &last_lines,
                ));
            }
        }
    };

    eprintln!("[quick-tunnel] up: {url} → http://127.0.0.1:{local_port}");
    Ok((child, url))
}

#[cfg(test)]
mod tests {
    use super::*;

    static RATE_LIMIT_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn with_temp_rate_limit_state<T>(f: impl FnOnce() -> T) -> T {
        let _guard = RATE_LIMIT_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap();
        let old_state_file = std::env::var_os("IICP_TUNNEL_RATE_LIMIT_STATE_FILE");
        let old_create_state_file = std::env::var_os("IICP_TUNNEL_CREATE_STATE_FILE");
        let old_create_lock_file = std::env::var_os("IICP_TUNNEL_CREATE_LOCK_FILE");
        let old_cooldown = std::env::var_os("IICP_TUNNEL_RATE_LIMIT_COOLDOWN_S");
        let old_create_interval = std::env::var_os("IICP_TUNNEL_CREATE_MIN_INTERVAL_S");
        let old_create_lease = std::env::var_os("IICP_TUNNEL_CREATE_LEASE_S");
        let path = std::env::temp_dir().join(format!(
            "iicp-quick-tunnel-cooldown-{}.json",
            uuid::Uuid::new_v4()
        ));
        let create_path = std::env::temp_dir().join(format!(
            "iicp-quick-tunnel-create-gate-{}.json",
            uuid::Uuid::new_v4()
        ));
        let lock_path = std::env::temp_dir().join(format!(
            "iicp-quick-tunnel-create-lock-{}.json",
            uuid::Uuid::new_v4()
        ));
        std::env::set_var("IICP_TUNNEL_RATE_LIMIT_STATE_FILE", &path);
        std::env::set_var("IICP_TUNNEL_CREATE_STATE_FILE", &create_path);
        std::env::set_var("IICP_TUNNEL_CREATE_LOCK_FILE", &lock_path);
        std::env::set_var("IICP_TUNNEL_RATE_LIMIT_COOLDOWN_S", "60");
        std::env::set_var("IICP_TUNNEL_CREATE_MIN_INTERVAL_S", "60");
        std::env::set_var("IICP_TUNNEL_CREATE_LEASE_S", "30");
        *quick_tunnel_rate_limit_store().lock().unwrap() = None;
        clear_persistent_rate_limit_if_safe();
        clear_create_gate_if_safe();
        let _ = fs::remove_file(&lock_path);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

        *quick_tunnel_rate_limit_store().lock().unwrap() = None;
        clear_persistent_rate_limit_if_safe();
        clear_create_gate_if_safe();
        let _ = fs::remove_file(&lock_path);
        match old_state_file {
            Some(value) => std::env::set_var("IICP_TUNNEL_RATE_LIMIT_STATE_FILE", value),
            None => std::env::remove_var("IICP_TUNNEL_RATE_LIMIT_STATE_FILE"),
        }
        match old_create_state_file {
            Some(value) => std::env::set_var("IICP_TUNNEL_CREATE_STATE_FILE", value),
            None => std::env::remove_var("IICP_TUNNEL_CREATE_STATE_FILE"),
        }
        match old_create_lock_file {
            Some(value) => std::env::set_var("IICP_TUNNEL_CREATE_LOCK_FILE", value),
            None => std::env::remove_var("IICP_TUNNEL_CREATE_LOCK_FILE"),
        }
        match old_cooldown {
            Some(value) => std::env::set_var("IICP_TUNNEL_RATE_LIMIT_COOLDOWN_S", value),
            None => std::env::remove_var("IICP_TUNNEL_RATE_LIMIT_COOLDOWN_S"),
        }
        match old_create_interval {
            Some(value) => std::env::set_var("IICP_TUNNEL_CREATE_MIN_INTERVAL_S", value),
            None => std::env::remove_var("IICP_TUNNEL_CREATE_MIN_INTERVAL_S"),
        }
        match old_create_lease {
            Some(value) => std::env::set_var("IICP_TUNNEL_CREATE_LEASE_S", value),
            None => std::env::remove_var("IICP_TUNNEL_CREATE_LEASE_S"),
        }

        match result {
            Ok(value) => value,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    #[test]
    fn extract_url_matches_trycloudflare_only() {
        assert_eq!(
            extract_url("INF | https://blue-fox-1.trycloudflare.com |").as_deref(),
            Some("https://blue-fox-1.trycloudflare.com")
        );
        assert_eq!(extract_url("INF | https://example.com"), None);
        assert_eq!(extract_url("no url here"), None);
    }

    #[test]
    fn trycloudflare_host_accepts_only_safe_quick_tunnel_hosts() {
        assert_eq!(
            trycloudflare_host("https://blue-fox-1.trycloudflare.com/iicp/health"),
            Some("blue-fox-1.trycloudflare.com")
        );
        assert_eq!(trycloudflare_host("https://example.com"), None);
        assert_eq!(
            trycloudflare_host("http://blue-fox-1.trycloudflare.com"),
            None
        );
        assert_eq!(
            trycloudflare_host("https://blue_fox.trycloudflare.com"),
            None
        );
    }

    #[test]
    fn likely_dns_error_detection_covers_macos_resolver_wording() {
        assert!(error_message_is_likely_dns(
            "error trying to connect: dns error: failed to lookup address information: \
                 nodename nor servname provided, or not known"
        ));
    }

    #[test]
    fn rate_limit_output_opens_process_local_cooldown() {
        with_temp_rate_limit_state(|| {
            let mut lines = VecDeque::new();
            lines.push_back(
                "ERR Error unmarshaling QuickTunnel response: error code: 1015".to_string(),
            );
            lines.push_back("status_code=\"429 Too Many Requests\"".to_string());
            assert!(cloudflared_output_is_rate_limited(&lines));
            let cooldown = mark_quick_tunnel_rate_limited();
            assert!(cooldown.as_secs() >= 60);
            assert!(quick_tunnel_rate_limit_remaining().is_some());
        });
    }

    #[test]
    fn rate_limit_cooldown_survives_process_local_reset() {
        with_temp_rate_limit_state(|| {
            let cooldown = mark_quick_tunnel_rate_limited();
            assert!(cooldown.as_secs() >= 60);

            // Simulate a supervised restart: in-process state is gone, but the
            // node state directory still carries the Cloudflare cooldown marker.
            *quick_tunnel_rate_limit_store().lock().unwrap() = None;

            let remaining = quick_tunnel_rate_limit_remaining()
                .expect("persistent cooldown should survive process-local reset");
            assert!(remaining.as_secs() >= 1);
            assert!(remaining <= cooldown);
        });
    }

    #[test]
    fn quick_tunnel_creation_gate_spaces_local_services() {
        with_temp_rate_limit_state(|| {
            assert!(quick_tunnel_create_gate_remaining().is_none());
            mark_quick_tunnel_create_attempt();
            let remaining =
                quick_tunnel_create_gate_remaining().expect("create gate should be active");
            assert!(remaining.as_secs() >= 1);
            assert!(remaining <= quick_tunnel_create_min_interval());
        });
    }

    #[test]
    fn quick_tunnel_creation_lease_serializes_parallel_spawns() {
        with_temp_rate_limit_state(|| {
            let lease = acquire_quick_tunnel_create_lease().expect("first lease acquired");
            let blocked = acquire_quick_tunnel_create_lease()
                .expect_err("second local node should be paced by the active lease");
            assert!(blocked.as_secs() >= 1);
            drop(lease);
            assert!(
                acquire_quick_tunnel_create_lease().is_ok(),
                "lease should release on drop"
            );
        });
    }

    #[test]
    fn managed_retry_delay_respects_persistent_rate_limit_pause() {
        let decision = extend_retry_for_spawn_error(
            TunnelDeadDecision::RetryAfter(Duration::from_secs(300)),
            "accountless Quick Tunnel creation paused for 599s after Cloudflare rate limiting",
        );

        assert_eq!(
            decision,
            TunnelDeadDecision::RetryAfter(Duration::from_secs(599))
        );
    }

    #[test]
    fn managed_retry_delay_respects_create_pacing_pause() {
        let decision = extend_retry_for_spawn_error(
            TunnelDeadDecision::RetryAfter(Duration::from_secs(30)),
            "accountless Quick Tunnel creation paced for 119s to avoid Cloudflare rate limits",
        );

        assert_eq!(
            decision,
            TunnelDeadDecision::RetryAfter(Duration::from_secs(119))
        );
    }
}
