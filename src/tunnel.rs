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

use std::io::BufRead;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    Ready,
    Twilight,
    Recovering,
    Dead,
}

/// GET `<url>/iicp/health` round-trips through the Cloudflare edge back to the local
/// node — the same path a browser consumer takes — so it detects an edge-drop, not
/// just a local-process death. Build error → treat as healthy (never self-restart on
/// our own client error). Used by the watchdog from its own (non-tokio) thread.
async fn tunnel_url_reachable(url: &str) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(_) => return true,
    };
    let probe = format!("{}/iicp/health", url.trim_end_matches('/'));
    matches!(client.get(&probe).send().await, Ok(r) if r.status().is_success())
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

    #[doc(hidden)]
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
                        on_dead();
                        return;
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
                            on_dead();
                            return;
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
    binary: &std::path::Path,
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
    binary: &std::path::Path,
) -> Result<(Child, String), String> {
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
    let url = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let _ = child.kill();
            return Err(format!(
                "cloudflared produced no tunnel URL within {}s",
                timeout.as_secs()
            ));
        }
        match rx.recv_timeout(remaining) {
            Ok(line) => {
                if let Some(u) = extract_url(&line) {
                    break u;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                return Err(format!(
                    "cloudflared produced no tunnel URL within {}s",
                    timeout.as_secs()
                ));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = child.kill();
                return Err("cloudflared exited before printing a tunnel URL".into());
            }
        }
    };

    eprintln!("[quick-tunnel] up: {url} → http://127.0.0.1:{local_port}");
    Ok((child, url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_url_matches_trycloudflare_only() {
        assert_eq!(
            extract_url("INF | https://blue-fox-1.trycloudflare.com |").as_deref(),
            Some("https://blue-fox-1.trycloudflare.com")
        );
        assert_eq!(extract_url("INF | https://example.com"), None);
        assert_eq!(extract_url("no url here"), None);
    }
}
