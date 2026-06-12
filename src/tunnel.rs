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
/// Bounded self-healing: after this many unexpected deaths, stop respawning.
pub const MAX_RESPAWNS: u32 = 3;

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
                loop {
                    // Poll instead of blocking wait(): close() needs the lock too.
                    loop {
                        {
                            let mut guard = child.lock().unwrap();
                            if let Ok(Some(_)) = guard.try_wait() {
                                break;
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
                            "[quick-tunnel] died {} times — giving up. Node is no longer \
                             publicly reachable; restart `iicp-node serve` to recover.",
                            n - 1
                        );
                        on_dead();
                        return;
                    }
                    eprintln!(
                        "[quick-tunnel] exited unexpectedly — respawning ({n}/{MAX_RESPAWNS})…"
                    );
                    match spawn_and_parse(local_port, TUNNEL_START_TIMEOUT, &binary) {
                        Ok((fresh_child, url)) => {
                            *child.lock().unwrap() = fresh_child;
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
