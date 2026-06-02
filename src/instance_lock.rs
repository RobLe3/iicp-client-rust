// SPDX-License-Identifier: Apache-2.0

//! #405 — single-instance lock per node_id.
//!
//! Two `iicp-node serve` processes for the SAME node_id fight: each
//! registration rotates the directory-issued token and invalidates the other's,
//! so they enter a 401 → re-register war that makes the node flap in the
//! directory. This guard prevents that by holding a pidfile at
//! `~/.iicp/run/<node_id>.pid`; a second live process for the same node_id is
//! refused (unless `--force`). Distinct node_ids are unaffected — a fleet of N
//! nodes runs fine (each has its own lock).
//!
//! **Fail-open**: any filesystem error degrades to a no-op lock (with a warning)
//! — the guard must never prevent a node from starting.

use std::path::PathBuf;

/// Held for the lifetime of `serve`; removes the pidfile on drop.
pub struct InstanceLock {
    path: PathBuf,
}

impl InstanceLock {
    /// Acquire the per-node_id lock. `Err(message)` if another LIVE process
    /// already serves this node_id and `force` is false. Fails open on I/O error.
    pub fn acquire(node_id: &str, force: bool) -> Result<Self, String> {
        let dir = match crate::identity::config_dir() {
            Ok(d) => d.join("run"),
            Err(_) => {
                return Ok(Self {
                    path: PathBuf::new(),
                })
            } // fail open
        };
        if std::fs::create_dir_all(&dir).is_err() {
            return Ok(Self {
                path: PathBuf::new(),
            }); // fail open
        }
        let path = dir.join(format!("{node_id}.pid"));
        if !force {
            if let Ok(existing) = std::fs::read_to_string(&path) {
                if let Ok(pid) = existing.trim().parse::<i32>() {
                    if pid != std::process::id() as i32 && pid_alive(pid) {
                        return Err(format!(
                            "node_id {node_id} is already being served by PID {pid}. \
                             Stop that process, choose a different --node, or pass --force to take over."
                        ));
                    }
                }
            }
        }
        // Best-effort write; a failure here still yields a (weaker) lock guard.
        let _ = std::fs::write(&path, std::process::id().to_string());
        Ok(Self { path })
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// True if a process with `pid` is alive. Unix: `kill -0` (no signal sent).
/// Non-unix: fail open (assume not alive) so the lock never blocks startup.
#[cfg(unix)]
fn pid_alive(pid: i32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn pid_alive(_pid: i32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::InstanceLock;

    fn with_tmp_home<F: FnOnce()>(f: F) {
        let tmp = std::env::temp_dir().join(format!("iicp_lock_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        std::env::set_var("IICP_HOME", &tmp);
        f();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn live_foreign_pid_is_refused() {
        with_tmp_home(|| {
            // Simulate another live process (same user, signalable) holding the lock
            // by spawning a real child and writing its PID into the pidfile.
            let mut child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("spawn sleep");
            let dir = crate::identity::config_dir().unwrap().join("run");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("dup-node.pid"), child.id().to_string()).unwrap();

            let r = InstanceLock::acquire("dup-node", false);
            let forced = InstanceLock::acquire("dup-node", true);
            let _ = child.kill();
            let _ = child.wait();

            assert!(r.is_err(), "a live foreign PID must refuse the acquire");
            assert!(forced.is_ok(), "force must override");
        });
    }

    #[test]
    fn distinct_nodes_and_release_on_drop() {
        with_tmp_home(|| {
            // distinct node_ids never conflict (fleet case)
            let a = InstanceLock::acquire("node-a", false);
            let b = InstanceLock::acquire("node-b", false);
            assert!(
                a.is_ok() && b.is_ok(),
                "distinct node_ids must both acquire"
            );
            // releasing (drop) frees the lock so it can be re-acquired
            drop(a);
            assert!(
                InstanceLock::acquire("node-a", false).is_ok(),
                "lock must be re-acquirable after drop"
            );
        });
    }
}
