// SPDX-License-Identifier: Apache-2.0

//! Single-instance lock per node ID.
//!
//! The lock remains the cross-SDK-compatible PID file at
//! `~/.iicp/run/<node_id>.pid`, but acquisition uses an atomic create operation.
//! Process liveness is checked through the operating system rather than an
//! external command.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Held for the lifetime of `serve`; removes only the PID file it owns on drop.
pub struct InstanceLock {
    path: PathBuf,
    owner_pid: u32,
}

impl InstanceLock {
    /// Acquire the per-node-ID lock. A live or unverifiable existing owner is
    /// rejected unless `force` was explicitly requested.
    pub fn acquire(node_id: &str, force: bool) -> Result<Self, String> {
        let dir = crate::identity::config_dir()
            .map_err(|error| format!("cannot resolve IICP configuration directory: {error}"))?
            .join("run");
        fs::create_dir_all(&dir)
            .map_err(|error| format!("cannot create instance-lock directory: {error}"))?;

        let path = dir.join(format!("{node_id}.pid"));
        let owner_pid = std::process::id();
        if force {
            remove_if_present(&path)
                .map_err(|error| format!("cannot replace the existing node lock: {error}"))?;
        }

        for attempt in 0..2 {
            match create_pidfile(&path, owner_pid) {
                Ok(()) => return Ok(Self { path, owner_pid }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let existing = read_owner_pid(&path);
                    if force && attempt == 0 {
                        remove_if_present(&path)
                            .map_err(|error| format!("cannot replace raced node lock: {error}"))?;
                        continue;
                    }
                    if existing == Some(owner_pid) {
                        return Err(already_serving(node_id, existing));
                    }
                    match existing.map(pid_state) {
                        Some(ProcessState::Absent) if attempt == 0 => {
                            remove_if_present(&path).map_err(|error| {
                                format!("cannot remove stale node instance lock: {error}")
                            })?;
                        }
                        _ => return Err(already_serving(node_id, existing)),
                    }
                }
                Err(error) => return Err(format!("cannot create node instance lock: {error}")),
            }
        }

        Err(already_serving(node_id, read_owner_pid(&path)))
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        if read_owner_pid(&self.path) == Some(self.owner_pid) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn create_pidfile(path: &Path, owner_pid: u32) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = write!(file, "{owner_pid}").and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn read_owner_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn already_serving(node_id: &str, pid: Option<u32>) -> String {
    let owner = pid
        .map(|pid| format!("PID {pid}"))
        .unwrap_or_else(|| "an unknown or unverifiable process".to_string());
    format!(
        "node_id {node_id} is already being served by {owner}. Stop that process, choose a different --node, or pass --force to take over."
    )
}

#[derive(Debug, Eq, PartialEq)]
enum ProcessState {
    Alive,
    Absent,
    Indeterminate,
}

#[cfg(unix)]
fn pid_state(pid: u32) -> ProcessState {
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return ProcessState::Alive;
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => ProcessState::Absent,
        Some(libc::EPERM) => ProcessState::Alive,
        _ => ProcessState::Indeterminate,
    }
}

#[cfg(not(unix))]
fn pid_state(_pid: u32) -> ProcessState {
    ProcessState::Indeterminate
}

#[cfg(test)]
mod tests {
    use super::{pid_state, InstanceLock, ProcessState};
    use std::sync::{Arc, Barrier, Mutex, OnceLock};

    fn environment_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn with_tmp_home<F: FnOnce(&std::path::Path)>(f: F) {
        let _guard = environment_lock();
        let tmp = std::env::temp_dir().join(format!(
            "iicp_lock_test_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("IICP_HOME", &tmp);
        f(&tmp);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[cfg(unix)]
    #[test]
    fn live_foreign_pid_is_refused_without_external_kill() {
        with_tmp_home(|home| {
            let mut child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            let run = home.join("run");
            std::fs::create_dir_all(&run).unwrap();
            std::fs::write(run.join("dup-node.pid"), child.id().to_string()).unwrap();
            assert!(InstanceLock::acquire("dup-node", false).is_err());
            assert!(InstanceLock::acquire("dup-node", true).is_ok());
            let _ = child.kill();
            let _ = child.wait();
        });
    }

    #[test]
    fn stale_pid_is_recovered() {
        with_tmp_home(|home| {
            let run = home.join("run");
            std::fs::create_dir_all(&run).unwrap();
            std::fs::write(run.join("stale.pid"), "2147483647").unwrap();
            assert!(InstanceLock::acquire("stale", false).is_ok());
        });
    }

    #[test]
    fn malformed_existing_owner_fails_closed() {
        with_tmp_home(|home| {
            let run = home.join("run");
            std::fs::create_dir_all(&run).unwrap();
            std::fs::write(run.join("bad.pid"), "not-a-pid").unwrap();
            assert!(InstanceLock::acquire("bad", false).is_err());
            assert!(InstanceLock::acquire("bad", true).is_ok());
        });
    }

    #[test]
    fn simultaneous_acquire_has_one_winner() {
        with_tmp_home(|_| {
            let barrier = Arc::new(Barrier::new(3));
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        InstanceLock::acquire("race", false)
                    })
                })
                .collect();
            barrier.wait();
            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        });
    }

    #[test]
    fn old_owner_does_not_remove_replacement_lock() {
        with_tmp_home(|home| {
            let old = InstanceLock::acquire("replace", false).unwrap();
            let path = home.join("run/replace.pid");
            std::fs::write(&path, "2147483647").unwrap();
            drop(old);
            assert!(path.is_file());
        });
    }

    #[test]
    fn distinct_nodes_and_release_on_drop() {
        with_tmp_home(|_| {
            let a = InstanceLock::acquire("node-a", false).unwrap();
            let b = InstanceLock::acquire("node-b", false).unwrap();
            drop(a);
            assert!(InstanceLock::acquire("node-a", false).is_ok());
            drop(b);
        });
    }

    #[test]
    fn current_pid_is_alive_and_impossible_pid_is_absent() {
        assert_eq!(pid_state(std::process::id()), ProcessState::Alive);
        #[cfg(unix)]
        assert_eq!(pid_state(2_147_483_647), ProcessState::Absent);
    }
}
