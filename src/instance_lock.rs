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
    owner_token: Option<String>,
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
        let owner_token = process_token(owner_pid);
        if force {
            remove_lock_files(&path)
                .map_err(|error| format!("cannot replace the existing node lock: {error}"))?;
        }

        for attempt in 0..2 {
            match create_pidfile(&path, owner_pid, owner_token.as_deref()) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        owner_pid,
                        owner_token,
                    })
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let existing = read_owner_pid(&path);
                    if force && attempt == 0 {
                        remove_lock_files(&path)
                            .map_err(|error| format!("cannot replace raced node lock: {error}"))?;
                        continue;
                    }
                    match existing.map(|pid| owner_state(&path, pid)) {
                        Some(OwnerState::Stale) if attempt == 0 => {
                            remove_lock_files(&path).map_err(|error| {
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
        if read_owner_pid(&self.path) == Some(self.owner_pid)
            && read_owner_token(&self.path) == self.owner_token
        {
            let _ = remove_lock_files(&self.path);
        }
    }
}

fn create_pidfile(path: &Path, owner_pid: u32, owner_token: Option<&str>) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = write!(file, "{owner_pid}").and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    if let Some(token) = owner_token {
        let metadata_path = metadata_path(path);
        if let Err(error) = remove_if_present(&metadata_path) {
            let _ = fs::remove_file(path);
            return Err(error);
        }
        let mut metadata = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&metadata_path)
        {
            Ok(value) => value,
            Err(error) => {
                let _ = fs::remove_file(path);
                return Err(error);
            }
        };
        if let Err(error) = write!(metadata, "{token}").and_then(|_| metadata.sync_all()) {
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(metadata_path);
            return Err(error);
        }
    }
    Ok(())
}

fn read_owner_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn metadata_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.meta", path.display()))
}

fn read_owner_token(path: &Path) -> Option<String> {
    fs::read_to_string(metadata_path(path))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn remove_lock_files(path: &Path) -> io::Result<()> {
    let pid_result = remove_if_present(path);
    let metadata_result = remove_if_present(&metadata_path(path));
    pid_result.and(metadata_result)
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

#[derive(Debug, Eq, PartialEq)]
enum OwnerState {
    Current,
    Stale,
    Indeterminate,
}

fn owner_state(path: &Path, pid: u32) -> OwnerState {
    match pid_state(pid) {
        ProcessState::Absent => OwnerState::Stale,
        ProcessState::Indeterminate => OwnerState::Indeterminate,
        ProcessState::Alive => match (read_owner_token(path), process_token(pid)) {
            (Some(recorded), Some(current)) if recorded != current => OwnerState::Stale,
            (Some(_), Some(_)) | (None, _) | (_, None) => OwnerState::Current,
        },
    }
}

/// Linux exposes a boot identity and a per-process start tick. Together they
/// distinguish a restarted container's new PID 1 from the previous PID 1 while
/// keeping the public lock file itself a cross-SDK-compatible decimal PID.
#[cfg(target_os = "linux")]
fn process_token(pid: u32) -> Option<String> {
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_name = stat.rsplit_once(") ")?.1;
    let start_ticks = after_name.split_whitespace().nth(19)?;
    Some(format!("{}:{}", boot.trim(), start_ticks))
}

#[cfg(not(target_os = "linux"))]
fn process_token(_pid: u32) -> Option<String> {
    None
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
    #[cfg(target_os = "linux")]
    use super::{metadata_path, process_token};
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

    #[cfg(target_os = "linux")]
    #[test]
    fn reused_live_pid_with_different_process_identity_is_recovered() {
        with_tmp_home(|home| {
            let run = home.join("run");
            std::fs::create_dir_all(&run).unwrap();
            let path = run.join("reused.pid");
            std::fs::write(&path, std::process::id().to_string()).unwrap();
            std::fs::write(metadata_path(&path), "different-boot:different-start").unwrap();
            assert!(InstanceLock::acquire("reused", false).is_ok());
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_pid_with_matching_process_identity_is_refused() {
        with_tmp_home(|home| {
            let run = home.join("run");
            std::fs::create_dir_all(&run).unwrap();
            let path = run.join("current.pid");
            let pid = std::process::id();
            std::fs::write(&path, pid.to_string()).unwrap();
            std::fs::write(metadata_path(&path), process_token(pid).unwrap()).unwrap();
            assert!(InstanceLock::acquire("current", false).is_err());
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
