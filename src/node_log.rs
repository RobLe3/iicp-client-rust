// SPDX-License-Identifier: Apache-2.0
//! Persistent node log writer — `~/.iicp/logs/<node-id>.log` + `events.jsonl`.
//! Used for registration, heartbeat, and deregistration events.
//!
//! Both files are append-only. Rotation triggers when either file exceeds
//! `MAX_LOG_BYTES` (10 MiB); up to `MAX_ROTATIONS` (3) generations are kept.
//! This module contains no credentials — callers MUST NOT pass token/key values.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB
const MAX_ROTATIONS: u32 = 3;

/// Thread-safe file logger for a single IICP node.
pub struct NodeLog {
    text_path: PathBuf,
    jsonl_path: PathBuf,
    /// Serialises rotation + append so two concurrent heartbeats don't race.
    lock: Mutex<()>,
}

impl NodeLog {
    /// Open (or create) the log directory and return a `NodeLog` for `node_id`.
    /// `log_dir` is created recursively if absent.
    pub fn open(log_dir: &Path, node_id: &str) -> std::io::Result<Self> {
        fs::create_dir_all(log_dir)?;
        Ok(Self {
            text_path: log_dir.join(format!("{node_id}.log")),
            jsonl_path: log_dir.join("events.jsonl"),
            lock: Mutex::new(()),
        })
    }

    /// Write one event to both the text log and `events.jsonl`.
    ///
    /// `event` is a snake_case key (e.g. `"register_ok"`, `"heartbeat_fail"`).
    /// `details` is a flat string appended verbatim to the human-readable line;
    /// it MUST NOT contain secret material.
    pub fn write(&self, event: &str, node_id: &str, details: &str) {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let ts = iso_now();
        let text = format!("{ts} [{event}] node={node_id} {details}\n");
        let jsonl = format!(
            "{{\"ts\":\"{ts}\",\"event\":\"{event}\",\"node_id\":\"{node_id}\",\"details\":\"{}\"}}\n",
            details.replace('"', "'")
        );
        let _ = self.append_rotating(&self.text_path, text.as_bytes());
        let _ = self.append_rotating(&self.jsonl_path, jsonl.as_bytes());
    }

    fn append_rotating(&self, path: &Path, data: &[u8]) -> std::io::Result<()> {
        if let Ok(m) = fs::metadata(path) {
            if m.len() >= MAX_LOG_BYTES {
                rotate(path);
            }
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?
            .write_all(data)
    }
}

fn rotate(path: &Path) {
    for i in (1..MAX_ROTATIONS).rev() {
        let from = suffixed(path, i);
        let to = suffixed(path, i + 1);
        let _ = fs::rename(from, to);
    }
    let _ = fs::rename(path, suffixed(path, 1));
}

fn suffixed(path: &Path, n: u32) -> PathBuf {
    let mut s = path.to_path_buf().into_os_string();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

fn iso_now() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let (y, mon, day, h, min, sec) = epoch_to_datetime(secs);
    format!("{y:04}-{mon:02}-{day:02}T{h:02}:{min:02}:{sec:02}Z")
}

fn epoch_to_datetime(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    // Minimal Gregorian calendar — avoids adding chrono formatting feature.
    let sec = (secs % 60) as u32;
    let min = ((secs / 60) % 60) as u32;
    let h = ((secs / 3600) % 24) as u32;
    let days = (secs / 86400) as u32;
    // Days since 1970-01-01
    let mut year = 1970u32;
    let mut rem = days;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if rem < dy {
            break;
        }
        rem -= dy;
        year += 1;
    }
    let leap = is_leap(year);
    let months = [31u32, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mon = 1u32;
    for &m in &months {
        if rem < m {
            break;
        }
        rem -= m;
        mon += 1;
    }
    (year, mon, rem + 1, h, min, sec)
}

fn is_leap(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    static TEST_CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn tmp_dir() -> PathBuf {
        // Use a monotonic counter to guarantee uniqueness across parallel tests.
        let id = TEST_CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("iicp_log_test_{id}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn creates_log_files() {
        let dir = tmp_dir();
        let log = NodeLog::open(&dir, "test-node").unwrap();
        log.write("register_ok", "test-node", "endpoint=http://localhost:9484");
        assert!(dir.join("test-node.log").exists());
        assert!(dir.join("events.jsonl").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn text_log_contains_event() {
        let dir = tmp_dir();
        let log = NodeLog::open(&dir, "abc").unwrap();
        log.write("heartbeat_ok", "abc", "seq=1");
        let content = fs::read_to_string(dir.join("abc.log")).unwrap();
        assert!(content.contains("heartbeat_ok"));
        assert!(content.contains("abc"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn jsonl_is_valid_json() {
        let dir = tmp_dir();
        let log = NodeLog::open(&dir, "n1").unwrap();
        log.write("register_fail", "n1", "error=timeout");
        let line = fs::read_to_string(dir.join("events.jsonl")).unwrap();
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["event"], "register_fail");
        assert_eq!(v["node_id"], "n1");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_on_size_limit() {
        let dir = tmp_dir();
        let log = NodeLog::open(&dir, "r").unwrap();
        // Write MAX_LOG_BYTES + 1 so the size check ">= MAX_LOG_BYTES" is unambiguously true.
        let padding: Vec<u8> = vec![b'X'; MAX_LOG_BYTES as usize + 1];
        fs::write(dir.join("r.log"), &padding).unwrap();
        let pre_size = fs::metadata(dir.join("r.log")).unwrap().len();
        assert!(pre_size > MAX_LOG_BYTES, "padding not written correctly: {pre_size}");
        log.write("serve_start", "r", "port=9484");
        // Original file was renamed to .1; new file exists with the event.
        assert!(
            dir.join("r.log.1").exists(),
            "rotation did not create r.log.1; r.log size was {pre_size}"
        );
        let new = fs::read_to_string(dir.join("r.log")).unwrap();
        assert!(new.contains("serve_start"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn iso_now_format() {
        let ts = iso_now();
        // Expect 20 chars: YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
    }
}
