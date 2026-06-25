// SPDX-License-Identifier: Apache-2.0
//! Self-updater P1 — read-only version check (#521 WQ-089).
//! Rust parity with iicp-client-python/updater.py and -typescript/updater.ts.
//!
//! Inert by design: reports whether a newer release exists and prints the
//! upgrade command. No download/install/restart (P2/P3 — opt-in, signed).

use std::sync::{Mutex, OnceLock};

const DEFAULT_AUTO_UPDATE_INTERVAL_SECS: u64 = 3600;

#[derive(Default, Clone)]
struct UpdateStatus {
    latest_seen: Option<String>,
    last_checked_at: Option<String>,
    error_class: Option<String>,
}

static UPDATE_STATUS: OnceLock<Mutex<UpdateStatus>> = OnceLock::new();

fn update_status() -> &'static Mutex<UpdateStatus> {
    UPDATE_STATUS.get_or_init(|| Mutex::new(UpdateStatus::default()))
}

/// Parse a dotted version into a comparable vec; truncate at the first
/// non-numeric segment ("1.2.3-rc1" → [1,2,3]).
pub fn parse_version(v: &str) -> Vec<u64> {
    let mut out = Vec::new();
    for part in v.trim().trim_start_matches(['v', 'V']).split('.') {
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            break;
        }
        match digits.parse::<u64>() {
            Ok(n) => out.push(n),
            Err(_) => break,
        }
    }
    out
}

/// True when `latest` is strictly newer than `current` (numeric, not lex).
pub fn is_outdated(current: &str, latest: &str) -> bool {
    let a = parse_version(current);
    let b = parse_version(latest);
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if y > x {
            return true;
        }
        if y < x {
            return false;
        }
    }
    false
}

pub const UPGRADE_COMMAND: &str = "cargo install iicp-client --force";

/// Fetch the newest published version from crates.io, or None on any error.
/// crates.io requires a descriptive User-Agent.
pub async fn latest_crates_version(timeout_secs: u64) -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .user_agent("iicp-client update-check (+https://iicp.network)")
        .build()
        .ok()?;
    let resp = client
        .get("https://crates.io/api/v1/crates/iicp-client")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let json: serde_json::Value = resp.json().await.ok()?;
    json.get("crate")?
        .get("newest_version")?
        .as_str()
        .map(str::to_string)
}

// ── P2 — background self-updater (#521) ─────────────────────────────────────────
// A node running `serve` periodically checks crates.io and, on a newer release,
// `cargo install --force`s and re-execs onto it. Removes the manual-upgrade
// dependency on downlevel hosters — once a node reaches the first release carrying
// this updater, every future release self-propagates. Default-on; opt out with
// IICP_AUTO_UPDATE=0. Loop-safe (post-upgrade running == latest) + failure-isolated.
// NB: the Rust upgrade recompiles from source (cargo install), so it can take several
// minutes; the node keeps serving until the re-exec.

/// Outcome of one auto-update evaluation (the pure, unit-tested decision).
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateAction {
    Disabled,
    Unknown,
    Current,
    ShouldUpgrade,
}

/// Pure decision: should this node upgrade right now? All I/O (fetch latest,
/// perform upgrade, re-exec) is the caller's; this is the unit-tested rule.
pub fn auto_update_decision(current: &str, latest: Option<&str>, enabled: bool) -> UpdateAction {
    if !enabled {
        return UpdateAction::Disabled;
    }
    match latest {
        None => UpdateAction::Unknown,
        Some(l) if is_outdated(current, l) => UpdateAction::ShouldUpgrade,
        Some(_) => UpdateAction::Current,
    }
}

/// Default-on; IICP_AUTO_UPDATE=0/false/no/off opts out.
pub fn auto_update_enabled() -> bool {
    !matches!(
        std::env::var("IICP_AUTO_UPDATE")
            .unwrap_or_else(|_| "1".into())
            .trim()
            .to_lowercase()
            .as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// Check cadence in seconds (default 1h), floored at 5 min.
pub fn auto_update_interval_secs() -> u64 {
    std::env::var("IICP_AUTO_UPDATE_INTERVAL_S")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(|n| n.max(300))
        .unwrap_or(DEFAULT_AUTO_UPDATE_INTERVAL_SECS)
}

/// Delay before the first background check; never later than five minutes.
pub fn auto_update_initial_delay_secs(interval: u64) -> u64 {
    interval.min(300)
}

/// `cargo install iicp-client --force --features <features>`. True on success.
/// Blocking (recompiles) — call from a blocking context.
pub fn perform_self_update(features: &str) -> bool {
    std::process::Command::new("cargo")
        .args(["install", "iicp-client", "--force", "--features", features])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Record the latest updater check for heartbeat observability.
pub fn record_update_check(latest: Option<String>, error_class: Option<String>) {
    let mut status = update_status().lock().expect("poisoned update status");
    status.latest_seen = latest;
    status.last_checked_at = Some(chrono::Utc::now().to_rfc3339());
    status.error_class = error_class;
}

/// Optional heartbeat fields that let the directory see updater health.
pub fn auto_update_status_json() -> serde_json::Value {
    let status = update_status()
        .lock()
        .expect("poisoned update status")
        .clone();
    serde_json::json!({
        "auto_update_enabled": auto_update_enabled(),
        "auto_update_interval_s": auto_update_interval_secs(),
        "sdk_latest_seen": status.latest_seen,
        "sdk_update_last_checked_at": status.last_checked_at,
        "sdk_update_error_class": status.error_class,
    })
}

/// Re-exec the current command so the just-installed binary runs. On Unix this
/// replaces the process image (like execv) and only returns on error.
#[cfg(unix)]
pub fn reexec() -> std::io::Error {
    use std::os::unix::process::CommandExt;
    let mut args = std::env::args();
    let exe = args.next().unwrap_or_else(|| "iicp-node".into());
    let rest: Vec<String> = args.collect();
    std::process::Command::new(exe).args(rest).exec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_update_decision_matrix() {
        // disabled → never acts
        assert_eq!(
            auto_update_decision("0.7.59", Some("0.7.60"), false),
            UpdateAction::Disabled
        );
        // unknown latest → no-op
        assert_eq!(
            auto_update_decision("0.7.59", None, true),
            UpdateAction::Unknown
        );
        // already current → no-op
        assert_eq!(
            auto_update_decision("0.7.60", Some("0.7.60"), true),
            UpdateAction::Current
        );
        // newer available → upgrade
        assert_eq!(
            auto_update_decision("0.7.59", Some("0.7.60"), true),
            UpdateAction::ShouldUpgrade
        );
        // loop-safety: once on latest, the next tick is Current (no re-upgrade)
        assert_eq!(
            auto_update_decision("0.7.60", Some("0.7.59"), true),
            UpdateAction::Current
        );
    }

    #[test]
    fn auto_update_initial_delay_is_at_most_five_minutes() {
        assert_eq!(auto_update_initial_delay_secs(300), 300);
        assert_eq!(auto_update_initial_delay_secs(900), 300);
        assert_eq!(auto_update_initial_delay_secs(21_600), 300);
    }

    #[test]
    fn auto_update_enabled_env_opt_out() {
        std::env::remove_var("IICP_AUTO_UPDATE");
        assert!(auto_update_enabled());
        for value in ["0", "false", "no", "off"] {
            std::env::set_var("IICP_AUTO_UPDATE", value);
            assert!(!auto_update_enabled());
        }
        std::env::set_var("IICP_AUTO_UPDATE", "1");
        assert!(auto_update_enabled());
        std::env::remove_var("IICP_AUTO_UPDATE");
    }

    #[test]
    fn auto_update_interval_env_floor_and_bad_value() {
        std::env::remove_var("IICP_AUTO_UPDATE_INTERVAL_S");
        assert_eq!(auto_update_interval_secs(), 3600);
        std::env::set_var("IICP_AUTO_UPDATE_INTERVAL_S", "42");
        assert_eq!(auto_update_interval_secs(), 300);
        std::env::set_var("IICP_AUTO_UPDATE_INTERVAL_S", "900");
        assert_eq!(auto_update_interval_secs(), 900);
        std::env::set_var("IICP_AUTO_UPDATE_INTERVAL_S", "not-a-number");
        assert_eq!(auto_update_interval_secs(), 3600);
        std::env::remove_var("IICP_AUTO_UPDATE_INTERVAL_S");
    }

    #[test]
    fn auto_update_status_payload_defaults_hourly() {
        std::env::remove_var("IICP_AUTO_UPDATE");
        std::env::remove_var("IICP_AUTO_UPDATE_INTERVAL_S");
        record_update_check(Some("0.7.67".into()), None);
        let payload = auto_update_status_json();
        assert_eq!(payload["auto_update_enabled"], true);
        assert_eq!(payload["auto_update_interval_s"], 3600);
        assert_eq!(payload["sdk_latest_seen"], "0.7.67");
        assert!(payload["sdk_update_last_checked_at"].is_string());
        assert!(payload["sdk_update_error_class"].is_null());
    }

    #[test]
    fn outdated_is_numeric_not_lexicographic() {
        assert!(is_outdated("0.7.56", "0.7.57"));
        assert!(!is_outdated("0.7.57", "0.7.57"));
        assert!(!is_outdated("0.7.57", "0.7.56"));
        assert!(is_outdated("0.7.9", "0.7.10")); // not lexicographic
        assert!(!is_outdated("1.0.0", "0.9.9"));
        assert!(is_outdated("v0.7.56", "0.7.57")); // leading v tolerated
    }

    #[test]
    fn parse_truncates_prerelease() {
        assert_eq!(parse_version("1.2.3-rc1"), vec![1, 2, 3]);
        assert_eq!(parse_version("0.7.57"), vec![0, 7, 57]);
    }
}
