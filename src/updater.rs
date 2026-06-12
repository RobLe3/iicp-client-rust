// SPDX-License-Identifier: Apache-2.0
//! Self-updater P1 — read-only version check (#521 WQ-089).
//! Rust parity with iicp-client-python/updater.py and -typescript/updater.ts.
//!
//! Inert by design: reports whether a newer release exists and prints the
//! upgrade command. No download/install/restart (P2/P3 — opt-in, signed).

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

#[cfg(test)]
mod tests {
    use super::*;

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
