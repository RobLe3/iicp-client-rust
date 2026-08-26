use iicp_client::runtime_health::{write_snapshot_atomic, RuntimeHealth};
use std::{fs, process::Command};

fn home() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("iicp-health-cli-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn healthcheck_reports_live_snapshot() {
    let home = home();
    let health = RuntimeHealth::new(false);
    health.mark_running();
    health.advance_runtime();
    let path = home.join(".iicp/run/test-node/health-v1.json");
    write_snapshot_atomic(&path, &health.snapshot()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_iicp-node"))
        .args(["healthcheck", "--node", "test-node", "--json"])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["health_schema_version"], 1);
    assert_eq!(value["liveness"], "live");
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn healthcheck_missing_snapshot_is_indeterminate() {
    let home = home();
    let output = Command::new(env!("CARGO_BIN_EXE_iicp-node"))
        .args(["healthcheck", "--node", "missing"])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn healthcheck_honors_iicp_home() {
    let home = home();
    let iicp_home = home.join("custom-iicp");
    let health = RuntimeHealth::new(false);
    health.mark_running();
    health.advance_runtime();
    let path = iicp_home.join("run/test-node/health-v1.json");
    write_snapshot_atomic(&path, &health.snapshot()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_iicp-node"))
        .args(["healthcheck", "--node", "test-node", "--json"])
        .env("HOME", &home)
        .env("IICP_HOME", &iicp_home)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["health_schema_version"], 1);
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn healthcheck_reads_legacy_default_home_only_when_canonical_is_missing() {
    let home = home();
    let iicp_home = home.join("custom-iicp");
    let health = RuntimeHealth::new(false);
    health.mark_running();
    health.advance_runtime();
    let legacy = home.join(".iicp/run/test-node/health-v1.json");
    write_snapshot_atomic(&legacy, &health.snapshot()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_iicp-node"))
        .args(["healthcheck", "--node", "test-node", "--json"])
        .env("HOME", &home)
        .env("IICP_HOME", &iicp_home)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("legacy runtime-health snapshot"));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["health_schema_version"], 1);
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn healthcheck_prefers_iicp_home_over_legacy_default_home() {
    let home = home();
    let iicp_home = home.join("custom-iicp");
    let canonical_health = RuntimeHealth::new(false);
    canonical_health.mark_running();
    canonical_health.advance_runtime();
    write_snapshot_atomic(
        &iicp_home.join("run/test-node/health-v1.json"),
        &canonical_health.snapshot(),
    )
    .unwrap();
    fs::create_dir_all(home.join(".iicp/run/test-node")).unwrap();
    fs::write(home.join(".iicp/run/test-node/health-v1.json"), b"invalid").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_iicp-node"))
        .args(["healthcheck", "--node", "test-node", "--json"])
        .env("HOME", &home)
        .env("IICP_HOME", &iicp_home)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    fs::remove_dir_all(home).unwrap();
}
