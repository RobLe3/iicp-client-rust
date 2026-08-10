use std::{fs, process::Command};
#[test]
fn service_install_dry_run_plans_effective_systemd_lifecycle() {
    let home = std::env::temp_dir().join(format!("iicp-service-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&home).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_iicp-node"))
        .args([
            "service",
            "install",
            "--node",
            "test",
            "--platform",
            "systemd",
            "--dry-run",
        ])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("systemctl --user daemon-reload"));
    assert!(stdout.contains("systemctl --user enable"));
    assert!(stdout.contains("systemctl --user start"));
    assert!(!home
        .join(".config/systemd/user/network.iicp.node.test.service")
        .exists());
    fs::remove_dir_all(home).unwrap();
}
