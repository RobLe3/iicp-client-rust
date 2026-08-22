use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use std::{fs, thread};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
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

#[cfg(unix)]
#[test]
fn supervised_local_only_start_resolves_protected_refs_without_prompt() {
    let root = std::env::temp_dir().join(format!("iicp-service-{}", uuid::Uuid::new_v4()));
    let nodes = root.join("nodes");
    let secrets = root.join("secrets");
    fs::create_dir_all(&nodes).unwrap();
    fs::create_dir_all(&secrets).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&nodes, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).unwrap();
    let token_path = secrets.join("node-token");
    let hmac_path = secrets.join("node-hmac-key");
    fs::write(&token_path, "protected-token").unwrap();
    fs::write(&hmac_path, "protected-hmac").unwrap();
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&hmac_path, fs::Permissions::from_mode(0o600)).unwrap();
    let identity = serde_json::json!({
        "node_id": "service-ref-test",
        "operator_id": "",
        "name": "test",
        "backend_url": "http://127.0.0.1:1",
        "backend_type": "openai_compat",
        "model": "test-model",
        "intent": "urn:iicp:intent:llm:chat:v1",
        "region": "local",
        "directory_url": "http://127.0.0.1:1",
        "max_concurrent": 1,
        "port": 9484,
        "host": "127.0.0.1",
        "public_endpoint": "",
        "auto_detect_nat": false,
        "external_ip_probe_url": "",
        "supported_receipt_profiles": [],
        "secret_refs": {
            "node_token": {"source":"file", "path": token_path},
            "node_hmac_key": {"source":"file", "path": hmac_path}
        },
        "created_at": "2026-08-22T00:00:00Z"
    });
    let identity_path = nodes.join("test.json");
    fs::write(
        &identity_path,
        serde_json::to_vec_pretty(&identity).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600)).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_iicp-node"))
        .args([
            "serve",
            "--node",
            "test",
            "--mode",
            "local-only",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--no-auto-detect-nat",
        ])
        .env("IICP_HOME", &root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let response = loop {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("supervised node exited before health check: {status}");
        }
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            stream
                .write_all(
                    b"GET /iicp/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            break response;
        }
        assert!(
            Instant::now() < deadline,
            "node health endpoint did not start"
        );
        thread::sleep(Duration::from_millis(50));
    };
    assert!(response.starts_with("HTTP/1.1 200"));
    child.kill().unwrap();
    child.wait().unwrap();
    let persisted = fs::read_to_string(identity_path).unwrap();
    assert!(!persisted.contains("protected-token"));
    assert!(!persisted.contains("protected-hmac"));
    fs::remove_dir_all(root).unwrap();
}
