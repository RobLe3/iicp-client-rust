use serde_json::Value;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_iicp-node"))
}

#[test]
fn public_and_local_only_reports_are_valid_without_side_effects() {
    for mode in ["public", "local_only"] {
        let output = command()
            .args(["config", "wizard", "--mode", mode])
            .output()
            .unwrap();
        assert!(output.status.success());
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["valid"], true);
        assert_eq!(report["config"]["mode"], mode);
    }
}

#[test]
fn private_writes_only_after_validation_and_matches_the_report() {
    let root = std::env::temp_dir().join(format!("iicp-wizard-{}", uuid::Uuid::new_v4()));
    let path = root.join("private.json");
    let output = command()
        .args([
            "config",
            "wizard",
            "--mode",
            "private",
            "--directory-url",
            "https://directory.example/api",
            "--directory-authority",
            "did:key:directory",
            "--trust-domain",
            "example.internal",
            "--membership-env",
            "IICP_MEMBERSHIP",
            "--output",
            path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let written: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(report["config"], written);
    assert_eq!(
        written["membership"]["credential"]["name"],
        "IICP_MEMBERSHIP"
    );
    let serialized = written.to_string();
    assert!(!serialized.contains("node_token"));
    assert!(!serialized.contains("private_key"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn invalid_private_and_reserved_federation_do_not_write() {
    for mode in ["private", "federated_private"] {
        let root = std::env::temp_dir().join(format!("iicp-wizard-{}", uuid::Uuid::new_v4()));
        let path = root.join("invalid.json");
        let output = command()
            .args([
                "config",
                "wizard",
                "--mode",
                mode,
                "--output",
                path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!path.exists());
    }
}

#[test]
fn interactive_and_noninteractive_paths_project_identical_public_config() {
    let expected = command()
        .args(["config", "wizard", "--mode", "public"])
        .output()
        .unwrap();
    let mut child = command()
        .args(["config", "wizard", "--interactive"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"public\n")
        .unwrap();
    let interactive = child.wait_with_output().unwrap();
    assert!(interactive.status.success());
    let expected: Value = serde_json::from_slice(&expected.stdout).unwrap();
    let prompt_and_json = String::from_utf8(interactive.stdout).unwrap();
    let start = prompt_and_json.find('{').unwrap();
    let actual: Value = serde_json::from_str(&prompt_and_json[start..]).unwrap();
    assert_eq!(expected["config"], actual["config"]);
    assert_eq!(expected["reproduce_argv"], actual["reproduce_argv"]);
}

#[test]
fn interactive_eof_is_a_bounded_cancellation() {
    let output = command()
        .args(["config", "wizard", "--interactive"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("wizard cancelled"));
}
