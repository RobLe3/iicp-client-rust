use std::fs;

const CARGO_TOML: &str = include_str!("../Cargo.toml");
const CARGO_LOCK: &str = include_str!("../Cargo.lock");
const QUALITY_RUNNER: &str = include_str!("../scripts/run_sdk_quality.py");
const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const UPDATER: &str = include_str!("../src/updater.rs");
const NODE: &str = include_str!("../src/bin/iicp_node.rs");

fn declared_package_field(name: &str) -> &str {
    CARGO_TOML
        .lines()
        .find_map(|line| {
            let (field, value) = line.split_once(" = ")?;
            (field == name).then(|| value.trim_matches('"'))
        })
        .unwrap()
}

#[test]
fn minimum_rust_version_is_declared_and_candidate_remains_pre1() {
    assert_eq!(declared_package_field("rust-version"), "1.86");
    assert_eq!(env!("CARGO_PKG_RUST_VERSION"), "1.86");
    assert_eq!(env!("CARGO_PKG_VERSION").split('.').next(), Some("0"));
}

#[test]
fn package_version_self_report_matches_candidate_contract() {
    assert_eq!(declared_package_field("name"), "iicp-client");
    assert_eq!(declared_package_field("version"), env!("CARGO_PKG_VERSION"));
    assert!(fs::read_to_string("README.md").unwrap().contains(&format!(
        "cargo install iicp-client --version {} --locked",
        env!("CARGO_PKG_VERSION")
    )));
}

#[test]
fn offline_candidate_contract_pins_locked_release_inputs() {
    assert!(CARGO_LOCK.contains("name = \"iicp-client\""));
    assert!(CARGO_LOCK.contains(&format!("version = \"{}\"", env!("CARGO_PKG_VERSION"))));
    for contract in [QUALITY_RUNNER, RELEASE_WORKFLOW] {
        assert!(contract.contains("package"));
        assert!(contract.contains("--locked"));
        assert!(contract.contains("install"));
    }
    assert!(RELEASE_WORKFLOW.contains("tar -tzf \"$crate\""));
    assert!(RELEASE_WORKFLOW.contains("/Cargo.lock$"));
}

#[test]
fn failed_update_preserves_current_runtime_and_uses_bounded_retry() {
    assert!(UPDATER.contains("cargo"));
    assert!(UPDATER.contains("--version"));
    assert!(UPDATER.contains("--locked"));
    assert!(UPDATER.contains("--registry"));
    assert!(UPDATER.contains("candidate_backoff_is_bounded_and_persisted_atomically"));
    let success = NODE.find("if ok {").unwrap();
    let reexec = success + NODE[success..].find("updater::reexec()").unwrap();
    let failure = reexec + NODE[reexec..].find("cargo_install_failed").unwrap();
    assert!(success < reexec && reexec < failure);
    assert!(NODE[success..reexec].contains("record_update_result"));
    assert!(NODE[success..reexec].contains("true"));
    assert!(NODE[failure..].contains("upgrade failed; will retry after bounded backoff"));
}
