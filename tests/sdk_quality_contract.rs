use std::fs;

#[test]
fn quality_runner_uses_shared_content_free_contract() {
    let source = fs::read_to_string("scripts/run_sdk_quality.py").unwrap();
    assert!(source.contains("iicp.sdk-quality-evidence.v1"));
    assert!(source.contains("COVERAGE_MINIMUM = 64.0"));
    assert!(source.contains("1.86.0"));
    assert!(!source.contains("\"commands\""));
}

#[test]
fn quality_documentation_is_explicit_about_crates_provenance() {
    let documentation = fs::read_to_string("QUALITY.md").unwrap();
    assert!(documentation.contains("scoped token"));
    assert!(documentation.contains("does not claim OIDC provenance parity"));
}
