// SPDX-License-Identifier: Apache-2.0
//! Side-effect-free configuration wizard projection.
//!
//! Interactive and non-interactive front ends both construct `WizardRequest`
//! and use this module. The wizard never owns a second configuration model.

use crate::runtime_config::{
    ConfigFinding, OperatingMode, RuntimeConfigV1, SecretRef, PUBLIC_DIRECTORY_URL,
};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WizardRequest {
    pub mode: OperatingMode,
    pub directory_url: Option<String>,
    pub directory_authority: Option<String>,
    pub trust_domain_id: Option<String>,
    pub trusted_domains: Vec<String>,
    pub membership_credential: Option<SecretRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WizardSummary {
    pub mode: &'static str,
    pub directory: String,
    pub trust_domain: Option<String>,
    pub membership: &'static str,
    pub public_fallback: bool,
    pub federation: &'static str,
    pub enrollment_handoff: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WizardReport {
    pub report_version: &'static str,
    pub valid: bool,
    pub config: RuntimeConfigV1,
    pub findings: Vec<ConfigFinding>,
    pub summary: WizardSummary,
    /// Safe argv representation; consumers must not reconstruct a shell string.
    pub reproduce_argv: Vec<String>,
}

impl WizardRequest {
    pub fn build(self) -> WizardReport {
        let mut config = RuntimeConfigV1::preset(self.mode);
        if let Some(url) = self.directory_url.filter(|value| !value.trim().is_empty()) {
            config.directory.url = Some(url);
        }
        config.directory.authority_id = self
            .directory_authority
            .filter(|value| !value.trim().is_empty());
        config.trust_domain_id = self
            .trust_domain_id
            .filter(|value| !value.trim().is_empty());
        config.federation.trusted_domains = self
            .trusted_domains
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect();
        config.membership.credential = self.membership_credential;

        let findings = config.validate();
        let summary = WizardSummary::from_config(&config);
        let reproduce_argv = reproduction_argv(&config);
        WizardReport {
            report_version: "iicp.config-wizard-report.v1",
            valid: findings.is_empty(),
            config,
            findings,
            summary,
            reproduce_argv,
        }
    }
}

impl WizardSummary {
    fn from_config(config: &RuntimeConfigV1) -> Self {
        let restricted = matches!(
            config.mode,
            OperatingMode::Private | OperatingMode::FederatedPrivate
        );
        Self {
            mode: mode_name(config.mode),
            directory: config
                .directory
                .url
                .clone()
                .unwrap_or_else(|| "local/static only".into()),
            trust_domain: config.trust_domain_id.clone(),
            membership: if restricted {
                "authenticated membership required"
            } else {
                "not required by this preset"
            },
            public_fallback: config.network.allow_public_fallback,
            federation: if config.mode == OperatingMode::FederatedPrivate {
                "configured but unavailable pending Phase 6 evidence"
            } else if config.federation.enabled {
                "enabled"
            } else {
                "disabled"
            },
            enrollment_handoff: if restricted && config.membership.credential.is_none() {
                "obtain membership externally and add a secret reference"
            } else if restricted {
                "membership secret reference configured"
            } else {
                "not applicable"
            },
        }
    }
}

pub fn mode_name(mode: OperatingMode) -> &'static str {
    match mode {
        OperatingMode::Public => "public",
        OperatingMode::Private => "private",
        OperatingMode::FederatedPrivate => "federated_private",
        OperatingMode::LocalOnly => "local_only",
        OperatingMode::Custom => "custom",
    }
}

fn reproduction_argv(config: &RuntimeConfigV1) -> Vec<String> {
    let mut argv = vec![
        "iicp-node".into(),
        "config".into(),
        "wizard".into(),
        "--mode".into(),
        mode_name(config.mode).into(),
    ];
    if config.directory.url.as_deref() != Some(PUBLIC_DIRECTORY_URL) {
        if let Some(value) = &config.directory.url {
            argv.extend(["--directory-url".into(), value.clone()]);
        }
    }
    if config.directory.local_discovery_enabled {
        argv.extend(["--local-directory-discovery".into(), "true".into()]);
    }
    if let Some(value) = &config.directory.authority_id {
        argv.extend(["--directory-authority".into(), value.clone()]);
    }
    if let Some(value) = &config.trust_domain_id {
        argv.extend(["--trust-domain".into(), value.clone()]);
    }
    for value in &config.federation.trusted_domains {
        argv.extend(["--trusted-domain".into(), value.clone()]);
    }
    if let Some(SecretRef::Environment { name }) = &config.membership.credential {
        argv.extend(["--membership-env".into(), name.clone()]);
    }
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(mode: OperatingMode) -> WizardRequest {
        WizardRequest {
            mode,
            directory_url: None,
            directory_authority: None,
            trust_domain_id: None,
            trusted_domains: Vec::new(),
            membership_credential: None,
        }
    }

    #[test]
    fn public_local_and_custom_presets_are_valid_and_headless() {
        for mode in [
            OperatingMode::Public,
            OperatingMode::LocalOnly,
            OperatingMode::Custom,
        ] {
            let report = request(mode).build();
            assert!(report.valid);
            assert_eq!(
                report.reproduce_argv[0..3],
                ["iicp-node", "config", "wizard"]
            );
        }
    }

    #[test]
    fn private_requires_domain_and_authority_before_any_writer_can_commit() {
        let report = request(OperatingMode::Private).build();
        assert!(!report.valid);
        assert_eq!(
            report
                .findings
                .iter()
                .map(|item| item.code)
                .collect::<Vec<_>>(),
            ["trust_domain_required", "directory_authority_required"]
        );
    }

    #[test]
    fn private_projection_is_deterministic_and_contains_only_a_secret_reference() {
        let mut input = request(OperatingMode::Private);
        input.directory_url = Some("https://directory.example/api".into());
        input.directory_authority = Some("did:key:directory".into());
        input.trust_domain_id = Some("example.internal".into());
        input.membership_credential = Some(SecretRef::Environment {
            name: "IICP_MEMBERSHIP".into(),
        });
        let first = input.clone().build();
        let second = input.build();
        assert_eq!(first, second);
        assert!(first.valid);
        let json = serde_json::to_string(&first).unwrap();
        assert!(json.contains("IICP_MEMBERSHIP"));
        assert!(!json.contains("node_token"));
        assert!(!json.contains("private_key"));
    }

    #[test]
    fn federated_private_is_projected_but_explicitly_unavailable() {
        let mut input = request(OperatingMode::FederatedPrivate);
        input.directory_authority = Some("did:key:a".into());
        input.trust_domain_id = Some("a.example".into());
        input.trusted_domains = vec!["b.example".into()];
        let report = input.build();
        assert!(!report.valid);
        assert_eq!(report.findings[0].code, "federated_private_not_supported");
        assert!(report.summary.federation.contains("Phase 6"));
    }
}
