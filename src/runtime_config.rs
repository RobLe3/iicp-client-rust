// SPDX-License-Identifier: Apache-2.0
//! Versioned, side-effect-free runtime configuration for restricted trust domains.
//!
//! This module does not enable private operation by itself. It gives the CLI,
//! future wizard and runtime one typed configuration authority and rejects
//! unsafe combinations before network activity.

use crate::identity::NodeIdentity;
use schemars::{schema_for, JsonSchema};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const RUNTIME_CONFIG_SCHEMA_VERSION: u32 = 1;
pub const PUBLIC_DIRECTORY_URL: &str = "https://iicp.network/api";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperatingMode {
    Public,
    Private,
    FederatedPrivate,
    LocalOnly,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectorySource {
    Public,
    Remote,
    Local,
    Static,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectoryConfig {
    pub source: DirectorySource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretRef {
    Environment { name: String },
    File { path: String },
    MacosKeychain { service: String, account: String },
    WindowsCredential { target: String },
    LinuxSecretService { collection: String, label: String },
    External { provider: String, reference: String },
}

impl SecretRef {
    fn is_valid(&self) -> bool {
        let nonempty = |value: &str| !value.trim().is_empty();
        match self {
            Self::Environment { name } => {
                nonempty(name)
                    && name
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            }
            Self::File { path } => nonempty(path),
            Self::MacosKeychain { service, account } => nonempty(service) && nonempty(account),
            Self::WindowsCredential { target } => nonempty(target),
            Self::LinuxSecretService { collection, label } => {
                nonempty(collection) && nonempty(label)
            }
            Self::External {
                provider,
                reference,
            } => nonempty(provider) && nonempty(reference),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MembershipConfig {
    pub required: bool,
    pub require_authenticated_clients: bool,
    pub require_authenticated_nodes: bool,
    pub reject_unknown_peers: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<SecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshConfig {
    pub enabled: bool,
    pub require_authenticated_gossip: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionConfig {
    pub allow_local: bool,
    pub allow_external_providers: bool,
    pub allow_public_iicp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CipConfig {
    pub enabled: bool,
    pub require_same_trust_domain: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationConfig {
    pub enabled: bool,
    #[serde(default)]
    pub trusted_domains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub allow_public_fallback: bool,
    pub allow_external_bootstrap: bool,
    pub allow_external_relay: bool,
    pub allow_auto_update_network: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfigV1 {
    pub schema_version: u32,
    pub mode: OperatingMode,
    pub directory: DirectoryConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain_id: Option<String>,
    pub membership: MembershipConfig,
    pub mesh: MeshConfig,
    pub execution: ExecutionConfig,
    pub cip: CipConfig,
    pub federation: FederationConfig,
    pub network: NetworkPolicy,
    #[serde(default)]
    pub secret_refs: BTreeMap<String, SecretRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigFinding {
    pub code: &'static str,
    pub path: &'static str,
    pub message: &'static str,
}

impl ConfigFinding {
    fn new(code: &'static str, path: &'static str, message: &'static str) -> Self {
        Self {
            code,
            path,
            message,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigOverrides {
    pub mode: Option<OperatingMode>,
    pub directory_url: Option<String>,
    pub directory_authority: Option<String>,
    pub trust_domain_id: Option<String>,
    pub allow_public_fallback: Option<bool>,
    pub trusted_domains: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyMigration {
    pub config: RuntimeConfigV1,
    pub contained_secret_material: bool,
}

impl RuntimeConfigV1 {
    pub fn preset(mode: OperatingMode) -> Self {
        let restricted = matches!(
            mode,
            OperatingMode::Private | OperatingMode::FederatedPrivate
        );
        let local = mode == OperatingMode::LocalOnly;
        let federated = mode == OperatingMode::FederatedPrivate;
        Self {
            schema_version: RUNTIME_CONFIG_SCHEMA_VERSION,
            mode,
            directory: DirectoryConfig {
                source: if local {
                    DirectorySource::Local
                } else if restricted {
                    DirectorySource::Remote
                } else {
                    DirectorySource::Public
                },
                url: if local {
                    None
                } else {
                    Some(PUBLIC_DIRECTORY_URL.to_string())
                },
                authority_id: None,
            },
            trust_domain_id: None,
            membership: MembershipConfig {
                required: restricted,
                require_authenticated_clients: restricted,
                require_authenticated_nodes: restricted,
                reject_unknown_peers: restricted,
                credential: None,
                revocation_source: None,
            },
            mesh: MeshConfig {
                enabled: !local,
                require_authenticated_gossip: restricted,
            },
            execution: ExecutionConfig {
                allow_local: true,
                allow_external_providers: !local,
                allow_public_iicp: !restricted && !local,
            },
            cip: CipConfig {
                enabled: false,
                require_same_trust_domain: restricted,
            },
            federation: FederationConfig {
                enabled: federated,
                trusted_domains: Vec::new(),
            },
            network: NetworkPolicy {
                allow_public_fallback: !restricted && !local,
                allow_external_bootstrap: !local,
                allow_external_relay: !local,
                allow_auto_update_network: !local,
            },
            secret_refs: BTreeMap::new(),
        }
    }

    pub fn schema_json() -> serde_json::Value {
        serde_json::to_value(schema_for!(RuntimeConfigV1)).expect("schema is serializable")
    }

    pub fn from_json(input: &str) -> Result<Self, String> {
        serde_json::from_str(input)
            .map_err(|error| format!("invalid runtime configuration: {error}"))
    }

    pub fn validate(&self) -> Vec<ConfigFinding> {
        let mut findings = Vec::new();
        if self.schema_version != RUNTIME_CONFIG_SCHEMA_VERSION {
            findings.push(ConfigFinding::new(
                "unsupported_schema_version",
                "/schema_version",
                "only runtime configuration schema version 1 is supported",
            ));
        }
        if matches!(
            self.directory.source,
            DirectorySource::Public | DirectorySource::Remote
        ) && self.directory.url.as_deref().is_none_or(str::is_empty)
        {
            findings.push(ConfigFinding::new(
                "directory_url_required",
                "/directory/url",
                "the selected directory source requires an explicit URL",
            ));
        }
        self.validate_restricted_mode(&mut findings);
        self.validate_federation(&mut findings);
        self.validate_reserved_restricted_features(&mut findings);
        self.validate_local_only(&mut findings);
        if self.cip.enabled && self.membership.required && !self.cip.require_same_trust_domain {
            findings.push(ConfigFinding::new(
                "cip_trust_domain_required",
                "/cip/require_same_trust_domain",
                "CIP in a restricted domain must inherit the originating trust-domain policy",
            ));
        }
        if self
            .secret_refs
            .values()
            .chain(self.membership.credential.iter())
            .any(|reference| !reference.is_valid())
        {
            findings.push(ConfigFinding::new(
                "invalid_secret_reference",
                "/secret_refs",
                "secret references must use a supported source and non-empty locator",
            ));
        }
        findings
    }

    fn validate_restricted_mode(&self, findings: &mut Vec<ConfigFinding>) {
        if matches!(
            self.mode,
            OperatingMode::Private | OperatingMode::FederatedPrivate
        ) {
            if self.trust_domain_id.as_deref().is_none_or(str::is_empty) {
                findings.push(ConfigFinding::new(
                    "trust_domain_required",
                    "/trust_domain_id",
                    "restricted modes require a trust-domain identifier",
                ));
            }
            if self
                .directory
                .authority_id
                .as_deref()
                .is_none_or(str::is_empty)
            {
                findings.push(ConfigFinding::new(
                    "directory_authority_required",
                    "/directory/authority_id",
                    "restricted modes require a configured directory authority",
                ));
            }
            if !self.has_restricted_membership_controls() {
                findings.push(ConfigFinding::new(
                    "restricted_membership_controls_required",
                    "/membership",
                    "restricted modes require authenticated clients, nodes, gossip and unknown-peer rejection",
                ));
            }
            if self.network.allow_public_fallback || self.execution.allow_public_iicp {
                findings.push(ConfigFinding::new(
                    "public_fallback_forbidden",
                    "/network/allow_public_fallback",
                    "restricted modes cannot enable public discovery or execution fallback",
                ));
            }
        }
    }

    fn validate_federation(&self, findings: &mut Vec<ConfigFinding>) {
        if self.mode == OperatingMode::FederatedPrivate
            && (!self.federation.enabled || self.federation.trusted_domains.is_empty())
        {
            findings.push(ConfigFinding::new(
                "trusted_federation_domain_required",
                "/federation/trusted_domains",
                "federated-private mode requires at least one explicit trusted domain",
            ));
        }
        if self.mode != OperatingMode::FederatedPrivate && self.federation.enabled {
            findings.push(ConfigFinding::new(
                "federation_mode_mismatch",
                "/federation/enabled",
                "federation requires federated-private mode",
            ));
        }
    }

    fn validate_reserved_restricted_features(&self, findings: &mut Vec<ConfigFinding>) {
        if self.membership.revocation_source.is_some() {
            findings.push(ConfigFinding::new(
                "revocation_source_not_supported",
                "/membership/revocation_source",
                "authenticated revocation sources are reserved until their contract is implemented",
            ));
        }
        if self.mode == OperatingMode::FederatedPrivate {
            findings.push(ConfigFinding::new(
                "federated_private_not_supported",
                "/mode",
                "federated-private operation remains unavailable until the Phase 6 evidence gate passes",
            ));
        }
    }

    fn validate_local_only(&self, findings: &mut Vec<ConfigFinding>) {
        if self.mode == OperatingMode::LocalOnly && self.has_external_access() {
            findings.push(ConfigFinding::new(
                "local_only_external_access_forbidden",
                "/network",
                "local-only mode cannot enable external control-plane, update or execution access",
            ));
        }
    }

    fn has_restricted_membership_controls(&self) -> bool {
        self.membership.required
            && self.membership.require_authenticated_clients
            && self.membership.require_authenticated_nodes
            && self.membership.reject_unknown_peers
            && self.mesh.require_authenticated_gossip
    }

    fn has_external_access(&self) -> bool {
        let external_directory = !matches!(
            self.directory.source,
            DirectorySource::Local | DirectorySource::Static
        ) || self.directory.url.is_some();
        let external_execution = self.execution.allow_external_providers
            || self.execution.allow_public_iicp
            || self.federation.enabled;
        let external_network = self.network.allow_public_fallback
            || self.network.allow_external_bootstrap
            || self.network.allow_external_relay
            || self.network.allow_auto_update_network;
        external_directory || self.mesh.enabled || external_execution || external_network
    }

    pub fn apply(&mut self, overlay: ConfigOverrides) {
        if let Some(mode) = overlay.mode {
            *self = Self::preset(mode);
        }
        if let Some(url) = overlay.directory_url {
            self.directory.url = Some(url);
            if self.directory.source == DirectorySource::Public {
                self.directory.source = DirectorySource::Remote;
            }
        }
        if let Some(authority) = overlay.directory_authority {
            self.directory.authority_id = Some(authority);
        }
        if let Some(domain) = overlay.trust_domain_id {
            self.trust_domain_id = Some(domain);
        }
        if let Some(allow) = overlay.allow_public_fallback {
            self.network.allow_public_fallback = allow;
        }
        if let Some(domains) = overlay.trusted_domains {
            self.federation.trusted_domains = domains;
        }
    }

    pub fn resolve(
        preset: OperatingMode,
        file: Option<Self>,
        mut environment: ConfigOverrides,
        mut cli: ConfigOverrides,
    ) -> Self {
        // Select the operating-mode preset first. A higher-precedence mode must
        // not erase unrelated lower-precedence values such as the directory
        // URL supplied by the environment.
        let file_mode = file.as_ref().map(|config| config.mode);
        let effective_mode = cli
            .mode
            .take()
            .or_else(|| environment.mode.take())
            .or(file_mode)
            .unwrap_or(preset);
        let mut config = match file {
            Some(config) if config.mode == effective_mode => config,
            _ => Self::preset(effective_mode),
        };
        config.apply(environment);
        config.apply(cli);
        config
    }

    pub fn migrate_legacy_node(node: &NodeIdentity) -> LegacyMigration {
        let mut config = Self::preset(OperatingMode::Public);
        config.directory.url = Some(node.directory_url.clone());
        if node.directory_url != PUBLIC_DIRECTORY_URL {
            config.directory.source = DirectorySource::Remote;
        }
        LegacyMigration {
            config,
            contained_secret_material: node.node_token.is_some() || node.node_hmac_key.is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_private() -> RuntimeConfigV1 {
        let mut config = RuntimeConfigV1::preset(OperatingMode::Private);
        config.trust_domain_id = Some("example.internal".into());
        config.directory.authority_id = Some("did:key:directory".into());
        config
    }

    #[test]
    fn public_preset_preserves_current_default() {
        let config = RuntimeConfigV1::preset(OperatingMode::Public);
        assert!(config.validate().is_empty());
        assert_eq!(config.directory.url.as_deref(), Some(PUBLIC_DIRECTORY_URL));
        assert!(config.network.allow_public_fallback);
    }

    #[test]
    fn private_preset_fails_until_domain_and_authority_are_explicit() {
        let findings = RuntimeConfigV1::preset(OperatingMode::Private).validate();
        assert_eq!(
            findings.iter().map(|f| f.code).collect::<Vec<_>>(),
            ["trust_domain_required", "directory_authority_required"]
        );
        assert!(valid_private().validate().is_empty());
    }

    #[test]
    fn higher_precedence_mode_preserves_lower_precedence_non_mode_values() {
        let environment = ConfigOverrides {
            directory_url: Some("https://directory.example/api".into()),
            ..Default::default()
        };
        let cli = ConfigOverrides {
            mode: Some(OperatingMode::Private),
            directory_authority: Some("did:key:directory".into()),
            trust_domain_id: Some("example.internal".into()),
            ..Default::default()
        };
        let config = RuntimeConfigV1::resolve(OperatingMode::Public, None, environment, cli);
        assert_eq!(config.mode, OperatingMode::Private);
        assert_eq!(
            config.directory.url.as_deref(),
            Some("https://directory.example/api")
        );
        assert!(config.validate().is_empty());
    }

    #[test]
    fn restricted_mode_rejects_public_fallback() {
        let mut config = valid_private();
        config.network.allow_public_fallback = true;
        assert!(config
            .validate()
            .iter()
            .any(|finding| finding.code == "public_fallback_forbidden"));
    }

    #[test]
    fn local_only_has_no_external_network_dependency() {
        let config = RuntimeConfigV1::preset(OperatingMode::LocalOnly);
        assert!(config.validate().is_empty());
        assert!(!config.network.allow_external_bootstrap);
        assert!(!config.network.allow_auto_update_network);
    }

    #[test]
    fn federated_private_is_reserved_even_with_explicit_peer_domain() {
        let mut config = RuntimeConfigV1::preset(OperatingMode::FederatedPrivate);
        config.trust_domain_id = Some("a.example".into());
        config.directory.authority_id = Some("did:key:a".into());
        assert!(config
            .validate()
            .iter()
            .any(|finding| finding.code == "trusted_federation_domain_required"));
        config.federation.trusted_domains.push("b.example".into());
        assert_eq!(
            config
                .validate()
                .iter()
                .map(|finding| finding.code)
                .collect::<Vec<_>>(),
            ["federated_private_not_supported"]
        );
    }

    #[test]
    fn configured_revocation_source_fails_closed_until_supported() {
        let mut config = valid_private();
        config.membership.revocation_source = Some("https://directory.example/revocations".into());
        assert_eq!(
            config
                .validate()
                .iter()
                .map(|finding| finding.code)
                .collect::<Vec<_>>(),
            ["revocation_source_not_supported"]
        );
        config.membership.revocation_source = None;
        assert!(config.validate().is_empty());
    }

    #[test]
    fn cli_overrides_environment_over_file() {
        let mut file = valid_private();
        file.trust_domain_id = Some("file.example".into());
        let resolved = RuntimeConfigV1::resolve(
            OperatingMode::Public,
            Some(file),
            ConfigOverrides {
                trust_domain_id: Some("env.example".into()),
                ..Default::default()
            },
            ConfigOverrides {
                trust_domain_id: Some("cli.example".into()),
                ..Default::default()
            },
        );
        assert_eq!(resolved.trust_domain_id.as_deref(), Some("cli.example"));
    }

    #[test]
    fn unknown_fields_and_versions_fail_closed() {
        let mut value =
            serde_json::to_value(RuntimeConfigV1::preset(OperatingMode::Public)).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(RuntimeConfigV1::from_json(&value.to_string()).is_err());
        let mut config = RuntimeConfigV1::preset(OperatingMode::Public);
        config.schema_version = 99;
        assert_eq!(config.validate()[0].code, "unsupported_schema_version");
    }

    #[test]
    fn schema_is_generated_and_secret_values_are_not_representable() {
        let schema = RuntimeConfigV1::schema_json();
        let committed: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/runtime-config-v1.schema.json")).unwrap();
        assert_eq!(
            schema, committed,
            "committed JSON Schema must match generated Rust types"
        );
        assert_eq!(schema["properties"]["schema_version"]["type"], "integer");
        let serialized = serde_json::to_string(&valid_private()).unwrap();
        assert!(!serialized.contains("node_token"));
        assert!(!serialized.contains("private_key"));
    }
}
