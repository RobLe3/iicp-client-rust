// SPDX-License-Identifier: Apache-2.0
//! Binding-neutral effective service capability advertisement and matching.
//!
//! The matcher consumes complete variants. It does not perform discovery,
//! authorize policy, validate a final route, or dispatch a request.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const EFFECTIVE_CAPABILITY_PROFILE_ID: &str = "urn:iicp:profile:effective-capability:v1";
pub const EFFECTIVE_CAPABILITY_SCHEMA_VERSION: &str = "1.0.0";

pub const REFUSAL_REQUIRED_UNKNOWN: &str = "required_capability_unknown";
pub const REFUSAL_REQUIRED_UNSUPPORTED: &str = "required_capability_unsupported";
pub const REFUSAL_REQUIRED_STALE: &str = "required_capability_stale";
pub const REFUSAL_LIMIT_UNSATISFIED: &str = "capability_limit_unsatisfied";
pub const REFUSAL_POLICY_DENIED: &str = "capability_policy_denied";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLimit {
    pub value: f64,
    pub unit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityClaimProvenance {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityExtension {
    pub required: bool,
    pub value: serde_json::Value,
}

/// One complete service-path variant. Matchers must never union its fields
/// with another variant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EffectiveCapability {
    pub intent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_modalities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_modalities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub execution_capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub limits: BTreeMap<String, CapabilityLimit>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_provenance: Option<CapabilityClaimProvenance>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, CapabilityExtension>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EffectiveCapabilityAdvertisement {
    pub schema_version: String,
    pub capabilities: Vec<EffectiveCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequirement {
    #[serde(rename = "class")]
    pub capability_class: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLimitRequirement {
    pub id: String,
    pub operator: String,
    pub value: f64,
    pub unit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequirements {
    pub schema_version: String,
    pub intent: String,
    #[serde(default)]
    pub requires: Vec<CapabilityRequirement>,
    #[serde(default)]
    pub prefers: Vec<CapabilityRequirement>,
    #[serde(default)]
    pub limits: Vec<CapabilityLimitRequirement>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EffectiveCapabilityMatch {
    pub eligible: bool,
    pub variant_ids: Vec<Option<String>>,
    pub preference_unavailable: bool,
    pub refusal: Option<&'static str>,
    pub preserved_extensions: Vec<String>,
}

impl EffectiveCapabilityAdvertisement {
    /// Validate invariants which cannot be expressed by Serde alone.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != EFFECTIVE_CAPABILITY_SCHEMA_VERSION {
            return Err("unsupported effective capability schema_version".into());
        }
        if self.capabilities.is_empty() {
            return Err("capabilities must be non-empty".into());
        }
        let mut identities = BTreeSet::new();
        for capability in &self.capabilities {
            if capability.intent.is_empty() {
                return Err("intent is required".into());
            }
            if !identities.insert((&capability.intent, &capability.variant_id)) {
                return Err("effective capability variants must be unique".into());
            }
            for limit in capability.limits.values() {
                if !limit.value.is_finite() || limit.value < 0.0 {
                    return Err("limit value must be a non-negative finite number".into());
                }
                if !matches!(
                    limit.unit.as_str(),
                    "tokens" | "items" | "bytes" | "milliseconds" | "dimensions"
                ) {
                    return Err("limit unit is unsupported".into());
                }
            }
            if let Some(provenance) = &capability.claim_provenance {
                if !matches!(
                    provenance.source.as_str(),
                    "heuristic_fallback"
                        | "operator_assertion"
                        | "provider_metadata"
                        | "runtime_introspection"
                        | "conformance_probe"
                ) {
                    return Err("claim provenance source is unsupported".into());
                }
                for timestamp in [
                    provenance.observed_at.as_deref(),
                    provenance.valid_until.as_deref(),
                ]
                .into_iter()
                .flatten()
                {
                    DateTime::parse_from_rfc3339(timestamp)
                        .map_err(|_| "claim provenance timestamp must be RFC 3339")?;
                }
            }
        }
        Ok(())
    }
}

/// Apply deterministic evidence precedence without merging incompatible sets.
pub fn resolve_effective_capabilities(
    explicit: &[EffectiveCapability],
    introspected: &[EffectiveCapability],
    heuristic: &[EffectiveCapability],
) -> Result<Vec<EffectiveCapability>, String> {
    if !explicit.is_empty() {
        return Ok(explicit.to_vec());
    }
    if !introspected.is_empty() {
        return Ok(introspected.to_vec());
    }
    if heuristic.iter().any(|capability| {
        capability
            .claim_provenance
            .as_ref()
            .map(|claim| claim.source.as_str())
            != Some("heuristic_fallback")
    }) {
        return Err("heuristic capability evidence must be labelled heuristic_fallback".into());
    }
    Ok(heuristic.to_vec())
}

fn refusal(code: &'static str) -> EffectiveCapabilityMatch {
    EffectiveCapabilityMatch {
        eligible: false,
        variant_ids: vec![],
        preference_unavailable: false,
        refusal: Some(code),
        preserved_extensions: vec![],
    }
}

fn known(vocabulary: &BTreeMap<String, Vec<String>>, requirement: &CapabilityRequirement) -> bool {
    vocabulary
        .get(&requirement.capability_class)
        .is_some_and(|values| values.contains(&requirement.id))
}

fn values<'a>(candidate: &'a EffectiveCapability, class: &str) -> Option<&'a [String]> {
    match class {
        "input_modality" => Some(&candidate.input_modalities),
        "output_modality" => Some(&candidate.output_modalities),
        "feature" => Some(&candidate.features),
        "execution_capability" => Some(&candidate.execution_capabilities),
        "profile" => Some(&candidate.supported_profiles),
        _ => None,
    }
}

fn supports(candidate: &EffectiveCapability, requirements: &[CapabilityRequirement]) -> bool {
    requirements.iter().all(|requirement| {
        values(candidate, &requirement.capability_class)
            .is_some_and(|items| items.contains(&requirement.id))
    })
}

fn fresh(candidate: &EffectiveCapability, evaluated_at: DateTime<Utc>) -> bool {
    candidate
        .claim_provenance
        .as_ref()
        .and_then(|claim| claim.valid_until.as_deref())
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .is_none_or(|until| until >= evaluated_at)
}

fn limits_match(candidate: &EffectiveCapability, required: &[CapabilityLimitRequirement]) -> bool {
    required.iter().all(|requirement| {
        candidate.limits.get(&requirement.id).is_some_and(|actual| {
            actual.unit == requirement.unit
                && match requirement.operator.as_str() {
                    "gte" => actual.value >= requirement.value,
                    "lte" => actual.value <= requirement.value,
                    "eq" => actual.value == requirement.value,
                    _ => false,
                }
        })
    })
}

/// Match complete variants and return portable refusal reasons.
pub fn match_effective_capabilities(
    capabilities: &[EffectiveCapability],
    request: &CapabilityRequirements,
    vocabulary: &BTreeMap<String, Vec<String>>,
    evaluated_at: DateTime<Utc>,
    policy_denials: &BTreeSet<CapabilityRequirement>,
) -> EffectiveCapabilityMatch {
    for requirement in &request.requires {
        if !known(vocabulary, requirement) {
            return refusal(REFUSAL_REQUIRED_UNKNOWN);
        }
        if policy_denials.contains(requirement) {
            return refusal(REFUSAL_POLICY_DENIED);
        }
    }

    let candidates: Vec<_> = capabilities
        .iter()
        .filter(|candidate| {
            candidate.intent == request.intent && supports(candidate, &request.requires)
        })
        .collect();
    if candidates.is_empty() {
        return refusal(REFUSAL_REQUIRED_UNSUPPORTED);
    }
    let candidates: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| fresh(candidate, evaluated_at))
        .collect();
    if candidates.is_empty() {
        return refusal(REFUSAL_REQUIRED_STALE);
    }
    let candidates: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| limits_match(candidate, &request.limits))
        .collect();
    if candidates.is_empty() {
        return refusal(REFUSAL_LIMIT_UNSATISFIED);
    }

    let preference_unavailable = request.prefers.iter().any(|preference| {
        !known(vocabulary, preference)
            || !candidates.iter().any(|candidate| {
                values(candidate, &preference.capability_class)
                    .is_some_and(|items| items.contains(&preference.id))
            })
    });
    let preserved_extensions = candidates
        .iter()
        .flat_map(|candidate| candidate.extensions.keys().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    EffectiveCapabilityMatch {
        eligible: true,
        variant_ids: candidates
            .iter()
            .map(|candidate| candidate.variant_id.clone())
            .collect(),
        preference_unavailable,
        refusal: None,
        preserved_extensions,
    }
}
