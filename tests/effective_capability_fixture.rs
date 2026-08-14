use chrono::{DateTime, Utc};
use iicp_client::effective_capability::{
    match_effective_capabilities, resolve_effective_capabilities, CapabilityClaimProvenance,
    CapabilityRequirement, CapabilityRequirements, EffectiveCapability,
    EffectiveCapabilityAdvertisement, EFFECTIVE_CAPABILITY_PROFILE_ID,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const FIXTURE_SHA256: &str = "e6e3c32aa7c4cf814e639d3a97cd1c1cb49ac020ed6ebe7e1e16bc2314e14761";

#[derive(Deserialize)]
struct Fixture {
    profile_id: String,
    evaluation_time: String,
    vocabulary: BTreeMap<String, Vec<String>>,
    advertisement: EffectiveCapabilityAdvertisement,
    matching_scenarios: Vec<Scenario>,
    invalid_advertisements: Vec<InvalidAdvertisement>,
}

#[derive(Deserialize)]
struct Scenario {
    name: String,
    #[serde(default)]
    evaluation_time: Option<String>,
    request: CapabilityRequirements,
    #[serde(default)]
    policy_denials: BTreeSet<CapabilityRequirement>,
    expected: Value,
}

#[derive(Deserialize)]
struct InvalidAdvertisement {
    name: String,
    value: Value,
}

fn fixture() -> Fixture {
    serde_json::from_slice(include_bytes!(
        "../parity/effective-capability-v1/fixture.json"
    ))
    .unwrap()
}

#[test]
fn exact_shared_fixture_and_schemas_are_pinned() {
    let bytes = include_bytes!("../parity/effective-capability-v1/fixture.json");
    assert_eq!(hex::encode(Sha256::digest(bytes)), FIXTURE_SHA256);
    assert_eq!(fixture().profile_id, EFFECTIVE_CAPABILITY_PROFILE_ID);
    let schemas = [
        (
            include_bytes!("../parity/effective-capability-v1/advertisement.schema.json")
                .as_slice(),
            "707da7eebc5e8b55a720386ca713c977beeadd640f4b09eb48ea99573d2b1ab0",
        ),
        (
            include_bytes!("../parity/effective-capability-v1/requirements.schema.json").as_slice(),
            "0d234ef4de420b977661d3222c3c9f433332e8224a3320175318338c76e760e9",
        ),
        (
            include_bytes!("../parity/effective-capability-v1/refusal.schema.json").as_slice(),
            "5d35b57c31eeb176bd7db72bfaf1ccaa84defe864bc63a10c59b97d689e52f9e",
        ),
    ];
    for (bytes, expected) in schemas {
        assert_eq!(hex::encode(Sha256::digest(bytes)), expected);
    }
}

#[test]
fn shared_scenarios_pass_without_cross_variant_union() {
    let fixture = fixture();
    fixture.advertisement.validate().unwrap();
    for scenario in fixture.matching_scenarios {
        let at = scenario
            .evaluation_time
            .as_deref()
            .unwrap_or(&fixture.evaluation_time);
        let actual = match_effective_capabilities(
            &fixture.advertisement.capabilities,
            &scenario.request,
            &fixture.vocabulary,
            DateTime::parse_from_rfc3339(at)
                .unwrap()
                .with_timezone(&Utc),
            &scenario.policy_denials,
        );
        assert_eq!(
            actual.eligible,
            scenario.expected["eligible"].as_bool().unwrap(),
            "{}",
            scenario.name
        );
        if actual.eligible {
            let expected: Vec<Option<String>> =
                serde_json::from_value(scenario.expected["variant_ids"].clone()).unwrap();
            assert_eq!(actual.variant_ids, expected, "{}", scenario.name);
            assert_eq!(
                actual.preference_unavailable,
                scenario.expected["preference_unavailable"]
                    .as_bool()
                    .unwrap_or(false),
                "{}",
                scenario.name
            );
            if let Some(extension) = scenario.expected["preserved_extension"].as_str() {
                assert!(actual.preserved_extensions.contains(&extension.to_string()));
            }
        } else {
            assert_eq!(
                actual.refusal,
                scenario.expected["refusal"]["code"].as_str(),
                "{}",
                scenario.name
            );
        }
    }
}

#[test]
fn invalid_shared_advertisements_are_rejected() {
    for invalid in fixture().invalid_advertisements {
        let parsed = serde_json::from_value::<EffectiveCapabilityAdvertisement>(invalid.value);
        assert!(
            parsed.is_err() || parsed.unwrap().validate().is_err(),
            "{}",
            invalid.name
        );
    }
}

#[test]
fn evidence_precedence_is_explicit_then_introspected_then_labelled_heuristic() {
    let capability = |variant: &str, source: Option<&str>| EffectiveCapability {
        intent: "urn:iicp:intent:llm:chat:v1".into(),
        version: None,
        phase: None,
        variant_id: Some(variant.into()),
        models: vec![],
        max_tokens: None,
        input_modalities: vec![],
        output_modalities: vec![],
        features: vec![],
        execution_capabilities: vec![],
        limits: BTreeMap::new(),
        supported_profiles: vec![],
        claim_provenance: source.map(|source| CapabilityClaimProvenance {
            source: source.into(),
            observed_at: None,
            valid_until: None,
            evidence_ref: None,
        }),
        extensions: BTreeMap::new(),
    };
    let explicit = capability("explicit", None);
    let introspected = capability("introspected", Some("runtime_introspection"));
    let heuristic = capability("heuristic", Some("heuristic_fallback"));
    assert_eq!(
        resolve_effective_capabilities(
            std::slice::from_ref(&explicit),
            std::slice::from_ref(&introspected),
            std::slice::from_ref(&heuristic)
        )
        .unwrap(),
        vec![explicit]
    );
    assert_eq!(
        resolve_effective_capabilities(
            &[],
            std::slice::from_ref(&introspected),
            std::slice::from_ref(&heuristic),
        )
        .unwrap(),
        vec![introspected]
    );
    assert_eq!(
        resolve_effective_capabilities(&[], &[], std::slice::from_ref(&heuristic)).unwrap(),
        vec![heuristic]
    );
    assert!(resolve_effective_capabilities(&[], &[], &[capability("bad", None)]).is_err());
}
