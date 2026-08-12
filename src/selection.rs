//! Candidate selection helpers.
//!
//! The external-ranker seam is deliberately client-local and experimental. It
//! receives only candidates that already passed IICP eligibility and policy
//! checks. The ranker can change their order, but it cannot add a provider,
//! mint a dispatch ticket, or perform dispatch itself.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::types::{Node, TaskRequest};

pub const CANDIDATE_EVIDENCE_SCHEMA_V0: &str = "iicp-candidate-evidence-v0";

/// Redacted, versioned candidate view supplied to an optional local ranker.
///
/// It intentionally excludes endpoint, full node identifier, credentials,
/// dispatch tickets, CX keys, and request/response content.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CandidateEvidenceV0 {
    pub schema_version: &'static str,
    pub candidate_ref: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    pub directory_score: f64,
    pub load: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory_observed_reachable: Option<bool>,
}

/// Local request context for a ranker.
///
/// `request` remains in process. IICP does not serialize or transmit it to the
/// ranker. An adapter is responsible for any additional privacy boundary it
/// chooses to introduce.
pub struct RankerRequest<'a> {
    pub request_ref: String,
    pub intent: &'a str,
    pub request: &'a TaskRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RankerMode {
    Normal,
    Exploration,
}

impl RankerMode {
    pub(crate) fn receipt_value(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Exploration => "exploration",
        }
    }
}

/// A ranker's bounded decision. `candidate_ref` must name one of the supplied
/// eligible candidates. `policy_id` is restricted before it reaches a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankerDecision {
    pub candidate_ref: String,
    pub policy_id: String,
    pub mode: RankerMode,
}

/// Optional local candidate ranker.
///
/// `Ok(None)` declines and preserves the configured built-in strategy.
/// Errors and unknown candidate references fail before provider dispatch.
pub trait CandidateRanker: Send + Sync {
    fn rank(
        &self,
        request: &RankerRequest<'_>,
        candidates: &[CandidateEvidenceV0],
    ) -> std::result::Result<Option<RankerDecision>, String>;
}

#[derive(Debug, Clone)]
pub(crate) struct AppliedRanker {
    pub candidates: Vec<Node>,
    pub decision: Option<RankerDecision>,
}

pub(crate) fn apply_candidate_ranker(
    ranker: &dyn CandidateRanker,
    request: &TaskRequest,
    eligible: &[Node],
    built_in_order: Vec<Node>,
    limit: usize,
) -> std::result::Result<AppliedRanker, String> {
    let evidence: Vec<_> = eligible.iter().map(candidate_evidence_v0).collect();
    let request_ref = opaque_ref("request", &request.task_id);
    let context = RankerRequest {
        request_ref,
        intent: &request.intent,
        request,
    };
    let Some(decision) = ranker.rank(&context, &evidence)? else {
        return Ok(AppliedRanker {
            candidates: built_in_order,
            decision: None,
        });
    };

    validate_policy_id(&decision.policy_id)?;
    let selected_index = evidence
        .iter()
        .position(|candidate| candidate.candidate_ref == decision.candidate_ref)
        .ok_or_else(|| {
            "candidate ranker selected a reference outside the eligible candidate set".to_string()
        })?;
    let selected = eligible[selected_index].clone();
    let mut reordered = vec![selected.clone()];
    reordered.extend(
        built_in_order
            .into_iter()
            .filter(|candidate| candidate.node_id != selected.node_id)
            .take(limit.saturating_sub(1)),
    );

    Ok(AppliedRanker {
        candidates: reordered,
        decision: Some(decision),
    })
}

pub(crate) fn ranker_receipt_profile(
    decision: &RankerDecision,
    selected_candidate_index: usize,
) -> String {
    let mode = if selected_candidate_index == 0 {
        decision.mode.receipt_value()
    } else {
        "fallback"
    };
    format!("external_ranker/{}/{mode}", decision.policy_id)
}

fn validate_policy_id(value: &str) -> std::result::Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(
            "candidate ranker policy_id must be 1-64 ASCII letters, digits, '.', '_' or '-'"
                .to_string(),
        );
    }
    Ok(())
}

fn candidate_evidence_v0(node: &Node) -> CandidateEvidenceV0 {
    CandidateEvidenceV0 {
        schema_version: CANDIDATE_EVIDENCE_SCHEMA_V0,
        candidate_ref: opaque_ref("candidate", &node.node_id),
        models: node.models.clone().unwrap_or_default(),
        directory_score: node.score,
        load: node.load,
        health_label: node.health_label.clone(),
        directory_observed_reachable: node.directory_observed_reachable,
    }
}

fn opaque_ref(domain: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("iicp:{domain}:v0\n").as_bytes());
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn weighted_v1_index(scores: &[f64], loads: &[f64], random_value: f64) -> usize {
    let weights: Vec<f64> = scores
        .iter()
        .zip(loads)
        .map(|(score, load)| score.max(0.01) / (1.0 + load.clamp(0.0, 1.0)))
        .collect();
    let mut remaining = random_value.clamp(0.0, 0.999_999_999) * weights.iter().sum::<f64>();
    for (index, weight) in weights.iter().enumerate() {
        remaining -= weight;
        if remaining <= 0.0 {
            return index;
        }
    }
    weights.len().saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{RoutingPolicy, TaskRequest};
    use std::sync::Mutex;

    fn node(id: &str, endpoint: &str, score: f64) -> Node {
        Node {
            node_id: id.into(),
            endpoint: endpoint.into(),
            score,
            load: 0.2,
            available: true,
            region: "eu".into(),
            models: Some(vec!["model-a".into()]),
            cip_policy: None,
            health_label: Some("healthy".into()),
            exposure_mode: None,
            cx_public_key: None,
            transport: vec!["https".into()],
            directory_observed_reachable: Some(true),
            route_evidence: None,
            routing_hint: None,
            browser_usable: None,
            latency_evidence: None,
            health_reasons: None,
            trust_progress: None,
            sdk_release: None,
            node_policy_manifest: None,
            dispatch_ticket_id_prefix: None,
        }
    }

    fn request() -> TaskRequest {
        TaskRequest {
            task_id: "task-secret-id".into(),
            intent: "urn:iicp:intent:llm:chat:v1".into(),
            payload: serde_json::json!({"prompt": "private prompt"}),
            constraints: None,
            route_constraints: None,
            auth: None,
            source_node_id: None,
            routing_policy: Some(RoutingPolicy::default()),
        }
    }

    struct RecordingRanker {
        selected_index: Option<usize>,
        observed: Mutex<Vec<CandidateEvidenceV0>>,
    }

    impl CandidateRanker for RecordingRanker {
        fn rank(
            &self,
            request: &RankerRequest<'_>,
            candidates: &[CandidateEvidenceV0],
        ) -> std::result::Result<Option<RankerDecision>, String> {
            assert_ne!(request.request_ref, request.request.task_id);
            *self.observed.lock().unwrap() = candidates.to_vec();
            Ok(self.selected_index.map(|index| RankerDecision {
                candidate_ref: candidates[index].candidate_ref.clone(),
                policy_id: "metaharness-local-v0".into(),
                mode: RankerMode::Normal,
            }))
        }
    }

    #[test]
    fn evidence_is_redacted_and_versioned() {
        let original = node("private-node-id", "https://secret.example", 0.9);
        let encoded = serde_json::to_string(&candidate_evidence_v0(&original)).unwrap();
        assert!(encoded.contains(CANDIDATE_EVIDENCE_SCHEMA_V0));
        assert!(!encoded.contains("private-node-id"));
        assert!(!encoded.contains("secret.example"));
        assert!(!encoded.contains("endpoint"));
        assert!(!encoded.contains("cx_public_key"));
    }

    #[test]
    fn selected_eligible_candidate_moves_first_without_adding_candidates() {
        let eligible = vec![
            node("node-a", "https://a.example", 0.9),
            node("node-b", "https://b.example", 0.8),
        ];
        let ranker = RecordingRanker {
            selected_index: Some(1),
            observed: Mutex::new(vec![]),
        };
        let applied =
            apply_candidate_ranker(&ranker, &request(), &eligible, eligible.clone(), 3).unwrap();
        assert_eq!(applied.candidates[0].node_id, "node-b");
        assert_eq!(applied.candidates.len(), 2);
        assert_eq!(ranker.observed.lock().unwrap().len(), 2);
        assert_eq!(
            ranker_receipt_profile(applied.decision.as_ref().unwrap(), 0),
            "external_ranker/metaharness-local-v0/normal"
        );
        assert_eq!(
            ranker_receipt_profile(applied.decision.as_ref().unwrap(), 1),
            "external_ranker/metaharness-local-v0/fallback"
        );
    }

    #[test]
    fn decline_preserves_built_in_order() {
        let eligible = vec![
            node("node-a", "https://a.example", 0.9),
            node("node-b", "https://b.example", 0.8),
        ];
        let built_in = vec![eligible[1].clone(), eligible[0].clone()];
        let ranker = RecordingRanker {
            selected_index: None,
            observed: Mutex::new(vec![]),
        };
        let applied = apply_candidate_ranker(&ranker, &request(), &eligible, built_in, 3).unwrap();
        assert!(applied.decision.is_none());
        assert_eq!(applied.candidates[0].node_id, "node-b");
    }

    struct UnknownRanker;
    impl CandidateRanker for UnknownRanker {
        fn rank(
            &self,
            _request: &RankerRequest<'_>,
            _candidates: &[CandidateEvidenceV0],
        ) -> std::result::Result<Option<RankerDecision>, String> {
            Ok(Some(RankerDecision {
                candidate_ref: "not-eligible".into(),
                policy_id: "test".into(),
                mode: RankerMode::Exploration,
            }))
        }
    }

    #[test]
    fn unknown_candidate_fails_closed() {
        let eligible = vec![node("node-a", "https://a.example", 0.9)];
        let err =
            apply_candidate_ranker(&UnknownRanker, &request(), &eligible, eligible.clone(), 3)
                .unwrap_err();
        assert!(err.contains("outside the eligible candidate set"));
    }

    struct FailingRanker;
    impl CandidateRanker for FailingRanker {
        fn rank(
            &self,
            _request: &RankerRequest<'_>,
            _candidates: &[CandidateEvidenceV0],
        ) -> std::result::Result<Option<RankerDecision>, String> {
            Err("local evaluator unavailable".into())
        }
    }

    #[test]
    fn ranker_errors_are_returned_without_fallback() {
        let eligible = vec![node("node-a", "https://a.example", 0.9)];
        let err =
            apply_candidate_ranker(&FailingRanker, &request(), &eligible, eligible.clone(), 3)
                .unwrap_err();
        assert_eq!(err, "local evaluator unavailable");
    }
}
