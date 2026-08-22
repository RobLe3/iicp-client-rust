// SPDX-License-Identifier: Apache-2.0
//! CIP consumer dispatch gates (S.12 §2.2) — Rust port of iicp_client.proxy.cip
//! (gates.py + dispatch.py). Decides LOCAL / REMOTE / ERROR for a cooperative-inference
//! request and surfaces the two structured errors the proxy maps to HTTP status:
//!   CipError::InsufficientCredits → IICP-E036 → 402
//!   CipError::NoEligibleWorkers   → IICP-E022 → 503
//!
//! Faithful to the Python reference (full-parity, #482b). The gateway pure-consumer path
//! passes no local node_list, so Gate 4 (local-first loopback preference) is skipped.

use serde_json::Value;

use crate::types::RestrictedEligibility;

const VALID_CIP_POLICIES: [&str; 3] = ["best_of_n", "majority_vote", "map_reduce"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipError {
    InsufficientCredits(String), // IICP-E036
    NoEligibleWorkers(String),   // IICP-E022
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipStrategy {
    LocalFirst,
    RemoteFirst,
    Balanced,
}

#[derive(Debug, Clone)]
pub struct CipConfig {
    pub enabled: bool,
    pub strategy: CipStrategy,
    pub max_credits_per_task: f64,
    pub session_credit_budget: Option<f64>,
    pub send_sensitive_prompts: bool,
    pub trusted_peers: Vec<String>,
    pub min_reputation: f64,
}

/// A CIP worker candidate plus process-local directory eligibility provenance.
///
/// The provenance is produced only after the client validates a restricted
/// directory response. It is never accepted from provider-controlled JSON.
#[derive(Debug, Clone)]
pub struct CipWorkerCandidate {
    pub node_id: String,
    pub allow_remote_inference: bool,
    pub reputation_score: f64,
    pub restricted_eligibility: Option<RestrictedEligibility>,
}

/// Expected trust boundary for a restricted CIP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipTrustScope {
    pub domain_id: String,
    pub authority_id: String,
    pub minimum_membership_generation: u64,
}

impl Default for CipConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            strategy: CipStrategy::LocalFirst,
            max_credits_per_task: 10.0,
            session_credit_budget: None,
            send_sensitive_prompts: false,
            trusted_peers: Vec::new(),
            min_reputation: 0.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchResult {
    Local,
    Remote,
    Error(String), // error code
}

#[derive(Debug, Clone, PartialEq)]
pub struct CipDispatchPlan {
    pub envelope: Option<Value>,
    /// Present only for remote CIP dispatch. Initial and replacement workers
    /// must remain within this process-local set.
    pub allowed_node_ids: Option<Vec<String>>,
}

impl CipDispatchPlan {
    fn local() -> Self {
        Self {
            envelope: None,
            allowed_node_ids: None,
        }
    }
}

/// Parse-time validation of cip.policy / cip.replicas / cip.quorum (S.12 §5.2).
pub fn validate_cip_request_fields(body: &Value) -> Option<String> {
    let cip = body.get("cip")?;
    if !cip.is_object() {
        return None;
    }
    if let Some(policy) = cip.get("policy").and_then(|p| p.as_str()) {
        if !VALID_CIP_POLICIES.contains(&policy) {
            return Some("IICP-E028".to_string());
        }
    }
    let policy = cip.get("policy").and_then(|p| p.as_str());
    let replicas = cip.get("replicas").and_then(|r| r.as_i64());
    if let Some(r) = cip.get("replicas") {
        if !r.is_i64() || !(1..=10).contains(&replicas.unwrap_or(0)) {
            return Some("IICP-E028".to_string());
        }
        if policy == Some("majority_vote") && replicas.unwrap_or(0) % 2 == 0 {
            return Some("IICP-E025".to_string());
        }
    }
    if let Some(q) = cip.get("quorum") {
        let quorum = q.as_i64();
        if !q.is_i64() || quorum.unwrap_or(0) < 1 {
            return Some("IICP-E028".to_string());
        }
        let eff = replicas.unwrap_or(1);
        if quorum.unwrap_or(0) > eff {
            return Some("IICP-E028".to_string());
        }
    }
    None
}

fn blocked_remote(config: &CipConfig, code: &str) -> DispatchResult {
    // local-first runs locally (graceful); other strategies surface the structured error.
    if config.strategy == CipStrategy::LocalFirst {
        DispatchResult::Local
    } else {
        DispatchResult::Error(code.to_string())
    }
}

/// Evaluate the §2.2 normative gates → dispatch decision (port of gates.decide_dispatch).
pub fn decide_dispatch(
    estimated_credits: f64,
    sensitivity: Option<&str>,
    eligible_workers: &[String],
    config: &CipConfig,
    replicas: i64,
    consumer_balance: Option<f64>,
    session_spent: f64,
) -> DispatchResult {
    // Gate 1 — not enabled → local.
    if !config.enabled {
        return DispatchResult::Local;
    }
    // Gates 2a–2c — affordability.
    if estimated_credits > config.max_credits_per_task {
        return DispatchResult::Local;
    }
    if let Some(budget) = config.session_credit_budget {
        if session_spent + estimated_credits > budget {
            return DispatchResult::Local;
        }
    }
    if let Some(bal) = consumer_balance {
        if estimated_credits > bal {
            return blocked_remote(config, "IICP-E036");
        }
    }
    // Gate 3 — sensitivity opt-in.
    if sensitivity == Some("high") && !config.send_sensitive_prompts {
        return DispatchResult::Local;
    }
    // Gate 4 (local-first loopback preference) skipped — pure consumer.
    // Gate 5/6 — eligible worker count must satisfy the replica requirement.
    if (eligible_workers.len() as i64) < replicas.max(1) {
        if config.strategy == CipStrategy::LocalFirst {
            return DispatchResult::Local;
        }
        return DispatchResult::Error("IICP-E022".to_string());
    }
    DispatchResult::Remote
}

/// Build the cip envelope object for a CALL body from a REMOTE decision (CIP-CALL-01).
pub fn build_cip_envelope(
    decision: &DispatchResult,
    parent_task_id: &str,
    session_key: &str,
) -> Option<Value> {
    if *decision != DispatchResult::Remote {
        return None;
    }
    Some(serde_json::json!({
        "cip_role": "worker",
        "cip_session_key": session_key,
        "cip_parent_task_id": parent_task_id,
    }))
}

/// Evaluate CIP consumer gates and build the dispatch envelope (port of
/// dispatch.compute_cip_envelope). Ok(None) for LOCAL/disabled/invalid; Err for the
/// blocking errors (E036/E022).
pub fn compute_cip_envelope(
    nodes: &[CipWorkerCandidate],
    body: &Value,
    config: &CipConfig,
    trust_scope: Option<&CipTrustScope>,
    task_id: &str,
    qos: Option<&str>,
    consumer_balance: Option<f64>,
) -> Result<CipDispatchPlan, CipError> {
    if !config.enabled || qos == Some("realtime") {
        return Ok(CipDispatchPlan::local());
    }
    if validate_cip_request_fields(body).is_some() {
        return Ok(CipDispatchPlan::local()); // invalid cip fields → local fallback
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut eligible: Vec<String> = nodes
        .iter()
        .filter(|n| {
            n.allow_remote_inference
                && !n.node_id.is_empty()
                && n.reputation_score >= config.min_reputation
                && trust_scope.is_none_or(|scope| {
                    n.restricted_eligibility.as_ref().is_some_and(|proof| {
                        proof.domain_id == scope.domain_id
                            && proof.authority_id == scope.authority_id
                            && proof.membership_generation >= scope.minimum_membership_generation
                            && proof.membership_expires_at > now
                    })
                })
        })
        .map(|n| n.node_id.clone())
        .collect();
    if !config.trusted_peers.is_empty() {
        eligible.retain(|id| config.trusted_peers.contains(id));
    }
    let replicas = body
        .get("cip")
        .and_then(|c| c.get("replicas"))
        .and_then(|r| r.as_i64())
        .unwrap_or(1);
    let sensitivity = body.get("sensitivity").and_then(|s| s.as_str());

    let decision = decide_dispatch(
        1.0,
        sensitivity,
        &eligible,
        config,
        replicas,
        consumer_balance,
        0.0,
    );
    match &decision {
        DispatchResult::Error(code) if code == "IICP-E036" => {
            Err(CipError::InsufficientCredits(code.clone()))
        }
        DispatchResult::Error(code) if code == "IICP-E022" => {
            Err(CipError::NoEligibleWorkers(code.clone()))
        }
        _ => {
            let session_key = format!("cip-sess-{task_id}");
            Ok(CipDispatchPlan {
                envelope: build_cip_envelope(&decision, task_id, &session_key),
                allowed_node_ids: (decision == DispatchResult::Remote).then_some(eligible),
            })
        }
    }
}

/// Load CIP config from IICP_PROXY_CIP_* env (enabled defaults OFF — §2.2 ¶1).
pub fn cip_config_from_env() -> CipConfig {
    let truthy = |k: &str| {
        matches!(
            std::env::var(k)
                .as_deref()
                .map(str::trim)
                .map(str::to_lowercase)
                .as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        )
    };
    let strategy = match std::env::var("IICP_PROXY_CIP_STRATEGY")
        .as_deref()
        .map(str::trim)
    {
        Ok("remote-first") => CipStrategy::RemoteFirst,
        Ok("balanced") => CipStrategy::Balanced,
        _ => CipStrategy::LocalFirst,
    };
    CipConfig {
        enabled: truthy("IICP_PROXY_CIP_ENABLED"),
        strategy,
        max_credits_per_task: std::env::var("IICP_PROXY_CIP_MAX_CREDITS_PER_TASK")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10.0),
        session_credit_budget: std::env::var("IICP_PROXY_CIP_SESSION_CREDIT_BUDGET")
            .ok()
            .and_then(|s| s.parse().ok()),
        send_sensitive_prompts: truthy("IICP_PROXY_CIP_SEND_SENSITIVE_PROMPTS"),
        trusted_peers: std::env::var("IICP_PROXY_CIP_TRUSTED_PEERS")
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        min_reputation: std::env::var("IICP_PROXY_CIP_MIN_REPUTATION")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> CipConfig {
        CipConfig {
            enabled: true,
            strategy: CipStrategy::RemoteFirst,
            ..Default::default()
        }
    }

    fn worker(node_id: &str) -> CipWorkerCandidate {
        CipWorkerCandidate {
            node_id: node_id.into(),
            allow_remote_inference: true,
            reputation_score: 0.9,
            restricted_eligibility: None,
        }
    }

    #[test]
    fn gate_not_enabled_is_local() {
        let c = CipConfig {
            enabled: false,
            ..cfg()
        };
        assert_eq!(
            decide_dispatch(1.0, None, &["a".into()], &c, 1, None, 0.0),
            DispatchResult::Local
        );
    }
    #[test]
    fn gate_unaffordable_remote_first_is_e036() {
        assert_eq!(
            decide_dispatch(1.0, None, &["a".into()], &cfg(), 1, Some(0.0), 0.0),
            DispatchResult::Error("IICP-E036".into())
        );
    }
    #[test]
    fn gate_unaffordable_local_first_is_local() {
        let c = CipConfig {
            strategy: CipStrategy::LocalFirst,
            ..cfg()
        };
        assert_eq!(
            decide_dispatch(1.0, None, &["a".into()], &c, 1, Some(0.0), 0.0),
            DispatchResult::Local
        );
    }
    #[test]
    fn gate_no_workers_remote_first_is_e022() {
        assert_eq!(
            decide_dispatch(1.0, None, &[], &cfg(), 1, Some(100.0), 0.0),
            DispatchResult::Error("IICP-E022".into())
        );
    }
    #[test]
    fn gate_all_pass_is_remote() {
        assert_eq!(
            decide_dispatch(
                1.0,
                None,
                &["a".into(), "b".into()],
                &cfg(),
                1,
                Some(100.0),
                0.0
            ),
            DispatchResult::Remote
        );
    }
    #[test]
    fn gate_sensitive_not_opted_is_local() {
        assert_eq!(
            decide_dispatch(
                1.0,
                Some("high"),
                &["a".into()],
                &cfg(),
                1,
                Some(100.0),
                0.0
            ),
            DispatchResult::Local
        );
    }

    #[test]
    fn envelope_unaffordable_errs_e036() {
        let nodes = vec![worker("n1")];
        let err = compute_cip_envelope(
            &nodes,
            &serde_json::json!({}),
            &cfg(),
            None,
            "t1",
            None,
            Some(0.0),
        )
        .unwrap_err();
        assert_eq!(err, CipError::InsufficientCredits("IICP-E036".into()));
    }
    #[test]
    fn envelope_no_eligible_errs_e022() {
        let mut node = worker("n1");
        node.allow_remote_inference = false;
        let nodes = vec![node];
        let err = compute_cip_envelope(
            &nodes,
            &serde_json::json!({}),
            &cfg(),
            None,
            "t1",
            None,
            Some(100.0),
        )
        .unwrap_err();
        assert_eq!(err, CipError::NoEligibleWorkers("IICP-E022".into()));
    }
    #[test]
    fn envelope_remote_builds_worker() {
        let nodes = vec![worker("n1")];
        let plan = compute_cip_envelope(
            &nodes,
            &serde_json::json!({}),
            &cfg(),
            None,
            "parent-1",
            None,
            Some(100.0),
        )
        .unwrap();
        let env = plan.envelope.unwrap();
        assert_eq!(env["cip_role"], "worker");
        assert_eq!(env["cip_parent_task_id"], "parent-1");
        assert_eq!(plan.allowed_node_ids, Some(vec!["n1".into()]));
    }
    #[test]
    fn envelope_disabled_is_none() {
        let c = CipConfig {
            enabled: false,
            ..cfg()
        };
        let plan =
            compute_cip_envelope(&[], &serde_json::json!({}), &c, None, "t1", None, None).unwrap();
        assert_eq!(plan, CipDispatchPlan::local());
    }

    #[test]
    fn restricted_scope_rejects_missing_and_foreign_provenance() {
        let scope = CipTrustScope {
            domain_id: "domain-a".into(),
            authority_id: "directory-a".into(),
            minimum_membership_generation: 7,
        };
        for proof in [
            None,
            Some(RestrictedEligibility {
                domain_id: "domain-b".into(),
                authority_id: "directory-a".into(),
                membership_generation: 7,
                membership_expires_at: u64::MAX,
            }),
        ] {
            let mut candidate = worker("n1");
            candidate.restricted_eligibility = proof;
            let err = compute_cip_envelope(
                &[candidate],
                &serde_json::json!({}),
                &cfg(),
                Some(&scope),
                "t1",
                None,
                Some(100.0),
            )
            .unwrap_err();
            assert_eq!(err, CipError::NoEligibleWorkers("IICP-E022".into()));
        }
    }

    #[test]
    fn restricted_scope_accepts_current_matching_provenance() {
        let scope = CipTrustScope {
            domain_id: "domain-a".into(),
            authority_id: "directory-a".into(),
            minimum_membership_generation: 7,
        };
        let mut candidate = worker("n1");
        candidate.restricted_eligibility = Some(RestrictedEligibility {
            domain_id: scope.domain_id.clone(),
            authority_id: scope.authority_id.clone(),
            membership_generation: 7,
            membership_expires_at: u64::MAX,
        });
        let plan = compute_cip_envelope(
            &[candidate],
            &serde_json::json!({}),
            &cfg(),
            Some(&scope),
            "t1",
            None,
            Some(100.0),
        )
        .unwrap();
        assert!(plan.envelope.is_some());
        assert_eq!(plan.allowed_node_ids, Some(vec!["n1".into()]));
    }

    #[test]
    fn restricted_scope_rejects_expired_or_stale_generation() {
        let scope = CipTrustScope {
            domain_id: "domain-a".into(),
            authority_id: "directory-a".into(),
            minimum_membership_generation: 7,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for (generation, expiry) in [(6, u64::MAX), (7, now)] {
            let mut candidate = worker("n1");
            candidate.restricted_eligibility = Some(RestrictedEligibility {
                domain_id: scope.domain_id.clone(),
                authority_id: scope.authority_id.clone(),
                membership_generation: generation,
                membership_expires_at: expiry,
            });
            assert_eq!(
                compute_cip_envelope(
                    &[candidate],
                    &serde_json::json!({}),
                    &cfg(),
                    Some(&scope),
                    "t1",
                    None,
                    Some(100.0),
                )
                .unwrap_err(),
                CipError::NoEligibleWorkers("IICP-E022".into())
            );
        }
    }

    #[test]
    fn trusted_peers_only_narrows_verified_members() {
        let scope = CipTrustScope {
            domain_id: "domain-a".into(),
            authority_id: "directory-a".into(),
            minimum_membership_generation: 7,
        };
        let mut candidate = worker("verified-but-not-allowed");
        candidate.restricted_eligibility = Some(RestrictedEligibility {
            domain_id: scope.domain_id.clone(),
            authority_id: scope.authority_id.clone(),
            membership_generation: 7,
            membership_expires_at: u64::MAX,
        });
        let mut config = cfg();
        config.trusted_peers = vec!["another-node".into()];
        assert_eq!(
            compute_cip_envelope(
                &[candidate],
                &serde_json::json!({}),
                &config,
                Some(&scope),
                "t1",
                None,
                Some(100.0),
            )
            .unwrap_err(),
            CipError::NoEligibleWorkers("IICP-E022".into())
        );
    }
    #[test]
    fn validate_invalid_policy_e028() {
        assert_eq!(
            validate_cip_request_fields(&serde_json::json!({"cip": {"policy": "nope"}})),
            Some("IICP-E028".into())
        );
    }
    #[test]
    fn validate_majority_even_e025() {
        assert_eq!(
            validate_cip_request_fields(
                &serde_json::json!({"cip": {"policy": "majority_vote", "replicas": 2}})
            ),
            Some("IICP-E025".into())
        );
    }
}
