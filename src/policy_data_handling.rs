//! Opt-in evaluator for the pre-normative policy/data-handling profile.
use serde_json::Value;
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDataDecision {
    pub eligible: bool,
    pub reason: &'static str,
}
fn reject(reason: &'static str) -> PolicyDataDecision {
    PolicyDataDecision {
        eligible: false,
        reason,
    }
}
fn string_array(value: Option<&Value>) -> impl Iterator<Item = &str> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}
fn rank(value: Option<&Value>, values: &[&str], fallback: i32) -> i32 {
    value
        .and_then(Value::as_str)
        .and_then(|s| values.iter().position(|v| *v == s))
        .map_or(fallback, |n| n as i32)
}

pub fn evaluate_policy_data_handling(
    requirement: &Value,
    declaration: &Value,
    context: &Value,
) -> PolicyDataDecision {
    let known: HashSet<&str> = [
        "version",
        "data_class",
        "remote_routing",
        "allowed_regions",
        "retention",
        "training_use",
        "subprocessors",
        "approval",
        "tool_risk",
        "requires_encryption",
        "requires_receipt",
        "requires_human_review",
        "critical_requirements",
    ]
    .into_iter()
    .collect();
    if string_array(requirement.get("critical_requirements")).any(|field| !known.contains(field)) {
        return reject("unsupported_policy_requirement");
    }
    if requirement.get("remote_routing").and_then(Value::as_str) == Some("local_only") {
        return reject("remote_routing_forbidden");
    }
    let data_class = requirement
        .get("data_class")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !string_array(declaration.get("accepted_data_classes")).any(|v| v == data_class) {
        return reject("data_class_not_accepted");
    }
    if requirement.get("remote_routing").and_then(Value::as_str) == Some("requires_approval")
        && context.get("approval_granted").and_then(Value::as_bool) != Some(true)
    {
        return reject("approval_required");
    }
    let regions: Vec<_> = string_array(requirement.get("allowed_regions")).collect();
    if !regions.is_empty()
        && !regions.contains(
            &declaration
                .get("jurisdiction")
                .and_then(Value::as_str)
                .unwrap_or(""),
        )
    {
        return reject("region_not_allowed");
    }
    let rr = requirement.get("retention").unwrap_or(&Value::Null);
    let dr = declaration.get("retention").unwrap_or(&Value::Null);
    let required_mode = rr.get("task_payload").and_then(Value::as_str);
    let declared_mode = dr.get("task_payload").and_then(Value::as_str);
    if required_mode == Some("none") && declared_mode != Some("none") {
        return reject("retention_requirement_unsatisfied");
    }
    if required_mode == Some("transient") {
        if !matches!(declared_mode, Some("none" | "transient")) {
            return reject("retention_requirement_unsatisfied");
        }
        if let Some(required_max) = rr.get("max_seconds").and_then(Value::as_u64) {
            let declared_max = if declared_mode == Some("none") {
                Some(0)
            } else {
                dr.get("max_seconds").and_then(Value::as_u64)
            };
            if declared_max.is_none_or(|v| v > required_max) {
                return reject("retention_requirement_unsatisfied");
            }
        }
    }
    if requirement.get("training_use").and_then(Value::as_str) == Some("none")
        && declaration.get("training_use").and_then(Value::as_str) != Some("none")
    {
        return reject("training_use_requirement_unsatisfied");
    }
    if requirement.get("subprocessors").and_then(Value::as_str) == Some("none")
        && declaration.get("subprocessors").and_then(Value::as_str) != Some("none")
    {
        return reject("subprocessor_requirement_unsatisfied");
    }
    let approvals = ["none", "user", "operator", "human_review"];
    if requirement.get("approval").is_some()
        && rank(declaration.get("approval"), &approvals, -1)
            < rank(requirement.get("approval"), &approvals, 99)
    {
        return reject("approval_requirement_unsatisfied");
    }
    let risks = ["none", "read_only", "write", "privileged"];
    if requirement.get("tool_risk").is_some()
        && rank(declaration.get("tool_risk"), &risks, 99)
            > rank(requirement.get("tool_risk"), &risks, -1)
    {
        return reject("tool_risk_requirement_unsatisfied");
    }
    if requirement
        .get("requires_encryption")
        .and_then(Value::as_bool)
        == Some(true)
        && context.get("encryption_ready").and_then(Value::as_bool) != Some(true)
    {
        return reject("encryption_requirement_unsatisfied");
    }
    if requirement.get("requires_receipt").and_then(Value::as_bool) == Some(true)
        && context.get("receipt_supported").and_then(Value::as_bool) != Some(true)
    {
        return reject("receipt_requirement_unsatisfied");
    }
    if requirement
        .get("requires_human_review")
        .and_then(Value::as_bool)
        == Some(true)
        && declaration
            .get("requires_human_review")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return reject("human_review_requirement_unsatisfied");
    }
    PolicyDataDecision {
        eligible: true,
        reason: "compatible",
    }
}
