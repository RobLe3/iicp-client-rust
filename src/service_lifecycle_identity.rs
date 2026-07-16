// SPDX-License-Identifier: Apache-2.0
//! Production-identity projection policy for opt-in lifecycle operations.

use serde_json::Value;

const ALLOWED_AUDIT: [&str; 9] = [
    "event_id",
    "task_ref",
    "principal_ref_digest",
    "credential_key_id",
    "revocation_epoch",
    "operation",
    "outcome",
    "reason_code",
    "occurred_at",
];

pub fn evaluate_lifecycle_identity(input: &Value, retention_seconds: i64) -> &'static str {
    if input["kind"] == "audit_retention" {
        return if input["age_seconds"].as_i64().unwrap_or(0) > retention_seconds {
            "audit_record_pruned"
        } else {
            "audit_record_retained"
        };
    }
    if input["kind"] == "audit_redaction" {
        let allowed = input["audit"].as_object().is_some_and(|audit| {
            audit
                .keys()
                .all(|field| ALLOWED_AUDIT.contains(&field.as_str()))
        });
        return if allowed {
            "audit_record_allowed"
        } else {
            "reject_before_write"
        };
    }
    if input["profile_requested"] != true && input["surface"] == "ordinary_task" {
        return "legacy_open_mesh_unchanged";
    }
    if input["credential_status"] != "valid" {
        return "unauthenticated";
    }
    if input["credential_revocation_epoch"].as_i64().unwrap_or(0)
        < input["minimum_revocation_epoch"].as_i64().unwrap_or(0)
    {
        return "unauthenticated";
    }
    let operation = input["operation"].as_str().unwrap_or("");
    let scopes = input["scope"].as_array().cloned().unwrap_or_default();
    let has_scope = |scope: &str| scopes.iter().any(|item| item == scope);
    if operation == "submit" {
        return if has_scope("submit") {
            "allowed_bind_owner"
        } else {
            "forbidden"
        };
    }
    if input["principal_ref_digest"] != input["task_owner_ref_digest"] {
        let operator_scope = format!("operator:{operation}");
        if input["operator_override"] == true && has_scope(&operator_scope) {
            return "allowed_operator_override";
        }
        return "concealed_task";
    }
    if has_scope(operation) {
        "allowed"
    } else {
        "forbidden"
    }
}
