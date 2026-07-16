// SPDX-License-Identifier: Apache-2.0
//! Portable evaluator for the pre-normative distributed lifecycle profile.

use serde_json::Value;

const ALLOWED: [&str; 6] = [
    "event_id",
    "progress",
    "reason_code",
    "outcome",
    "receipt_digest",
    "checkpoint_digest",
];

pub fn evaluate_distributed_lifecycle(vector: &Value) -> &'static str {
    match vector["kind"].as_str() {
        Some("owner_write") => {
            if vector["writer_epoch"] == vector["current_epoch"] {
                "write_accepted"
            } else {
                "stale_owner_rejected"
            }
        }
        Some("failover_submit") => {
            if vector["request_digest_matches"] != true || vector["idempotency_key_matches"] != true
            {
                "conflict_no_new_execution"
            } else if vector["execution_started"] == true {
                "existing_execution_recovered"
            } else {
                "existing_record_recovered"
            }
        }
        Some("append_event") => {
            if vector["event_id_seen"] == true {
                "duplicate_event_ignored"
            } else if vector["sequence"].as_i64()
                == vector["latest_sequence"].as_i64().map(|value| value + 1)
            {
                "event_appended"
            } else {
                "sequence_gap_rejected"
            }
        }
        Some("observe") => {
            let gap = vector["after_sequence"].as_i64().unwrap_or(-1) + 1
                < vector["first_retained_sequence"].as_i64().unwrap_or(0);
            if gap && vector["terminal"] == true {
                "terminal_snapshot_with_replay_gap"
            } else if gap {
                "resume_unavailable"
            } else {
                "replay_available"
            }
        }
        Some("terminal_retention") => {
            if vector["age_ms"].as_i64().unwrap_or(0) > vector["ttl_ms"].as_i64().unwrap_or(0) {
                "unknown_task_after_expiry"
            } else {
                "terminal_snapshot_available"
            }
        }
        Some("mutation_admission") => {
            if vector["quorum_available"] == true {
                "mutation_allowed"
            } else {
                "temporarily_unavailable_no_write"
            }
        }
        Some("content_minimization") => {
            let allowed = vector["detail"]
                .as_object()
                .is_some_and(|detail| detail.keys().all(|field| ALLOWED.contains(&field.as_str())));
            if allowed {
                "accepted"
            } else {
                "reject_before_write"
            }
        }
        _ => "unsupported_vector",
    }
}
