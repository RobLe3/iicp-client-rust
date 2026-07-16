//! Pure, opt-in accounting decisions for the draft service lifecycle profile.

use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleAccountingDecision {
    pub decision: String,
    pub reservation_action: &'static str,
    pub settlement_action: &'static str,
    pub new_execution: bool,
}

fn result(
    decision: impl Into<String>,
    reservation_action: &'static str,
    settlement_action: &'static str,
    new_execution: bool,
) -> LifecycleAccountingDecision {
    LifecycleAccountingDecision {
        decision: decision.into(),
        reservation_action,
        settlement_action,
        new_execution,
    }
}

fn simple(decision: &str) -> LifecycleAccountingDecision {
    result(decision, "none", "none", false)
}

pub fn decide_lifecycle_accounting(input: &Value) -> LifecycleAccountingDecision {
    let operation = input.get("operation").and_then(Value::as_str);
    let binding = input.get("binding").and_then(Value::as_str);
    let reservation_exists = input.get("reservation_exists").and_then(Value::as_bool) == Some(true);
    let settlement_exists = input.get("settlement_exists").and_then(Value::as_bool) == Some(true);
    let accepted = input.get("accepted").and_then(Value::as_bool) == Some(true);
    let delivery = input.get("delivery").and_then(Value::as_str);

    if !matches!(
        operation,
        Some("submit" | "status" | "observe" | "resume" | "cancel" | "terminal")
    ) || !matches!(binding, Some("same" | "conflict" | "fresh"))
        || !matches!(delivery, Some("none" | "partial" | "complete"))
    {
        return simple("reject_invalid_input");
    }
    if matches!(
        operation,
        Some("status" | "observe" | "cancel" | "terminal")
    ) && binding != Some("same")
    {
        return simple("reject_conflict");
    }

    match operation.expect("validated operation") {
        "status" => simple("return_status"),
        "observe" => simple("replay_events"),
        "resume" => {
            if input.get("resume_available").and_then(Value::as_bool) == Some(true) {
                return simple("replay_events");
            }
            if input.get("explicit_new_task").and_then(Value::as_bool) != Some(true) {
                return simple("explicit_new_task_required");
            }
            if binding != Some("fresh")
                || input.get("fresh_task_id").and_then(Value::as_bool) != Some(true)
                || input.get("fresh_idempotency_key").and_then(Value::as_bool) != Some(true)
            {
                return simple("reject_identifier_reuse");
            }
            result("start_new_task", "create", "none", true)
        }
        "submit" => {
            if binding == Some("conflict") {
                simple("reject_conflict")
            } else if binding == Some("same") && reservation_exists {
                result("reuse_execution", "reuse", "none", false)
            } else if binding == Some("same") {
                simple("reject_missing_reservation")
            } else if reservation_exists {
                simple("reject_conflict")
            } else {
                result("start_execution", "create", "none", true)
            }
        }
        "cancel" => {
            if settlement_exists {
                return result("return_existing_settlement", "reuse", "reuse", false);
            }
            if !reservation_exists {
                return simple("cancel_without_accounting");
            }
            if !accepted {
                return result("cancel_before_acceptance", "release", "none", false);
            }
            let decision = if delivery == Some("partial") {
                "cancel_after_partial_delivery"
            } else {
                "cancel_after_acceptance"
            };
            result(decision, "reuse", "create", false)
        }
        "terminal" => {
            if settlement_exists {
                return result("return_existing_settlement", "reuse", "reuse", false);
            }
            if !reservation_exists {
                return simple("reject_missing_reservation");
            }
            let terminal_state = input.get("terminal_state").and_then(Value::as_str);
            if !matches!(
                terminal_state,
                Some("completed" | "failed" | "cancelled" | "expired")
            ) {
                return simple("reject_invalid_input");
            }
            let suffix = if delivery == Some("partial") {
                "_partial"
            } else {
                ""
            };
            result(
                format!(
                    "settle_{}{suffix}",
                    terminal_state.expect("validated terminal state")
                ),
                "reuse",
                "create",
                false,
            )
        }
        _ => simple("reject_invalid_input"),
    }
}
