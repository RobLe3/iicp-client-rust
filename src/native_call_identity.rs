//! Fail-closed identity validation for negotiated native lifecycle CALLs.

use std::collections::{HashMap, HashSet};

use serde_json::Value;
use thiserror::Error;

pub const LIFECYCLE_PROFILE: &str = "urn:iicp:profile:service-lifecycle:v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NativeCallIdentityError {
    #[error("missing_task_id")]
    MissingTaskId,
    #[error("missing_call_id")]
    MissingCallId,
    #[error("missing_idempotency_key")]
    MissingIdempotencyKey,
    #[error("call_id_reuse")]
    CallIdReuse,
    #[error("task_identity_conflict")]
    TaskIdentityConflict,
}

#[derive(Debug, Default)]
pub struct NativeCallIdentityRegistry {
    tasks: HashMap<String, String>,
    calls: HashSet<String>,
}

impl NativeCallIdentityRegistry {
    pub fn accept(&mut self, call: &Value) -> Result<(), NativeCallIdentityError> {
        if call.get("profile").and_then(Value::as_str) != Some(LIFECYCLE_PROFILE) {
            return Ok(());
        }
        let task_id = required(call, "task_id", NativeCallIdentityError::MissingTaskId)?;
        let call_id = required(call, "call_id", NativeCallIdentityError::MissingCallId)?;
        let idempotency_key = required(
            call,
            "idempotency_key",
            NativeCallIdentityError::MissingIdempotencyKey,
        )?;
        if self.calls.contains(call_id) {
            return Err(NativeCallIdentityError::CallIdReuse);
        }
        if self
            .tasks
            .get(task_id)
            .is_some_and(|known| known != idempotency_key)
        {
            return Err(NativeCallIdentityError::TaskIdentityConflict);
        }
        self.tasks
            .insert(task_id.to_owned(), idempotency_key.to_owned());
        self.calls.insert(call_id.to_owned());
        Ok(())
    }
}

fn required<'a>(
    call: &'a Value,
    key: &str,
    error: NativeCallIdentityError,
) -> Result<&'a str, NativeCallIdentityError> {
    call.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(error)
}
