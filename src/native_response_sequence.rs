// SPDX-License-Identifier: Apache-2.0
//! Transport-independent validation for negotiated native RESPONSE sequences.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeLifecycleEnvelope {
    pub task_id: String,
    pub sequence: u64,
    pub event: String,
    pub is_final: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeResponseFrame {
    pub session_id: String,
    pub call_id: String,
    pub status: String,
    pub is_final: bool,
    pub lifecycle: NativeLifecycleEnvelope,
    #[serde(default)]
    pub result: serde_json::Value,
    #[serde(default)]
    pub error: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{code}")]
pub struct NativeResponseSequenceError {
    pub code: &'static str,
}

#[derive(Clone, Debug)]
pub struct NativeResponseSequence {
    session_id: String,
    call_id: String,
    task_id: String,
    next_sequence: u64,
    terminal_seen: bool,
}

impl NativeResponseSequence {
    pub fn new(
        session_id: impl Into<String>,
        call_id: impl Into<String>,
        task_id: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            call_id: call_id.into(),
            task_id: task_id.into(),
            next_sequence: 0,
            terminal_seen: false,
        }
    }

    pub fn accept(
        &mut self,
        frame: &NativeResponseFrame,
    ) -> Result<(), NativeResponseSequenceError> {
        if self.terminal_seen {
            return Err(error("response_after_terminal"));
        }
        if frame.session_id != self.session_id {
            return Err(error("session_id_drift"));
        }
        if frame.call_id != self.call_id {
            return Err(error("call_id_drift"));
        }
        if frame.lifecycle.task_id != self.task_id {
            return Err(error("task_id_drift"));
        }
        if frame.lifecycle.sequence != self.next_sequence {
            return Err(error("sequence_drift"));
        }
        if frame.is_final != frame.lifecycle.is_final {
            return Err(error("finality_disagreement"));
        }
        let status_matches = match frame.status.as_str() {
            "partial" => frame.lifecycle.event == "partial",
            "success" => frame.lifecycle.event == "completed",
            "error" => matches!(frame.lifecycle.event.as_str(), "failed" | "cancelled"),
            "timeout" => matches!(frame.lifecycle.event.as_str(), "timed_out" | "expired"),
            _ => false,
        };
        if !status_matches {
            return Err(error("status_event_disagreement"));
        }
        if (frame.status == "partial" && frame.is_final)
            || (frame.status != "partial" && !frame.is_final)
        {
            return Err(error("terminal_flag_mismatch"));
        }
        self.next_sequence += 1;
        self.terminal_seen = frame.is_final;
        Ok(())
    }

    pub fn finish(&self) -> Result<(), NativeResponseSequenceError> {
        if self.terminal_seen {
            Ok(())
        } else {
            Err(error("missing_terminal_response"))
        }
    }
}

fn error(code: &'static str) -> NativeResponseSequenceError {
    NativeResponseSequenceError { code }
}
