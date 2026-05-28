// SPDX-License-Identifier: Apache-2.0
//! QoS-aware admission policy for the provider serve path (parity Block C, #340).
//!
//! Port of the QoS *contract* from iicp-adapter `scheduling/queue.py`. The adapter runs a
//! full priority-queue dispatcher; the SDK serve gate is deliberately fail-fast (queuing
//! would hide overload from the proxy). To close the cat-8 parity gap without contradicting
//! that design, the SDK applies QoS-aware admission:
//!
//!   - realtime / interactive → queue-eligible: wait briefly ([`QUEUE_WAIT`]) for a slot.
//!   - batch / best-effort / unspecified → fail fast with IICP-E021.
//!
//! Priority ordering (lower = higher priority) is exposed for telemetry parity.

use std::time::Duration;

/// Bounded wait for queue-eligible tiers.
pub const QUEUE_WAIT: Duration = Duration::from_secs(2);

/// Priority rank for a QoS class (lower = higher priority; unknown → 3). Both the
/// hyphen ("best-effort", adapter) and underscore ("best_effort", SDK) spellings map
/// to the same rank.
pub fn qos_priority(qos: &str) -> u8 {
    match qos {
        "realtime" => 0,
        "interactive" => 1,
        "batch" => 2,
        _ => 3,
    }
}

/// True if a task of this QoS class should wait briefly for a slot at capacity.
pub fn is_queue_eligible(qos: &str) -> bool {
    matches!(qos, "realtime" | "interactive")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_realtime_highest() {
        assert!(qos_priority("realtime") < qos_priority("interactive"));
        assert!(qos_priority("interactive") < qos_priority("batch"));
        assert!(qos_priority("batch") <= qos_priority("best_effort"));
    }

    #[test]
    fn unknown_and_best_effort_lowest() {
        assert_eq!(qos_priority("best_effort"), 3);
        assert_eq!(qos_priority("best-effort"), 3);
        assert_eq!(qos_priority("nonsense"), 3);
    }

    #[test]
    fn only_realtime_interactive_eligible() {
        assert!(is_queue_eligible("realtime"));
        assert!(is_queue_eligible("interactive"));
        for q in ["batch", "best_effort", "best-effort", "unknown"] {
            assert!(!is_queue_eligible(q), "{q} must not be queue-eligible");
        }
    }
}
