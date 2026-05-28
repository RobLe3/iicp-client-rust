// SPDX-License-Identifier: Apache-2.0
//! Idempotency guard — task_id dedup with TTL eviction (parity Block E, #340).
//!
//! Port of iicp-adapter `services/idempotency.py` (ADR-010). Prevents duplicate task
//! execution when a proxy retries a CALL. Distinct from the nonce replay cache: nonce
//! protects a signed request from replay; this dedups on `task_id`. In-memory, 5-minute
//! TTL, lazy eviction. Cross-restart dedup is intentionally not provided.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(300); // matches ADR-010 §3 + nonce cache.

#[derive(Debug)]
pub struct IdempotencyGuard {
    ttl: Duration,
    seen: Mutex<HashMap<String, Instant>>,
}

impl Default for IdempotencyGuard {
    fn default() -> Self {
        Self::new(TTL)
    }
}

impl IdempotencyGuard {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, seen: Mutex::new(HashMap::new()) }
    }

    /// Return `true` if `task_id` is new; `false` if a duplicate within the TTL.
    /// Empty task_id is always treated as new (caller didn't opt into idempotency).
    pub fn check_and_register(&self, task_id: &str) -> bool {
        if task_id.is_empty() {
            return true;
        }
        let now = Instant::now();
        let mut seen = self.seen.lock().expect("idempotency lock");
        seen.retain(|_, &mut exp| exp > now);
        if seen.contains_key(task_id) {
            return false;
        }
        seen.insert(task_id.to_string(), now + self.ttl);
        true
    }

    pub fn size(&self) -> usize {
        self.seen.lock().expect("idempotency lock").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_new_duplicate_rejected() {
        let g = IdempotencyGuard::default();
        assert!(g.check_and_register("t1"));
        assert!(!g.check_and_register("t1"));
    }

    #[test]
    fn distinct_ids_both_new() {
        let g = IdempotencyGuard::default();
        assert!(g.check_and_register("a"));
        assert!(g.check_and_register("b"));
    }

    #[test]
    fn empty_always_new() {
        let g = IdempotencyGuard::default();
        assert!(g.check_and_register(""));
        assert!(g.check_and_register(""));
    }

    #[test]
    fn ttl_expiry_allows_reuse() {
        let g = IdempotencyGuard::new(Duration::from_millis(30));
        assert!(g.check_and_register("t"));
        assert!(!g.check_and_register("t"));
        std::thread::sleep(Duration::from_millis(50));
        assert!(g.check_and_register("t"));
    }
}
