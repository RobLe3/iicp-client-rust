// SPDX-License-Identifier: Apache-2.0
//! CIP-W01/CIP-W02 provider-side policy gate — S.12, ADR-012.
//!
//! Rust port of iicp-client-python's cip_policy.py (iter-1429) and
//! iicp-client-typescript's cip_policy.ts (iter-1430). Closes Tier 2 Item 2
//! of #340 across all 3 hybrid SDKs.
//!
//! Safe Phase-4 defaults: all three CIP roles (consumer / coordinator /
//! worker) are OFF until the operator opts in. The capacity gate enforces
//! S.12 §2.2 — workers at capacity MUST return IICP-E021 rather than
//! silently queue or delay.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

/// Provider-side CIP policy with safe-by-default flags and a built-in
/// capacity gate. Mirrors the iicp-adapter `CooperativeInferencePolicy`
/// contract so wire behaviour stays identical between adapter and hybrid
/// clients.
#[derive(Debug)]
pub struct CooperativeInferencePolicy {
    pub enabled: bool,
    pub allow_coordinator: bool,
    pub allow_worker: bool,
    pub max_replicas: usize,
    /// Bounded to [1, 60000] ms.
    pub max_worker_timeout_ms: u32,
    pub max_concurrent_remote: usize,
    in_flight: AtomicUsize,
}

#[derive(Debug, Clone)]
pub struct CooperativeInferencePolicyOptions {
    pub enabled: bool,
    pub allow_coordinator: bool,
    pub allow_worker: bool,
    pub max_replicas: usize,
    pub max_worker_timeout_ms: u32,
    pub max_concurrent_remote: usize,
}

impl Default for CooperativeInferencePolicyOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_coordinator: false,
            allow_worker: false,
            max_replicas: 3,
            max_worker_timeout_ms: 30_000,
            max_concurrent_remote: 2,
        }
    }
}

impl CooperativeInferencePolicy {
    pub fn new(opts: CooperativeInferencePolicyOptions) -> Self {
        Self {
            enabled: opts.enabled,
            allow_coordinator: opts.allow_coordinator,
            allow_worker: opts.allow_worker,
            max_replicas: opts.max_replicas.max(1),
            max_worker_timeout_ms: opts.max_worker_timeout_ms.clamp(1, 60_000),
            max_concurrent_remote: opts.max_concurrent_remote.max(1),
            in_flight: AtomicUsize::new(0),
        }
    }

    /// CIP-W01: returns true if this node may act as a CIP coordinator.
    pub fn check_coordinator(&self) -> bool {
        self.enabled && self.allow_coordinator
    }

    /// CIP-W02: returns true if this node may accept CIP worker tasks.
    pub fn check_worker(&self) -> bool {
        self.enabled && self.allow_worker
    }

    /// CIP-A1-GATE-06: try to acquire a worker concurrency slot.
    ///
    /// Returns true on success — caller MUST call [`release_cip_slot`]
    /// when done. Returns false when at capacity, in which case the caller
    /// MUST respond with `IICP-E021` rather than queue or delay
    /// (S.12 §2.2 explicit non-silent-queue rule).
    pub fn try_acquire_cip_slot(&self) -> bool {
        // CAS loop to keep the gate strictly bounded at max_concurrent_remote.
        let mut cur = self.in_flight.load(Ordering::Acquire);
        loop {
            if cur >= self.max_concurrent_remote {
                return false;
            }
            match self
                .in_flight
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    pub fn release_cip_slot(&self) {
        let prev = self.in_flight.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "release_cip_slot called more times than acquire");
    }

    /// Build the `policy` sub-object the directory expects in /v1/register.
    /// Returns `None` when CIP is disabled — disabled-by-default operators
    /// shouldn't clutter the register payload with `allow_*: false`.
    pub fn as_register_policy_block(&self) -> Option<serde_json::Value> {
        if !self.enabled {
            return None;
        }
        Some(serde_json::json!({
            "allow_remote_inference": self.allow_worker,
        }))
    }
}

// ── Module-level default policy ──────────────────────────────────────────

static GLOBAL_POLICY: OnceLock<RwLock<Arc<CooperativeInferencePolicy>>> = OnceLock::new();

fn lock() -> &'static RwLock<Arc<CooperativeInferencePolicy>> {
    GLOBAL_POLICY.get_or_init(|| {
        RwLock::new(Arc::new(CooperativeInferencePolicy::new(
            CooperativeInferencePolicyOptions::default(),
        )))
    })
}

/// Return the active CIP policy (safe defaults until [`configure_cip_policy`]
/// is called).
pub fn get_cip_policy() -> Arc<CooperativeInferencePolicy> {
    lock().read().expect("poisoned").clone()
}

/// Replace the module-level CIP policy. Returns the new policy for chaining.
pub fn configure_cip_policy(
    opts: CooperativeInferencePolicyOptions,
) -> Arc<CooperativeInferencePolicy> {
    let new = Arc::new(CooperativeInferencePolicy::new(opts));
    let mut guard = lock().write().expect("poisoned");
    *guard = new.clone();
    new
}
