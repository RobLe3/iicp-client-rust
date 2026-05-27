// SPDX-License-Identifier: Apache-2.0
//! Unified concurrency gate for the hybrid client.
//!
//! Rust port of iicp-client-python's `concurrency.py` (iter-1438) and
//! iicp-client-typescript's `concurrency.ts` (iter-1439). Tier 2 Item 5
//! of #340 — closes the entire Tier 1+2 matrix across all 3 SDKs once
//! this lands.
//!
//! Caps simultaneous inference tasks at `max_concurrent`. Non-blocking
//! acquire — when at capacity the SDK returns IICP-E021 (429) on
//! whichever transport carries the CALL rather than queueing. A queue
//! would mask overload from the proxy; the proxy MUST learn back-pressure
//! immediately so it can route elsewhere (ADR-008).

use std::sync::atomic::{AtomicUsize, Ordering};

/// Returned by [`ConcurrencyGate::acquire`] when the gate is at capacity.
/// Callers MUST translate to IICP-E021:
///   - HTTP /v1/task → 429 with Retry-After
///   - IICP TCP CALL → RESPONSE error_code=429
#[derive(Debug, thiserror::Error)]
#[error("max_concurrent ({max_concurrent}) reached")]
pub struct CapacityExceededError {
    pub max_concurrent: usize,
}

/// Cap simultaneous inference tasks at `max_concurrent`. Lock-free
/// implementation via AtomicUsize CAS — no Mutex contention on the hot path.
pub struct ConcurrencyGate {
    max_concurrent: usize,
    active: AtomicUsize,
}

impl ConcurrencyGate {
    pub fn new(max_concurrent: usize) -> Self {
        assert!(max_concurrent >= 1, "max_concurrent must be >= 1");
        Self {
            max_concurrent,
            active: AtomicUsize::new(0),
        }
    }

    /// Non-blocking acquire. Returns [`CapacityExceededError`] when full.
    /// On success the caller MUST call [`release`] when the task completes;
    /// prefer [`run`] for automatic release.
    pub fn acquire(&self) -> Result<(), CapacityExceededError> {
        let mut cur = self.active.load(Ordering::Acquire);
        loop {
            if cur >= self.max_concurrent {
                return Err(CapacityExceededError {
                    max_concurrent: self.max_concurrent,
                });
            }
            match self
                .active
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Ok(()),
                Err(actual) => cur = actual,
            }
        }
    }

    pub fn release(&self) {
        let prev = self.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "release called more times than acquire");
    }

    /// Run `fut` while holding a slot. Auto-releases on success or panic.
    pub async fn run<F, T>(&self, fut: F) -> Result<T, CapacityExceededError>
    where
        F: std::future::Future<Output = T>,
    {
        self.acquire()?;
        // Use a guard so we release even on panic (catch_unwind isn't async-friendly,
        // but a Drop guard suffices).
        struct ReleaseOnDrop<'a>(&'a ConcurrencyGate);
        impl<'a> Drop for ReleaseOnDrop<'a> {
            fn drop(&mut self) {
                self.0.release();
            }
        }
        let _guard = ReleaseOnDrop(self);
        Ok(fut.await)
    }

    pub fn active_jobs(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    pub fn max(&self) -> usize {
        self.max_concurrent
    }

    /// Load fraction in [0.0, 1.0]. Reported in heartbeats so the directory's
    /// NodeScorer can down-rank busy nodes (ADR-008).
    pub fn load(&self) -> f64 {
        if self.max_concurrent == 0 {
            return 1.0;
        }
        self.active_jobs() as f64 / self.max_concurrent as f64
    }
}
