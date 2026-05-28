// SPDX-License-Identifier: Apache-2.0
//! Time-based availability windows — operator capacity shaping by time-of-day.
//!
//! Port of iicp-adapter `scheduling/availability.py` (parity Block D, #340). Lets an
//! operator dedicate different fractions of `max_concurrent` at different times.
//!
//!   - start/end: "HH:MM" in local time.
//!   - share: fraction of max_concurrent (0.0 = closed, 1.0 = full).
//!   - Outside all windows: 0.5 (available but not primary).
//!   - No windows: always 1.0.
//!
//! The directory learns live load via heartbeats and scores accordingly (ADR-001).

use chrono::{Local, Timelike};

/// One availability window. `share` is a fraction in [0.0, 1.0].
#[derive(Debug, Clone, PartialEq)]
pub struct Window {
    pub start: String, // "HH:MM"
    pub end: String,   // "HH:MM"
    pub share: f64,
}

/// Evaluates time-based availability windows (local time). No windows → always 1.0.
#[derive(Debug, Clone, Default)]
pub struct AvailabilityEvaluator {
    windows: Vec<Window>,
}

impl AvailabilityEvaluator {
    pub fn new(windows: Vec<Window>) -> Self {
        Self { windows }
    }

    fn now_hhmm() -> String {
        let now = Local::now();
        format!("{:02}:{:02}", now.hour(), now.minute())
    }

    /// Capacity share [0,1] for the current local time-of-day.
    pub fn current_share(&self) -> f64 {
        self.share_at(&Self::now_hhmm())
    }

    /// Pure core: share for an explicit "HH:MM" (used by tests + `current_share`).
    pub fn share_at(&self, current: &str) -> f64 {
        if self.windows.is_empty() {
            return 1.0;
        }
        for w in &self.windows {
            if w.start <= w.end {
                if w.start.as_str() <= current && current <= w.end.as_str() {
                    return w.share;
                }
            } else if current >= w.start.as_str() || current <= w.end.as_str() {
                // Midnight-spanning window (e.g. 22:00–06:00).
                return w.share;
            }
        }
        0.5 // outside all windows
    }

    /// Scale `base_max` by the current share (floor 1 when share > 0). A base of 0
    /// (operator explicitly disabled) stays 0.
    pub fn effective_max_concurrent(&self, base_max: usize) -> usize {
        self.effective_at(base_max, &Self::now_hhmm())
    }

    /// Pure core of [`effective_max_concurrent`] for an explicit "HH:MM".
    pub fn effective_at(&self, base_max: usize, current: &str) -> usize {
        if base_max == 0 {
            return 0;
        }
        let share = self.share_at(current);
        if share <= 0.0 {
            return 0;
        }
        std::cmp::max(1, (base_max as f64 * share) as usize)
    }

    pub fn is_within_window(&self) -> bool {
        self.windows.is_empty() || self.current_share() > 0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(start: &str, end: &str, share: f64) -> Window {
        Window { start: start.into(), end: end.into(), share }
    }

    #[test]
    fn no_windows_full() {
        let ev = AvailabilityEvaluator::default();
        assert_eq!(ev.share_at("03:00"), 1.0);
        assert_eq!(ev.effective_at(4, "14:00"), 4);
    }

    #[test]
    fn inside_normal_window() {
        let ev = AvailabilityEvaluator::new(vec![win("08:00", "22:00", 0.5)]);
        assert_eq!(ev.share_at("12:00"), 0.5);
        assert_eq!(ev.effective_at(4, "12:00"), 2);
    }

    #[test]
    fn outside_window_half() {
        let ev = AvailabilityEvaluator::new(vec![win("08:00", "22:00", 1.0)]);
        assert_eq!(ev.share_at("02:00"), 0.5);
    }

    #[test]
    fn floors_at_one_when_share_positive() {
        let ev = AvailabilityEvaluator::new(vec![win("08:00", "22:00", 0.1)]);
        assert_eq!(ev.effective_at(4, "10:00"), 1);
    }

    #[test]
    fn base_zero_stays_zero() {
        let ev = AvailabilityEvaluator::default();
        assert_eq!(ev.effective_at(0, "10:00"), 0);
    }

    #[test]
    fn midnight_spanning_window() {
        let ev = AvailabilityEvaluator::new(vec![win("22:00", "06:00", 1.0)]);
        assert_eq!(ev.share_at("23:30"), 1.0);
        assert_eq!(ev.share_at("02:00"), 1.0);
        assert_eq!(ev.share_at("12:00"), 0.5);
    }

    #[test]
    fn closed_window_zero_capacity() {
        let ev = AvailabilityEvaluator::new(vec![win("00:00", "23:59", 0.0)]);
        assert_eq!(ev.effective_at(4, "10:00"), 0);
    }
}
