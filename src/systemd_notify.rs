// SPDX-License-Identifier: Apache-2.0
//! Thin, opt-in systemd consumer of the platform-neutral runtime-health model.

#[cfg(target_os = "linux")]
use crate::runtime_health::RuntimeHealth;
#[cfg(any(test, target_os = "linux"))]
use crate::runtime_health::{Lifecycle, Liveness, Readiness};
#[cfg(target_os = "linux")]
use sd_notify::NotifyState;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
const OPT_IN_ENV: &str = "IICP_SYSTEMD_NOTIFY";

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NotificationDecision {
    ready: bool,
    watchdog: bool,
}

#[cfg(any(test, target_os = "linux"))]
fn decision(
    lifecycle: Lifecycle,
    liveness: Liveness,
    _readiness: Readiness,
    ready_sent: bool,
    watchdog_configured: bool,
) -> NotificationDecision {
    let live_running = lifecycle == Lifecycle::Running && liveness == Liveness::Live;
    NotificationDecision {
        ready: live_running && !ready_sent,
        watchdog: live_running && watchdog_configured,
    }
}

/// Start the native notifier only after explicit opt-in and systemd socket discovery.
///
/// The pulse timer is a consumer, never the health source. A stalled Tokio runtime
/// cannot keep this task alive, and a stale health snapshot withholds the pulse.
#[cfg(target_os = "linux")]
pub fn spawn_if_enabled(health: RuntimeHealth) -> Option<tokio::task::JoinHandle<()>> {
    if std::env::var(OPT_IN_ENV).as_deref() != Ok("1")
        || std::env::var_os("NOTIFY_SOCKET").is_none()
    {
        return None;
    }
    let watchdog = sd_notify::watchdog_enabled();
    let cadence = watchdog
        .map(|duration| duration.div_f32(2.0))
        .unwrap_or(Duration::from_millis(500))
        .max(Duration::from_millis(100));
    Some(tokio::spawn(async move {
        let mut ready_sent = false;
        let mut interval = tokio::time::interval(cadence);
        loop {
            interval.tick().await;
            let snapshot = health.snapshot();
            let action = decision(
                snapshot.lifecycle,
                snapshot.liveness,
                snapshot.readiness,
                ready_sent,
                watchdog.is_some(),
            );
            let status = format!(
                "liveness={:?}; readiness={:?}",
                snapshot.liveness, snapshot.readiness
            )
            .to_lowercase();
            if action.ready {
                let _ = sd_notify::notify(&[NotifyState::Ready, NotifyState::Status(&status)]);
                ready_sent = true;
            } else {
                let _ = sd_notify::notify(&[NotifyState::Status(&status)]);
            }
            if action.watchdog {
                let _ = sd_notify::notify(&[NotifyState::Watchdog]);
            }
        }
    }))
}

/// Report an orderly stop; the service manager remains the restart authority.
#[cfg(target_os = "linux")]
pub fn notify_stopping() {
    if std::env::var(OPT_IN_ENV).as_deref() == Ok("1") {
        let _ = sd_notify::notify(&[NotifyState::Stopping, NotifyState::Status("Stopping")]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_and_watchdog_require_meaningful_live_runtime_progress() {
        let action = decision(
            Lifecycle::Running,
            Liveness::Live,
            Readiness::Degraded,
            false,
            true,
        );
        assert_eq!(
            action,
            NotificationDecision {
                ready: true,
                watchdog: true
            }
        );
    }

    #[test]
    fn stale_runtime_withholds_watchdog_even_when_process_and_timer_exist() {
        let action = decision(
            Lifecycle::Running,
            Liveness::NotLive,
            Readiness::NotReady,
            true,
            true,
        );
        assert_eq!(
            action,
            NotificationDecision {
                ready: false,
                watchdog: false
            }
        );
    }

    #[test]
    fn external_degradation_does_not_withhold_local_liveness_pulse() {
        let action = decision(
            Lifecycle::Running,
            Liveness::Live,
            Readiness::Degraded,
            true,
            true,
        );
        assert_eq!(
            action,
            NotificationDecision {
                ready: false,
                watchdog: true
            }
        );
    }
}
