// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "runtime-health-fault-injection")]

use iicp_client::runtime_health::{
    Liveness, Readiness, RuntimeHealth, RuntimeHealthFault, SubsystemState,
};

fn live_health() -> RuntimeHealth {
    let health = RuntimeHealth::new(false);
    health.mark_running();
    health.advance_runtime();
    health.inject_fault(RuntimeHealthFault::Clear);
    health
}

#[test]
fn runtime_and_required_supervisor_stalls_are_not_live() {
    for fault in [
        RuntimeHealthFault::RuntimeProgressStale,
        RuntimeHealthFault::SupervisorProgressStale,
    ] {
        let health = live_health();
        health.inject_fault(fault);
        let snapshot = health.snapshot();
        assert_eq!(snapshot.liveness, Liveness::NotLive);
        assert_eq!(snapshot.readiness, Readiness::NotReady);
    }
}

#[test]
fn external_outages_degrade_readiness_but_preserve_local_liveness() {
    for fault in [
        RuntimeHealthFault::DirectoryUnavailable,
        RuntimeHealthFault::DnsUnavailable,
        RuntimeHealthFault::InternetUnavailable,
    ] {
        let health = live_health();
        health.inject_fault(fault);
        let snapshot = health.snapshot();
        assert_eq!(snapshot.liveness, Liveness::Live);
        assert_eq!(snapshot.readiness, Readiness::Degraded);
    }
}

#[test]
fn recoverable_tunnel_and_provider_failures_do_not_masquerade_as_runtime_death() {
    let tunnel = live_health();
    tunnel.inject_fault(RuntimeHealthFault::TunnelRecovering);
    let snapshot = tunnel.snapshot();
    assert_eq!(snapshot.liveness, Liveness::Live);
    assert_eq!(snapshot.readiness, Readiness::Degraded);
    assert_eq!(snapshot.subsystems["tunnel"], SubsystemState::Recovering);

    let provider = live_health();
    provider.inject_fault(RuntimeHealthFault::ProviderUnavailable);
    let snapshot = provider.snapshot();
    assert_eq!(snapshot.liveness, Liveness::Live);
    assert_eq!(snapshot.readiness, Readiness::NotReady);
}

#[test]
fn clear_restores_progress_after_every_injected_fault() {
    let health = live_health();
    health.inject_fault(RuntimeHealthFault::RuntimeProgressStale);
    assert_eq!(health.snapshot().liveness, Liveness::NotLive);
    health.inject_fault(RuntimeHealthFault::Clear);
    assert_eq!(health.snapshot().liveness, Liveness::Live);
    assert_eq!(health.snapshot().readiness, Readiness::Ready);
}
