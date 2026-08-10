// SPDX-License-Identifier: Apache-2.0
//! Development-only process used by the isolated systemd evidence lane.

#[cfg(target_os = "linux")]
use iicp_client::runtime_health::{RuntimeHealth, RuntimeHealthFault};
#[cfg(target_os = "linux")]
use std::{path::PathBuf, time::Duration};

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "stall-once".to_string());
    let marker = std::env::args().nth(2).map(PathBuf::from);
    let should_stall = match mode.as_str() {
        "always-stall" => true,
        "stall-once" => {
            let marker = marker.expect("stall-once requires a marker path");
            if marker.exists() {
                false
            } else {
                std::fs::write(marker, b"stalled\n").expect("write stall marker");
                true
            }
        }
        "healthy" => false,
        _ => panic!("mode must be healthy, stall-once, or always-stall"),
    };

    let health = RuntimeHealth::new(true);
    health.mark_running();
    health.advance_runtime();
    health.advance_supervisor();
    let _notifier = iicp_client::systemd_notify::spawn_if_enabled(health.clone())
        .expect("systemd notification must be enabled by the evidence unit");

    let mut cycles = 0_u64;
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        cycles += 1;
        if should_stall && cycles == 5 {
            health.inject_fault(RuntimeHealthFault::RuntimeProgressStale);
            continue;
        }
        if !should_stall {
            health.advance_runtime();
            health.advance_supervisor();
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("systemd_watchdog_fixture requires Linux");
    std::process::exit(2);
}
