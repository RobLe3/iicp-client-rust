#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Isolated, content-free systemd manager recovery evidence.
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]] || ! command -v systemd-run >/dev/null; then
  echo "ERROR: Linux with systemd-run is required" >&2
  exit 2
fi

scope="${IICP_SYSTEMD_EVIDENCE_SCOPE:-user}"
case "$scope" in
  user) manager=(systemctl --user); runner=(systemd-run --user) ;;
  system) manager=(systemctl); runner=(systemd-run) ;;
  *) echo "ERROR: IICP_SYSTEMD_EVIDENCE_SCOPE must be user or system" >&2; exit 2 ;;
esac
"${manager[@]}" show-environment >/dev/null 2>&1 || {
  echo "ERROR: the selected systemd manager is not available" >&2
  exit 2
}

output="${1:-systemd-watchdog-evidence.json}"
started="$(date -u +%FT%TZ)"
work="$(mktemp -d)"
unit="iicp-health-evidence-$RANDOM"
storm="${unit}-storm"
marker="$work/stalled-once"

cleanup() {
  "${manager[@]}" stop "$unit.service" "$storm.service" >/dev/null 2>&1 || true
  "${manager[@]}" reset-failed "$unit.service" "$storm.service" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

cargo build --locked --example systemd_watchdog_fixture \
  --features systemd-notify,runtime-health-fault-injection
fixture="$(pwd)/target/debug/examples/systemd_watchdog_fixture"

common=(
  --property=Type=notify
  --property=NotifyAccess=main
  --property=WatchdogSec=2s
  --property=Restart=on-failure
  --property=RestartSec=250ms
  --setenv=IICP_SYSTEMD_NOTIFY=1
)

"${runner[@]}" --unit="$unit" "${common[@]}" \
  --property=StartLimitIntervalSec=20s --property=StartLimitBurst=4 \
  "$fixture" stall-once "$marker" >/dev/null

recovered=0
for _ in $(seq 1 80); do
  restarts="$("${manager[@]}" show "$unit.service" -p NRestarts --value)"
  active="$("${manager[@]}" show "$unit.service" -p ActiveState --value)"
  if [[ "$restarts" -ge 1 && "$active" == "active" ]]; then
    recovered=1
    break
  fi
  sleep 0.25
done
[[ "$recovered" -eq 1 ]] || {
  echo "ERROR: systemd did not recover the one-time PID-alive stall" >&2
  exit 1
}

"${runner[@]}" --unit="$storm" "${common[@]}" \
  --property=StartLimitIntervalSec=20s --property=StartLimitBurst=2 \
  "$fixture" always-stall >/dev/null

limited=0
for _ in $(seq 1 100); do
  active="$("${manager[@]}" show "$storm.service" -p ActiveState --value)"
  result="$("${manager[@]}" show "$storm.service" -p Result --value)"
  restarts="$("${manager[@]}" show "$storm.service" -p NRestarts --value)"
  if [[ "$active" == "failed" && "$result" == "watchdog" && "$restarts" -ge 2 ]]; then
    limited=1
    break
  fi
  sleep 0.25
done
[[ "$limited" -eq 1 ]] || {
  echo "ERROR: restart-storm limit was not observed" >&2
  exit 1
}

completed="$(date -u +%FT%TZ)"
arch="$(uname -m)"
systemd_version="$(systemctl --version | awk 'NR==1 {print $2}')"
python3 - "$output" "$started" "$completed" "$scope" "$arch" "$systemd_version" <<'PY'
import json
import pathlib
import sys

path, started, completed, scope, arch, systemd = sys.argv[1:]
record = {
    "schema": "iicp.runtime_health_systemd_evidence.v1",
    "content_free": True,
    "started_at": started,
    "completed_at": completed,
    "platform": {"os": "linux", "arch": arch, "systemd": systemd, "scope": scope},
    "checks": {
        "pid_alive_stall_watchdog_recovery": "pass",
        "post_restart_healthy_instance": "pass",
        "restart_storm_limit": "pass",
    },
    "watchdog_seconds": 2,
    "limitations": [
        "temporary_fixture_process_not_a_registered_iicp_provider",
        "does_not_classify_the_original_raspberry_pi_incident",
        "does_not_authorize_default_watchdog_enablement",
    ],
}
pathlib.Path(path).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
PY

echo "systemd watchdog evidence written to $output"
