# Runtime-health Linux and ARM validation

The opt-in systemd notifier must remain disabled by default until Linux and
ARM evidence shows that meaningful stalls are detected without restarting a
healthy node during dependency loss or legitimate load.

Run the content-free source-level lane on Linux with:

```bash
./scripts/validate_runtime_health_arm.sh /tmp/runtime-health-evidence.json
```

The lane validates deterministic runtime and supervisor stalls, dependency
degradation, the native notification socket, and strict Clippy. It does not
alter a service, choose a watchdog timeout, or prove boot and restart-storm
behavior.

On a Linux host with an active systemd manager, run the separate isolated
manager lane:

```bash
./scripts/validate_systemd_watchdog.sh /tmp/systemd-watchdog-evidence.json
```

It creates four temporary transient units. One stalls once and must recover to
a healthy second process; one exits unsuccessfully once and must recover through
ordinary process supervision; another stalls on every start and must reach the
configured start limit. The fourth uses the node's five-second runtime progress
cadence under bounded CPU and synchronous-storage pressure and must remain live
without a restart or crossing the existing 30-second stale threshold. A trap
stops and resets all units and load generators. Set
`IICP_SYSTEMD_EVIDENCE_SCOPE=system` only in an already isolated test host where
the invoking user is authorized to control the system manager; user scope is
the default. The two-second watchdog is specific to the deterministic fixture
and is not a production timeout recommendation.

The ordinary quality job runs this lane against the active system manager on
its isolated Linux x86-64 runner and prints only the content-free result. ARM64
evidence must still be collected separately on an isolated ARM host or systemd
container; an emulated architecture must be labeled as such.

The loaded lane records the maximum observed interval rather than treating a
single pass/fail pulse as timing evidence. It uses the node's current
five-second progress cadence, two bounded CPU workers and repeated 32 MiB
synchronous writes. This is scheduler and storage-pressure evidence for the
health loop, not an inference-performance benchmark or a production watchdog
timeout selection.

Before issue #66 can close, a maintainer must additionally record on x86-64
Linux and Raspberry Pi OS or Debian ARM64:

1. normal and worst-case progress cadence during startup, slow storage, CPU
   pressure, memory pressure, and long inference;
2. process-crash recovery and PID-alive runtime-stall recovery under an
   isolated temporary unit (the manager lane covers the deterministic stall);
3. directory, DNS, Internet, provider, and tunnel loss without restart loops;
4. restart-rate limiting and recovery attribution;
5. reboot and logout behavior for the intended user-service and linger policy.

Use a temporary node identity and content-free output. Do not publish hostnames,
addresses, node IDs, credentials, prompts, model output, or raw logs. Remove the
temporary unit after the exercise. Default enablement requires a separate
maintainer decision after both architecture classes pass.

Copy `evidence/systemd-operator-validation-v1.json` before the representative
run and complete the copy with content-free outcomes and measured cadence. Run:

```bash
python3 scripts/check_systemd_operator_validation.py <completed-record.json>
```

The repository copy remains blank. A completed record recommends either
`retain_opt_in` or `propose_default_enablement`; it does not itself authorize a
default-policy change. A failed or unavailable representative run is valid
evidence for retaining opt-in behavior.
