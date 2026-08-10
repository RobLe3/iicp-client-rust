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

Before issue #66 can close, a maintainer must additionally record on x86-64
Linux and Raspberry Pi OS or Debian ARM64:

1. normal and worst-case progress cadence during startup, slow storage, CPU
   pressure, memory pressure, and long inference;
2. process-crash recovery and PID-alive runtime-stall recovery under an
   isolated temporary user unit;
3. directory, DNS, Internet, provider, and tunnel loss without restart loops;
4. restart-rate limiting and recovery attribution;
5. reboot and logout behavior for the intended user-service and linger policy.

Use a temporary node identity and content-free output. Do not publish hostnames,
addresses, node IDs, credentials, prompts, model output, or raw logs. Remove the
temporary unit after the exercise. Default enablement requires a separate
maintainer decision after both architecture classes pass.
