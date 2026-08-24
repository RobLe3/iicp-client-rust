# Native systemd watchdog policy

## Decision

The native systemd watchdog remains **opt-in**. The implementation and its
controlled x86-64 and ARM64 lanes are complete, but the project does not have a
representative operator record covering slow startup, long inference, reboot,
logout and the intended user-service/linger policy. Absence of that evidence is
not a reason to choose a universal timeout or enable restarts by default.

Operators can enable the `systemd-notify` feature and the generated native
watchdog configuration when their deployment policy calls for it. Ordinary
non-systemd Linux and `Type=simple` operation remain supported.

## Safety boundary

The notifier follows the shared implementation-controlled runtime-health
snapshot. Directory, DNS, tunnel or provider failure alone must not be reported
as local runtime death. A separate timer or watchdog daemon must not mask a
stalled executor. Manager restart limits and operator rollback remain required.

## Reconsideration gate

Default enablement may be reconsidered only after a content-free representative
operator record passes `scripts/check_systemd_operator_validation.py` and the
maintainer reviews its measured cadence, service scope, failure behavior and
rollback result. Such evidence informs a later policy decision; it does not
automatically authorize one.
