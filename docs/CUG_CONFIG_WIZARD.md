# CUG configuration wizard and GUI boundary

Status: accepted implementation decision for the Rust reference runtime.

## Decision

The canonical `RuntimeConfigV1` Rust type and its generated JSON Schema remain
the only configuration authority. `iicp-node config wizard` is a front end that
projects operator choices into that type, runs the existing validator and only
writes a file after validation succeeds.

A future graphical interface should use a narrow local Rust library or
loopback-only service exposing configuration projection, validation, enrollment
handoff and redacted runtime status. It must not define settings, defaults,
policy decisions or secret formats of its own. Every graphical action must have
an equivalent argv or configuration-file operation.

Tauri is the preferred packaging candidate because it can reuse the Rust
boundary while providing accessible platform UI and native packaging on macOS,
Windows and Linux. This is not approval to implement a GUI. A native Rust GUI
would reduce the web boundary but currently has a higher accessibility and UI
maintenance burden. A general local web application would be easier to prototype
but would enlarge the authentication, browser-origin and privilege boundary.

## Safety boundary

- Invalid configurations are reported before filesystem, network or service
  side effects.
- Wizard output contains secret references, never secret values.
- Membership issuance remains a directory-authority operation. When no
  reference is supplied, the report produces an external enrollment handoff
  rather than inventing or exporting a credential.
- `federated_private` can be projected for review, but validation remains
  unsuccessful until the Phase 6 evidence gate is complete.
- Machine consumers use the `reproduce_argv` array directly. It is not a shell
  command string.

## Compatibility

The existing interactive `iicp-node init` flow and public defaults are
unchanged. The wizard is additive and writes schema version 1 configuration
that the current `serve --config` path already consumes.
