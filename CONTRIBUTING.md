# Contributing

Use this repository for **iicp-client-rust** bugs, documentation fixes, tests and pull
requests:

- Issues: https://github.com/RobLe3/iicp-client-rust/issues
- Protocol and cross-component proposals: https://github.com/RobLe3/IICP/issues/new?template=protocol-proposal.yml
- Community discussion: https://iicp.network/forum/
- Private vulnerability reports: https://github.com/RobLe3/iicp-client-rust/security/advisories/new

Do not include credentials, private topology, production records, task
payloads or personal data in public issues. Participation does not confer
protocol authority; public proposal decisions remain recorded in the owning
issue or pull request under the current founder-led governance process.

Please include the client version, operating mode (`serve`, `relay`, Docker,
launchd/systemd, library use), relevant logs without secrets, and the command or
small reproducer you used. For protocol or behaviour changes, keep Rust, Python
and TypeScript parity in mind and mention which clients are affected.

Pull requests are welcome. Prefer small, test-backed changes; update the README
or CHANGELOG whenever operator-facing behaviour changes.

## Reproducing the checks

Use the Rust toolchain declared by `Cargo.toml`:

```bash
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo package --locked --allow-dirty
```

Release, coverage and operator-evidence scripts use an isolated Cargo target
with incremental compilation disabled. Successful runs remove only that
run-owned target. Set `IICP_KEEP_FAILED_CARGO_TARGET=1` when a failed build tree
is needed for diagnosis; ordinary interactive Cargo commands still use the
repository `target/` directory.

The public [IICP repository map](https://github.com/RobLe3/IICP/blob/main/ecosystem/public-repositories.json)
identifies normative and implementation ownership. A pull request does not
authorize a package release. Maintainers publish immutable, versioned artifacts
only after the repository's release checks pass.

## License

By contributing, you agree your contributions are licensed under Apache-2.0.
