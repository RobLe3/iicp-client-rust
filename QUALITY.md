# SDK quality evidence

The local release-quality lane exercises the declared Rust 1.86 minimum and the
current stable toolchain, runs formatting and Clippy with warnings denied, uses
the checked-in lockfile, verifies that the public library still compiles without
default transport features, audits RustSec advisories, measures coverage,
packages the crate and installs the CLI into a clean temporary root. The
no-default contract applies to the library target; the operator CLI is qualified
with its declared feature set rather than as a featureless binary.

The initial measured line-coverage floor is 64%. The establishing run measured
64.69%. Raise the floor after durable test additions; never lower it merely to
pass a release.

Run:

```bash
python3 scripts/run_sdk_quality.py --output target/sdk-quality/rust.json
```

The output follows `iicp.sdk-quality-evidence.v1`. It contains only the release
version, exact commit, named outcomes, runtime names and coverage values. It is
candidate evidence, not publication or Genesis deployment permission. crates.io
still uses a scoped token; this repository does not claim OIDC provenance parity
with PyPI or npm.
