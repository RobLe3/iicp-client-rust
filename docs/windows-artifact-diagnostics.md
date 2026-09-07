# Artifact-builder diagnostics

The pre-stable artifact builder captures Cargo command stdout/stderr in bounded
8 MiB tails per stream and emits sanitized output and step summaries. This does
not change the client runtime or protocol. Native command failures retain their
exit code; an unavailable command cannot count as a test pass.

Buffered pipes are read incrementally so short flushed records do not wait for
64 KiB or process exit. Each wrapped command emits a content-free
`iicp.pre1-build-step-event.v1` start before process creation and a matching
success/failure event afterward, including failed launches. Events contain a
step identity and allowlisted command category, never the original argv or
environment. Optional event-output failure does not change the native result.
The existing terminal summary remains available. These command events are not
a complete test inventory or an artifact-success claim.

On failure, the builder also inspects up to 32 build-script output/stderr files,
reading at most 64 KiB from each before disposable cleanup. Dependency names must
appear in Cargo.lock. Symlinks and junctions are refused. A failed build script
may leave no output file, so file inspection alone is insufficient; command
capture is the primary fallback.

Diagnostics remove credential-bearing lines, environment values, identifying
paths and arbitrary quoted values. Cargo's validated custom-build package/version
prefix is retained. Redaction work and retained lines are bounded, including for
very large single-line output. The records are sampled and explicitly report
stream truncation; they are not complete transcripts or per-case qualification
receipts. Do not publish their output without review.

The Windows isolated custom-build failure tracked in #172 remains unresolved.
Passing local fixture tests does not fix or qualify that historical failure.
Compare the exact builder's fresh cache, path depth, concurrency and toolchain
against the passing standalone probe before attributing a client defect.

Run the deterministic diagnostics tests where Cargo is installed:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_pre1_cargo_diagnostics.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_pre1_candidate_artifacts.py
```

The suite includes a real, dependency-free failing Cargo build script. Its source
and target are removed before assertions against retained diagnostic text. It
also verifies large-output bounds, redaction, missing capture and successful
native execution. No AWS host, network dependency or permanent build cache is
created by that fixture.

The common artifact helper also emits version and preparation command events.
Installation events distinguish online from offline operations. Event categories
are allowlisted and never contain the original argv, paths or environment values.
These events describe command execution, not discovered/executed test-case coverage.
