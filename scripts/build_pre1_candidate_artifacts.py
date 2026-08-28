#!/usr/bin/env python3
"""Build and prove the Rust client pre-stable crate/offline fragment."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import tomllib
from pathlib import Path

import pre1_artifact_common as common
import pre1_rust_build as rust_build


ROOT = Path(__file__).resolve().parents[1]
COMPONENT = "client-rust"
TARGETS = {
    "linux-x86_64",
    "linux-aarch64",
    "macos-x86_64",
    "macos-arm64",
    "windows-x86_64",
}


def describe() -> dict:
    return {
        "schema": "iicp.pre1-artifact-builder-description.v1",
        "component": COMPONENT,
        "artifact_identities": [
            ["crate", "any"],
            ["vendored-offline-package", "any"],
        ],
        "gates": sorted(common.GATES),
        "requires_clean_source": True,
        "non_authorizing": True,
    }


def build(destination: Path, requested_target: str | None) -> dict:
    common.safe_output(destination)
    target = common.require_target(requested_target, TARGETS)
    commit = common.require_clean_source(ROOT)
    package = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
    version = package["version"]
    if package.get("rust-version") != "1.86":
        raise ValueError("Rust client MSRV differs from the qualification policy")
    run_root = Path(tempfile.mkdtemp(prefix="iicp-pre1-rust-client-", dir=destination.parent))
    staging = run_root / "fragment"
    staging.mkdir()
    try:
        quality_env = rust_build.cargo_environment(run_root, "quality")
        common.run(["cargo", "test", "--locked"], ROOT, quality_env)
        crate, extracted, bundle, cache_digest = rust_build.package_and_vendor(
            ROOT, run_root, "iicp-client", version
        )
        online = rust_build.install_and_report(
            ROOT, run_root, extracted, "iicp-node", version, offline=False
        )
        offline = rust_build.install_and_report(
            ROOT, run_root, bundle / "source", "iicp-node", version, offline=True
        )
        if online != offline:
            raise ValueError("online and offline Rust client self-reports differ")

        copied_crate = staging / crate.name
        shutil.copyfile(crate, copied_crate)
        offline_package = staging / f"iicp-client-{version}-vendored-offline.tar.gz"
        rust_build.deterministic_tar(bundle, offline_package)
        fragment = common.emit_fragment(
            staging,
            component=COMPONENT,
            source_commit=commit,
            source_version=version,
            build_target=target,
            artifacts=[
                common.artifact("crate", "any", copied_crate),
                common.artifact("vendored-offline-package", "any", offline_package),
            ],
            lock_inputs_sha256=common.files_sha256(
                ROOT, [ROOT / "Cargo.toml", ROOT / "Cargo.lock"]
            ),
            dependency_cache_sha256=cache_digest,
            toolchains={
                "cargo": common.output(["cargo", "--version"], ROOT),
                "rustc": common.output(["rustc", "--version"], ROOT),
            },
        )
        common.publish_staging(staging, destination)
        return fragment
    finally:
        common.clean_failed_staging(run_root)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--describe", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--target")
    args = parser.parse_args()
    if args.describe:
        print(json.dumps(describe(), indent=2, sort_keys=True))
        return 0
    if args.output is None:
        parser.error("--output is required unless --describe is used")
    try:
        value = build(args.output.resolve(), args.target)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
