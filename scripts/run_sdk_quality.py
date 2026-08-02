#!/usr/bin/env python3
"""Run Rust SDK release gates and emit content-free quality evidence."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import tomllib
from datetime import UTC, datetime
from pathlib import Path

COVERAGE_MINIMUM = 64.0


def run(argv: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        check=False,
    )


def require(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        raise RuntimeError(f"{label} failed")


def git_value(*argv: str) -> str:
    result = run(["git", *argv], capture=True)
    require(result, "git evidence")
    return result.stdout.strip()


def toolchain(name: str, *argv: str) -> subprocess.CompletedProcess[str]:
    return run(["rustup", "run", name, "cargo", *argv])


def coverage_percent(path: Path) -> float:
    document = json.loads(path.read_text(encoding="utf-8"))
    return float(document["data"][0]["totals"]["lines"]["percent"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if git_value("status", "--porcelain=v1", "--untracked-files=all"):
        print("Rust SDK quality stopped: worktree is not clean")
        return 2
    commit = git_value("rev-parse", "HEAD")
    version = tomllib.loads(Path("Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
    try:
        require(run(["cargo", "fmt", "--all", "--", "--check"]), "format")
        require(toolchain("stable", "clippy", "--locked", "--all-targets", "--all-features", "--", "-D", "warnings"), "Clippy")
        require(toolchain("1.86.0", "test", "--locked", "--all-features"), "Rust 1.86")
        require(toolchain("stable", "test", "--locked", "--all-features"), "stable Rust")
        require(run(["cargo", "audit"]), "RustSec audit")
        with tempfile.TemporaryDirectory(prefix="iicp-rust-quality-") as temporary:
            temp = Path(temporary)
            coverage = temp / "coverage.json"
            require(
                run(
                    [
                        "rustup", "run", "stable", "cargo", "llvm-cov", "--locked", "--all-features",
                        "--workspace", "--json", "--output-path", str(coverage),
                    ]
                ),
                "coverage",
            )
            measured = coverage_percent(coverage)
            if measured < COVERAGE_MINIMUM:
                raise RuntimeError("coverage ratchet failed")
            require(toolchain("stable", "package", "--locked"), "locked package")
            install_root = temp / "install"
            require(
                toolchain(
                    "stable", "install", "--locked", "--path", ".", "--features", "nat", "--root", str(install_root)
                ),
                "clean install",
            )
            require(run([str(install_root / "bin" / "iicp-node"), "--version"]), "installed CLI smoke")
    except (RuntimeError, OSError, KeyError, IndexError, json.JSONDecodeError) as error:
        print(f"Rust SDK quality failed: {error}")
        return 1

    evidence = {
        "schema": "iicp.sdk-quality-evidence.v1",
        "sdk": "rust",
        "version": version,
        "commit": commit,
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "status": "pass",
        "runtimes": [{"name": "1.86", "status": "pass"}, {"name": "stable", "status": "pass"}],
        "gates": {
            "static_analysis": {"status": "pass"},
            "coverage": {"status": "pass", "percent": round(measured, 3), "minimum_percent": COVERAGE_MINIMUM},
            "dependency_audit": {"status": "pass"},
            "locked_build": {"status": "pass"},
            "clean_install": {"status": "pass"},
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(f"Rust SDK quality evidence passed for {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
