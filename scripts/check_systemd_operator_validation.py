#!/usr/bin/env python3
"""Validate blank or completed representative systemd operator evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "evidence/systemd-operator-validation-v1.json"
CHECKS = {
    "slow_startup",
    "memory_or_long_inference_pressure",
    "process_crash_recovery",
    "runtime_stall_recovery",
    "dependency_loss_no_restart_loop",
    "reboot_start",
    "logout_survival",
    "linger_verified",
    "restart_limit_verified",
    "rollback_verified",
}
RESULTS = {"pass", "fail", "not_applicable"}
RECOMMENDATIONS = {"retain_opt_in", "propose_default_enablement"}


def current_sdk_version(root: Path = ROOT) -> str:
    with (root / "Cargo.toml").open("rb") as manifest:
        return str(tomllib.load(manifest)["package"]["version"])


def validate_common(record: dict) -> list[str]:
    errors: list[str] = []
    for field in ("privacy", "claim_boundary"):
        values = record.get(field, {})
        if not values or any(value is not False for value in values.values()):
            errors.append(f"{field} must retain every content-free boundary")
    if set(record.get("checks", {})) != CHECKS:
        errors.append("operator record must contain the complete check set")
    if record.get("artifact", {}).get("sdk_version") != current_sdk_version():
        errors.append("operator record must pin the current Rust SDK release")
    return errors


def validate_completed(record: dict) -> list[str]:
    errors: list[str] = []
    if record.get("consent_confirmed") is not True:
        errors.append("completed record requires operator consent")
    if not record.get("observed_at_utc"):
        errors.append("completed record requires UTC observation time")

    platform = record.get("platform", {})
    for field in ("distribution", "architecture", "systemd_version", "service_scope"):
        if not platform.get(field):
            errors.append(f"completed record requires platform {field}")
    if platform.get("representative_operator_environment") is not True:
        errors.append("completed record must come from a representative operator environment")

    artifact = record.get("artifact", {})
    if not artifact.get("source_commit") or not artifact.get("binary_sha256"):
        errors.append("completed record requires source commit and binary digest")
    if artifact.get("native_watchdog_enabled") is not True:
        errors.append("operator lane must exercise the native watchdog")

    measurements = record.get("measurements", {})
    if any(not isinstance(value, int) or value <= 0 for value in measurements.values()):
        errors.append("completed record requires positive integer measurements")
    checks = record.get("checks", {})
    if any(value not in RESULTS for value in checks.values()):
        errors.append("every operator check must be pass, fail, or not_applicable")
    if record.get("policy_recommendation") not in RECOMMENDATIONS or not record.get("policy_rationale"):
        errors.append("completed record requires bounded policy recommendation and rationale")
    return errors


def validate(record: dict) -> list[str]:
    present = record.get("result_present")
    if present not in {True, False}:
        return ["result_present must be boolean"]
    errors = validate_common(record)
    if not present:
        if record.get("status") != "blank-representative-operator-template":
            errors.append("empty record must identify itself as a blank template")
        return errors
    return errors + validate_completed(record)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("record", nargs="?", type=Path, default=DEFAULT)
    args = parser.parse_args()
    errors = validate(json.loads(args.record.read_text(encoding="utf-8")))
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("systemd operator validation record valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
