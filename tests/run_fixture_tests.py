#!/usr/bin/env python3
"""Run deterministic profile and ledger fixtures against a staged or installed skill."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skill", required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    skill = Path(args.skill).resolve()
    detector = skill / "scripts" / "detect_security_profiles.py"
    validator = skill / "scripts" / "validate_security_ledger.py"
    expected = json.loads((here / "expected-profiles.json").read_text())
    failures: list[str] = []

    for name, profiles in sorted(expected.items()):
        result = run([sys.executable, str(detector), str(here / "fixtures" / name)])
        if result.returncode:
            failures.append(f"{name}: detector exited {result.returncode}: {result.stderr.strip()}")
            continue
        actual = json.loads(result.stdout)
        if actual.get("profiles") != profiles:
            failures.append(f"{name}: expected {profiles}, got {actual.get('profiles')}")
        if actual.get("execution_performed") is not False:
            failures.append(f"{name}: detector did not affirm non-execution")

    valid = run([sys.executable, str(validator), str(here / "ledgers" / "valid-blocked.json")])
    if valid.returncode:
        failures.append(f"valid ledger rejected: {valid.stderr.strip()}")

    for path in sorted((here / "ledgers").glob("invalid-*.json")):
        invalid = run([sys.executable, str(validator), str(path)])
        if invalid.returncode == 0:
            failures.append(f"invalid ledger accepted: {path.name}")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print(f"PASS: {len(expected)} routing fixtures and ledger invariants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
