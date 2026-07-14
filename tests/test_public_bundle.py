#!/usr/bin/env python3
"""Validate public repository structure, privacy, metadata, and CI invariants."""

from __future__ import annotations

import json
from pathlib import Path
import py_compile
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skill" / "review-software-security"
REQUIRED = {
    "README.md", "LICENSE", "NOTICE", "SECURITY.md", "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md", "GOVERNANCE.md", "SUPPORT.md", "CHANGELOG.md",
    "CITATION.cff", ".github/CODEOWNERS", ".github/dependabot.yml",
    ".github/workflows/validate.yml", "skill/review-software-security/SKILL.md",
    "skill/review-software-security/agents/openai.yaml",
    "skill/review-software-security/assets/security-ledger.schema.json",
    "skill/review-software-security/scripts/detect_security_profiles.py",
    "skill/review-software-security/scripts/validate_security_ledger.py",
}
TEXT_SUFFIXES = {"", ".md", ".txt", ".py", ".json", ".yaml", ".yml", ".cff"}
PRIVATE_PATTERNS = {
    "private absolute path": re.compile(r"(?:/Users/|/private/|[A-Za-z]:\\\\Users\\\\)"),
    "unpublished project identity": re.compile(r"\b(?:nativity|united public square|unitedpublicsquare)\b", re.I),
    "placeholder schema host": re.compile(r"example\.invalid", re.I),
}
SECRET_PATTERNS = {
    "PEM private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "Twilio live key": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
}


def public_files() -> list[Path]:
    return [
        path for path in sorted(ROOT.rglob("*"))
        if path.is_file() and ".git" not in path.parts and "dist" not in path.parts
        and "__pycache__" not in path.parts
    ]


def main() -> int:
    errors: list[str] = []
    for relative in sorted(REQUIRED):
        if not (ROOT / relative).is_file():
            errors.append(f"missing required file: {relative}")

    for path in ROOT.rglob("*"):
        if ".git" in path.parts or "dist" in path.parts:
            continue
        if path.is_symlink():
            errors.append(f"symlink not permitted: {path.relative_to(ROOT)}")
        if path.is_file() and path.stat().st_size > 1024 * 1024:
            errors.append(f"file exceeds 1 MiB: {path.relative_to(ROOT)}")

    for path in public_files():
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        relative = path.relative_to(ROOT)
        if path.resolve() == Path(__file__).resolve():
            patterns = SECRET_PATTERNS
        else:
            patterns = {**PRIVATE_PATTERNS, **SECRET_PATTERNS}
            if "fixtures" in path.parts:
                patterns.pop("placeholder schema host", None)
        for label, pattern in patterns.items():
            if pattern.search(content):
                errors.append(f"{label} found in {relative}")

    skill_text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    yaml_text = (SKILL / "agents" / "openai.yaml").read_text(encoding="utf-8")
    if not skill_text.startswith("---\nname: review-software-security\n"):
        errors.append("SKILL.md name metadata is missing or inconsistent")
    if 'display_name: "Software Security Review"' not in yaml_text:
        errors.append("agents/openai.yaml display_name is inconsistent")
    if "allow_implicit_invocation: true" not in yaml_text:
        errors.append("implicit invocation is not enabled")
    if "$review-software-security" not in yaml_text:
        errors.append("default prompt does not explicitly name the skill")

    schema = json.loads((SKILL / "assets" / "security-ledger.schema.json").read_text(encoding="utf-8"))
    if schema.get("$id") != "urn:review-software-security:security-ledger:1.0":
        errors.append("security ledger uses an unexpected schema identifier")

    for script in (
        SKILL / "scripts" / "detect_security_profiles.py",
        SKILL / "scripts" / "validate_security_ledger.py",
        ROOT / "scripts" / "build_release.py",
        ROOT / "tests" / "run_fixture_tests.py",
    ):
        try:
            py_compile.compile(str(script), doraise=True)
        except py_compile.PyCompileError as exc:
            errors.append(f"Python compilation failed for {script.relative_to(ROOT)}: {exc.msg}")

    workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
    if not re.search(r"permissions:\s*\n\s+contents: read", workflow):
        errors.append("workflow must set contents: read permissions")
    for forbidden in ("pull_request_target", "self-hosted"):
        if forbidden in workflow:
            errors.append(f"workflow contains forbidden construct: {forbidden}")
    for line in workflow.splitlines():
        match = re.search(r"\buses:\s*[^@\s]+@([^\s#]+)", line)
        if match and not re.fullmatch(r"[0-9a-f]{40}", match.group(1)):
            errors.append(f"workflow action is not pinned to a full SHA: {line.strip()}")

    detector = SKILL / "scripts" / "detect_security_profiles.py"
    result = subprocess.run(
        [sys.executable, str(detector), str(ROOT)],
        text=True, capture_output=True, check=False,
    )
    if result.returncode:
        errors.append(f"detector failed on public repository: {result.stderr.strip()}")
    else:
        detected = json.loads(result.stdout)
        if detected.get("execution_performed") is not False:
            errors.append("detector did not affirm non-execution")

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: public bundle invariants ({len(public_files())} files inspected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
