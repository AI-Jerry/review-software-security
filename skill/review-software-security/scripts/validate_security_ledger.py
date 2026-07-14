#!/usr/bin/env python3
"""Validate the security ledger contract and default release-gate invariants."""

from __future__ import annotations

import argparse
from datetime import date, datetime
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse


SEVERITIES = {"critical", "high", "medium", "low", "info"}
CONFIDENCE = {"high", "medium", "low"}
FINDING_STATUS = {"confirmed", "likely", "unverified"}
MODES = {"diff", "standard", "deep"}
DECISIONS = {"ready", "conditional", "not-ready"}
APPLICABILITY = {"applicable", "not-applicable", "unknown"}
OUTCOMES = {"pass", "fail", "not-tested"}
FRESHNESS = {"current", "stale", "offline-unverified"}
STANDARD_STATUS = {"stable", "advisory", "draft", "evolving"}
FINDING_KEYS = {
    "id", "title", "severity", "confidence", "status", "location", "evidence",
    "attack_path", "impact", "standard_references", "cwe", "remediation",
    "verification", "release_blocking",
}
TOP_LEVEL_KEYS = {"schema_version", "metadata", "standards", "profiles", "findings", "coverage", "release"}
METADATA_KEYS = {"review_id", "generated_at", "repository", "revision", "scope", "mode", "asvs_level"}
STANDARD_KEYS = {"id", "version", "status", "source", "checked_at", "freshness"}
COVERAGE_KEYS = {"control_reference", "applicability", "outcome", "method", "evidence"}
RELEASE_KEYS = {"decision", "blocking_findings", "rationale"}


def nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def string_list(value: object) -> bool:
    return isinstance(value, list) and all(nonempty_string(v) for v in value)


def valid_date(value: object, with_time: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    try:
        if with_time:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            date.fromisoformat(value)
        return True
    except ValueError:
        return False


def check_keys(errors: list[str], prefix: str, value: dict, required: set[str], allowed: set[str]) -> None:
    missing = required - value.keys()
    extra = value.keys() - allowed
    if missing:
        errors.append(f"{prefix} missing keys: {', '.join(sorted(missing))}")
    if extra:
        errors.append(f"{prefix} has unsupported keys: {', '.join(sorted(extra))}")


def validate(data: object) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["ledger must be a JSON object"]
    check_keys(errors, "ledger", data, TOP_LEVEL_KEYS, TOP_LEVEL_KEYS)
    if data.get("schema_version") != "1.0":
        errors.append("schema_version must equal '1.0'")

    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        errors.append("metadata must be an object")
    else:
        check_keys(
            errors, "metadata", metadata,
            {"review_id", "generated_at", "repository", "revision", "scope", "mode"},
            METADATA_KEYS,
        )
        for key in ("review_id", "repository", "revision", "scope"):
            if not nonempty_string(metadata.get(key)):
                errors.append(f"metadata.{key} must be a non-empty string")
        if metadata.get("mode") not in MODES:
            errors.append("metadata.mode must be diff, standard, or deep")
        if not valid_date(metadata.get("generated_at"), with_time=True):
            errors.append("metadata.generated_at must be an ISO-8601 date-time")
        if "asvs_level" in metadata and metadata["asvs_level"] not in {1, 2, 3, "not-applicable"}:
            errors.append("metadata.asvs_level must be 1, 2, 3, or not-applicable")

    standards = data.get("standards")
    if not isinstance(standards, list) or not standards:
        errors.append("standards must be a non-empty array")
    else:
        for i, item in enumerate(standards):
            prefix = f"standards[{i}]"
            if not isinstance(item, dict):
                errors.append(f"{prefix} must be an object")
                continue
            check_keys(errors, prefix, item, STANDARD_KEYS, STANDARD_KEYS)
            for key in ("id", "version"):
                if not nonempty_string(item.get(key)):
                    errors.append(f"{prefix}.{key} must be a non-empty string")
            if item.get("status") not in STANDARD_STATUS:
                errors.append(f"{prefix}.status is invalid")
            source = item.get("source")
            if not nonempty_string(source) or urlparse(source).scheme not in {"http", "https"}:
                errors.append(f"{prefix}.source must be an HTTP(S) URL")
            if not valid_date(item.get("checked_at")):
                errors.append(f"{prefix}.checked_at must be an ISO-8601 date")
            if item.get("freshness") not in FRESHNESS:
                errors.append(f"{prefix}.freshness is invalid")

    profiles = data.get("profiles")
    if not string_list(profiles) or not profiles or len(profiles or []) != len(set(profiles or [])):
        errors.append("profiles must be a non-empty array of unique non-empty strings")

    findings = data.get("findings")
    blockers: set[str] = set()
    finding_ids: list[str] = []
    if not isinstance(findings, list):
        errors.append("findings must be an array")
    else:
        for i, finding in enumerate(findings):
            prefix = f"findings[{i}]"
            if not isinstance(finding, dict):
                errors.append(f"{prefix} must be an object")
                continue
            check_keys(errors, prefix, finding, FINDING_KEYS, FINDING_KEYS)
            fid = finding.get("id")
            if not isinstance(fid, str) or not re.fullmatch(r"SEC-[0-9]{3,}", fid):
                errors.append(f"{prefix}.id must match SEC- followed by at least three digits")
            else:
                finding_ids.append(fid)
            for key in ("title", "location", "attack_path", "impact", "remediation", "verification"):
                if not nonempty_string(finding.get(key)):
                    errors.append(f"{prefix}.{key} must be a non-empty string")
            if finding.get("severity") not in SEVERITIES:
                errors.append(f"{prefix}.severity is invalid")
            if finding.get("confidence") not in CONFIDENCE:
                errors.append(f"{prefix}.confidence is invalid")
            if finding.get("status") not in FINDING_STATUS:
                errors.append(f"{prefix}.status is invalid")
            if not string_list(finding.get("evidence")) or not finding.get("evidence"):
                errors.append(f"{prefix}.evidence must be a non-empty array of non-empty strings")
            refs = finding.get("standard_references")
            if not string_list(refs) or not refs:
                errors.append(f"{prefix}.standard_references must be a non-empty array of non-empty strings")
            else:
                for ref in refs:
                    if ref.upper().startswith("OWASP") and not re.search(r"(?:V?\d{1,4})(?:[.-]\d+)*", ref, re.IGNORECASE):
                        errors.append(f"{prefix} OWASP reference must include a version or year: {ref}")
                    if ref.upper().startswith("OWASP-CICD") and not re.search(r"accessed-\d{4}-\d{2}-\d{2}", ref, re.IGNORECASE):
                        errors.append(f"{prefix} unversioned OWASP CI/CD reference must use accessed-YYYY-MM-DD, not an inferred release year: {ref}")
            cwe = finding.get("cwe")
            if not isinstance(cwe, list) or not all(isinstance(v, str) and re.fullmatch(r"CWE-[0-9]+", v) for v in cwe):
                errors.append(f"{prefix}.cwe must contain only CWE-<number> strings")
            blocking = finding.get("release_blocking")
            if not isinstance(blocking, bool):
                errors.append(f"{prefix}.release_blocking must be boolean")
                blocking = False
            must_block = finding.get("status") == "confirmed" and finding.get("severity") in {"critical", "high"}
            if must_block and not blocking:
                errors.append(f"{prefix} confirmed critical/high finding must block release")
            if not must_block and blocking:
                errors.append(f"{prefix} cannot block under the default policy")
            if blocking and isinstance(fid, str):
                blockers.add(fid)
        if len(finding_ids) != len(set(finding_ids)):
            errors.append("finding IDs must be unique")

    coverage = data.get("coverage")
    if not isinstance(coverage, list) or not coverage:
        errors.append("coverage must be a non-empty array")
    else:
        for i, item in enumerate(coverage):
            prefix = f"coverage[{i}]"
            if not isinstance(item, dict):
                errors.append(f"{prefix} must be an object")
                continue
            check_keys(errors, prefix, item, COVERAGE_KEYS, COVERAGE_KEYS)
            for key in ("control_reference", "method"):
                if not nonempty_string(item.get(key)):
                    errors.append(f"{prefix}.{key} must be a non-empty string")
            control_ref = item.get("control_reference")
            if isinstance(control_ref, str) and control_ref.upper().startswith("OWASP") and not re.search(r"(?:V?\d{1,4})(?:[.-]\d+)*", control_ref, re.IGNORECASE):
                errors.append(f"{prefix}.control_reference OWASP reference must include a version, year, or access date")
            if isinstance(control_ref, str) and control_ref.upper().startswith("OWASP-CICD") and not re.search(r"accessed-\d{4}-\d{2}-\d{2}", control_ref, re.IGNORECASE):
                errors.append(f"{prefix}.control_reference unversioned OWASP CI/CD reference must use accessed-YYYY-MM-DD")
            if item.get("applicability") not in APPLICABILITY:
                errors.append(f"{prefix}.applicability is invalid")
            if item.get("outcome") not in OUTCOMES:
                errors.append(f"{prefix}.outcome is invalid")
            if not string_list(item.get("evidence")) or not item.get("evidence"):
                errors.append(f"{prefix}.evidence must be a non-empty array of non-empty strings")

    release = data.get("release")
    if not isinstance(release, dict):
        errors.append("release must be an object")
    else:
        check_keys(errors, "release", release, RELEASE_KEYS, RELEASE_KEYS)
        decision = release.get("decision")
        listed = release.get("blocking_findings")
        if decision not in DECISIONS:
            errors.append("release.decision is invalid")
        if not string_list(listed) or len(listed or []) != len(set(listed or [])):
            errors.append("release.blocking_findings must be an array of unique non-empty strings")
            listed_set: set[str] = set()
        else:
            listed_set = set(listed)
        if not nonempty_string(release.get("rationale")):
            errors.append("release.rationale must be a non-empty string")
        if listed_set != blockers:
            errors.append(f"release.blocking_findings must exactly match blocking finding IDs: {sorted(blockers)}")
        if blockers and decision != "not-ready":
            errors.append("release.decision must be not-ready when blockers exist")
        if not blockers and decision == "not-ready":
            errors.append("release.decision cannot be not-ready without a default-policy blocker")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger")
    args = parser.parse_args()
    path = Path(args.ledger)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"invalid: {exc}", file=sys.stderr)
        return 1
    errors = validate(data)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"valid: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
