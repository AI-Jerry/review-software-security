# Security review: v0.1.0

## Decision

**Conditional — no confirmed Critical or High findings.** The clean replacement source and deterministic release artifacts satisfy the repository-controlled gates. Publication remains conditional until GitHub-hosted validation, CodeQL, and the required repository security controls are re-enabled and observed on the replacement repository.

The matched machine-readable record is [`security-review-v0.1.0.json`](security-review-v0.1.0.json).

## Scope and mode

- Mode: `standard`
- Scope: public source tree, installable skill, deterministic scripts, synthetic tests, GitHub Actions workflow, governance files, and v0.1.0 release artifacts
- Excluded from application-profile routing: intentionally unsafe synthetic fixtures, except as test inputs
- Active testing: not authorized and not performed
- Production data and external targets: not accessed

Applicable production profiles were **core**, **agentic**, **CI/CD**, and **supply-chain**. Web, API, AI/LLM, Kubernetes, mobile, and serverless signals came only from synthetic fixtures and were not treated as deployed product components.

## Attack surface and trust boundaries

| Surface | Untrusted input | Security objective | Review result |
| --- | --- | --- | --- |
| Skill instructions | Repository content and user prompts | Prevent unauthorized mutation, probing, execution, and false assurance | Pass by instruction trace |
| Profile detector | Paths and bounded repository text | Detect evidence without executing target code | Pass by source trace and fixture execution |
| Ledger validator | Untrusted JSON ledger | Reject malformed evidence and release-gate bypasses | Pass by positive and negative fixtures |
| Release builder | Skill files and version argument | Reject symlinks, produce deterministic artifacts and hashes | Pass by source trace and repeat build |
| GitHub Actions | Pull-request and repository content | Maintain least privilege and immutable dependencies | Pass by workflow inspection; hosted run pending |
| Public contribution surfaces | Issues, pull requests, disclosures | Prevent accidental secret or private-data publication | Pass by templates and policy; platform reporting pending |

Primary abuse cases included malicious repository text attempting to induce tool use, a crafted ledger hiding a blocker, a dependency or workflow reference changing after review, symlink-based release substitution, and accidental disclosure of credentials or private project details.

## Findings

No confirmed, likely, or unverified vulnerability finding met the project’s finding threshold in the reviewed local tree.

This is not a clean bill of health. The following coverage remains open:

- an external secret scanner was unavailable and was not installed without authorization;
- GitHub-hosted validation, CodeQL, secret protection, dependency controls, private reporting, and protected-main rules must be re-established after replacement;
- immutable-release status can be verified only after the v0.1.0 release is published.

These items are not represented as passes and keep the replacement repository conditional before publication.

## Evidence summary

- Public-bundle validation: `PASS`, 64 files inspected.
- Routing and ledger fixtures: `PASS`, eight routing fixtures plus valid/invalid ledger invariants.
- Skill-creator validation: `Skill is valid!` on both the staged directory and extracted release ZIP.
- Python compilation: `PASS` for skill, release, and test scripts.
- Release reproducibility: two builds compared byte-for-byte with `cmp` and matched.
- ZIP inspection: 13 intended skill files under one `review-software-security/` directory; fixed timestamps; no symlinks.
- Secret/privacy regex scan: no match outside deliberately encoded test patterns; no file over 1 MiB; no symlink.
- CI inspection: `contents: read`, full-SHA checkout pin, no `pull_request_target`, no self-hosted runner, no secret use.
- Hosted validation and security controls: pending recreation and fresh observation on the clean replacement repository.
- Network/target interaction: none performed by the skill scripts or review.

## Required publication checks

Before changing the decision to ready, recreate the repository from this clean no-reply history; re-enable secret scanning, push protection, private vulnerability reporting, dependency graph, Dependabot, CodeQL, and protected-main rules; confirm hosted checks; then create and verify the v0.1.0 release artifacts.

## Limitations

This review evaluated the repository-controlled release process and deterministic scripts. It did not perform exploit testing, assess an application deployed from the synthetic fixtures, inspect GitHub infrastructure, or establish certification. Absence of a finding is not proof of absence.
