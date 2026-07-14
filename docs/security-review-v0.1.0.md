# Security review: v0.1.0

## Decision

**Ready — no confirmed Critical or High findings.** The clean replacement source, deterministic release artifacts, fresh GitHub-hosted validation, CodeQL scan, and repository security controls satisfy the v0.1.0 release-candidate gates. The unavailable external secret scanner remains explicitly `not-tested` and is documented as residual coverage, not a pass.

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
| GitHub Actions | Pull-request and repository content | Maintain least privilege and immutable dependencies | Pass by workflow inspection and hosted run 29302004890 |
| Public contribution surfaces | Issues, pull requests, disclosures | Prevent accidental secret or private-data publication | Pass by templates, policy, private reporting, secret scanning, and push protection |

Primary abuse cases included malicious repository text attempting to induce tool use, a crafted ledger hiding a blocker, a dependency or workflow reference changing after review, symlink-based release substitution, and accidental disclosure of credentials or private project details.

## Findings

No confirmed, likely, or unverified vulnerability finding met the project’s finding threshold in the reviewed local tree.

This is not a clean bill of health. The following residual coverage remains open:

- an external secret scanner was unavailable and was not installed without authorization;
- immutable-release status can be verified only after the v0.1.0 release is published.

These items are not represented as passes. They do not create a confirmed Critical or High finding under the documented release policy.

## Evidence summary

- Public-bundle validation: `PASS`, 66 files inspected.
- Routing and ledger fixtures: `PASS`, eight routing fixtures plus valid/invalid ledger invariants.
- Skill-creator validation: `Skill is valid!` on both the staged directory and extracted release ZIP.
- Python compilation: `PASS` for skill, release, and test scripts.
- Release reproducibility: two builds compared byte-for-byte with `cmp` and matched.
- ZIP inspection: 13 intended skill files under one `review-software-security/` directory; fixed timestamps; no symlinks.
- Secret/privacy regex scan: no match outside deliberately encoded test patterns; no file over 1 MiB; no symlink.
- CI inspection: `contents: read`, full-SHA checkout pin, no `pull_request_target`, no self-hosted runner, no secret use.
- Hosted validation: `PASS` on commit `55bfa8bd6d667fcac0036d7743cdc229f384118e` in run `29302004890`.
- CodeQL default setup: `PASS` for Python and GitHub Actions in run `29302092949`.
- Platform controls: private vulnerability reporting, dependency graph, Dependabot alerts/security/grouped updates, malware alerts, CodeQL, secret scanning, and push protection enabled and observed.
- Protected main: active ruleset `18904743` requires pull requests, linear history, current branches, conversation resolution, `deterministic-validation`, and CodeQL results at High-or-higher security / Errors standard thresholds; deletion and force-push are blocked; repository administrators retain an emergency bypass.
- Network/target interaction: none performed by the skill scripts or review.

## Publication status

The clean repository and hosted controls are ready for the final assurance pull request and v0.1.0 release packaging. The published release and immutable-release state must still be verified after publication.

## Limitations

This review evaluated the repository-controlled release process and deterministic scripts. It did not perform exploit testing, assess an application deployed from the synthetic fixtures, inspect GitHub infrastructure, or establish certification. Absence of a finding is not proof of absence.
