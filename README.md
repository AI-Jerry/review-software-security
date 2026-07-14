# review-software-security

An evidence-based, OWASP-led Codex skill for reviewing software repositories and release readiness.

`review-software-security` inventories a repository, selects only the security profiles supported by repository evidence, and produces two consistent artifacts: a human-readable Markdown review and a machine-readable JSON security ledger. It reviews first and changes code only when explicitly asked.

> [!IMPORTANT]
> This is an independent open-source project. It is not an OWASP project and is not endorsed by the OWASP Foundation. It supports technical review and triage; it is not a certification, compliance attestation, or substitute for an authorized penetration test or qualified human review.

## Why this exists

AI-assisted development can compress the time from idea to deployment. It does not automatically supply the design discipline, threat modeling, authorization review, evidence handling, or release gates that mature security programs provide.

This skill makes a practical subset of that discipline repeatable for AI-assisted builders, volunteer teams, startups, and established organizations. Its differentiator is not another universal checklist. It combines:

- evidence-based profile routing, so irrelevant specialist guidance is not loaded;
- version-aware OWASP sources, with maturity and freshness recorded;
- explicit `pass`, `fail`, and `not-tested` coverage outcomes;
- `confirmed`, `likely`, and `unverified` findings instead of false certainty;
- matched Markdown and JSON outputs for people and automation;
- a deterministic release gate: confirmed Critical or High findings make a release not ready;
- safety boundaries that prohibit unapproved mutation, external probing, production-data access, exploit-oriented testing, and tool installation.

## Routed profiles

The core profile uses OWASP ASVS 5.0.0 as its verification baseline, with OWASP Top 10:2025 for prioritization and WSTG 4.2 for procedures. Repository evidence can add API Security Top 10:2023, LLM Top 10:2025, agentic application risks, Kubernetes Top 10:2025, CI/CD, supply-chain, mobile, or serverless guidance. Complementary CIS, provider, and protocol controls may be used when OWASP does not provide enough verification detail; they must be clearly labeled.

The full version and maturity registry is in [source-registry.md](skill/review-software-security/references/source-registry.md).

## Review modes

| Mode | Purpose | Safety boundary |
| --- | --- | --- |
| `diff` | Changed-code security gate | Static inspection of the supplied diff and relevant context |
| `standard` | Default risk-based repository review | Read-only repository inspection and approved local checks |
| `deep` | Dynamic or active testing | Requires explicit target, scope, authorization, and constraints |

Missing evidence, an unavailable scanner, or an unexecuted test is never reported as a pass.

## Install

Copy the installable directory into your personal Codex skills directory:

```bash
mkdir -p ~/.codex/skills
cp -R skill/review-software-security ~/.codex/skills/review-software-security
```

Restart Codex if needed, then invoke it explicitly:

```text
Use $review-software-security in standard mode to review this repository.
```

Or run a changed-code gate:

```text
Use $review-software-security in diff mode to review the current changes for release readiness.
```

Implicit invocation is enabled for explicit security reviews and work that crosses meaningful security boundaries. The skill should not activate for ordinary low-risk edits or generic code-quality review.

## Outputs

Each review produces:

1. a Markdown report based on [`security-review-report.md`](skill/review-software-security/assets/security-review-report.md); and
2. a JSON ledger conforming to [`security-ledger.schema.json`](skill/review-software-security/assets/security-ledger.schema.json).

Every finding includes severity, confidence, status, affected location, redacted evidence, attack path, impact, versioned references, CWE where applicable, remediation, verification method, and release-blocking state.

## Validate locally

The project has no runtime package dependencies. Python 3.10 or newer is recommended.

```bash
python3 tests/test_public_bundle.py
python3 tests/run_fixture_tests.py --skill skill/review-software-security
python3 scripts/build_release.py --version 0.1.0
```

The fixture suite covers web/API, LLM agents, CI pipelines, Kubernetes, dependency risk, mobile, serverless, and a neutral repository. Fixtures are synthetic and intentionally include unsafe examples; do not deploy them.

## Repository layout

```text
skill/review-software-security/  Installable Codex skill
tests/                           Deterministic routing and ledger fixtures
scripts/                         Reproducible release tooling
docs/                            Assurance, privacy, standards, and release records
.github/                         CI and community-health configuration
```

## Security and privacy

- Report vulnerabilities privately using [GitHub private vulnerability reporting](../../security/advisories/new) when available; see [SECURITY.md](SECURITY.md).
- Do not include real secrets, production data, customer data, or private repository contents in issues or fixtures.
- Review evidence must be minimized and secrets redacted.
- The detector is non-executing: it inspects names and bounded text; it does not run repository code.

See [Privacy](docs/privacy.md) and [Assurance model](docs/assurance-model.md) for the project’s guarantees and limitations.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and the [Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request. Significant control changes must include authoritative sources, version/maturity metadata, tests, and an explanation of false-positive and false-negative risks.

## License and attribution

The project is licensed under the [Apache License 2.0](LICENSE). Third-party standards and trademarks remain the property of their respective owners; see [NOTICE](NOTICE) and [Standards and attribution](docs/standards-and-attribution.md).
