# Governance

## Model

This project currently uses a maintainer-led model. Jerry Lartey (`@AI-Jerry`) is the initial maintainer and release manager.

The maintainer is responsible for scope, security policy, source quality, releases, and final merge decisions. Routine changes are decided through pull-request review. Material changes to release-gate behavior, safety boundaries, ledger schema, or authoritative-source policy require a documented rationale and tests.

## Decision principles

Decisions prioritize:

1. user safety and honest evidence;
2. deterministic, inspectable behavior;
3. narrowly routed guidance over universal checklists;
4. accessibility without overstating assurance;
5. backward compatibility of published ledger contracts.

Substantial disagreement should be recorded in the relevant issue or pull request. A future multi-maintainer project may adopt voting or a formal request-for-comments process when contributor volume justifies it.

## Releases

Only maintainers may create releases. Releases follow [docs/release-process.md](docs/release-process.md), include checksums and an SBOM, and must pass the documented security gate.
