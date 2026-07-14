# Release process

## Preconditions

1. Update version metadata, changelog, source freshness, and documentation.
2. Run the public-bundle test and all fixtures.
3. Run the skill-creator validator in a clean environment.
4. Perform the repository’s standard security review and reconcile Markdown and JSON conclusions.
5. Record unavailable scanners or platform controls as not tested; do not convert absence into a pass.
6. Confirm there are no confirmed Critical or High findings.

## Build

Run:

```bash
python3 scripts/build_release.py --version X.Y.Z
```

Build twice from the same tree and compare `SHA256SUMS`. The release ZIP has a stable top-level `review-software-security/` directory. The build also emits a CycloneDX JSON SBOM containing file hashes.

## Publish

1. Create a draft GitHub release for tag `vX.Y.Z`.
2. Upload the ZIP, `SHA256SUMS`, CycloneDX SBOM, and security-review ledger.
3. Verify release notes, assets, hashes, and installation instructions from the draft.
4. Publish only after required checks and review rules pass.
5. Enable immutable releases when available so the tag and assets cannot be altered after publication.

Never build or publish a release from an unreviewed fork pull request or a workflow with write permissions to untrusted code.
