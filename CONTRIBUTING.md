# Contributing

Thank you for helping make software-security review more accessible and rigorous.

## Before you start

- Use an issue for substantial behavior, schema, or source-registry changes.
- Use private vulnerability reporting for security-sensitive defects.
- Never contribute real secrets, production data, customer information, or private repository evidence.
- Keep the installable skill concise. Put detailed guidance in its `references/` directory.

## Development workflow

1. Fork the repository and create a focused branch.
2. Make the smallest coherent change.
3. Add or update synthetic positive and negative fixtures.
4. Run:

   ```bash
   python3 tests/test_public_bundle.py
   python3 tests/run_fixture_tests.py --skill skill/review-software-security
   python3 scripts/build_release.py --version 0.1.0
   ```

5. Update `CHANGELOG.md` under **Unreleased** for user-visible changes.
6. Open a pull request using the repository template.

## Control and source changes

Changes to security guidance must:

- cite a primary or authoritative source;
- record an explicit version or access date;
- label maturity as stable, advisory, draft, or evolving;
- explain applicability and likely false-positive/false-negative effects;
- preserve the distinction between `pass`, `fail`, and `not-tested`;
- never infer a pass from missing tooling or missing evidence.

OWASP Top 10 lists are prioritization and awareness resources, not exhaustive verification standards. Do not present them as certification criteria.

## Pull-request expectations

Pull requests should be reviewable, contain no unrelated formatting churn, and pass all checks. Maintainers may request threat-model notes for changes that affect execution, file traversal, output integrity, release gating, CI permissions, or external references.

By contributing, you agree that your contribution is licensed under Apache-2.0 and that you have the right to submit it.
