## Summary

Describe the problem and the smallest coherent change.

## Security and privacy impact

- [ ] No real secrets, personal data, production evidence, or private repository content is included.
- [ ] Safety boundaries and least privilege are unchanged, or the change is explained below.
- [ ] New or changed controls cite authoritative, versioned sources and state maturity.
- [ ] False-positive and false-negative risks are documented where applicable.

## Validation

- [ ] `python3 tests/test_public_bundle.py`
- [ ] `python3 tests/run_fixture_tests.py --skill skill/review-software-security`
- [ ] `python3 scripts/build_release.py --version 0.1.0`
- [ ] User-visible changes are recorded under `CHANGELOG.md` → **Unreleased**.

## Evidence

List the synthetic fixtures, expected outcomes, and any checks that were not run. Missing tooling must be reported as not tested, never as a pass.
