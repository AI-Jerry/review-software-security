# Testing strategy

## Deterministic checks

`tests/test_public_bundle.py` verifies public-package structure, metadata consistency, Python compilation, workflow hardening, privacy patterns, basic secret patterns, and non-executing detector behavior.

`tests/run_fixture_tests.py` runs the detector against synthetic repositories and checks valid and invalid security ledgers. Fixtures cover relevant positive routes and a neutral negative route.

`scripts/build_release.py` creates a stable ZIP, SHA-256 checksums, and a CycloneDX SBOM without executing skill or fixture code.

## What these tests do not prove

They do not prove that every prompt will trigger correctly, every security issue will be found, every source remains current, or every generated review is semantically sound. They also do not replace CodeQL, secret scanning, dependency analysis, adversarial evaluation, or independent human review. Any unavailable check must remain visible as not tested.

## Adding fixtures

Fixtures must be synthetic, minimal, non-deployable, and free of real credentials or private data. Unsafe examples should contain an explicit comment or nearby documentation explaining that they are test inputs. Add both a positive case and, where practical, a negative case to control over-triggering.
