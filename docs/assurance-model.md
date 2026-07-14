# Assurance model

## Claim

`review-software-security` provides structured, evidence-based review assistance. It improves consistency in repository inventory, control selection, finding documentation, and release triage. It does not prove that software is secure.

## Trust boundaries

The skill operates inside an AI-assisted development environment and depends on:

- the completeness of the repository and scope supplied by the user;
- the model’s reasoning and accurate use of the instructions;
- the quality and freshness of cited standards;
- explicit authorization for any dynamic or active testing;
- independent verification of consequential findings and remediations.

The deterministic scripts narrow two risks: profile detection does not execute target code, and ledger validation enforces structural and release-gate invariants. They do not validate every semantic claim in a review.

## Safety invariants

- Review first; remediation requires an explicit request.
- Never install tools, probe external targets, access production data, or run exploit-oriented tests without authorization.
- Deep mode requires an explicit target, scope, authorization, and constraints.
- Missing evidence or unavailable tooling is `not-tested`, never `pass`.
- Confirmed Critical or High findings block release.
- Secrets are redacted and evidence is minimized.
- Markdown and JSON release conclusions must agree.

## Failure modes

The review can miss vulnerabilities, misclassify applicability, rely on stale sources, overestimate an attack path, or understate contextual risk. Generated findings should be treated as hypotheses until supported by evidence. High-impact decisions require human review, and internet-facing or high-consequence systems may still need professional threat modeling, architecture review, testing, and monitoring.

## Verification layers

1. **Structural validation:** skill metadata, expected files, Python compilation, schema and ledger invariants.
2. **Synthetic evaluation:** positive and negative profile fixtures and release-gate cases.
3. **Repository security review:** applicable profiles, threat model, evidence ledger, and privacy scan.
4. **Platform controls:** GitHub permissions, review rules, secret scanning, dependency alerts, code scanning, private reporting, and immutable releases where available.
5. **Human review:** source accuracy, finding quality, usability, and disclosure decisions.

No layer should be represented as covering a check that was not actually performed.
