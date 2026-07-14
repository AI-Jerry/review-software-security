# Evidence, severity, and release decisions

## Separate the dimensions

- **Severity** estimates realized impact and exploitation conditions: `critical`, `high`, `medium`, `low`, or `info`.
- **Confidence** estimates support for the conclusion: `high`, `medium`, or `low`.
- **Finding status** states whether the weakness is `confirmed`, `likely`, or `unverified`.
- **Coverage status** states whether an applicable control `pass`, `fail`, or was `not-tested`.

Never convert low confidence into low severity. Never convert unavailable evidence into a pass.

## Finding evidence

For each finding include:

- exact repository-relative location and revision;
- security-relevant behavior at the enforcement point;
- preconditions and attacker-controlled input or capability;
- attack path and affected asset;
- confidentiality, integrity, availability, privacy, safety, or business impact;
- counterevidence and uncertainty;
- versioned control references and CWE where a mapping is defensible;
- a safe reproduction or verification method that does not expose secrets.

Use `confirmed` only when code, configuration, tests, or authorized runtime evidence demonstrates the weakness and its necessary conditions. Use `likely` when a strong pattern exists but an important condition remains unverified. Use `unverified` for a hypothesis that needs material additional evidence.

## Severity guide

- `critical`: Plausible low-friction compromise with catastrophic scope, such as broad unauthenticated control, production credential disclosure, arbitrary execution across a high-value boundary, or systemic supply-chain compromise.
- `high`: Serious compromise of sensitive data, privileged action, tenant boundary, deployment integrity, or agent/tool authority with realistic preconditions.
- `medium`: Material weakness with limited scope, stronger preconditions, or meaningful defense in depth remaining.
- `low`: Narrow impact or hard-to-exploit weakness that still warrants correction.
- `info`: Hardening, observation, or governance gap without a demonstrated vulnerability.

Consider business context and blast radius. Use CVSS or AIVSS only when enough facts exist and label the scoring system/version; a numeric score is optional.

## Release gate

- Every confirmed `critical` or `high` finding must be release blocking.
- A ledger with any blocker must declare `not-ready` and list exactly those finding IDs.
- `likely` and `unverified` findings cannot automatically block under the default policy. Escalate them for confirmation and explain risk acceptance needs.
- A confirmed `medium`, `low`, or `info` finding is non-blocking by default unless the user supplies a stricter policy.
- `ready` requires no blocking findings. `conditional` may describe non-blocking work but must not hide blockers.

## Coverage rules

- `pass` requires affirmative evidence that the control operates for the assessed scope.
- `fail` requires evidence of a control gap; create a linked finding when the gap is security-relevant.
- `not-tested` covers unavailable tools, unexecuted tests, missing environments, permission boundaries, and insufficient evidence.
- `not-applicable` is applicability, not a test outcome. Explain why the control cannot apply.
- Keep a coverage item when it was scoped but not tested so omissions remain visible.

## Redaction

Never copy live secret values, access tokens, private keys, personal records, session identifiers, or unnecessary exploit payloads into artifacts. Preserve evidence using variable names, hashes, line locations, response shapes, or redacted excerpts.

For an unversioned standard, use its native identifier plus `accessed-YYYY-MM-DD`. A plausible-looking invented year is an evidence defect, not a citation.
