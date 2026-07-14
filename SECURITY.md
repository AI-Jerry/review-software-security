# Security policy

## Supported versions

Security fixes are provided for the latest published release and the default branch.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Default branch | Yes |
| Older releases | No |

## Report a vulnerability privately

Please use [GitHub private vulnerability reporting](https://github.com/AI-Jerry/review-software-security/security/advisories/new). Do not open a public issue for a suspected vulnerability.

Include only the minimum information needed to reproduce the issue:

- affected version, file, or control;
- security impact and realistic attack path;
- safe reproduction steps using synthetic data;
- suggested mitigation, if known.

Do not send real credentials, tokens, personal data, production data, weaponized payloads, or material from repositories you are not authorized to disclose. Redact secrets and use placeholders.

We aim to acknowledge a report within 5 business days, provide an initial assessment within 10 business days, and coordinate disclosure after a fix or documented mitigation is available. These are targets, not service-level guarantees.

## Scope

In scope:

- unsafe behavior caused by the skill instructions or deterministic scripts;
- release-gate bypasses or Markdown/JSON conclusion mismatches;
- path traversal, unintended code execution, or unauthorized network behavior;
- privacy leaks in project-controlled fixtures or release artifacts;
- material weaknesses in the public release workflow.

Out of scope:

- vulnerabilities in third-party standards or services;
- findings produced only by intentionally unsafe synthetic fixtures;
- reports requiring access to production data or external targets;
- social-engineering, denial-of-service, or destructive testing.

Please test only systems and data you own or are explicitly authorized to assess.
