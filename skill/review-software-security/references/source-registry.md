# Source registry

Use this registry to select and cite authoritative controls. Verify changing versions against primary project pages when network access is available. Record the exact version and `checked_at` date in the ledger.

## Freshness rules

- Pin identifiers and links to a released version whenever the project offers one.
- Treat `latest`, draft, release-candidate, public-review, and unversioned project content as unstable.
- Prefer OWASP project pages and official repositories over blogs, mirrors, or vendor summaries.
- Use the pinned baseline when offline, set freshness to `offline-unverified`, and never describe it as current.
- Do not silently translate an identifier between versions. Record both versions when crosswalking.
- When a project publishes no version, cite the native identifier with `accessed-YYYY-MM-DD`; never invent a release year to satisfy a versioning rule.
- Label CIS, NIST, cloud-provider, language, and protocol guidance as complementary rather than OWASP.

## Baseline verified 2026-07-13

| Profile | Source | Pinned release/status | Authority | Use |
|---|---|---|---|---|
| Core/web | OWASP ASVS | 5.0.0 stable | https://owasp.org/www-project-application-security-verification-standard/ | Primary web control requirements; cite as `OWASP-ASVS-v5.0.0-<id>` |
| Web priority | OWASP Top 10 | 2025 stable | https://owasp.org/Top10/ | Awareness and prioritization; not a complete verification standard |
| Web testing | OWASP WSTG | 4.2 stable; 5.0 in development | https://owasp.org/www-project-web-security-testing-guide/ | Testing procedures; cite stable scenarios as `OWASP-WSTG-v42-<id>` |
| API | OWASP API Security Top 10 | 2023 stable | https://owasp.org/www-project-api-security/ | API-specific risk priorities; combine with ASVS requirements |
| LLM/GenAI | OWASP Top 10 for LLM and GenAI | 2025 release | https://genai.owasp.org/llm-top-10/ | LLM-specific risks |
| AI testing | OWASP AI Testing Guide | v1 released 2025-11-26 | https://owasp.org/www-project-ai-testing-guide/ | Trustworthiness and adversarial AI test methodology |
| Broad AI | OWASP AI Exchange | Flagship, evolving | https://owasp.org/www-project-ai-security-and-privacy-guide/ | Broad AI security/privacy controls and crosswalks; record access date |
| Agentic | OWASP Agentic AI Threats and Mitigations | v1.1 family, evolving | https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/ | Agent threat modeling and mitigations |
| Agentic apps | OWASP Top 10 for Agentic Applications | 2026 release (published 2025-12-09) | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | Agentic application priority risks |
| Agent skills | OWASP Agentic Skills Top 10 | New project/public-review material | https://owasp.org/www-project-agentic-skills-top-10/ | Advisory only until a stable release is verified |
| Kubernetes | OWASP Kubernetes Top 10 | 2025 available; feedback invited | https://owasp.org/www-project-kubernetes-top-ten/ | Kubernetes risk priorities; supplement with platform benchmarks |
| CI/CD | OWASP Top 10 CI/CD Security Risks | Project list, unversioned | https://owasp.org/www-project-top-10-ci-cd-security-risks/ | Pipeline threat review; cite as `OWASP-CICD-SEC-<n>-accessed-YYYY-MM-DD` |
| Supply chain | OWASP CycloneDX | Verify current specification | https://cyclonedx.org/ | SBOM format and component metadata |
| Supply chain operations | OWASP Dependency-Track | Verify deployed/current version | https://dependencytrack.org/ | SBOM analysis and portfolio risk operations; do not require deployment |
| Mobile | OWASP MASVS, MASWE, MASTG | Verify current releases | https://mas.owasp.org/ | Mobile requirements, weakness taxonomy, and test procedures |
| Serverless | OWASP Serverless Top 10 | Project maturity/version must be verified | https://owasp.org/www-project-serverless-top-10/ | Advisory serverless routing; supplement with provider guidance |

## Complementary-source rule

Use a complementary source only when it closes a concrete gap, such as cloud identity, managed-service configuration, Kubernetes hardening, TLS behavior, or language/framework defaults. Cite its version and primary URL, explain why it is needed, and do not imply OWASP endorsement.
