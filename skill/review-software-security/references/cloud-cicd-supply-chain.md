# Cloud, CI/CD, containers, and supply chain

Load only the detected subsections. Use OWASP for the organizing risks and label complementary CIS, provider, protocol, or language guidance.

## Supply chain

- Inventory direct, transitive, build, development, runtime, model, container-base, action, plugin, and tool dependencies.
- Review lockfiles, immutable references, integrity hashes, registries, dependency confusion/typosquatting exposure, install/build scripts, provenance, signatures, and maintainer/update trust.
- Review generated artifacts and release attestations separately from source. Trace who can modify source, pipeline, dependencies, and published artifacts.
- Assess SBOM readiness using CycloneDX concepts: component identity, versions, hashes, licenses, dependency relationships, services, and provenance. Do not claim Dependency-Track coverage unless an actual deployment and current analysis are evidenced.
- Never infer “no known vulnerabilities” without a current vulnerability database and successful scan. Record offline or stale analysis as `not-tested` or freshness-limited.

## CI/CD

Use the project's native, unversioned identifiers and add the access date: `OWASP-CICD-SEC-<n>-accessed-YYYY-MM-DD`. Do not append an invented release year. The project list is:

1. `CICD-SEC-1` Insufficient Flow Control Mechanisms
2. `CICD-SEC-2` Inadequate Identity and Access Management
3. `CICD-SEC-3` Dependency Chain Abuse
4. `CICD-SEC-4` Poisoned Pipeline Execution
5. `CICD-SEC-5` Insufficient Pipeline-Based Access Controls
6. `CICD-SEC-6` Insufficient Credential Hygiene
7. `CICD-SEC-7` Insecure System Configuration
8. `CICD-SEC-8` Ungoverned Usage of Third-Party Services
9. `CICD-SEC-9` Improper Artifact Integrity Validation
10. `CICD-SEC-10` Insufficient Logging and Visibility

- Map repository roles, branch protections, workflow triggers, approval gates, environments, runners, tokens, secrets, caches, artifacts, deployment identities, and logs.
- Review untrusted code execution in privileged workflow contexts, pull-request target patterns, script interpolation, poisoned pipeline execution, mutable third-party actions, and unsafe self-hosted runners.
- Enforce minimal token permissions, environment separation, protected secrets, short-lived identities, artifact integrity, controlled promotion, and auditable deploys.
- Treat third-party actions, build output, issue/PR text, branch names, commit messages, and generated files as untrusted inputs.

## Containers

- Review base-image provenance and pinning, non-root execution, capabilities, seccomp/AppArmor, read-only filesystems, secret injection, health checks, exposed ports, build context, multi-stage boundaries, and image scanning evidence.
- Inspect runtime configuration rather than relying only on the Dockerfile.

## Kubernetes

Use only the 2025 mapping unless explicitly crosswalking an older release:

- `K01` Insecure Workload Configurations
- `K02` Overly Permissive Authorization Configurations
- `K03` Secrets Management Failures
- `K04` Lack of Cluster Level Policy Enforcement
- `K05` Missing Network Segmentation Controls
- `K06` Overly Exposed Kubernetes Components
- `K07` Misconfigured and Vulnerable Cluster Components
- `K08` Cluster to Cloud Lateral Movement
- `K09` Broken Authentication Mechanisms
- `K10` Inadequate Logging and Monitoring

- Route to OWASP Kubernetes Top 10:2025 and inspect workload security contexts, RBAC, service accounts, secrets, admission/policy enforcement, network policies, exposed components, cluster/cloud identity, component versions, logging, and monitoring. Never reuse a 2022 identifier under a 2025 label.
- Flag privileged mode, host namespaces, host paths, dangerous capabilities, broad cluster roles, default service-account tokens, unrestricted egress, public control components, and unsigned/unpinned images when context supports impact.
- Use a versioned CIS benchmark or provider hardening guide only as a labeled complementary source.

## Cloud and IaC

- Map accounts/projects/subscriptions, environments, identities, trust policies, public exposure, network paths, encryption keys, data stores, logging, break-glass access, and state backends.
- Review least privilege, cross-account trust, workload identity, secret storage, public access, default resources, state-file sensitivity, drift, deletion protection, audit coverage, and recovery.
- Validate generated plans or deployed configuration when authorized; source IaC alone may not match runtime state.

## Serverless

- Review event sources, function identities, per-function privilege, package/dependency trust, secrets, concurrency and cost limits, retries/idempotency, dead-letter handling, temporary storage, outbound access, logging, and provider control-plane exposure.
- Treat the OWASP Serverless Top 10 as advisory unless a current stable release is verified. Supplement with the detected provider's primary security guidance and label it.
