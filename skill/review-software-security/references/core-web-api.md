# Core, web, and API review

Apply the universal core to every software review. Add web and API sections only when the repository or requested scope exposes those surfaces.

## Universal core

- Map assets, trust boundaries, identities, privilege transitions, sensitive data, entry points, outbound calls, background work, and administrative paths.
- Review authentication, authorization at every object/function boundary, session/token lifecycle, least privilege, tenant isolation, and failure behavior.
- Trace untrusted input through parsing, validation, canonicalization, queries, templates, interpreters, file paths, URLs, headers, and logs.
- Review secrets, cryptography, key ownership, transport protection, data retention/deletion, backups, logging, alerting, and exceptional conditions.
- Review dependency trust, artifact integrity, unsafe defaults, debug behavior, error leakage, concurrency, resource exhaustion, and abuse-prone business flows.
- Select and record ASVS 5.0.0 depth. Default to a practical Level 1 baseline; use Level 2 for applications handling meaningful sensitive data or transactions and Level 3 only for the highest-value or safety-critical systems.

## Web profile

- Use ASVS requirements as the control baseline and Top 10:2025 only to prioritize likely risk concentrations.
- Use versioned WSTG 4.2 scenarios for authorized test procedures. Do not cite development content as stable.
- Inspect browser boundaries: CSP, framing, CORS, cookies, cache behavior, CSRF, DOM injection, redirects, uploads/downloads, service workers, cross-origin messaging, and client-side secret exposure.
- Verify security controls at the server even when the client hides or validates an action.
- Expand diff review to middleware, shared authorization helpers, schemas, serializers, templates, and deployment headers affected by the change.

## API profile

- Test object-level, property-level, and function-level authorization independently. Vary identity, tenant, role, object identifier, fields, and method.
- Review authentication and token audience/issuer/expiry, replay, key rotation, service identities, and machine-to-machine authorization.
- Review schema enforcement, mass assignment/property filtering, response minimization, pagination, batching, query complexity, rate/resource limits, and sensitive business-flow abuse.
- Inventory versions, hosts, debug/admin endpoints, deprecated routes, documentation, and shadow APIs.
- Treat outbound API responses and webhook inputs as untrusted. Review SSRF, redirect handling, DNS/IP validation, timeouts, TLS verification, response size, and unsafe deserialization.
- Review GraphQL field/resolver authorization, introspection policy, aliases/batching, depth/cost limits, and error leakage when GraphQL is detected.

## Evidence expectations

Prefer a trace from route or entry point through authentication, authorization, validation, data access, serialization, and logging. A framework annotation or middleware name alone is not proof that the control covers every path.
