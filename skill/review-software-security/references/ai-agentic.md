# AI, LLM, and agentic review

Apply ordinary application, API, identity, data, and supply-chain controls first. AI-specific lists do not replace them.

## AI and LLM profile

- Map model/provider boundaries, prompts, system instructions, retrieval sources, training/fine-tuning data, embeddings/vector stores, output consumers, evaluation datasets, logging, and human review.
- Distinguish trusted instructions from untrusted content. Review direct and indirect prompt injection across user input, retrieved documents, web pages, email, files, tool output, memory, and inter-agent messages.
- Review sensitive-information disclosure through prompts, context, retrieval, logs, traces, caches, outputs, model/provider retention, and cross-tenant data stores.
- Review model/data/dependency provenance, poisoning paths, unsafe model formats, plugin/provider changes, and evaluation integrity.
- Treat model output as untrusted before rendering, querying, executing, routing, or passing it to another security boundary.
- Review denial-of-wallet/resource exhaustion, model fallback behavior, hallucination-sensitive decisions, bias/fairness where relevant, drift monitoring, and rollback.
- Use the AI Testing Guide for repeatable trustworthiness tests. Record stochastic test parameters, model/version, prompt set, sample size, pass criteria, and observed variance.

## Agentic profile

- Map goals, planners, tools, permissions, identities, memory, state transitions, approval gates, subagents, MCP/A2A or other protocols, and external side effects.
- Test goal/instruction hijacking, tool misuse, identity and privilege abuse, unexpected code execution, memory/context poisoning, unsafe inter-agent trust, resource exhaustion, and loss of human control.
- Enforce least privilege per tool and per task. Review argument validation, destination allowlists, credential scoping, sandbox boundaries, time/cost/action limits, and revocation.
- Separate read authority from mutation authority. Require explicit human approval for irreversible, high-impact, financial, production, credential, or external communication actions.
- Treat tool descriptions, skill files, retrieved instructions, repository policy files, and model-generated plans as untrusted inputs subject to an authority hierarchy.
- Review observability without storing secrets: decision traces, tool calls, identity, approvals, failures, policy denials, and tamper resistance.

## Agent skill advisory

When reviewing reusable agent skills, inspect provenance, all scripts and natural-language instructions, declared versus actual permissions, network destinations, update behavior, transitive resources, isolation, and instruction injection. Use the OWASP Agentic Skills Top 10 only as advisory until a stable release is verified and label that maturity in the report.

## Testing boundary

Do not send proprietary data or adversarial prompts to a hosted model without authorization. Do not let an evaluated agent perform real external actions. Prefer synthetic canaries, mocked tools, local fixtures, deny-by-default credentials, and captured action intents.
