# Roadmap

## Phase 0: Project Foundation

- Create project structure.
- Define product brief and architecture.
- Define initial manifest and rule schemas.
- Choose implementation stack.

## Phase 1: CLI MVP

- Scan local project folders for AI agent surfaces.
- Parse skills, plugin manifests, MCP configs, agent instructions, env references, CI workflows, and common RAG/memory paths.
- Generate `agent-manifest.json`.
- Run built-in static rules.
- Produce JSON and Markdown reports.

## Phase 2: Blast Radius and Policy

- Add permission and side-effect classification.
- Build graph-based blast-radius analysis.
- Add `agentcsp.yaml` policy files.
- Add `agentcsp.yaml` policy-integrity posture for broad suppressions, permissive control downgrades, and risky trust overrides.
- Add A2A and public agent-card exposure posture for external discovery, anonymous caller access, privileged capability categories, rate limits, and approval gates.
- Add outbound remote-agent federation posture for dynamic A2A discovery, model-selected peers, sensitive context forwarding, credential forwarding, peer verification, allowlists, and approval gates.
- Add remote prompt-registry posture for auto-synced system/developer prompts, unpinned revisions, verification controls, and untrusted prompt selectors.
- Add MCP prompt and resource context inventory for model-visible server-supplied context that can steer privileged MCP authority.
- Add MCP client-context posture for roots, sampling, and elicitation requests from remote or third-party servers.
- Add MCP OAuth authorization posture for dynamic client registration, PKCE/state/resource-indicator controls, broad scopes, refresh-token storage, token forwarding, and untrusted server selection.
- Add OpenAPI and Swagger tool-import posture for authenticated external API writes, user-controlled request schemas, sensitive data categories, and approval boundaries.
- Add hosted assistant and deployable agent-definition posture for automatic tool choice, hosted code/file/vector/function resources, sensitive context, guardrail posture, and approval boundaries.
- Add realtime and voice agent session posture for external callers, raw audio and transcript capture, recording redaction, prompt-injection filtering, privileged tool authority, and approval boundaries.
- Add agent authorization-broker posture for model-selected tool grants, dynamic resource scopes, default-allow/fail-open decisions, audit posture, credential exposure, and approval boundaries.
- Add runtime posture inventory for sandbox, approval, network, tool authority, disabled safety controls, and fail-open agent safety fallback posture.
- Add browser extension/profile posture for privileged extensions, password-manager/autofill exposure, and download/upload path redaction.
- Add identity delegation posture for agent OAuth, OIDC, service-account, workload-identity, and token-broker authority.
- Add cloud control-plane authority posture for agent IAM, compute, storage, secret, audit-log, IaC, and auto-remediation authority.
- Add dynamic extension-loader posture for remote skills, plugins, tools, prompts, and MCP capabilities.
- Add self-modification posture for agent-controlled prompt, policy, runtime, tool, memory, and workflow writes.
- Add approval-gate integrity posture for model-mediated decisions, default-allow review paths, auto-execution, and human-review boundaries.
- Add context-composer posture for role-boundary assembly, source promotion, sanitization, delimiters, and privileged tool exposure.
- Add tool-output policy posture for raw browser, shell, MCP, API, retrieval, and customer observations that can enter prompt context or request privileged follow-up actions.
- Add visual and OCR context posture for screenshots, uploaded images, OCR text, and multimodal observations that can enter prompt context or request privileged follow-up actions.
- Add artifact/output export posture for generated prompts, completions, tool outputs, browser artifacts, retrieval context, memory, secrets, public access, retention, and redaction boundaries.
- Add webhook/callback egress posture for model-generated payload delivery, sensitive context capture, retry queues, redaction posture, and approval boundaries.
- Add background agent task-queue posture for asynchronous job consumers, untrusted queued payloads, retry and dead-letter replay, privileged tool authority, credentials, and approval boundaries.
- Add container runtime isolation posture for privileged containers, Docker socket mounts, host paths, host namespaces, dangerous capabilities, untrusted inputs, and approval boundaries.
- Add code interpreter and notebook runtime posture for model-generated code execution, network/package installation, filesystem access, credential mounts, output persistence, untrusted inputs, and approval boundaries.
- Add AI training and fine-tuning dataset posture for prompts, completions, tool outputs, retrieval context, memory, browser context, PII, secrets, model-update authority, redaction posture, and approval boundaries.
- Add AI feedback and RLHF pipeline posture for ratings, reviewer notes, production interactions, tool traces, retrieval, memory, PII, secrets, training/eval promotion, consent, redaction, and approval boundaries.
- Add AI telemetry trace-sharing posture for public links, anonymous viewers, shared workspaces, RBAC/SSO controls, sensitive trace capture, redaction, credential references, and approval boundaries.
- Add LLM prompt, response, completion, and semantic cache posture for shared cache replay, sensitive capture, persistence, redaction posture, untrusted inputs, and approval boundaries.
- Add AI model router and fallback posture for provider routing, automatic failover, sensitive context forwarding, redaction posture, output recording, and approval boundaries.
- Add AI embedding and indexing posture for third-party embedding providers, vector upserts, sensitive source capture, redaction posture, retention, and approval boundaries.
- Add RAG ingestion poisoning posture for user uploads, ticket attachments, public web pages, and message sources that auto-index into trusted retrieval namespaces without quarantine, instruction stripping, provenance, or approval.
- Add RAG retrieval-authorization posture for user-controlled queries and filters, broad private retrieval scope, ACL/provenance/trust filtering, prompt-injection passthrough, and tool-context injection.
- Add agent package-manifest supply-chain posture for agent/MCP/model/RAG dependencies, risky dependency references, lifecycle scripts, and credential exposure without broad generic SCA noise.
- Add agent deployment image-provenance posture for mutable remote images, digest pinning, pull policy, privileged host authority, service accounts, host mounts, credential exposure, and approval boundaries.
- Support allow, deny, approval, redaction, and quarantine recommendations.
- Add SARIF output and CI integrations for code-scanning workflows.
- Add high-confidence correlated findings that combine provenance, data class, authority, and side effects.

## Phase 3: Red-Team Rule Exchange

- Define public rule format.
- Ship core rules.
- Add community rule packs.
- Inventory live eval and red-team harness authority before generating app-specific adversarial tests from discovered tools and data flows.

## Phase 4: Secure RAG and Memory Lab

- Add test fixtures for poisoned docs, logs, tool outputs, and vector records.
- Simulate persistence, retrieval, and memory contamination.
- Inventory memory-store authority, sharing, approval gates, and replay boundaries before generating runtime experiments.
- Report whether injected instructions survive across sessions or retrieval paths.

## Phase 5: OSS Bug Report Verifier

- Add GitHub issue scanner.
- Score reports for reproducibility, affected version, impact, PoC, logs, and patch guidance.
- Output maintainer-friendly triage labels and comments.

## Phase 6: Runtime Enforcement

- Add adapters for MCP, LangChain/LangGraph, OpenAI Agents SDK, and coding-agent hooks where feasible.
- Enforce policy before tool calls and sensitive memory writes.
- Emit signed or tamper-evident evidence records.

## Phase 7: AgentCSP Platform

- Add a local-first platform deployment for teams that need a persistent manifest registry, policy governance, evidence history, and AI agent security inventory.
- Support self-hosted deployment first, with optional cloud deployment for organizations that need centralized multi-repo visibility.
- Keep CLI, schemas, rules, and scanner engine fully open and usable without the platform.
