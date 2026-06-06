# Production Hardening Plan

AgentCSP should become useful to cybersecurity teams by producing high-confidence findings with evidence, not by maximizing alert volume.

## Quality Bar

A finding should be considered production-grade when it includes:

- normalized object type
- file path
- trust level
- data class
- authority/action
- side effect and reversibility
- external reach
- secret exposure signal
- reason
- confidence and confidence rationale
- confidence-aware CI failure gates
- baseline comparison for new, existing, and resolved findings
- scan coverage counts for skipped files, ignored paths, and traversal limits
- diagnostic severity counts in scan coverage so parser-degraded scans are machine-readable
- redacted parser diagnostics for malformed security-relevant configuration
- redacted policy diagnostics for malformed, schema-invalid, or explicitly missing advisory policy configs
- built-in rule pack loading that cannot be suppressed by a project-local `rules/` directory
- packaged built-in rule assets under `@agentcsp/core` so installed builds retain the same detection baseline
- CI package-artifact verification for compiled modules and bundled built-in rule counts
- fixture artifact verification for manifest/finding schema validity, SARIF structure, expected signal, safe-fixture quietness, and redaction invariants
- redacted project-local rule diagnostics for malformed, schema-invalid, or duplicate custom rules
- optional CI failure on diagnostics when malformed agent configuration should block release
- negation-aware action classification so safety policy text is not treated as granted authority
- MCP package-runner posture for unpinned third-party runtime launchers
- remote MCP transport posture for credential-backed plaintext endpoints
- local MCP implementation presence checks for secret-backed agent-callable servers
- tool-name collision metadata for authority ambiguity and shadowing
- tool-schema integrity signals for open-world privileged arguments and read-only hint conflicts
- model-visible tool-description injection signals without emitting raw descriptions
- tool-schema content-input signals for prompt-like text sent to external destinations
- tool-schema path-to-external data-flow signals for exfiltration risk
- instruction-file context bridge signals for untrusted inputs routed into tool or memory authority
- Cursor project-rule metadata for always-applied broad workspace rules without emitting rule descriptions, globs, or body text
- runtime-to-MCP reference signals for approval bypass into secret-backed MCP servers
- Claude-style runtime permission allowlists normalized into redacted auto-approved privileged tool signals
- auto-approved destructive MCP tool refs correlated to credential-backed runtime servers
- runtime permission allowlists correlated to exact package scripts and release authority
- browser-session metadata for persistent authenticated state, broad origins, and untrusted click/form authority without emitting cookie files, profile paths, origins, or endpoints
- inbound agent trigger metadata for email, chat, ticket, webhook, and queue payloads that reach agent tools without emitting mailbox names, sender addresses, URLs, labels, agent names, or payload text
- multi-agent orchestration metadata for delegation, shared memory, tool authority, and approval posture without emitting agent names, role prompts, task text, graph labels, memory namespaces, or raw tool lists
- agent safety-control metadata for disabled guardrails, validation, moderation, tool-result sanitization, and redaction without emitting policy names, source names, tool strings, action lists, data-field labels, or prompt text
- AI eval harness metadata for live red-team execution, adversarial cases, production targets, privileged tool authority, output retention, and approval posture without emitting suite names, scenario names, prompts, target URLs, agent names, tool strings, assertion values, output paths, or data-field labels
- agent identity delegation metadata for credential issuance, impersonation, broad scopes, untrusted subjects, tool injection, and approval posture without emitting issuers, token endpoints, service-account IDs, raw scopes, IAM roles, subject labels, tool names, data-field labels, or token placeholders
- agent extension loader metadata for remote registries, auto-install/update posture, pinning, signature/provenance verification, untrusted selectors, and tool authority without emitting registry URLs, Git URLs, package names, extension names, permission strings, selector fields, source labels, or token placeholders
- agent self-modification metadata for untrusted writes to instructions, prompts, policy, runtime config, tools, memory, or workflows without emitting target paths, patch rules, reload commands, source labels, tool names, data-field labels, or token placeholders
- agent approval-gate metadata for model-mediated decisions, untrusted approval prompts, default-allow posture, auto-execution, human-review posture, and privileged action categories without emitting prompts, model names, action strings, reviewer labels, source labels, or token placeholders
- SaaS/API connector metadata for broad credential-backed write scopes without emitting raw OAuth scopes, endpoints, workspaces, channels, queues, or customer-system names
- secret-manager metadata for read/list credential-broker authority without emitting vault URLs, secret paths, policy names, role names, or resource IDs
- database connector metadata for credential-backed read/write/query authority without emitting hosts, connection strings, usernames, or table names
- AI model endpoint metadata for prompt, tool-output, retrieval, and memory egress without emitting model gateway URLs or model names
- AI telemetry export metadata for prompt, completion, tool-output, retrieval, and memory capture without emitting trace payloads or endpoints
- workflow-to-agent-script signals for unattended automation with secrets and write authority
- workflow event-payload signals for issue, pull request, discussion, or repository-dispatch text passed into privileged agent automation without emitting raw event expressions or payload content
- prompt-template variables and redacted context signals for untrusted-input bridges
- prompt-template role-boundary signals for untrusted variables injected into system or developer roles
- exact callable-reference signals for prompts, memory, RAG, instructions, and skills that name discovered privileged tools or MCP servers
- prompt-template memory persistence signals for cross-session contamination
- memory replay signals for persisted context that explicitly names privileged tools
- RAG and memory data-egress signals for sensitive context routed toward external destinations
- RAG/vector-store connector metadata for remote credential-backed stores with write or sync ingestion
- agent memory-store metadata for remote/shared durable memory, untrusted writes, tool/prompt/retrieval/secret capture, replay posture, and approval state without emitting connection strings, hostnames, store names, namespaces, source labels, replay targets, or data-field labels
- skill data-flow signals for context-to-external-output bridges
- source-anchored attack paths for dangerous context that reaches direct data-egress capabilities
- source-anchored attack paths for project prompt templates that route untrusted variables to explicit privileged tools
- source-anchored attack paths for runtime permissions that auto-approve exact release package scripts
- source-anchored generated-state paths that replay transcripts or cached outputs into exact privileged tools
- attack-path de-noising when exact callable references make broader speculative source paths less useful
- recommended control
- OWASP, MITRE ATLAS, and NIST AI RMF mappings where applicable
- redacted evidence
- exported JSON Schema drift verification against Zod source definitions

## High-Signal Rule Strategy

Prefer correlated rules over keyword rules.

Examples:

- network retrieval plus shell execution
- MCP server plus credential key names plus side effects
- remote third-party MCP server plus auth headers or credential references
- remote MCP server plus plaintext transport plus credential-backed access
- local MCP implementation path missing from scan plus credential exposure and side effects
- package-runner MCP server plus unpinned package version plus credential exposure
- runtime allowlist plus secret-backed MCP server plus approval bypass
- auto-approved destructive MCP tool plus credential-backed server
- auto-approved privileged runtime permissions plus credential key exposure
- auto-approved runtime package script plus release or deploy authority
- external write tool plus prompt-like content input and URL destination
- model-visible tool-description injection plus external write and side-effect authority
- workflow automation plus agent package script plus secrets and write authority
- workflow automation plus untrusted event payload plus agent package script plus secrets and write authority
- instruction file plus untrusted context reference plus tool and memory bridge
- always-applied broad Cursor project rule plus untrusted-to-privileged context bridge
- tool-name collision plus different authority signatures and a privileged peer
- skill consumes retrieved/tool/memory context plus external publication
- prompt template with user/customer/context variables plus explicit privileged tool reference
- prompt template with user/customer/context variables embedded in system or developer roles
- persisted memory with instruction-like content plus explicit privileged tool reference
- prompt template with user/customer/context variables plus memory persistence directives
- prompt template with user/customer/context variables plus tool or external directives
- runtime config with unsandboxed execution plus no approval gate
- runtime config with network access plus secret env keys plus privileged tools
- authenticated browser session plus broad origins plus untrusted navigation plus click/form/upload authority
- inbound email/chat/ticket/webhook payload plus agent invocation plus tool authority plus secrets plus no approval gate
- multi-agent delegation plus untrusted input plus shared memory plus privileged specialist tools plus credentials plus no approval gate
- disabled agent safety controls plus untrusted input plus privileged tools plus credentials plus no approval gate
- live eval harness plus adversarial prompts plus production agent target plus privileged tools plus credentials plus no approval gate
- agent identity delegation plus credential issuance plus service-account impersonation plus broad scopes plus untrusted subject inputs plus no approval gate
- remote agent extension loader plus auto-install plus unpinned unsigned capabilities plus untrusted selector inputs plus privileged tool authority plus no approval gate
- agent self-modification plus untrusted inputs plus auto-applied writes to instructions, policy, runtime config, and tool definitions plus no approval gate
- model-mediated approval gate plus untrusted approval context plus default-allow behavior plus auto-executed privileged actions and no required human reviewer
- SaaS connector with broad write scopes plus credentials plus untrusted input plus no approval gate
- secret manager connector with read/list scope plus tool injection plus untrusted input plus no approval gate
- database connector with credentials plus write/query authority plus sensitive data plus untrusted input
- AI model endpoint with plaintext transport plus sensitive context plus credential reference
- AI telemetry remote export plus sensitive agent-context capture plus disabled redaction plus credential reference
- pull request workflow plus write permissions plus secrets
- untrusted RAG source plus privileged tool path
- memory write plus untrusted source provenance
- RAG or memory content with instruction-like text plus tool/external directives
- retrieved content plus sensitive context reference plus external data-egress directive
- remote vector store plus credential reference plus untrusted source ingestion plus write/sync authority
- remote/shared memory store plus untrusted writes plus tool, prompt, retrieval, and secret capture plus future-context replay plus no approval gate
- generated transcripts or cached tool output with instruction-like tool/external directives
- local path input plus URL-like destination plus external write capability
- open-world tool schema plus external, filesystem, credential, or execution authority
- read-only tool hint plus destructive or external write behavior
- scheduled or externally dispatched automation plus secrets and write authority
- issue/comment/repository-dispatch event payloads passed into secret-backed agent automation with write authority
- package publish/release authority plus agent-influenced workflow
- attack paths that connect specific context-risk signals to concrete privileged capabilities
- source-anchored RAG data-egress paths that preserve the retrieval finding as the reason for the blast radius
- exact customer-data paths from retrieved context into PII-capable external tools
- source-anchored prompt paths that preserve explicit privileged-tool references from untrusted template variables
- source-anchored memory replay paths that preserve the persisted-memory finding as the reason for the blast radius
- exact generated-state replay paths that preserve transcript or cached-output provenance without expanding into unrelated privileged targets
- exact runtime auto-approval paths that preserve permission-to-package-script provenance for release or deploy authority
- blast-radius summary counts for sensitive-data, PII, and credential external reach and attack paths

## CI Expectations

Every production change should pass:

- reproducible install from lockfile
- TypeScript check
- unit tests
- build
- high/critical dependency audit for the tool's own release hygiene
- fixture scan
- SARIF validation
- fixture artifact validation
- JSON Schema export verification

## Near-Term Production Work

- Add SARIF upload examples for adopters.
- Add MCP and tool schema parsing beyond config files.
- Continue expanding runtime configuration inventory across more agent frameworks.
- Continue expanding graph edges between context sources, capabilities, data classes, and side effects while keeping heuristic-only paths out of prioritized attack paths.
- Add attack-path regression fixtures for common production AI architectures.
- Add suppression and waiver workflow with expiry.
- Calibrate confidence levels across larger true-positive and false-positive fixture sets.
- Add multi-fixture regression tests for true positives and false positives.
- Add benchmarking against known vulnerable agent patterns.
