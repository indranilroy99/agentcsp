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
- local MCP implementation presence checks for secret-backed agent-callable servers
- tool-name collision metadata for authority ambiguity and shadowing
- tool-schema integrity signals for open-world privileged arguments and read-only hint conflicts
- tool-schema content-input signals for prompt-like text sent to external destinations
- tool-schema path-to-external data-flow signals for exfiltration risk
- instruction-file context bridge signals for untrusted inputs routed into tool or memory authority
- Cursor project-rule metadata for always-applied broad workspace rules without emitting rule descriptions, globs, or body text
- runtime-to-MCP reference signals for approval bypass into secret-backed MCP servers
- Claude-style runtime permission allowlists normalized into redacted auto-approved privileged tool signals
- auto-approved destructive MCP tool refs correlated to credential-backed runtime servers
- runtime permission allowlists correlated to exact package scripts and release authority
- workflow-to-agent-script signals for unattended automation with secrets and write authority
- prompt-template variables and redacted context signals for untrusted-input bridges
- exact callable-reference signals for prompts, memory, RAG, instructions, and skills that name discovered privileged tools or MCP servers
- prompt-template memory persistence signals for cross-session contamination
- memory replay signals for persisted context that explicitly names privileged tools
- RAG and memory data-egress signals for sensitive context routed toward external destinations
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
- local MCP implementation path missing from scan plus credential exposure and side effects
- package-runner MCP server plus unpinned package version plus credential exposure
- runtime allowlist plus secret-backed MCP server plus approval bypass
- auto-approved destructive MCP tool plus credential-backed server
- auto-approved privileged runtime permissions plus credential key exposure
- auto-approved runtime package script plus release or deploy authority
- external write tool plus prompt-like content input and URL destination
- workflow automation plus agent package script plus secrets and write authority
- instruction file plus untrusted context reference plus tool and memory bridge
- always-applied broad Cursor project rule plus untrusted-to-privileged context bridge
- tool-name collision plus different authority signatures and a privileged peer
- skill consumes retrieved/tool/memory context plus external publication
- prompt template with user/customer/context variables plus explicit privileged tool reference
- persisted memory with instruction-like content plus explicit privileged tool reference
- prompt template with user/customer/context variables plus memory persistence directives
- prompt template with user/customer/context variables plus tool or external directives
- runtime config with unsandboxed execution plus no approval gate
- runtime config with network access plus secret env keys plus privileged tools
- pull request workflow plus write permissions plus secrets
- untrusted RAG source plus privileged tool path
- memory write plus untrusted source provenance
- RAG or memory content with instruction-like text plus tool/external directives
- retrieved content plus sensitive context reference plus external data-egress directive
- generated transcripts or cached tool output with instruction-like tool/external directives
- local path input plus URL-like destination plus external write capability
- open-world tool schema plus external, filesystem, credential, or execution authority
- read-only tool hint plus destructive or external write behavior
- scheduled or externally dispatched automation plus secrets and write authority
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
