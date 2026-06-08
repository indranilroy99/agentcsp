# Thread Handoff

Use this file to continue the AgentCSP work in a new Codex project chat.

## How to Resume

In the new `agentcsp` project chat, send:

```text
Read AGENTS.md, README.md, and docs/thread-handoff.md. Then continue building AgentCSP from the roadmap.
```

## Conversation Summary

The user asked for a world-class open-source AI security idea after scanning the market and cybersecurity community.

The selected idea became **AgentCSP**, positioned as:

**Context Security Policy for AI Agents**

Enterprise one-liner:

**AgentCSP is an open-source control plane for discovering, testing, and enforcing security policy across AI agents, tools, skills, MCP servers, RAG, memory, and runtime actions.**

## Strategic Direction

AgentCSP should not be just another prompt injection scanner. Existing tools already cover pieces of the problem, including red-team frameworks, vulnerability scanners, guardrail libraries, eval frameworks, and MCP scanners.

AgentCSP should focus on the gap:

- agent attack surface management
- context provenance
- authority and permission mapping
- runtime policy enforcement
- red-team validation
- blast-radius simulation
- audit-ready evidence

The central product insight:

**If the agent can consume it as context, it can be an injection surface. If the agent can call it as a capability, it is part of the blast radius.**

## Required Scope

AgentCSP must scan everything available to an AI agent:

- skill files such as `SKILL.md`
- skill scripts, assets, and references
- plugin manifests and marketplace metadata
- MCP server configs, tool descriptions, schemas, and auth requirements
- agent instruction files such as `AGENTS.md`, custom rules, and prompts
- runtime config such as sandbox mode, approvals, network access, env exposure
- filesystem, shell, browser, GitHub, Slack, email, database, and API tools
- secrets paths, `.env` files, token references, and auth material
- RAG sources, indexes, embeddings, and retrieval policies
- memory stores, long-term memories, summaries, logs, transcripts, and cached outputs
- automations, scheduled jobs, CI/CD workflows, webhooks, and background agents
- generated state that can later be consumed by the agent

## Planned Modules

1. Agent Surface Scanner
2. MCP SBOM and Trust Registry
3. Policy Engine
4. AI Red-Team Rule Exchange
5. Secure RAG and Memory Lab
6. AI Bug Report Verifier for OSS Maintainers
7. Agent Blast-Radius Simulator
8. Evidence Dashboard

## Key Product Concept

The core data structure should be a provenance and authority graph.

Example:

```text
untrusted_webpage -> agent_context -> tool_call:shell -> reads:.env -> outbound_request
```

This graph should drive:

- findings
- policy decisions
- red-team scenario generation
- blast-radius analysis
- evidence records

## Naming Decision

Project name: **AgentCSP**

Repo/folder name: `agentcsp`

Tagline: **Context Security Policy for AI Agents**

Avoid names that sounded generic, crowded, or less enterprise-ready, including `TaintGuard`, `GuardPlane`, `TrustGraph`, `AgentGate`, and `ContextGate`.

## Current Project Location

```text
/Users/indranil.roy/Documents/Codex/projects/agentcsp
```

The folder has been added to the Codex app Projects sidebar as an existing folder.

## Current Files

- `README.md`
- `AGENTS.md`
- `docs/product-brief.md`
- `docs/architecture.md`
- `docs/roadmap.md`
- `docs/context.md`
- `docs/thread-handoff.md`
- `.gitignore`

The repo is initialized locally on branch `main`, with no remote configured yet.

## MVP Scaffold Added

The first implementation pass is a TypeScript local-first CLI scaffold:

- pnpm workspace
- `packages/core` for schemas, scanner, manifest building, rule engine, policy loading, risk scoring, and reports
- `packages/cli` for `agentcsp scan`
- Zod schemas with JSON Schema exports in `schemas/`
- constrained YAML rules in `rules/core`
- generic vulnerable fixture in `examples/vulnerable-agent`
- Vitest coverage for scanner safety, rule matching, report generation, and CLI option validation

The README has been rewritten for GitHub with professional positioning, quick start, scanner safety guarantees, CLI usage, repo layout, manifest/rule/policy sections, roadmap, and Apache 2.0 license notice.

Verified locally:

- `pnpm test`
- `pnpm build`
- `pnpm lint`
- `pnpm agentcsp scan examples/vulnerable-agent --out .agentcsp --quiet`

## Production-Hardening Pass

The next pass added:

- SARIF output through `--format sarif`
- GitHub Actions CI for install, TypeScript check, tests, build, audit, fixture scan, and SARIF validation
- high-signal correlated rules for network-to-shell package scripts, secret-backed MCP authority, PR workflow write permissions with secrets, release/publish authority, and unknown-provenance RAG sources
- scanner metadata for PR workflow triggers, write permissions, command signals, network-to-shell behavior, and publish/release authority
- severity tuning so generic findings do not automatically escalate to critical
- platform direction docs in `docs/platform.md`
- production hardening docs in `docs/production-hardening.md`

## Graph and Attack-Path Pass

The next iteration added:

- manifest `relationships`
- manifest `attack_paths`
- graph builder for context-to-capability and secret-to-capability paths
- static attack path section in Markdown reports
- blast-radius counts for relationships, attack paths, and critical attack paths
- graph regression tests

## Suppression and Waiver Pass

The next iteration added:

- `agentcsp.yaml` suppressions with `id`, `reason`, `owner`, `expires_at`, and match fields
- finding-level suppression metadata with active/expired status
- active suppressions excluded from `--fail-on` gates
- expired suppressions retained as active risk
- SARIF external suppression metadata
- Markdown report sections for active and suppressed findings
- blast-radius counts for active and expired suppressions
- CLI summary of suppressed findings
- `--fail-on critical` support
- suppression regression tests

## MCP and Tool Schema Authority Pass

The current iteration adds:

- parsing of individual JSON/YAML tool schemas from tool definition files
- tool metadata for schema properties, required properties, read-only hints, idempotency hints, and open-world schemas
- authority classification for external writes, database writes, destructive actions, credential-like inputs, filesystem paths, URL inputs, browser control, memory access, and shell execution
- high-signal rules for external writes with credential-like inputs and destructive filesystem tool schemas
- fixture coverage for risky and read-only tools

## Source Tool Registration Pass

The current iteration adds:

- bounded TypeScript/JavaScript source extraction for common MCP SDK `server.tool(...)` and `server.registerTool(...)` registrations
- bounded Python/FastMCP source extraction for common `@mcp.tool(...)` decorator registrations
- bounded Python agent-framework extraction for LangChain/LangGraph `@tool(...)`, `StructuredTool.from_function(...)`, OpenAI Agents `@function_tool`, and CrewAI-style `@tool(...)` registrations
- bounded JavaScript/TypeScript agent-framework extraction for AI SDK `tool(...)` and LangChain `new DynamicStructuredTool(...)` registrations
- local Python Pydantic/BaseModel request-model field extraction without emitting model class names, `Field(...)` bodies, docstrings, or handler source
- bounded JavaScript/TypeScript inline and locally referenced Zod field-map extraction with `.optional()` posture and no schema variable name, raw schema, schema description, or handler source emission
- normalization of source-defined MCP and agent-framework tools into the same `tool` manifest objects used by JSON/YAML tool schemas
- redacted source metadata for framework/registration kind, argument count, schema style, schema field names, required/optional posture, read-only/idempotency hints when available, and source/handler redaction posture
- vulnerable fixture coverage for source-defined MCP, LangChain, and AI SDK tools that combine external writes, PII/customer data, credential-like inputs, open-world arguments, Python signature/Pydantic extraction, Zod field extraction, and destructive filesystem authority
- safe fixture coverage for strict read-only source-defined MCP, LangChain, and AI SDK tools that produce no high or critical findings
- graph hardening so the bounded Static Blast-Radius Summary preserves coverage across runtime approval bypass, memory replay, generated-state replay, direct egress, mutable database, multi-agent, eval, inbound-trigger, and disabled-safety categories when new source-defined tool findings increase candidate volume
- scanner, rule, fixture verifier, and docs coverage proving source handler bodies and raw source descriptions stay out of evidence

## Runtime Posture Pass

The current iteration adds:

- parsing of common JSON, YAML, and TOML runtime config files in `.codex`, `.agents`, and `.cursor`
- runtime metadata for sandbox mode, approval policy, network access, privileged tool allowlists, and env key names
- rules for unsandboxed runtime with approval bypass and networked privileged tools with secret env exposure
- graph/report treatment of risky runtime config as agent authority
- fixture coverage for a risky Codex-style runtime config

## Finding Confidence and False-Positive Pass

The current iteration adds:

- finding-level `confidence` and `confidence_rationale` fields
- Markdown and SARIF export of confidence signals
- severity-plus-confidence sorting for findings
- a safe read-only fixture used as a false-positive regression target
- tests that require very-high-confidence findings on the vulnerable fixture and no high/critical findings on the safe fixture

## Advisory Policy Control Pass

The current iteration adds:

- application of `agentcsp.yaml` `recommended_controls` to matching findings
- finding-level `policy_control` metadata with previous control, reason, match fields, and application time
- Markdown and SARIF export of policy-control metadata
- regression coverage showing policy controls update recommendations without suppressing evidence

## Remote MCP Trust and Auth Pass

The current iteration adds:

- remote MCP server parsing for `url`, `endpoint`, `transport`, and headers
- redacted remote metadata with host/scheme/header names and secret reference key names only
- third-party trust classification for external remote MCP servers
- a high-signal rule for credential-backed third-party remote MCP access
- fixture and test coverage proving raw URL paths and token placeholders are not emitted

## RAG and Memory Content Signal Pass

The current iteration adds:

- file-level redacted content-signal analysis for RAG and memory surfaces
- metadata for instruction-like content, instruction override, tool directives, memory-write directives, external directives, secret references, and signal counts
- high-signal rules for retrieval poisoning and cross-session memory contamination
- fixture and regression coverage proving raw poisoning text is not emitted

## Automation Authority Pass

The current iteration adds:

- automation surfaces derived from GitHub workflow triggers such as `schedule`, `workflow_dispatch`, `repository_dispatch`, `workflow_run`, and `workflow_call`
- automation metadata for scheduled/manual/external dispatch, write permissions, and secrets context
- a high-signal rule for secret-backed automation with write authority
- fixture and test coverage for scheduled/manual/webhook-style agent maintenance workflows

## Production Triage Summary Pass

The current iteration adds:

- manifest-level `triage_summary` with total, active, suppressed, and expired-suppression counts
- active finding rollups by severity, confidence, surface type, category, and recommended control
- top active rules and top active risks with stable finding/object IDs, paths, risk scores, and controls
- Markdown Triage Summary rendered near the top of the report
- SARIF run properties for `agentcsp_triage_summary` and `agentcsp_static_blast_radius`
- regression coverage for vulnerable and safe fixtures

## Confidence-Aware CI Gate Pass

The current iteration adds:

- `--fail-on-confidence very_high|high|medium|low` for precision-tuned CI gates
- scan config `fail_on_confidence`
- severity-only `--fail-on` behavior remains backward compatible
- active suppressions remain excluded from fail gates
- regression coverage for severity-only, confidence-aware, and suppressed finding gates
- lint script updated to type-check package projects directly under TypeScript 5.9

## Baseline Comparison Pass

The current iteration adds:

- `--baseline <path>` for comparing current findings against previous `findings.json` or `agent-manifest.json`
- `--fail-on-new` for failing CI only on newly introduced findings that meet severity/confidence thresholds
- finding-level `baseline_status` for current findings
- manifest-level `baseline_comparison` with new, existing, and resolved counts and stable IDs
- Markdown Baseline Comparison section
- SARIF result `baselineState` and run-level `agentcsp_baseline_comparison`
- regression coverage for manifest baselines, findings baselines, resolved findings, and new-only fail gates

## Scan Coverage Pass

The current iteration adds:

- manifest-level `scan_coverage` for deterministic scan-scope auditing
- coverage counts for directories visited, files seen/indexed, oversized files, ignore skips, hidden/log directory skips, diagnostic severity counts, max-file limits, and max-file-limit exhaustion
- Markdown Scan Coverage section
- SARIF run-level `agentcsp_scan_coverage`
- CLI coverage summary in non-quiet output
- walker and report regression coverage
- note: default excluded directories were already applied through `IgnoreMatcher`; this pass makes scan scope visible rather than changing default ignore semantics

## Scan Diagnostics Pass

The current iteration adds:

- manifest-level `diagnostics` for redacted scan health warnings
- parser diagnostics for malformed MCP configs, package manifests, GitHub workflows, runtime configs, and tool definition files
- policy diagnostics for malformed `agentcsp.yaml`, schema-invalid policy files, and explicitly supplied missing `--config` paths
- malformed or invalid policy scans continue with empty advisory policy so manifest, findings, Markdown, and SARIF are still emitted
- built-in rules always run before project-local `rules/` entries, preventing a scanned repo's generic `rules/` folder from replacing AgentCSP detections
- package builds copy built-in YAML rules into `packages/core/dist/builtin-rules`, and `@agentcsp/core` package files include the compiled distribution
- core build uses forced TypeScript project emit before copying rule assets so stale `dist` state cannot omit compiled modules
- `pnpm verify:packages` checks compiled package modules, package `files`, and built-in rule count parity between source and packaged artifacts
- `pnpm verify:schemas` checks exported JSON Schema files against the current Zod source schemas without rewriting them
- `pnpm verify:fixtures` validates generated fixture manifests/findings against runtime schemas, checks SARIF structure, enforces vulnerable/safe fixture signal expectations, and searches output for redaction regressions
- project-local malformed, schema-invalid, or duplicate custom rules are skipped with redacted diagnostics
- parse-error metadata on affected fallback surfaces
- Markdown Scan Diagnostics section
- SARIF run-level `agentcsp_diagnostics`
- CLI diagnostics count in non-quiet output, including warning/error breakdown when coverage is available
- `scan_coverage` diagnostic counters for CI and dashboard consumers: `diagnostics_total`, `diagnostics_errors`, `diagnostics_warnings`, and `diagnostics_info`
- regression coverage proving raw malformed content and secret-like values are not emitted

## Generated-State Replay Pass

The current iteration adds:

- redacted generated-state metadata for RAG/memory/log-derived surfaces
- metadata for generated state kinds, transcript-like content, tool-output-like content, and cached-output-like content
- rule `AGENTCSP-GENSTATE-001` for generated state that can replay instruction-like tool/external directives
- vulnerable log fixture with replay-risk transcript content, still excluded by default
- regression coverage proving the finding appears only with `include_logs` and raw transcript text is not emitted

## Evidence-Led Attack Path Pass

The current iteration adds:

- bounded, sorted high-risk capability selection for static graph construction
- context-to-capability influence edges only when normalized context evidence shows instruction-like content, tool directives, external directives, memory-write directives, generated-state replay, or explicit instruction/skill authority
- no heuristic-only RAG, memory, or log directory markers as prioritized influence sources
- negation-aware action classification so text like "should not publish or call external services" is not treated as granted authority
- attack-path reasons that name the normalized context signal and target authority while keeping raw context redacted
- regression coverage for file-specific RAG-to-tool paths and generated-state replay paths when logs are explicitly included

## Tool Schema Integrity Pass

The current iteration adds:

- normalized tool metadata for `open_world_authority` and `read_only_hint_conflict`
- side-effect classification for tools whose read-only hints conflict with destructive, external-write, execution, or state-changing authority
- rule `AGENTCSP-TOOL-005` for privileged open-world tool schemas
- rule `AGENTCSP-TOOL-006` for read-only hint conflicts
- vulnerable fixture tools for unbounded external webhook publishing and a destructive cleanup tool mislabeled read-only
- scanner and rule regression coverage proving the safe read-only fixture remains clean

## MCP Package-Runner Authority Pass

The current iteration adds:

- redacted MCP package-runner metadata for launchers such as `npx`, `uvx`, `pnpm dlx`, `yarn dlx`, `npm exec`, `bunx`, and `pipx run`
- package name and version-pinning signals without emitting raw runner arguments or credential values
- third-party trust and external-reach classification for package-runner MCP servers
- rule `AGENTCSP-MCP-004` for unpinned package-runner MCP servers with credential-backed authority
- vulnerable fixture coverage for an unpinned credential-backed MCP package launcher
- regression coverage proving raw package-runner args and token placeholders are not emitted

## Tool Shadowing Pass

The current iteration adds:

- deterministic post-scan tool name collision annotation
- normalized collision metadata for name, count, paths, trust levels, authority mismatch, and privileged peers
- rule `AGENTCSP-TOOL-007` for colliding tool names with different authority signatures
- vulnerable fixture coverage for a neutral tool name that resolves to both a read-only definition and an external credential-backed definition
- scanner and rule regression coverage proving raw shadow-tool descriptions are not emitted

## Prompt Template Bridge Pass

The current iteration adds:

- prompt template discovery under prompt/template paths and prompt-specific filenames
- redacted prompt metadata for template variable names, variable counts, untrusted template variables, and context/tool/external directive signals
- untrusted-to-privileged marking when prompt templates bridge untrusted variables into tool, external, memory, or secret-sensitive directives
- rule `AGENTCSP-PROMPT-001` for prompt templates that combine untrusted variables with tool and external directives
- vulnerable fixture coverage for a customer-note prompt template routed to a publishing tool
- regression coverage proving raw prompt template text is not emitted

## Skill Data-Flow Bridge Pass

The current iteration adds:

- redacted skill metadata for retrieved context input, tool output input, memory input, prompt input, context input sources, external output, and local write output
- context-to-external-output bridge marking for skills that combine agent context inputs with external publication
- rule `AGENTCSP-SKILL-001` for skills that route retrieved/tool/memory/prompt context into external side effects
- fixture coverage using the existing external publisher skill
- scanner and rule regression coverage proving skill text remains redacted

## Tool Path Exfiltration Pass

The current iteration adds:

- rule `AGENTCSP-TOOL-008` for parsed tool schemas that accept local path-like input, a URL-like destination, and external-write authority
- regression coverage binding the rule to the vulnerable `customer_record` tool
- scanner assertions proving the tool carries parsed path, URL, external-write, and credential-like authority metadata
- documentation updates for local-path-to-external data-flow detection as a high-signal AgentCSP rule pattern

## Instruction Context Bridge Pass

The current iteration adds:

- redacted instruction content signals for untrusted context references, tool directives, memory-write directives, external directives, and context bridges
- negation-aware context-signal matching so safety policy text such as "should not call external services" is not treated as granted authority
- rule `AGENTCSP-INSTRUCTION-001` for instruction files that route untrusted context into both tool and memory authority
- confidence rationale credit for redacted content-signal analysis
- scanner and rule regression coverage proving vulnerable instructions are flagged while the safe fixture remains clean

## Runtime MCP Reference Pass

The current iteration adds:

- post-scan runtime annotation that correlates allowed MCP runtime entries such as `mcp:<server>` with discovered MCP server objects
- static graph `calls` relationships from runtime configs to referenced MCP servers
- redacted runtime metadata for referenced MCP servers, privileged MCP references, secret-backed MCP references, and approvalless MCP bridge flags
- rule `AGENTCSP-RUNTIME-003` for runtime configs that allow secret-backed MCP servers while approval is bypassed
- regression coverage proving the vulnerable Codex-style runtime points to the secret-backed `filesystem-admin` MCP server
- docs updates for runtime-to-MCP reference detection as a concrete blast-radius signal

## Agent Automation Script Pass

The current iteration adds:

- redacted workflow run-command signals for package-manager agent script execution
- post-scan workflow annotation that correlates CI/CD and automation surfaces to discovered `package-script:*` tool objects
- static graph `triggers` relationships from workflows to referenced package scripts
- rule `AGENTCSP-AUTOMATION-002` for unattended workflows that run agent package scripts with secrets and write authority
- regression coverage proving the vulnerable workflow references `package-script:agent:run` while the safe fixture remains clean

## Prompt Memory Bridge Pass

The current iteration adds:

- prompt-template bridge metadata for untrusted template variables flowing toward tool, memory, external, or secret-sensitive directives
- vulnerable prompt fixture for untrusted customer-note persistence into long-term memory
- rule `AGENTCSP-PROMPT-002` for prompt templates that persist untrusted template input into memory
- scanner and rule regression coverage proving raw prompt text stays redacted while the safe fixture remains clean

## MCP Local Implementation Visibility Pass

The current iteration adds:

- project-local MCP implementation path inventory for launchers such as `node tools/server.js`, while keeping raw command arguments and secret placeholders redacted
- metadata for found and missing local MCP implementation paths, including `opaque_local_mcp_implementation`
- credential-like handling for webhook environment references used inside MCP configs
- rule `AGENTCSP-MCP-005` for secret-backed MCP servers whose local implementation file was missing from the scan
- scanner and rule regression coverage proving the vulnerable fixture surfaces opaque MCP authority without emitting raw credential placeholders

## RAG Data-Egress Directive Pass

The current iteration adds:

- redacted context signals for sensitive/internal context references and external data-egress directives
- `context_bridge_data_egress` metadata for untrusted or retrieved content that tries to move sensitive context toward an external destination
- contextual data-class enrichment so affected RAG and memory objects can carry `confidential` without emitting raw content
- rule `AGENTCSP-RAG-003` for retrievable content that combines sensitive-context references, tool directives, and external-egress instructions
- scanner and rule regression coverage proving the vulnerable RAG fixture is flagged while the raw poisoning text remains redacted

## Source-Anchored Blast-Radius Pass

The current iteration adds:

- attack paths that can be anchored on source-side context findings, not only target capability findings
- direct data-egress target filtering for RAG data-egress paths so the bounded blast-radius list favors tools and MCP servers that can actually move data externally
- attack-path prioritization for source-anchored RAG data-egress and generated-state replay paths
- graph regression coverage proving `rag/customer-note.md` can route sensitive context to external agent authority while keeping raw retrieval text redacted
- regression coverage preserving generated-state replay visibility when logs are explicitly included

## Explicit Callable Reference Pass

The current iteration adds:

- post-scan annotation for exact references from instructions, prompts, skills, RAG, and memory content to discovered tool and MCP names
- privileged callable metadata such as `referenced_privileged_tools`, `explicit_callable_reference`, and `privileged_callable_reference`
- graph prioritization so exact prompt-to-tool references are preserved ahead of generic tool-directive fanout
- rule `AGENTCSP-PROMPT-003` for prompt templates that accept untrusted variables and explicitly reference a privileged discovered tool
- scanner, rule, and graph regression coverage proving `prompts/support-ticket.prompt.md` references `publish_summary` without emitting raw prompt text

## Prompt Source-Anchored Blast-Radius Pass

The current iteration adds:

- source-anchored attack-path eligibility for project prompt templates when the finding proves untrusted-to-privileged flow
- source-finding preference for `AGENTCSP-PROMPT-003` when the target is the exact referenced tool
- attack-path prioritization for prompt paths that route untrusted template input to specific privileged tools
- graph regression coverage proving `support-ticket.prompt.md` can route untrusted input to `publish_summary` while keeping raw prompt text redacted

## Memory Replay Tool Reference Pass

The current iteration adds:

- rule `AGENTCSP-MEMORY-003` for persisted memory that contains instruction-like content and explicitly references a discovered privileged tool
- source-finding preference for `AGENTCSP-MEMORY-003` when the target is the exact referenced tool
- attack-path prioritization for memory replay paths that can steer future runs into privileged tools
- graph regression coverage proving `release-notes.md` can replay memory into `publish_summary` while keeping raw memory text redacted

## Runtime Broad Web Access Pass

The current iteration adds:

- redacted runtime metadata for auto-approved network tools and normalized scope categories such as `wildcard_domain`
- broad-scope flags for wildcard, all-tools, and unscoped web permissions without emitting raw domains, URLs, or runtime arguments
- rule `AGENTCSP-RUNTIME-007` for runtime configs that auto-approve broad web access while exposing credential key names and bypassing per-call approval
- scanner and rule regression coverage proving `.claude/settings.json` is flagged without leaking the raw web-permission allowlist entry

## Tool PII External Write Pass

The current iteration adds:

- tool-schema metadata for PII-like input, customer-data input, and accepted data classes derived from normalized tool names and schema fields
- data-class enrichment for agent-callable tools that accept customer identifiers while preserving redacted descriptions and schema output boundaries
- rule `AGENTCSP-TOOL-010` for parsed tool schemas that can send PII-like input to URL-like external destinations
- scanner and rule regression coverage proving customer-data egress tools are flagged while read-only local tools remain quiet

## Sensitive Blast-Radius Summary Pass

The current iteration adds:

- static blast-radius counts for sensitive-data, PII, and credential external reach
- static blast-radius counts for sensitive-data, PII, and credential attack paths
- Markdown and SARIF property coverage for the new summary fields
- report regression coverage proving the vulnerable fixture exposes sensitive-data blast radius while the safe fixture remains zero

## Customer-Data Attack Path Pass

The current iteration adds:

- graph titles that distinguish customer-data routes into PII-capable external tools from generic sensitive-context egress
- target capability context appended to source-anchored attack paths when the target has a matching PII/path/content egress tool finding
- attack-path prioritization for external PII data routes
- graph regression coverage proving `rag/customer-note.md` can route customer data to `post_customer_update` without leaking raw retrieval text

## Diagnostics CI Gate Pass

The current iteration adds:

- CLI flag `--fail-on-diagnostics` for teams that want malformed security-relevant config files to fail CI
- opt-in exit-code behavior that remains separate from severity and confidence finding gates
- CLI regression coverage proving diagnostics do not fail by default but do fail when requested

## Cursor Rule Boundary Pass

The current iteration adds:

- first-class redacted metadata for `.cursor/rules/` files, including frontmatter parse state, always-apply mode, broad scope categories, and body redaction
- redacted diagnostics for malformed Cursor rule frontmatter
- fixture coverage for an always-applied Cursor `.mdc` rule that routes customer escalation context into memory without emitting the rule description, globs, or body text
- rule `AGENTCSP-CURSOR-001` for broad always-applied Cursor project rules that bridge untrusted context into privileged agent behavior
- scanner and rule regression coverage proving the Cursor rule is flagged as high-confidence while the safe fixture remains quiet

## RAG Vector Store Boundary Pass

The current iteration adds:

- first-class redacted metadata for RAG/vector-store connector configs, including provider, remote destination categories, write/sync authority, untrusted-source ingestion, sensitive collection signals, namespace redaction, and credential key references
- redacted diagnostics for malformed RAG connector configuration
- vulnerable fixture coverage for a remote credential-backed vector store that syncs customer/support sources without emitting raw endpoints, collection names, namespaces, source labels, or secret placeholders
- rule `AGENTCSP-RAG-004` for remote vector stores that combine credentials, write authority, and untrusted ingestion
- scanner, rule, fixture verifier, and redaction coverage proving the vector-store finding is high-confidence while the safe fixture remains quiet

## AI Telemetry Export Pass

The current iteration adds:

- first-class redacted metadata for AI telemetry and trace-export configs, including provider, remote destination categories, prompt/completion/tool-output/retrieval/memory capture, redaction posture, retention, and credential key references
- redacted diagnostics for malformed AI telemetry configuration
- vulnerable fixture coverage for a remote LangSmith-style trace exporter that captures sensitive agent context with redaction disabled without emitting raw endpoints, project names, or secret placeholders
- rule `AGENTCSP-RUNTIME-008` for remote telemetry export that combines sensitive capture, disabled redaction, and credential references
- scanner, rule, fixture verifier, and redaction coverage proving the telemetry finding is high-confidence while the safe fixture remains quiet

## Tool Description Injection Pass

The current iteration adds:

- redacted model-visible tool-description metadata for instruction override, untrusted context, tool, memory, external, secret, sensitive-context, and data-egress signals
- vulnerable fixture coverage for a poisoned external webhook tool description without emitting the raw injected description
- rule `AGENTCSP-TOOL-011` for model-visible tool descriptions that combine prompt-injection signals with external write and side-effect authority
- scanner, rule, fixture verifier, and redaction coverage proving the finding is high-confidence while the safe fixture remains quiet

## MCP Plaintext Transport Pass

The current iteration adds:

- remote MCP transport posture metadata for plaintext versus encrypted remote endpoints without emitting raw MCP URLs
- vulnerable fixture coverage for a credential-backed remote MCP server over plaintext HTTP
- rule `AGENTCSP-MCP-006` for remote MCP servers that combine plaintext transport with auth headers or credential references
- scanner, rule, fixture verifier, and redaction coverage proving the finding is high-confidence while the safe fixture remains quiet

## AI Model Endpoint Pass

The current iteration adds:

- first-class redacted metadata for AI model provider, gateway, router, proxy, and inference configs, including provider, remote destination categories, plaintext/encrypted transport, prompt/tool-output/retrieval/memory context, PII context, and credential key references
- vulnerable fixture coverage for an OpenAI-compatible model gateway over plaintext HTTP with raw request logging and disabled redaction without emitting raw endpoint URLs, model names, request payloads, or secret placeholders
- rule `AGENTCSP-RUNTIME-009` for credential-backed model endpoints that send sensitive agent context over plaintext transport
- rule `AGENTCSP-RUNTIME-086` for remote or custom model gateways that log unredacted prompts, tool outputs, retrieval context, memory, and PII from untrusted agent context without approval
- scanner, rule, fixture verifier, and redaction coverage proving the finding is high-confidence while the safe fixture remains quiet

## Prompt Role Boundary Pass

The current iteration adds:

- redacted prompt-template metadata for system/developer role segments, privileged role names, and untrusted variables placed inside those roles
- vulnerable fixture coverage using the existing support-ticket prompt so customer and ticket variables enter a `System:` role before tool/external directives
- rule `AGENTCSP-PROMPT-004` for untrusted template variables injected into system or developer prompt roles
- scanner, rule, fixture verifier, and redaction coverage proving the finding is high-confidence while the safe fixture remains quiet

## Database Connector Authority Pass

The current iteration adds:

- first-class redacted metadata for database connector configs, including provider, remote destination categories, read/write/delete/query authority, natural-language query input, sensitive/PII scope, table-name redaction, and credential key references
- database connection URL placeholders treated as credential-bearing references in database connector fields without emitting connection strings or hostnames
- vulnerable fixture coverage for a remote Postgres-style support database that allows agent-driven SQL writes over sensitive customer/support data
- rule `AGENTCSP-RUNTIME-010` for credential-backed database connectors that combine write/query authority, untrusted query input, and sensitive data scope
- rule `AGENTCSP-RUNTIME-083` for remote database connectors where untrusted natural-language SQL can execute write and delete operations against sensitive PII-bearing records without approval
- static graph regression coverage proving retrievable untrusted context can influence the database authority path while raw retrieval text, hostnames, table names, usernames, and secret placeholders stay redacted

## Browser Session Authority Pass

The current iteration adds:

- first-class redacted metadata for browser-agent session configs, including provider, persistent profile state, cookie/session storage, authenticated-session posture, remote debugging, broad origins, untrusted navigation sources, click/form/upload authority, path redaction, and credential key references
- vulnerable fixture coverage for a Playwright-style authenticated support browser profile driven by customer/retrieval context across broad origins
- rule `AGENTCSP-RUNTIME-011` for authenticated browser sessions that combine broad origins, untrusted navigation, click/form authority, and credential exposure
- static graph regression coverage proving retrievable untrusted context can influence authenticated browser-session authority while raw cookie files, profile paths, origins, endpoints, and secret placeholders stay redacted

## SaaS Connector Authority Pass

The current iteration adds:

- first-class redacted metadata for SaaS/API connector configs, including provider, destination categories, normalized OAuth/API scope categories, broad/admin scope posture, read/write authority, untrusted input, sensitive/PII scope, approval posture, and credential key references
- vulnerable fixture coverage for a Slack-style customer-success connector with broad write scopes, untrusted customer/retrieval inputs, and no approval gate
- safe fixture coverage for an approval-gated read-only Slack-style connector using approved source context and no external write scope
- rule `AGENTCSP-RUNTIME-012` for SaaS connectors that combine broad credential-backed external write authority, untrusted input, and missing approval
- rule `AGENTCSP-RUNTIME-110` for messaging SaaS connectors that combine credential-backed read/write scopes, untrusted customer or retrieval context, sensitive PII-bearing data, external publication authority, and no approval
- scanner, rule, fixture verifier, and redaction coverage proving raw OAuth scopes, webhook URLs, workspace names, channel names, customer-system labels, and secret placeholders stay redacted

## SaaS Recipient Boundary Pass

The current iteration adds:

- first-class redacted metadata for messaging/SaaS recipient posture, including recipient categories, user/model-selected recipients, external/shared destinations, public channel destinations, direct messages, broadcast destinations, attachment upload authority, and recipient allowlist posture
- vulnerable fixture coverage for a Slack connector where untrusted customer and retrieval context can drive credential-backed posts/uploads into model-selected external/shared/public/direct-message/broadcast destinations without a recipient allowlist or approval
- safe fixture coverage for an internal read-only Slack digest connector with approved recipient controls, no write scope, no model-selected recipient, no attachment upload, and required approval
- rule `AGENTCSP-RUNTIME-126` for SaaS recipient-boundary exposure that combines Slack messaging write scope, untrusted context, model/user-selected external recipients, public destination exposure, upload authority, missing recipient allowlist, sensitive PII, credentials, and no approval
- scanner, rule, fixture verifier, and redaction coverage proving raw Slack scopes, channel names, workspace names, recipient selectors, webhook URLs, and token placeholders stay redacted

## Secret Manager Authority Pass

The current iteration adds:

- first-class redacted metadata for Vault, cloud secret manager, key vault, KMS, Kubernetes secret, and credential-broker configs, including provider, destination categories, normalized secret scope categories, read/list/write posture, broad scope, tool injection, untrusted input, sensitive/PII scope, approval posture, and credential key references
- vulnerable fixture coverage for a HashiCorp Vault-style connector that lets customer/retrieval context read and list production support secrets and inject them into tools without approval
- rule `AGENTCSP-RUNTIME-013` for secret-manager connectors that combine read/list scope, broad sensitive secret scope, tool injection, untrusted input, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving raw vault URLs, secret paths, policy names, secret labels, and token placeholders stay redacted

## Workflow Event Input Authority Pass

The current iteration adds:

- redacted metadata for GitHub workflow event payloads that pass issue comments, pull request text, discussion text, or repository-dispatch payloads into agent jobs
- vulnerable fixture coverage for an issue/comment and repository-dispatch workflow that feeds event text into an agent package script with secrets and write permissions
- rule `AGENTCSP-AUTOMATION-003` for untrusted workflow event input reaching privileged agent automation
- scanner, rule, fixture verifier, and redaction coverage proving raw GitHub event expressions and event payload content stay redacted

## Inbound Agent Trigger Authority Pass

The current iteration adds:

- first-class redacted metadata for inbound email, chat, ticket, webhook, and queue triggers that pass external message content into agent execution
- vulnerable fixture coverage for a support inbox trigger that can invoke agent tools, reply externally, write customer state, persist memory, and access browser/database/secret-manager authority with credentials and no approval gate
- rule `AGENTCSP-RUNTIME-014` for inbound untrusted messages that can drive privileged agent tools
- rule `AGENTCSP-RUNTIME-094` for inbound attachments that can reach browser, database, external response, memory, and secret-manager tools without approval
- scanner, rule, fixture verifier, and redaction coverage proving raw mailbox names, webhook URLs, sender addresses, labels, agent names, prompt fields, and token placeholders stay redacted

## Multi-Agent Orchestration Authority Pass

The current iteration adds:

- first-class redacted metadata for CrewAI, AutoGen, LangGraph, Semantic Kernel, swarm-style, and related multi-agent orchestration configs
- vulnerable fixture coverage for a support crew where untrusted intake delegates automatically into a privileged executor with shared memory, browser/database/secret/messaging/filesystem authority, credentials, and no approval gate
- rule `AGENTCSP-RUNTIME-015` for multi-agent delegation that routes untrusted context to privileged agents
- rule `AGENTCSP-RUNTIME-080` for shared-memory bridges where untrusted intake can seed context consumed by privileged executor agents with external, write, filesystem, memory, and secret-manager authority
- scanner, rule, fixture verifier, and redaction coverage proving raw crew names, agent names, role prompts, memory namespaces, graph labels, raw tool lists, and token placeholders stay redacted

## Agent Safety-Control Posture Pass

The current iteration adds:

- first-class redacted metadata for agent safety, guardrail, moderation, validation, sanitization, and redaction configs
- vulnerable fixture coverage for a support agent runtime with disabled prompt-injection filtering, output validation, tool-result sanitization, moderation, PII redaction, and secret redaction while privileged tools, credentials, untrusted input, external writes, and memory writes remain available without approval
- rule `AGENTCSP-RUNTIME-016` for disabled agent safety controls exposing privileged tools to untrusted context
- scanner, rule, fixture verifier, and redaction coverage proving raw policy names, input source names, tool strings, action lists, data-field labels, and token placeholders stay redacted

## Live Eval Harness Authority Pass

The current iteration adds:

- first-class redacted metadata for AI eval, red-team, adversarial scenario, and prompt test harness configs
- vulnerable fixture coverage for a promptfoo-style live production red-team suite that sends adversarial prompts to a production support agent with browser/database/secret/messaging authority, credentials, output retention, and no approval gate
- rule `AGENTCSP-RUNTIME-017` for live eval harnesses that run adversarial prompts against privileged agents
- rule `AGENTCSP-RUNTIME-096` for live production red-team evals that retain sensitive privileged tool outputs and results while external writes, credentials, and no approval are present
- static graph regression coverage proving retrievable untrusted context can influence the live eval harness authority path
- scanner, rule, fixture verifier, and redaction coverage proving raw suite names, scenario names, prompts, target URLs, agent names, tool strings, assertion values, output paths, data-field labels, and token placeholders stay redacted

## Agent Memory Store Posture Pass

The current iteration adds:

- first-class redacted metadata for Redis, Postgres, SQLite, Zep, Mem0, LangGraph-style checkpointer, and related durable agent memory-store configs
- vulnerable fixture coverage for remote long-term memory with untrusted customer, retrieval, and tool-output writes, shared cross-agent retention, secret capture, future-context replay, and no approval gate
- rule `AGENTCSP-MEMORY-004` for remote memory stores that combine untrusted writes, replay into future agent context, credential exposure, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving connection strings, hostnames, store names, namespaces, source labels, replay targets, data-field labels, and token placeholders stay redacted

## Agent Memory Access Boundary Pass

The current iteration adds:

- first-class redacted metadata for public memory access, cross-tenant sharing, disabled access control, and disabled tenant or namespace isolation in durable agent memory-store configs
- vulnerable fixture coverage for a public cross-tenant long-term memory store that accepts untrusted writes, captures secrets, shares memory across agents and tenants, and lacks approval
- safe fixture coverage for local private session memory with RBAC, tenant isolation, explicit disabled captures, no replay, and approval-required writes
- rule `AGENTCSP-MEMORY-005` for shared memory stores that cross tenant boundaries without isolation while untrusted context and secrets can persist
- scanner, rule, fixture verifier, and redaction coverage proving tenant selectors, shared-with labels, namespaces, source labels, connection strings, and token placeholders stay redacted

## Agent Memory Retention Pass

The current iteration adds:

- first-class redacted metadata for durable memory retention and redaction posture, including retention-day categories, long or unbounded retention, and disabled redaction controls
- vulnerable fixture coverage for remote long-term memory that captures prompts, retrieval context, tool outputs, PII, and secrets for long retention while redaction and approval are disabled
- safe fixture coverage for local private session memory with short retention, enabled redaction controls, disabled sensitive capture, and approval-required writes
- rule `AGENTCSP-MEMORY-006` for remote durable memory stores that retain sensitive, PII, or secret-bearing context without redaction or approval
- scanner, rule, fixture verifier, and redaction coverage proving connection strings, hostnames, store names, namespaces, tenant labels, data-field labels, and token placeholders stay redacted

## Semantic Prompt Cache Boundary Pass

The current iteration adds:

- first-class redacted metadata for shared semantic prompt-cache posture, including user-controlled cache-key inputs, broad match thresholds, cross-tenant replay, and tenant-isolation controls
- vulnerable fixture coverage for a Redis-backed shared semantic response cache that accepts untrusted customer, retrieval, and browser context as cache-key material, uses a broad similarity threshold, reuses entries across tenants, captures sensitive context, disables redaction, and does not require approval
- safe fixture coverage for a local exact-match cache with tenant-scoped digest keys, no semantic reuse, no cross-tenant replay, enabled redaction, and approval required
- rule `AGENTCSP-RUNTIME-050` for shared semantic prompt caches that can replay untrusted sensitive context across tenant boundaries
- scanner, rule, fixture verifier, and redaction coverage proving cache URLs, namespaces, cache-key labels, tenant labels, record labels, source labels, and token placeholders stay redacted

## Agent Identity Delegation Pass

The current iteration adds:

- first-class redacted metadata for OAuth, OIDC, service-account, workload-identity, IAM, token-broker, and credential-delegation configs
- vulnerable fixture coverage for Google Workload Identity-style token issuance and service-account impersonation with broad scopes, untrusted subject inputs, token refresh, tool injection, and no approval gate
- rule `AGENTCSP-RUNTIME-018` for identity delegation that combines credential issuance, impersonation, broad scope, untrusted input, credential exposure, and missing approval
- rule `AGENTCSP-RUNTIME-072` for refreshable agent-issued credentials that combine impersonation, broad scope, untrusted subject input, tool injection, credential exposure, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving issuer URLs, token endpoints, service-account IDs, raw scopes, IAM roles, subject labels, tool names, data-field labels, and token placeholders stay redacted

## Agent Extension Loader Pass

The current iteration adds:

- first-class redacted metadata for remote skill, plugin, tool, prompt, MCP, marketplace, registry, catalog, and capability-loader configs
- vulnerable fixture coverage for a remote extension marketplace that auto-installs and auto-updates unpinned, unsigned skills/plugins selected from customer/retrieval/browser context with privileged tool authority and no approval gate
- rule `AGENTCSP-RUNTIME-019` for remote extension loaders that combine auto-install, unpinned references, disabled signature verification, untrusted input, privileged authority, and missing approval
- rule `AGENTCSP-RUNTIME-098` for remote extension loaders that auto-install and auto-update unpinned unsigned skills or plugins with browser, database, filesystem, memory, external-response, and secret-manager authority from untrusted selectors
- scanner, rule, fixture verifier, and redaction coverage proving registry URLs, Git URLs, package names, extension names, version strings, permission strings, selector fields, source labels, data-field labels, and token placeholders stay redacted

## Agent Self-Modification Pass

The current iteration adds:

- first-class redacted metadata for self-modifying agent, policy-writer, prompt-writer, runtime-writer, autofix, codemod, and mutation configs
- vulnerable fixture coverage for untrusted customer/retrieval/browser context that can auto-apply persistent writes to instructions, prompt templates, policy, runtime config, tool definitions, and memory, then reload agent execution without approval
- rule `AGENTCSP-RUNTIME-020` for self-modification configs that combine untrusted input, auto-applied persistent control-plane writes, instruction/policy/tool targets, and missing approval
- rule `AGENTCSP-RUNTIME-077` for self-modification configs that persist policy/runtime/tool rewrites, execute or reload after update, disable rollback, and lack approval
- scanner, rule, fixture verifier, and redaction coverage proving target paths, patch-rule field names, reload commands, source labels, tool names, data-field labels, and token placeholders stay redacted

## Agent Approval-Gate Integrity Pass

The current iteration adds:

- first-class redacted metadata for agent approval, review, human-in-the-loop, model-reviewer, and decision-gate configs
- vulnerable fixture coverage for an LLM-driven approval gate where customer/retrieval/browser context shapes the approval prompt, human review is not required, default behavior approves, and privileged actions auto-execute
- rule `AGENTCSP-RUNTIME-021` for model-mediated approval gates that combine untrusted approval context, default-allow behavior, auto-executed privileged actions, credential exposure, and no required human reviewer
- rule `AGENTCSP-RUNTIME-090` for LLM-driven approval prompts that include raw untrusted customer, retrieval, memory, or tool context before automatically executing database, browser, external response, memory, or secret-manager actions
- scanner, rule, fixture verifier, and redaction coverage proving approval prompts, model names, action strings, source labels, data-field labels, and token placeholders stay redacted

## Agent Context-Composer Role Boundary Pass

The current iteration adds:

- first-class redacted metadata for context-composer, prompt-composer, prompt-assembly, context-router, prompt-router, message-builder, and role-map configs
- vulnerable fixture coverage for customer, retrieval, browser, tool-output, and memory context promoted into system and developer role assembly with disabled sanitization, no delimiter boundary, privileged tools, credentials, and no approval gate
- rule `AGENTCSP-RUNTIME-022` for context composers that combine untrusted sources, privileged role injection, disabled sanitization/delimiting, privileged tool authority, credential exposure, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving role prompts, source labels, tool names, action strings, data-field labels, and token placeholders stay redacted

## Browser Remote-Debugging Session Pass

The current iteration adds:

- rule `AGENTCSP-RUNTIME-023` for authenticated browser-agent sessions that expose remote debugging while reusing cookie, storage-state, or profile references and credential key names
- vulnerable fixture coverage through the existing Playwright browser-session config with persistent profile, storage state, cookie jar, remote debugging, broad origins, untrusted navigation, and no approval gate
- rule, fixture verifier, and redaction coverage proving debugging URLs, cookie/storage paths, profile paths, origin names, and token placeholders stay redacted

## Agent Artifact Export Boundary Pass

The current iteration adds:

- first-class redacted metadata for agent artifact, generated-output, report, screenshot, recording, and run-export configs
- vulnerable fixture coverage for public remote S3-style artifact export that captures prompts, completions, tool outputs, browser artifacts, retrieval context, memory, PII, and secrets with disabled redaction and long retention
- rule `AGENTCSP-RUNTIME-024` for artifact/output export boundaries that combine remote/public destination, sensitive capture, disabled redaction, and credential exposure
- rule `AGENTCSP-RUNTIME-093` for public retained generated-run artifacts that contain prompts, tool outputs, browser artifacts, retrieval context, memory, PII, and secrets without redaction or approval
- scanner, rule, fixture verifier, and redaction coverage proving bucket names, endpoints, data-scope labels, generated outputs, and token placeholders stay redacted

## Agent Webhook Egress Boundary Pass

The current iteration adds:

- first-class redacted metadata for agent webhook, callback, outbound sink, event-sink, response-hook, reply-hook, and notification-sink configs
- vulnerable fixture coverage for model-generated callback delivery that posts prompts, completions, tool outputs, browser context, retrieval context, memory, PII, and secrets to a remote endpoint with disabled redaction, retry queues, credentials, and no approval gate
- rule `AGENTCSP-RUNTIME-025` for webhook/callback egress that combines remote delivery, model-generated or untrusted payloads, sensitive context, disabled redaction, credential exposure, and missing approval
- rule `AGENTCSP-RUNTIME-085` for webhook retry queues that can replay unredacted model, tool-output, retrieval, memory, browser, PII, and secret payloads from untrusted context to credentialed remote endpoints without approval
- scanner, rule, fixture verifier, and redaction coverage proving callback endpoints, payload bodies, source labels, data-field labels, and token placeholders stay redacted

## Agent Container Isolation Boundary Pass

The current iteration adds:

- first-class redacted metadata for agent container, sandbox, Docker, Compose, runner, executor, and runtime isolation configs
- vulnerable fixture coverage for a privileged Docker agent container with Docker socket access, host filesystem root and credential mounts, host network/PID/IPC namespaces, dangerous capabilities, untrusted inputs, credential env, and no approval gate
- safe fixture coverage for a rootless approval-gated container with no Docker socket, host mounts, host namespaces, dangerous capabilities, secret environment references, or untrusted-to-privileged path
- rule `AGENTCSP-RUNTIME-026` for container host-escape boundaries that combine privileged mode, Docker socket, host path mounts, host networking, untrusted input, credential exposure, and missing approval
- rule `AGENTCSP-RUNTIME-107` for privileged root agent containers that expose Docker socket, host filesystem root and credential mounts, host namespaces, dangerous capabilities, shell/filesystem/Docker authority, secret environment exposure, untrusted input, and no approval
- graph-priority tuning that keeps concrete RAG-to-exfiltration and RAG-to-mutable-record paths visible as the runtime surface inventory grows
- scanner, rule, fixture verifier, and redaction coverage proving image names, host paths, Docker socket paths, credential paths, input labels, tool names, and token placeholders stay redacted

## Agent Code Interpreter Runtime Pass

The current iteration adds:

- first-class redacted metadata for agent code interpreter, notebook, Jupyter, Python REPL, kernel, and code-runner configs
- vulnerable fixture coverage for untrusted customer/retrieval/browser context that can execute model-generated code with network access, package installation, shell/filesystem access, credential mounts, output persistence, and no approval gate
- rule `AGENTCSP-RUNTIME-027` for code interpreter runtimes that combine model-driven code execution, untrusted input, network/package-install authority, filesystem access, credential exposure, and missing approval
- rule `AGENTCSP-RUNTIME-081` for code interpreter runtimes where credential mounts, secret environment references, shell access, network egress, package installation, and persisted outputs create a direct exfiltration path from untrusted code execution
- scanner, rule, fixture verifier, and redaction coverage proving kernel values, mounted paths, input labels, output labels, and token placeholders stay redacted

## AI Training Dataset Boundary Pass

The current iteration adds:

- first-class redacted metadata for AI training, fine-tuning, distillation, feedback-training, RLHF, and dataset-export configs
- vulnerable fixture coverage for a model-update dataset pipeline that captures raw prompts, completions, tool outputs, retrieval context, memory, browser context, PII, and secrets from untrusted customer sources, uploads to a managed provider, retains data, and has no approval gate
- rule `AGENTCSP-RUNTIME-028` for training dataset boundaries that combine model-update authority, remote upload, sensitive capture, disabled redaction, untrusted input, credential exposure, and missing approval
- rule `AGENTCSP-RUNTIME-089` for retained raw production traces in fine-tuning pipelines where prompts, completions, tool outputs, retrieval context, memory, browser context, PII, and secrets cross from untrusted sources into durable model-update storage
- scanner, rule, fixture verifier, and redaction coverage proving endpoints, dataset names, record labels, source labels, training records, and token placeholders stay redacted

## LLM Prompt Cache Boundary Pass

The current iteration adds:

- first-class redacted metadata for LLM prompt, response, completion, semantic, and model-cache configs
- vulnerable fixture coverage for a shared remote Redis-style prompt cache that stores raw prompts, completions, tool outputs, retrieval context, memory, browser context, PII, and secrets from untrusted customer sources, then replays cached context into future model calls without approval
- rule `AGENTCSP-RUNTIME-029` for prompt-cache boundaries that combine shared remote storage, sensitive capture, disabled redaction, replay, untrusted input, credential exposure, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving cache URLs, namespaces, keys, values, record labels, source labels, and token placeholders stay redacted

## AI Model Router/Fallback Boundary Pass

The current iteration adds:

- first-class redacted metadata for AI model router, provider-routing, fallback, failover, and model-gateway configs
- vulnerable fixture coverage for a LiteLLM-style router that automatically fails over sensitive prompts, tool outputs, retrieval context, memory, PII, and secrets from untrusted customer sources to third-party model providers with disabled redaction, output recording, credentials, and no approval gate
- rule `AGENTCSP-RUNTIME-030` for model-router boundaries that combine third-party fallback, sensitive context, disabled redaction, untrusted input, credential exposure, and missing approval
- rule `AGENTCSP-RUNTIME-088` for model routers that record unredacted fallback outputs for prompts, tool outputs, retrieval context, memory, PII, and secrets from untrusted context without approval
- scanner, rule, fixture verifier, and redaction coverage proving provider endpoints, model aliases, fallback labels, routing strategy values, source labels, context labels, and token placeholders stay redacted

## AI Embedding/Indexing Boundary Pass

The current iteration adds:

- first-class redacted metadata for AI embedding, indexing, vectorization, document-index, and RAG-index pipelines
- vulnerable fixture coverage for a third-party embedding pipeline that indexes documents, prompts, tool outputs, browser context, retrieval context, memory, PII, and secrets from untrusted customer sources into a vector destination with disabled redaction, raw-chunk retention, credentials, and no approval gate
- rule `AGENTCSP-RUNTIME-031` for embedding boundaries that combine third-party embedding, vector writes, sensitive capture, disabled redaction, untrusted input, credential exposure, and missing approval
- rule `AGENTCSP-RUNTIME-087` for embedding and RAG-index pipelines that retain raw untrusted prompts, documents, tool outputs, retrieval context, memory, browser context, PII, and secrets in remote vector destinations without approval
- scanner, rule, fixture verifier, and redaction coverage proving embedding endpoints, model aliases, vector-store destinations, namespaces, source labels, document chunks, context labels, and token placeholders stay redacted

## Agent Package Manifest Supply-Chain Pass

The current iteration adds:

- first-class redacted metadata for agent-relevant `package.json` manifests with agent, MCP, model, RAG, vector, or browser-automation dependencies
- vulnerable fixture coverage for floating and remote agent dependency specs combined with a credentialed lifecycle script
- rule `AGENTCSP-SUPPLYCHAIN-001` for package manifests that combine risky agent dependency references, install-time execution, external dependency reach, and credential exposure
- rule `AGENTCSP-SUPPLYCHAIN-003` for mutable remote agent dependencies that are bootstrapped by credentialed install-time lifecycle scripts before the agent runtime starts
- scanner, rule, fixture verifier, and redaction coverage proving dependency names, dependency specs, remote package URLs, Git references, lifecycle commands, local script paths, and token placeholders stay redacted

## Agent Deployment Image Provenance Pass

The current iteration adds:

- first-class redacted metadata for agent deployment manifests with image provenance, digest pinning, pull policy, privileged runtime, service-account, host-mount, and credential posture
- vulnerable fixture coverage for a Kubernetes-style support agent deployed from a mutable remote image with pull-always policy, privileged root execution, host network, Docker socket and credential mounts, secret-backed env, and no approval gate
- rule `AGENTCSP-SUPPLYCHAIN-002` for deployment manifests that combine mutable remote agent images, privileged host authority, credential exposure, and missing approval
- rule `AGENTCSP-RUNTIME-084` for deployment manifests where privileged root agent workloads have host networking, Docker socket or host mounts, credential mounts, service-account authority, secret-backed env, and no approval gate
- scanner, rule, fixture verifier, and redaction coverage proving image references, registry paths, service-account names, secret names, host paths, and token placeholders stay redacted

## Cloud Control-Plane Authority Pass

The current iteration adds:

- first-class redacted metadata for cloud, IAM, IaC, Terraform, Kubernetes platform, and control-plane configs with provider, broad/admin scope, IAM, compute, storage, secret, audit-log, auto-remediation, tool-authority, untrusted-input, credential, and approval posture
- vulnerable fixture coverage for an AWS-style support agent that can run cloud/IaC remediation against broad cloud resources with untrusted customer/runbook inputs, cloud credential references, and no approval gate
- rule `AGENTCSP-RUNTIME-032` for cloud control-plane agents that combine broad credentialed write authority, IAM mutation, secret access, compute/storage mutation, untrusted input, and missing approval
- rule `AGENTCSP-RUNTIME-082` for cloud auto-remediation where untrusted runbooks or customer context can drive admin-scoped IAM, secret, compute, storage, delete, audit-log, cloud CLI, or IaC apply authority without approval
- scanner, rule, fixture verifier, and redaction coverage proving account IDs, ARNs, role names, policy/action values, resource identifiers, tool strings, source labels, and token placeholders stay redacted

## MCP Prompt and Resource Context Pass

The current iteration adds:

- first-class redacted metadata for MCP prompts and resources declared in MCP config, including context kind, source field, associated server posture, URI/name redaction, content-signal booleans, and credential key references
- vulnerable fixture coverage for server-supplied MCP prompt/resource context that tries to route untrusted customer context through a secret-backed privileged MCP server
- rule `AGENTCSP-MCP-007` for MCP prompt/resource context that combines untrusted input, tool/external directives, privileged server authority, and credential-backed MCP access
- scanner, rule, fixture verifier, and redaction coverage proving raw MCP prompt text, resource text, prompt names, descriptions, URIs, URLs, and token placeholders stay redacted

## MCP Client-Context Exposure Pass

The current iteration adds:

- first-class redacted metadata for MCP client roots, sampling, and elicitation, including broad root scope categories, context-request authority, sampling context inclusion, sensitive elicitation posture, and credential key references
- vulnerable fixture coverage for a remote credential-backed MCP server with broad client roots, sampling enabled, elicitation enabled, and sensitive client-context exposure
- rule `AGENTCSP-MCP-008` for remote MCP servers that combine broad client roots, sampling or elicitation authority, external reach, and credential-backed access
- scanner, rule, fixture verifier, and redaction coverage proving raw root URIs, root names, root paths, elicitation field names, and token placeholders stay redacted

## MCP Sensitive Elicitation Pass

The current iteration adds:

- first-class redacted metadata for MCP elicitation sensitive-field counts, sensitive-field categories, redaction posture, sanitization posture, and approval posture
- vulnerable fixture coverage for a remote credential-backed MCP context broker that can elicit customer and token-like fields while redaction, sanitization, and approval are disabled
- rule `AGENTCSP-MCP-012` for remote MCP servers that can collect credential and PII elicitation fields across an external trust boundary without local controls or approval
- regression coverage proving raw elicitation field names, remote MCP URLs, and token placeholders stay redacted

## MCP Sensitive Sampling Pass

The current iteration adds:

- first-class redacted metadata for MCP sampling context categories, sensitive sampling posture, redaction posture, prompt-injection filtering posture, and approval posture
- vulnerable fixture coverage for a remote credential-backed MCP context broker that can request sampling over workspace, prompt, tool-output, and secret-like client context while controls are disabled
- rule `AGENTCSP-MCP-013` for remote MCP servers that can process sensitive client context through server-initiated sampling without redaction, prompt-injection filtering, or approval
- regression coverage proving raw sampling context labels, remote MCP URLs, and token placeholders stay redacted

## MCP Client Root Boundary Pass

The current iteration adds:

- first-class redacted metadata for MCP client-root credential-path scope, host-root scope, sensitive-root scope, and approval posture
- vulnerable fixture coverage for a remote credential-backed MCP context broker configured with `.ssh`, workspace, and host-root client roots
- rule `AGENTCSP-MCP-014` for remote MCP servers that receive credential-path and host-root client roots without approval
- regression coverage proving raw root URIs, root names, remote MCP URLs, and token placeholders stay redacted

## MCP Ambient Environment Exposure Pass

The current iteration adds:

- first-class redacted metadata for MCP process-environment inheritance, wildcard env passthrough, sensitive env patterns, and ambient secret-risk posture
- vulnerable fixture coverage for a remote credential-backed MCP server that forwards broad process environment and sensitive env patterns across an external tool boundary
- rule `AGENTCSP-MCP-009` for MCP servers that combine broad env passthrough, external reach, credential evidence, and side-effecting agent-callable authority
- scanner, rule, fixture verifier, and redaction coverage proving raw process-env expressions, wildcard env patterns, remote MCP URLs, and token placeholders stay redacted

## Browser Extension/Profile Exposure Pass

The current iteration adds:

- first-class redacted metadata for browser extension/profile posture, including extension counts, extension categories, privileged extension permission signals, extension automation signals, password-manager/autofill posture, and download/upload path redaction
- vulnerable fixture coverage for an authenticated Playwright-style browser profile that loads password-manager and wallet-like extension state while untrusted customer/retrieval context can drive broad-origin browser actions
- rule `AGENTCSP-RUNTIME-033` for browser-agent sessions that combine authenticated state, untrusted navigation, broad origins, privileged extensions, autofill/password-manager exposure, and secret exposure
- scanner, rule, fixture verifier, and redaction coverage proving raw extension names, extension IDs, extension paths, download/upload paths, browser profile paths, origins, and token placeholders stay redacted

## AgentCSP Policy-Integrity Pass

The current iteration adds:

- first-class redacted metadata for AgentCSP advisory policy posture, including trust-override counts and kinds, broad/high-severity suppression posture, long-lived active suppression posture, permissive recommended-control downgrade posture, and weakening-control categories
- vulnerable fixture coverage for a project-local `agentcsp.yaml` that marks retrieved context trusted, defines a broad high-severity long-lived suppression, and downgrades critical legacy-agent findings to `allow`
- rule `AGENTCSP-RUNTIME-034` for policy files that combine trust elevation for untrusted context, broad high-severity suppression, and permissive recommended-control downgrades
- rule `AGENTCSP-RUNTIME-116` for policy files that combine trust elevation, active long-lived broad critical suppressions, wildcard-path matching, and `allow` downgrades for critical findings
- confidence scoring improvement so structured `parsed_*_config` metadata and write/approval actions contribute to very-high confidence when a rule is otherwise well correlated
- scanner, rule, fixture verifier, and redaction coverage proving raw policy IDs, owners, reasons, trust paths, match categories, and token placeholders stay redacted from policy-integrity surface metadata

## Remote Prompt Registry Supply Pass

The current iteration adds:

- first-class redacted metadata for remote prompt-registry posture, including registry destination categories, prompt reference counts and kinds, auto-sync, unpinned references, signature/provenance verification, untrusted selectors, privileged role injection, tool/memory/external directives, and approval posture
- vulnerable fixture coverage for a remote prompt registry that auto-syncs unpinned system and developer prompts selected by untrusted customer and retrieval context
- rule `AGENTCSP-RUNTIME-035` for prompt registries that combine remote auto-sync, unpinned prompt refs, disabled verification, untrusted selectors, privileged role injection, tool directives, and no approval gate
- rule `AGENTCSP-RUNTIME-117` for prompt registries that combine remote unpinned privileged prompts with memory and external-response directives over sensitive context without approval
- scanner, rule, fixture verifier, and redaction coverage proving raw registry URLs, prompt IDs, selector fields, directive strings, data-scope labels, and token placeholders stay redacted

## Public Agent-Card Exposure Pass

The current iteration adds:

- first-class redacted metadata for public A2A and agent-card exposure, including endpoint categories, capability counts, authentication posture, anonymous external caller access, privileged authority categories, callback/signing credential posture, rate-limit posture, and approval posture
- vulnerable fixture coverage for a `.well-known/agent-card.json` that exposes browser, database, memory, secret, and external-response authority to anonymous external agents
- rule `AGENTCSP-RUNTIME-036` for public agent cards that combine anonymous external access, privileged tool authority, missing approval, missing rate limits, and credential exposure
- rule `AGENTCSP-RUNTIME-114` for anonymous public A2A agent cards that combine callback/signing credentials, secret-manager access, memory/write authority, missing approval, and missing rate limits
- scanner, rule, fixture verifier, and redaction coverage proving raw endpoint URLs, agent names, skill IDs, tool strings, caller labels, data-scope labels, and token placeholders stay redacted

## Remote Agent Federation Pass

The current iteration adds:

- first-class redacted metadata for outbound A2A and remote-agent federation posture, including remote destination categories, agent reference counts, dynamic discovery, untrusted agent selectors, auto-delegation, context forwarding, tool-result forwarding, memory forwarding, credential forwarding, verification posture, allowlist posture, and approval posture
- vulnerable fixture coverage for an A2A federation config that dynamically selects third-party agents from untrusted customer/retrieval/browser context and forwards prompts, retrieval context, tool results, memory, and credentials without verification, allowlists, or approval
- rule `AGENTCSP-RUNTIME-037` for remote agent federation that combines dynamic discovery, untrusted peer selection, sensitive context forwarding, credential forwarding, missing identity verification, missing allowlists, and no approval
- rule `AGENTCSP-RUNTIME-102` for A2A federation that auto-delegates to unverified remote peers while forwarding prompts, retrieval context, tool results, browser output, memory, authorization headers, or tokens from untrusted selectors
- scanner, rule, fixture verifier, and redaction coverage proving raw registry URLs, agent-card URLs, peer names, selector fields, source labels, task names, data-scope labels, and token placeholders stay redacted

## MCP OAuth Authorization Pass

The current iteration adds:

- first-class redacted metadata for MCP OAuth authorization posture, including remote authorization/resource endpoint categories, plaintext endpoint posture, dynamic client registration, public-client/client-secret posture, device-flow exposure, redirect/callback capture posture, PKCE/state/resource-indicator controls, scope categories, refresh-token storage, token forwarding, untrusted server selection, and approval posture
- vulnerable fixture coverage for an MCP OAuth client that dynamically registers against remote authorization metadata, requests broad and sensitive scopes, stores refresh tokens, forwards authorization headers to a plaintext untrusted MCP server, and does not require approval
- safe fixture coverage for a TLS-only, PKCE-bound, state/resource-bound, approval-gated MCP OAuth client that does not forward or persist delegated credentials
- rule `AGENTCSP-RUNTIME-038` for MCP OAuth delegation that combines remote DCR, disabled PKCE/state/resource indicators, broad scopes, refresh-token storage, token forwarding, untrusted server selection, credential exposure, and no approval
- rule `AGENTCSP-RUNTIME-118` for MCP OAuth refresh-token replay risk where public-client/client-secret exposure, missing PKCE/state/resource binding, broad write/PII scopes, persisted refresh tokens, and token forwarding can reach untrusted MCP servers without approval
- rule `AGENTCSP-RUNTIME-125` for MCP OAuth clients that forward or persist delegated credentials across plaintext MCP resource endpoints without approval
- rule `AGENTCSP-RUNTIME-127` for MCP OAuth callback capture risk where dynamic public clients allow wildcard or user-selected redirect callbacks with disabled redirect validation, missing PKCE/state/resource binding, persisted refresh tokens, token forwarding, and no approval
- rule `AGENTCSP-RUNTIME-128` for MCP OAuth device-flow exposure where user/device codes or verification URI material can enter agent or model context while broad delegated tokens are persisted or forwarded to untrusted MCP servers without approval
- graph hardening so explicitly referenced privileged tools and MCP servers remain in bounded attack-path analysis even when newly discovered runtime surfaces increase capability volume
- scanner, rule, fixture verifier, and redaction coverage proving raw authorization endpoints, MCP URLs, redirect callback selectors, device-code labels, verification URI selectors, OAuth scopes, selector values, token-cache paths, data-scope labels, and token placeholders stay redacted

## Tool Output Injection Boundary Pass

The current iteration adds:

- first-class redacted metadata for tool-output policy posture, including browser/shell/MCP/API/customer source categories, raw-output handling, prompt-context injection, delimiter posture, sanitization posture, prompt-injection filtering, follow-up tool authority, memory writes, shell authority, external reach, secret access, and approval posture
- vulnerable fixture coverage for raw tool observations that can enter developer prompt context, request follow-up tools, write customer records, send Slack replies, persist memory, run shell commands, and access a secret lookup tool without approval
- rule `AGENTCSP-RUNTIME-039` for tool-output injection boundaries that combine untrusted raw observations, disabled sanitization and prompt-injection filtering, privileged follow-up action authority, credential exposure, and no approval
- rule `AGENTCSP-RUNTIME-079` for tool-output approval poisoning where raw untrusted tool observations become approval decision context and can trigger privileged write, external, shell, memory, or secret-backed follow-up actions without approval
- scanner, rule, fixture verifier, and redaction coverage proving raw observation labels, tool names, data-scope labels, and token placeholders stay redacted

## Visual Context Injection Boundary Pass

The current iteration adds:

- first-class redacted metadata for visual context policy posture, including browser screenshot, screen-capture, uploaded-image, document-image, OCR-text, raw-image handling, prompt-context injection, visual boundary posture, sanitization posture, prompt-injection filtering, follow-up tool authority, memory writes, shell authority, external reach, secret access, and approval posture
- vulnerable fixture coverage for raw screenshots and OCR text that can enter system prompt context, request follow-up tools, write customer records, submit browser forms, send Slack replies, persist memory, run shell commands, and access a secret lookup tool without approval
- rule `AGENTCSP-RUNTIME-040` for visual context injection boundaries that combine untrusted raw screenshots or OCR text, disabled visual sanitization and prompt-injection filtering, privileged follow-up action authority, credential exposure, and no approval
- rule `AGENTCSP-RUNTIME-095` for visual/OCR context promoted into system or developer context and approval decision context while browser, database, external response, memory, shell, and secret-manager tools can execute without approval
- scanner, rule, fixture verifier, and redaction coverage proving raw screenshot labels, OCR source labels, tool names, data-scope labels, and token placeholders stay redacted

## RAG Retrieval Authorization Pass

The current iteration adds:

- first-class redacted metadata for RAG/vector retrieval authorization posture, including user-controlled query inputs, redacted filter categories, broad sensitive retrieval scope, ACL posture, provenance/trust-filter posture, raw chunk passthrough, prompt-injection passthrough, tool-context injection, and approval posture
- vulnerable fixture coverage for a remote credential-backed vector store that accepts customer-controlled retrieval selectors across broad private support data, injects raw chunks into prompt/tool context, disables ACL/provenance/trust/prompt-injection filters, and does not require approval
- rule `AGENTCSP-RAG-005` for RAG retrieval authorization bypass that combines remote vector retrieval, user-controlled queries/filters, broad sensitive scope, disabled controls, tool-context injection, credential exposure, and no approval
- scanner, rule, fixture verifier, and redaction coverage proving raw query selector values, filter values, source labels, vector endpoints, namespaces, collection names, and token placeholders stay redacted

## RAG Ingestion Poisoning Pass

The current iteration adds:

- first-class redacted metadata for RAG/vector ingestion posture, including ingestion source categories, auto-ingest, trusted namespace writes, quarantine posture, moderation posture, instruction-stripping posture, sanitization posture, provenance requirements, and approval posture
- vulnerable fixture coverage for a remote credential-backed vector store that auto-indexes customer uploads, support-ticket attachments, public web pages, and inbox messages into a trusted internal corpus while quarantine, moderation, instruction stripping, sanitization, provenance, and approval are disabled
- rule `AGENTCSP-RAG-006` for RAG ingestion poisoning that combines remote credential-backed vector ingestion, untrusted auto-indexed sources, trusted namespace writes, disabled ingestion controls, missing provenance, and no approval
- scanner, rule, fixture verifier, and redaction coverage proving raw ingestion source labels, trusted namespace labels, vector endpoints, collection names, and token placeholders stay redacted

## RAG Remote Fetch Boundary Pass

The current iteration adds:

- first-class redacted metadata for RAG/vector remote-fetch posture, including user or model-selected URL sources, redirect following, private-network reach, metadata-service reach, network allowlist posture, credential forwarding, and approval posture
- vulnerable fixture coverage for a remote vector-store ingestion pipeline that auto-fetches untrusted URLs, follows redirects, permits private and metadata-service targets, forwards credential-bearing cookies, lacks a network allowlist, and writes into a trusted retrieval pipeline without approval
- safe fixture coverage for a local read-only vector-store config with remote fetch disabled, private and metadata destinations blocked, explicit network allowlisting, provenance, sanitization, and approval
- rule `AGENTCSP-RAG-007` for RAG ingestion SSRF exposure that combines untrusted/model-selected URL fetch, redirects, internal-network and metadata-service reach, credential forwarding, missing allowlist, credential exposure, and no approval
- scanner, rule, fixture verifier, and redaction coverage proving fetched URL source labels, vector endpoints, collection names, and token placeholders stay redacted

## Repository Security Automation Pass

The current iteration adds:

- Dependabot version-update configuration for npm/pnpm dependencies and GitHub Actions with grouped minor/patch updates and major-version review boundaries
- GitHub code-scanning upload for AgentCSP SARIF on default-branch pushes using `github/codeql-action/upload-sarif@v4`
- CI fixture scan alignment with local verification by including log-derived generated-state signals in the vulnerable fixture scan
- a `SECURITY.md` disclosure policy covering scanner evidence leaks, policy bypass, unsafe scan-scope behavior, and packaged artifact or CI supply-chain issues

## Agent Authorization Broker Pass

The current iteration adds:

- first-class redacted metadata for agent authorization-broker posture, including remote broker destinations, dynamic grant requests, model-selected tool/resource scope, untrusted subject/resource inputs, default-allow and fail-open behavior, wildcard tool/resource scope, privileged authority categories, audit posture, grant TTL posture, credential exposure, and approval posture
- vulnerable fixture coverage for a model-selected tool-permission broker that grants broad support, browser, Slack, database, and secret-manager authority from customer/retrieval/browser context with default-allow/fail-open behavior, disabled audit logging, credentials, and no approval
- safe fixture coverage for a scoped local policy engine that denies by default, disables dynamic grants, requires review, audits decisions, and sets a grant TTL
- rule `AGENTCSP-RUNTIME-041` for authorization brokers that combines dynamic grants, model-selected scope, untrusted subjects, broad privileged tool/resource authority, default-open behavior, credential exposure, and missing approval
- rule `AGENTCSP-RUNTIME-075` for fail-open authorization brokers that issue dynamic wildcard grants without TTL, audit logging, or approval while destructive and secret-backed authority is available
- rule `AGENTCSP-RUNTIME-115` for model-selected authorization bypass where untrusted context can request wildcard tool/resource grants with default-open behavior, disabled audit logging, missing TTLs, database/browser/external-response/secret-manager authority, and no approval
- scanner, rule, fixture verifier, and redaction coverage proving raw broker endpoints, tool names, wildcard tenant/resource scopes, data-scope labels, and token placeholders stay redacted

## OpenAPI Tool Import Pass

The current iteration adds:

- first-class redacted metadata for OpenAPI and Swagger tool imports, including agent-import signals, method class, server category, authentication posture, request-input posture, sensitive data categories, write/destructive authority, external reach, and approval posture
- vulnerable fixture coverage for an agent-imported OpenAPI spec that exposes an authenticated external support API write with user-controlled sensitive request inputs and no approval boundary
- safe fixture coverage for an approval-gated read-only OpenAPI import against a relative/internal API server
- rule `AGENTCSP-TOOL-012` for OpenAPI tool imports that combine authenticated external writes, user-controlled inputs, sensitive scope, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving raw API server URLs, paths, operation IDs, summaries, request schemas, request field names, and token placeholders stay redacted

## Hosted Assistant Definition Pass

The current iteration adds:

- first-class redacted metadata for hosted assistant and deployable agent definitions, including provider category, model/instruction redaction, hosted tool categories, tool-choice posture, file/vector resources, sensitive context, untrusted input, guardrail posture, and approval posture
- vulnerable fixture coverage for a hosted support assistant that auto-routes untrusted ticket and thread context into code interpreter, file search, vector-store resources, and function tools over sensitive customer context without approval
- safe fixture coverage for an approval-gated read-only hosted assistant with manual/no automatic tool routing
- rule `AGENTCSP-RUNTIME-042` for hosted assistants that combine untrusted input, privileged hosted tools, sensitive context, automatic tool choice, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving raw assistant IDs, model names, instructions, tool names, tool descriptions, file IDs, vector-store IDs, data labels, and token placeholders stay redacted

## Hosted Assistant Parallel Fanout Pass

The current iteration adds:

- first-class redacted metadata for hosted assistant parallel privileged tool fanout, including privileged tool category counts and fanout posture
- vulnerable fixture coverage through the existing support assistant with untrusted thread context, automatic tool choice, parallel tool calls, code interpreter, file-search resources, function tools, disabled guardrails, credentials, and no approval gate
- safe fixture coverage through the existing read-only assistant with manual/no tool routing, no parallel tool calls, and approval required
- rule `AGENTCSP-RUNTIME-049` for hosted assistants that combine untrusted context, automatic tool choice, parallel privileged fanout, disabled guardrails, credential exposure, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving assistant IDs, model names, tool names, file/vector IDs, data labels, and token placeholders stay redacted

## Realtime Agent Session Pass

The current iteration adds:

- first-class redacted metadata for realtime, voice, streaming, telephony, WebRTC, WebSocket, Twilio, LiveKit, and similar agent-session posture, including external caller/audio input, transcript and recording capture, redaction and sanitization controls, prompt-injection filtering, tool-authority categories, memory writes, sensitive/PII context, credential exposure, and approval posture
- vulnerable fixture coverage for a support voice agent that accepts external callers, records and transcribes calls, disables transcript sanitization and prompt-injection filtering, writes memory, and can invoke function, MCP, secret, state-write, and external-response tools without approval
- safe fixture coverage for an approval-gated read-only realtime session that keeps callers internal, disables recording, and avoids external writes
- rule `AGENTCSP-RUNTIME-043` for realtime agents that combine external caller/audio input, privileged tool authority, sensitive context, disabled prompt-injection filtering, and missing approval
- rule `AGENTCSP-RUNTIME-069` for realtime agents that capture external caller transcripts and recordings while transcript sanitization, recording redaction, and approval controls are disabled
- rule `AGENTCSP-RUNTIME-111` for realtime caller audio that is recorded, unsanitized, and allowed to drive secret-aware write or external-response tools without approval
- scanner, rule, fixture verifier, and redaction coverage proving raw endpoints, model names, tool names, caller labels, recording labels, data-scope labels, and token placeholders stay redacted

## AI Feedback And RLHF Pipeline Pass

The current iteration adds:

- first-class redacted metadata for AI feedback, human review, ratings, annotations, labeling, preference, and RLHF pipelines, including remote feedback destination categories, captured prompt/completion/tool/retrieval/memory/browser/PII/secret categories, training/eval/model-update promotion posture, redaction, consent, retention, and approval controls
- vulnerable fixture coverage for a feedback loop that collects untrusted customer ratings and freeform feedback, captures raw production prompts, completions, tool outputs, retrieval context, memory, browser context, PII, and secret fields, and promotes them into training/eval/model-update paths without redaction, consent, or approval
- safe fixture coverage for a local approved feedback queue that captures only feedback labels, keeps model-update and eval promotion disabled, and keeps redaction, consent, and approval controls enabled
- rule `AGENTCSP-RUNTIME-044` for feedback/RLHF pipelines that combine untrusted sensitive capture, remote export, training promotion, disabled redaction, and missing approval
- rule `AGENTCSP-RUNTIME-097` for feedback/RLHF pipelines that retain raw prompts, completions, tool outputs, retrieval context, memory, browser context, PII, and secrets while auto-promoting to training, eval, or model-update paths without consent, redaction, or approval
- scanner, rule, fixture verifier, and redaction coverage proving raw feedback endpoints, source labels, data-field labels, dataset names, and token placeholders stay redacted

## Agent Safety Fail-Open Posture Pass

The current iteration adds:

- first-class redacted metadata for agent safety fail-open posture, including default-allow, timeout-allow, error-allow, and monitor-only fallback categories
- vulnerable fixture coverage for an otherwise enabled guardrail policy that allows by default, allows on timeout and error, runs monitor-only, and can reach database, secret-manager, and external-response tools without approval
- safe fixture coverage for an approval-gated default-deny safety policy that blocks timeout and error paths
- rule `AGENTCSP-RUNTIME-045` for safety policies that fail open around privileged tools when untrusted input, credentials, and missing approval are present
- rule `AGENTCSP-RUNTIME-105` for enabled safety policies whose default, timeout, error, and monitor-only paths can release secret-backed database and external-response authority without deterministic pre-tool enforcement or approval
- scanner, rule, fixture verifier, graph tie-break, and redaction coverage proving raw policy names, fallback tokens, tool names, and data-scope labels stay redacted

## Background Agent Task Queue Pass

The current iteration adds:

- first-class redacted metadata for background agent, task-queue, job-queue, worker, BullMQ, Celery, Temporal, SQS, Pub/Sub, Kafka, RabbitMQ, and similar async-agent posture
- vulnerable fixture coverage for a BullMQ support-agent queue that auto-executes untrusted customer jobs, passes prompt/tool-output context, redrives failed jobs, and can reach database, Slack, browser, and secret-manager tools without approval
- safe fixture coverage for a local in-memory internal review queue with approval required, no auto-execution, no replay, no untrusted payload, and no privileged authority
- rule `AGENTCSP-RUNTIME-046` for background agent queues that combine background consumers, auto-execution, untrusted payloads, privileged tool authority, credential exposure, and missing approval
- rule `AGENTCSP-RUNTIME-073` for background queue retry/DLQ redrive that replays untrusted prompt or tool-output jobs into privileged credential-backed workers without approval
- scanner, rule, fixture verifier, and redaction coverage proving raw queue names, queue URLs, DLQ names, job labels, payload labels, tool names, and token placeholders stay redacted

## AI Telemetry Public Trace Sharing Pass

The current iteration adds:

- first-class redacted metadata for public and shared AI telemetry trace access, including public share links, anonymous viewers, shared recipients, disabled RBAC/SSO controls, and approval posture
- vulnerable fixture coverage for a LangSmith-style trace export that captures prompts, completions, tool outputs, retrieval, memory, PII, and secret fields into a remote project with public sharing and disabled access controls
- safe fixture coverage for a local OpenTelemetry-style trace config with remote export disabled, redaction enabled, public sharing disabled, RBAC/SSO enabled, and approval required
- rule `AGENTCSP-RUNTIME-047` for sensitive remote trace exports exposed through public or broadly shared access without redaction, access control, or approval
- scanner, rule, fixture verifier, and redaction coverage proving raw endpoints, project names, workspace names, vendor labels, trace labels, and token placeholders stay redacted

## Browser File-Transfer Boundary Pass

The current iteration adds:

- first-class redacted metadata for browser file-transfer posture, including automatic download acceptance, file chooser/upload enablement, approval posture, and false-value handling for browser session controls
- vulnerable fixture coverage through the existing Playwright browser-session config with authenticated state, broad origins, untrusted navigation, auto-accepted downloads, upload paths, sensitive browser context, credentials, and no approval gate
- safe fixture coverage for a local unauthenticated read-only browser config with disabled cookie/storage state, disabled remote debugging, disabled file transfer, scoped origins, and approval required
- rule `AGENTCSP-RUNTIME-048` for authenticated browser sessions that can transfer sensitive local files from untrusted navigation without approval
- scanner, rule, fixture verifier, and redaction coverage proving raw browser profile paths, transfer paths, origins, data labels, and token placeholders stay redacted

## Public Model Gateway Pass

The current iteration adds:

- first-class redacted metadata for AI model endpoint and gateway exposure posture, including public or anonymous access, authentication posture, request logging, redaction posture, tool-calling authority, untrusted inputs, sensitive context capture, and approval boundaries
- vulnerable fixture coverage for an HTTPS OpenAI-compatible model gateway that is public, unauthenticated, records prompts, tool calls, tool outputs, retrieval context, memory, PII, and secrets, and exposes tool calling without approval
- safe fixture coverage for a localhost-only authenticated model gateway with request logging and tool calling disabled
- rule `AGENTCSP-RUNTIME-051` for public or anonymous model gateways that combine disabled auth, sensitive context logging, disabled redaction, tool calling, and missing approval
- rule `AGENTCSP-RUNTIME-108` for public anonymous model gateways that combine broad CORS, missing rate limits, unredacted prompt/tool/retrieval/memory/PII/secret logging, automatic database/external-response tool execution, credentials, and no approval
- scanner, rule, fixture verifier, and redaction coverage proving raw gateway URLs, gateway names, tool names, data-scope labels, and token placeholders stay redacted

## Approval Channel Integrity Pass

The current iteration adds:

- first-class redacted metadata for human approval-channel posture, including ChatOps, webhook, email, ticket, and comment channel categories, external-channel exposure, channel authentication, approver identity verification, replay protection, broad approver scope, privileged action authority, and auto-execution posture
- vulnerable fixture coverage for a Slack-style approval webhook that accepts broad public channel approvals from unverified/requester-controlled approvers, disables signature and replay checks, and auto-executes database, browser, Slack, and secret-manager actions
- safe fixture coverage for an internal SSO/RBAC-backed review console with signature checks, replay protection, approver allowlists, no raw untrusted context, and no auto-execution
- rule `AGENTCSP-RUNTIME-052` for spoofable approval channels that combine external approval ingress, disabled channel authentication, unverified approver identity, disabled replay protection, broad approver scope, privileged action authority, and auto-execution
- rule `AGENTCSP-RUNTIME-078` for approval requests that forward raw untrusted customer, retrieval, or tool context into an external human review channel and then auto-execute privileged write, browser, external, or secret-backed actions
- scanner, rule, fixture verifier, and redaction coverage proving raw approval URLs, channel names, approver labels, action names, data-scope labels, and token placeholders stay redacted

## Live Agent Session-Sharing Pass

The current iteration adds:

- first-class redacted metadata for live agent session-sharing and collaboration posture, including public links, anonymous access, external collaborators, disabled authentication, live prompt/tool/approval control, replay and handoff behavior, sensitive capture, redaction posture, and approval boundaries
- vulnerable fixture coverage for a public shared-copilot session where anonymous external collaborators can inject messages, edit prompt context, approve actions, run tools, resume/replay the session, and capture browser, retrieval, memory, transcript, PII, and secret context without redaction or approval
- safe fixture coverage for an authenticated internal read-only review session with SSO/RBAC, no external collaborators, no live control, no capture, redaction enabled, and approval required
- rule `AGENTCSP-RUNTIME-053` for public or external shared live sessions that combine disabled authentication, live control, tool authority, sensitive context, disabled redaction, credential exposure, and missing independent approval
- rule `AGENTCSP-RUNTIME-106` for public anonymous shared sessions that expose prompt injection, live control, tool control, approval control, resume/replay, and secret capture without redaction or approval
- scanner, rule, fixture verifier, and redaction coverage proving raw session URLs, session names, collaborator labels, tool names, source labels, data-scope labels, and token placeholders stay redacted

## Computer-Use Desktop Control Pass

The current iteration adds:

- first-class redacted metadata for computer-use, desktop automation, remote desktop, VNC/RDP, workstation, operator, and UI automation posture, including signed-in desktop sessions, screen/OCR capture, clipboard access, keyboard/mouse control, file transfer, app/terminal control, remote desktop endpoints, credential-store exposure, redaction posture, and approval boundaries
- vulnerable fixture coverage for a computer-use desktop agent that can observe a signed-in support desktop, use OCR, type/click, read/write clipboard, upload/download files, control desktop apps, and act on untrusted customer/browser context while redaction and approval are disabled
- safe fixture coverage for a local read-only desktop review config with no signed-in session, screen capture, clipboard, keyboard/mouse, file transfer, app control, credential store, or untrusted input
- rule `AGENTCSP-RUNTIME-054` for computer-use agents that combine authenticated desktop state, screen capture, keyboard/mouse control, clipboard and file authority, untrusted input, disabled redaction, credential exposure, and missing approval
- rule `AGENTCSP-RUNTIME-099` for computer-use agents where credential-store or autofill state, OCR capture, clipboard writes, file transfer, auto-accepted downloads, untrusted input, disabled redaction, and missing approval create a direct credential-transfer boundary
- graph candidate-window hardening so the Static Blast-Radius Summary keeps earlier high-signal context-to-capability paths as the runtime posture inventory grows, while the final attack-path output remains bounded
- scanner, rule, fixture verifier, and redaction coverage proving raw remote desktop endpoints, app names, window titles, local transfer paths, data-scope labels, and token placeholders stay redacted

## Context-Window Instruction Integrity Pass

The current iteration adds:

- first-class redacted metadata for context-window, token-budget, truncation, compaction, summarization, and overflow-policy posture, including strategy categories, priority categories, privileged instruction retention or eviction, safety-policy retention or eviction, summary verification, delimiter/redaction posture, privileged tool categories, credential exposure, and approval boundaries
- vulnerable fixture coverage for a sliding-window support-agent policy that preserves untrusted customer, tool-output, retrieval, and memory context while dropping system, developer, and safety instructions, trusting summaries without verification, disabling delimiters and redaction, and allowing database, Slack, and vault tool authority without approval
- safe fixture coverage for a pinned-system-first context-window policy that preserves system, developer, and safety instructions, drops lower-trust user/tool context first, verifies summaries, keeps delimiters and redaction enabled, and requires approval
- rule `AGENTCSP-RUNTIME-055` for context-window instruction eviction that combines enabled truncation, untrusted/tool/memory priority, privileged instruction eviction, safety-policy eviction, unverified summaries, privileged tool authority, credential exposure, and missing approval
- rule `AGENTCSP-RUNTIME-071` for unverified context-window summaries that replay untrusted, tool, retrieval, or memory context into privileged tools while delimiters, redaction, and approval are disabled
- scanner, rule, fixture verifier, and redaction coverage proving raw priority labels, summary strategy names, tool names, data-scope labels, and token placeholders stay redacted

## Agent Network Egress Metadata Pass

The current iteration adds:

- first-class redacted metadata for agent web, browser, fetch, and network-egress posture, including private-network, localhost, cloud metadata service, wildcard destination, untrusted URL source, user-controlled URL, redirect handling, DNS-rebinding protection, header and credential forwarding, response capture, data-class, credential exposure, and approval boundaries
- vulnerable fixture coverage for a web egress policy that lets untrusted customer, browser, and retrieval links drive WebFetch/browser/http tools to metadata, localhost, private/internal, and wildcard destinations while forwarding credentials, following redirects, disabling DNS-rebinding protection, and lacking approval
- safe fixture coverage for an approval-gated public-documentation egress policy that blocks metadata, private ranges, localhost, redirects, credential forwarding, and response capture
- rule `AGENTCSP-RUNTIME-058` for model-steered web egress to cloud metadata/private network destinations with credential forwarding and no approval
- rule `AGENTCSP-RUNTIME-074` for untrusted or model-selected web egress that follows redirects across wildcard/private destinations while forwarding authorization headers or credentials and capturing sensitive responses without approval
- scanner, rule, fixture verifier, and redaction coverage proving raw URLs, hostnames, IP addresses, source labels, response data labels, and token placeholders stay redacted

## Agent Reasoning State Exposure Pass

The current iteration adds:

- first-class redacted metadata for agent reasoning-state, scratchpad, planner-state, run-state, chain-of-thought, and thought-log posture, including capture categories, persistent/shared/remote destinations, public access, replay into future model context, planner/system-prompt hydration, redaction, access control, retention, credential exposure, and approval boundaries
- vulnerable fixture coverage for a remote shared scratchpad that captures reasoning steps, plans, tool observations, prompts, retrieval, memory, PII, and secrets from untrusted context, replays the state into future planner context, disables redaction and access controls, and lacks approval
- safe fixture coverage for a local ephemeral scratchpad with capture, persistence, sharing, remote storage, replay, and secret collection disabled while redaction, access controls, and approval remain enabled
- rule `AGENTCSP-RUNTIME-057` for persisted and replayed reasoning state that combines remote persistence, untrusted sensitive capture, disabled redaction/access controls, credential exposure, and missing approval
- rule `AGENTCSP-RUNTIME-070` for public or shared reasoning scratchpads that capture reasoning traces, prompt context, or tool observations while redaction, access controls, and approval are disabled
- rule `AGENTCSP-RUNTIME-113` for public reasoning state that captures untrusted scratchpad, prompt, retrieval, memory, tool-observation, PII, and secret context, then hydrates future planner or system-prompt context without redaction, access controls, or approval
- scanner, rule, fixture verifier, and redaction coverage proving raw reasoning destinations, workspace names, source labels, data-scope labels, and token placeholders stay redacted

## Agent Tool Retry Replay Pass

The current iteration adds:

- first-class redacted metadata for agent tool retry, replay, retry budgets, retry-on-error classes, idempotency, duplicate suppression, exactly-once controls, non-idempotent action authority, untrusted input, tool-output replay, credential exposure, and approval boundaries
- vulnerable fixture coverage for an automatic retry/replay policy that can re-run support database, messaging, and vault-backed tool calls from untrusted customer, browser, retrieval, and tool-output context while idempotency, deduplication, exactly-once controls, backoff, and approval are disabled
- safe fixture coverage for an approval-gated read-only retry policy with one attempt, replay disabled, idempotency and duplicate suppression enabled, and no credential exposure
- rule `AGENTCSP-RUNTIME-056` for automatic replay of non-idempotent privileged tools from untrusted context when idempotency controls and approval are missing
- rule `AGENTCSP-RUNTIME-101` for model-selected retry/replay that reuses tool arguments and tool outputs across database, external-response, and secret-manager actions while backoff, idempotency, deduplication, exactly-once controls, and approval are disabled
- scanner, rule, fixture verifier, and redaction coverage proving raw tool names, retry argument labels, source labels, data-scope labels, and token placeholders stay redacted

## Workspace Context Sync Exposure Pass

The current iteration adds:

- first-class redacted metadata for agent workspace-context, context-sync, file-context, repository-context, and workspace-index posture, including source categories for env files, SSH keys, cloud credentials, kubeconfig, git history, home directories, private repositories, workspace files, and untrusted selectors
- destination posture for remote context indexes, prompt context, RAG/vector indexes, memory stores, and shared workspaces without emitting raw paths, repository names, URLs, field labels, or token placeholders
- vulnerable fixture coverage for an automatic remote workspace context sync that can ingest `.env`, SSH, AWS, kubeconfig, git history, private repository paths, and untrusted selectors into prompt, RAG, memory, and remote context while redaction and approval are disabled
- safe fixture coverage for a local scoped context loader that only reads explicit docs/source folders, respects `.agentcspignore`, excludes credential paths, keeps redaction enabled, and requires approval
- rule `AGENTCSP-RUNTIME-059` for workspace context sync exposure that combines automatic sync, sensitive local source categories, credential exposure, remote sync, untrusted selectors, disabled redaction, and missing approval
- rule `AGENTCSP-RUNTIME-100` for workspace context sync that persists env files, SSH keys, cloud credentials, kubeconfig, git history, home-directory, and private-repository sources into remote prompt, RAG, and memory sinks while bypassing `.agentcspignore`
- scanner, rule, fixture verifier, and redaction coverage proving raw local paths, home-directory paths, credential paths, remote context URLs, data-field labels, and token placeholders stay redacted

## Autonomous Agent Loop Authority Pass

The current iteration adds:

- first-class redacted metadata for autonomous agent, control-loop, planner-executor, and self-directed runner configs, including goal-source categories, auto-execution, privileged tool categories, tool-output feedback, iteration/runtime budgets, stop conditions, kill-switch posture, dry-run posture, approval posture, and credential exposure
- vulnerable fixture coverage for an automatic customer-ticket driven agent loop that can repeatedly call browser, database, messaging, shell, memory, and secret-manager authority from untrusted goals while budget, stop, kill-switch, dry-run, and approval controls are missing
- safe fixture coverage for a bounded read-only review loop that disables autonomous execution, limits iterations, keeps tool-output feedback out of future planning, requires approval, and exposes no credentials
- rule `AGENTCSP-RUNTIME-060` for autonomous loops that route untrusted goals through tool-output feedback into privileged actions without budgets, kill switches, or approval
- rule `AGENTCSP-RUNTIME-112` for autonomous loops that can recurse through shell, secret-manager, memory, and tool-output feedback without runtime budgets, stop conditions, dry-run, kill-switch, or approval controls
- scanner, rule, fixture verifier, and redaction coverage proving raw goals, planner prompts, tool names, observation labels, action strings, data-field labels, and token placeholders stay redacted

## Secret Prompt Materialization Pass

The current iteration adds:

- first-class redacted metadata for secret-manager prompt/context materialization, including prompt-context categories, redaction posture, untrusted selector posture, approval posture, and credential exposure
- vulnerable fixture coverage for a Vault-backed support agent broker that reads broad customer-support secrets and materializes raw secret values into system and model prompt context from customer or retrieved inputs while redaction and approval are disabled
- safe fixture coverage for an approval-gated local secret-alias broker that resolves scoped aliases without materializing raw secret values into prompts or model context
- rule `AGENTCSP-RUNTIME-061` for secret managers that expose raw credentials to model-visible context from untrusted selectors without redaction or approval
- scanner, rule, fixture verifier, and redaction coverage proving raw prompt targets, model-context labels, vault selectors, alias names, data-scope labels, and token placeholders stay redacted

## Public Agent Chat Ingress Pass

The current iteration adds:

- first-class redacted metadata for public chat, chatbot, customer-support widget, and web assistant ingress posture, including endpoint categories, anonymous access, auth/CORS/CSRF/rate-limit/abuse-control posture, file uploads, automatic tool invocation, privileged authority categories, redaction posture, approval posture, and credential exposure
- vulnerable fixture coverage for a public support widget that accepts anonymous messages and attachments, disables auth and abuse controls, auto-invokes database, Slack, memory, and secret-manager tools, disables redaction, and lacks approval
- safe fixture coverage for an authenticated internal read-only chat that requires SSO and approval, disables automatic tool invocation, keeps rate limits and redaction enabled, and exposes no credentials
- rule `AGENTCSP-RUNTIME-062` for public chat ingress that routes anonymous prompt input into privileged tools without abuse controls, redaction, or approval
- rule `AGENTCSP-RUNTIME-092` for public chat uploads that can automatically trigger database, external-response, memory, and secret-manager tools when CSRF, rate limits, abuse protection, redaction, and approval are disabled
- scanner, rule, fixture verifier, and redaction coverage proving raw endpoints, allowed origins, visitor labels, upload labels, tool names, context labels, and token placeholders stay redacted

## Agent Debug Console Exposure Pass

The current iteration adds:

- first-class redacted metadata for agent debug, playground, prompt-inspector, developer-console, and admin-inspection posture, including endpoint categories, anonymous access, auth/CORS posture, prompt/raw-context/trace/memory/tool-schema visibility, prompt editing, impersonation, live tool invocation, authority categories, redaction posture, audit posture, approval posture, and credential exposure
- vulnerable fixture coverage for a public agent playground that exposes system and developer prompts, raw context, traces, memory, and tool schemas while allowing prompt editing, impersonation, and database, Slack, memory, and secret-manager tool invocation without redaction, audit logging, or approval
- safe fixture coverage for an SSO-protected internal prompt inspector that keeps system/developer prompts, raw context, traces, memory, prompt editing, impersonation, and live tool invocation disabled while requiring approval and audit logging
- rule `AGENTCSP-RUNTIME-063` for public debug/playground consoles that expose prompt/context internals and privileged tool invocation without redaction, audit logging, or approval
- rule `AGENTCSP-RUNTIME-076` for public debug/playground consoles that combine prompt editing, user impersonation, live privileged tool invocation, external/write authority, secret context exposure, disabled audit logging, disabled redaction, and no approval gate
- scanner, rule, fixture verifier, and redaction coverage proving raw endpoints, prompt labels, trace labels, memory labels, context labels, tool names, and token placeholders stay redacted

## Agent Response Stream Disclosure Pass

The current iteration adds:

- first-class redacted metadata for agent response, output-stream, SSE/event-stream, and client-visible output policies, including endpoint categories, anonymous access, auth/CORS posture, streaming posture, reasoning visibility, system/developer prompt visibility, raw tool-output and tool-argument visibility, retrieval chunk visibility, memory visibility, redaction posture, approval posture, and credential exposure
- vulnerable fixture coverage for a public response stream that exposes chain-of-thought, reasoning traces, planner scratchpad, system/developer prompts, raw tool outputs, tool arguments, retrieved chunks, memory context, PII, and secret-bearing fields without redaction or approval
- safe fixture coverage for an SSO-protected internal event stream that keeps reasoning, prompt internals, tool outputs, tool arguments, retrieval chunks, memory, and secrets redacted while requiring approval
- rule `AGENTCSP-RUNTIME-064` for public response streams that expose model internals, tool data, RAG context, memory, and secrets to clients without redaction or approval
- rule `AGENTCSP-RUNTIME-091` for anonymous broad-CORS response streams that leak system/developer prompts, reasoning traces, raw tool outputs, and tool arguments across the public client boundary
- scanner, rule, fixture verifier, and redaction coverage proving raw stream endpoints, response field labels, reasoning labels, retrieval labels, memory labels, data-scope labels, and token placeholders stay redacted

## Agent Action Router Auto-Execution Pass

The current iteration adds:

- first-class redacted metadata for action-router, tool-dispatch, command-router, model-action, output-parser, and action-DSL configs, including model-output input posture, untrusted input sources, accepted action formats, schema validation posture, unknown-action handling, JSON repair, batch execution, auto-execution, privileged authority categories, dry-run posture, redaction posture, approval posture, and credential exposure
- vulnerable fixture coverage for a model-output action router that accepts untrusted customer, retrieval, and browser-output inputs, disables schema validation, allows unknown actions, repairs invalid JSON, permits unlimited action batches, and auto-executes database, Slack, shell, secret-manager, and memory actions without redaction, dry-run, or approval controls
- safe fixture coverage for a scoped structured tool-call router that uses strict schema validation, denies unknown actions, disables JSON repair and auto-execution, limits actions per response, redacts arguments and secrets, runs dry-run, and requires approval
- rule `AGENTCSP-RUNTIME-065` for model-output action routers that route untrusted model text into privileged tools without closed schemas, redaction, dry-run, or approval
- rule `AGENTCSP-RUNTIME-104` for open-schema model-output action routers that repair and batch-execute unknown model-selected database, external-response, memory, secret-manager, and shell actions with credentials and no approval
- scanner, rule, fixture verifier, and redaction coverage proving raw input-source labels, action names, context labels, safe internal labels, and token placeholders stay redacted

## MCP Dynamic Tool Catalog Trust Pass

The current iteration adds:

- first-class redacted metadata for MCP tool catalogs, registries, manifests, dynamic discovery, model-visible descriptions, remote schema trust, pinning, signature/provenance verification, unreviewed tool posture, privileged tool categories, context data classes, approval posture, and credential exposure
- vulnerable fixture coverage for a remote MCP tool catalog that dynamically refreshes unpinned model-visible tool definitions from a trusted remote registry, disables signature and provenance verification, allows unreviewed database, Slack, shell, secret-manager, and memory tools, exposes customer context, and lacks approval
- safe fixture coverage for a local reviewed static MCP tool manifest that pins and verifies tools, does not trust remote descriptions, disables auto-refresh and unreviewed tools, exposes only read-only docs search, and requires approval
- rule `AGENTCSP-MCP-010` for dynamic remote MCP tool catalogs that combine mutable tool supply, model-visible descriptions, remote schema trust, disabled verification, unreviewed privileged tools, credentials, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving raw catalog URLs, source values, tool names, context labels, safe manifest labels, and token placeholders stay redacted

## Context Composer Env Secret Materialization Pass

The current iteration adds:

- first-class redacted metadata for context composers that materialize environment references into system, developer, prompt, or model-visible context, including target categories, secret-bearing env posture, redaction posture, untrusted selector posture, approval posture, and credential key names
- vulnerable fixture coverage for a context composer that injects credential-bearing environment references into system, developer, and model context while untrusted customer, retrieval, browser, command, and memory sources are present, redaction is disabled, and approval is missing
- safe fixture coverage for a scoped context composer that explicitly disables env materialization, keeps redaction enabled, and requires approval
- rule `AGENTCSP-RUNTIME-066` for context composers that combine untrusted sources, env-secret materialization into privileged/model context, disabled redaction, credential exposure, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving raw env placeholders, untrusted selector labels, source labels, tool names, and safe internal labels stay redacted

## Remote Instruction Loader Authority Pass

The current iteration adds:

- first-class redacted metadata for remote instruction loaders and instruction-sync configs, including destination categories, instruction reference counts, role categories, refresh and pinning posture, signature/provenance verification, untrusted selector posture, privileged tool-authority categories, approval posture, data-class booleans, and credential key names
- vulnerable fixture coverage for a remote instruction loader that auto-refreshes unpinned system and developer instructions selected by untrusted customer, retrieval, and browser context while disabled verification and privileged database, browser, Slack, memory, and secret-manager authority are present
- safe fixture coverage for a local pinned instruction bundle that disables remote fetch and auto-refresh, verifies signatures and provenance, rejects untrusted selectors, exposes no credentials, and requires approval
- rule `AGENTCSP-RUNTIME-067` for remote instruction loaders that combine remote auto-refresh, unpinned instructions, disabled verification, untrusted selectors, privileged role injection, privileged tool authority, and missing approval
- rule `AGENTCSP-RUNTIME-103` for remote instruction refresh that grants browser, database, external-response, memory, and secret-manager authority from untrusted-selected system and developer instructions with credential evidence and no approval
- scanner, rule, fixture verifier, and redaction coverage proving raw instruction URLs, instruction IDs, selector labels, tool names, data-scope labels, and token placeholders stay redacted

## Model-Only Guardrail Enforcement Pass

The current iteration adds:

- first-class redacted metadata for safety policies that rely on prompt-only, LLM-judge, model-reviewer, self-review, or post-hoc guardrails while deterministic pre-tool enforcement is missing
- vulnerable fixture coverage for a model-only guardrail that accepts untrusted customer, retrieval, and browser context, lacks deterministic schema or allowlist enforcement before tool calls, and protects credential-backed database, browser, Slack, and secret-manager tools only through model review
- safe fixture coverage for a default-deny deterministic pre-tool safety policy that explicitly disables model reviewers and self-review while requiring approval
- rule `AGENTCSP-RUNTIME-068` for model-only guardrails that combine missing deterministic pre-tool policy, untrusted input, privileged tool authority, credential exposure, and missing approval
- rule `AGENTCSP-RUNTIME-109` for enabled model-only safety review that combines prompt-only, LLM-judge, self-review, post-hoc enforcement, missing deterministic pre-tool controls, database, browser, external-response, and secret-manager authority, PII, secrets, credentials, and no approval
- scanner, rule, fixture verifier, and redaction coverage proving raw policy names, model-reviewer labels, policy-prompt labels, source labels, tool names, data-scope labels, and token placeholders stay redacted

## MCP Resource Subscription Context Bridge Pass

The current iteration adds:

- first-class redacted metadata for MCP resource subscriptions, live resource watches, server-pushed updates, model-visible context auto-inclusion, raw-content passthrough, untrusted source posture, sanitization/redaction/prompt-injection filtering, provenance verification, privileged follow-up authority categories, approval posture, and credential exposure
- vulnerable fixture coverage for a remote credential-backed MCP context broker that subscribes to untrusted customer-ticket and tool-output resources, auto-refreshes raw model-visible context, disables sanitization, redaction, prompt-injection filtering, and provenance verification, and allows database, Slack, memory, and secret-manager follow-up authority without approval
- safe fixture coverage for a local reviewed docs MCP server that keeps resource subscriptions non-dynamic, non-model-visible, sanitized, redacted, provenance-verified, read-only, and approval-gated
- rule `AGENTCSP-MCP-011` for remote MCP resource subscriptions that combine live untrusted context, raw model-visible injection, disabled controls, privileged authority, credentials, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving raw subscribed resource URIs, stream labels, trust labels, context labels, action names, safe resource paths, and token placeholders stay redacted

## SARIF Code-Scanning Metadata Pass

The current iteration adds:

- GitHub code-scanning compatible `security-severity` metadata on SARIF rules and results while preserving the existing `securitySeverity` compatibility field
- SARIF rule and result ranks, precision, tags, result-level rule tags, automation details, and rule help markdown so CI and code-scanning platforms can triage AgentCSP findings without parsing Markdown reports
- report and fixture-output regression coverage proving SARIF emits scan-level triage, coverage, blast-radius context, security severity, precision, tags, ranks, and help metadata

## Package Tarball Verification Pass

The current iteration adds:

- `pnpm verify:packages` now runs `pnpm pack` for both `@agentcsp/core` and `agentcsp`
- tarball inspection proving the core package ships the compiled entrypoint, schemas export, scanner, rule engine, and the full copied built-in rule pack
- tarball inspection proving the CLI package ships the executable entrypoint, banner module, and scan command implementation
- package metadata checks for the core exports and the `agentcsp` CLI bin target
- installed-tree package smoke testing that combines packed AgentCSP artifacts with runtime dependencies, validates publish-compatible CLI-to-core package metadata, and runs `agentcsp scan` from the packed CLI entrypoint against the safe fixture

## Approval Self-Authorization Bypass Pass

The current iteration adds:

- first-class approval-gate metadata for requester or same-actor self-approval, separate from broad approver scope
- rule `AGENTCSP-RUNTIME-119` for human approval gates where an unauthenticated external channel allows requester self-approval, lacks replay protection, includes raw untrusted context, and auto-executes privileged write, external, or secret-backed actions
- regression coverage proving the vulnerable ChatOps approval fixture produces the finding while raw webhook URLs, channel names, action names, source labels, data labels, and token placeholders stay redacted

## Inbound Attachment Parser Boundary Pass

The current iteration adds:

- first-class inbound-trigger metadata for raw attachment text extraction, sandbox posture, malware/content scanning posture, and prompt-instruction stripping posture
- fixture coverage for an inbound support mailbox that accepts PDF, HTML, archive, and OCR image attachments, extracts raw content, disables sandboxing/scanning/instruction stripping, and routes attachment-derived context into browser, database, external-response, memory, and secret-manager tools without approval
- rule `AGENTCSP-RUNTIME-120` for unsandboxed inbound attachment parsing that can drive privileged agent tools with credential-backed authority
- regression coverage proving raw attachment filenames, mail endpoints, mailbox names, agent names, tool names, source labels, data labels, and token placeholders stay redacted

## Public Chat Upload Parser Boundary Pass

The current iteration adds:

- first-class public-chat upload metadata for raw uploaded content extraction, sandbox posture, malware/content scanning posture, and prompt-instruction stripping posture
- fixture coverage for an anonymous public support widget that accepts PDF, HTML, archive, and OCR image uploads, extracts raw content, disables sandboxing/scanning/instruction stripping, and routes upload-derived context into database, external-response, memory, and secret-manager tools without approval
- rule `AGENTCSP-RUNTIME-121` for unsandboxed public chat upload parsing that can drive privileged agent tools with credential-backed authority
- regression coverage proving raw upload filenames, public endpoints, visitor labels, tool names, context labels, data labels, and token placeholders stay redacted

## Inbound Webhook Integrity Pass

The current iteration adds:

- first-class inbound-trigger metadata for webhook signature verification posture, timestamp freshness posture, and replay-protection posture
- fixture coverage for an inbound support webhook that accepts unsigned partner events, skips timestamp validation, disables nonce/delivery-id replay protection, and routes forged webhook-derived context into browser, database, external-response, memory, and secret-manager tools without approval
- rule `AGENTCSP-RUNTIME-122` for unsigned or replayable inbound webhooks that can drive privileged agent tools with credential-backed authority
- regression coverage proving raw webhook header names, delivery identifiers, source labels, endpoints, mailbox names, agent names, prompt fields, and token placeholders stay redacted

## AI Telemetry Trace Replay Pass

The current iteration adds:

- first-class AI telemetry metadata for retained trace replay, replay target categories, eval promotion, and training promotion
- fixture coverage for a remote shared LangSmith-style trace exporter that captures prompts, completions, tool outputs, retrieval context, memory, PII, and secrets, then allows public shared traces to replay into future agent context, red-team eval datasets, fine-tuning candidates, and debugging prompt replay without redaction or approval
- rule `AGENTCSP-RUNTIME-123` for retained sensitive AI telemetry traces that can replay into agent, eval, or training paths with public access, disabled access controls, disabled redaction, credentials, and no approval gate
- regression coverage proving raw telemetry endpoints, project names, workspace names, vendor labels, replay source labels, replay target labels, and token placeholders stay redacted

## Browser Download Parser Boundary Pass

The current iteration adds:

- first-class browser download parser metadata for raw downloaded content extraction, agent-context ingestion, parser sandbox posture, malware/content scanning posture, and prompt-instruction stripping posture
- fixture coverage for an authenticated Playwright browser session that auto-accepts untrusted downloads, extracts raw PDF/HTML/ZIP/OCR content into agent context, disables parser sandboxing and scanning, and lacks approval
- rule `AGENTCSP-RUNTIME-124` for untrusted browser downloads that can become privileged agent context without sandboxing, scanning, prompt-instruction stripping, or approval
- regression coverage proving raw browser profile paths, cookie files, extension names, extension IDs, download paths, downloaded filenames, origins, and token placeholders stay redacted

## Automation Shell-Argument Boundary Pass

The current iteration adds:

- first-class GitHub Actions metadata for untrusted event payloads that are mapped into environment variables and then used as shell command arguments
- rule `AGENTCSP-AUTOMATION-004` for issue, pull request, or repository-dispatch text passed as an argument to a secret-backed agent package script running with write permissions
- regression coverage proving raw GitHub event expressions and raw agent shell command text stay redacted while the normalized environment-key data flow remains available for triage

## Expired Suppression CI Gate Pass

The current iteration adds:

- an opt-in `--fail-on-expired-suppressions` CLI gate so SOC and platform teams can block stale accepted-risk records independently of severity thresholds
- core scan-config support for expired-suppression gating while preserving default exit-code behavior for adoption-friendly scans
- Markdown report visibility for findings matched by expired suppressions, keeping stale waivers visible as active risk
- regression coverage proving expired suppressions can fail CI without a `--fail-on` severity gate and remain non-failing unless the gate is explicitly enabled

## CI Gate Summary Pass

The current iteration adds:

- a first-class `ci_gate_summary` in the manifest that records pass/fail status, enabled gates, failed gate names, evaluated finding counts, severity-gate matches, active suppressions excluded, expired suppression counts, and diagnostic counts
- shared core gate evaluation for severity/confidence, new-only baseline gates, expired suppressions, and diagnostics so CLI exit behavior and machine-readable output stay aligned
- Markdown and SARIF `agentcsp_ci_gate_summary` output for CI, code-scanning, and future dashboard ingestion
- regression coverage proving diagnostic gates, expired-suppression gates, and default pass behavior are explainable without raw evidence or secret values

## Adopter SARIF Workflow Examples Pass

The current iteration adds:

- copy-pasteable GitHub code-scanning workflows under `examples/ci/` for advisory rollout and gated rollout
- a `pnpm verify:ci-examples` verifier that parses the example workflows and enforces the expected SARIF upload, permissions, pinned CLI version, quiet output, and gated-enforcement behavior
- CI coverage for the workflow examples so adopter documentation cannot silently drift from supported CLI flags
- `docs/ci.md` rollout guidance for advisory scans, diagnostics and expired-suppression gates, severity/confidence gates, baseline/new-only gating, version pinning, and machine-readable `ci_gate_summary` consumption

## Source Tool Handler Authority Pass

The current iteration adds:

- redacted handler-body authority signals for MCP SDK, Python/FastMCP, Python agent-framework, and JavaScript/TypeScript agent-framework source-defined tools
- handler metadata for external network writes, caller-selected URLs, endpoints, webhooks, or destinations passed into HTTP client calls, external service SDK writes, caller-selected external-service recipients or channels passed into SDK writes, model-provider SDK calls, caller-selected model, deployment, provider, endpoint, or base URL routing passed into model-provider SDK calls, embedding-provider calls with caller/customer text persisted into vector memory, telemetry/tracing export calls with caller/customer/prompt/tool-output payloads, prompt-cache writes with caller-controlled cache keys and prompt/customer/tool-output values, AI training or fine-tuning dataset exports with caller/customer/prompt/completion/tool-output payloads, authenticated browser or screen visual-context capture returned to model-visible output from caller-selected targets, remote-agent/A2A delegation with caller-selected targets and forwarded caller/customer context, privileged prompt-role composition, credentialed network reads, network response capture into model-visible output, memory/vector/RAG/state persistence, caller-selected memory namespaces or scopes passed into durable memory writes, agent control-plane file writes, credential issuance or identity impersonation, caller-selected subjects, scopes, roles, audiences, tenants, or accounts passed into credential broker APIs, nested tool invocation, browser automation, caller-selected URLs, selectors, form inputs, or customer payloads passed into browser page/driver calls, secret-manager and vault reads, caller-controlled secret path arguments passed to vault APIs, environment-backed secret access, secret-to-output materialization, database query/write execution, caller-controlled SQL/query arguments passed into database APIs, shell execution, caller-controlled command arguments passed to shell execution, caller-controlled path arguments passed to filesystem APIs, dynamic in-process code execution, caller-controlled code arguments passed to dynamic execution, unsafe deserialization, caller-controlled serialized payloads passed to unsafe loaders, arbitrary local file disclosure, filesystem reads/writes/deletes, signal counts, authority categories, and env key names without emitting handler bodies, URLs, headers, SQL strings, caller-controlled network destination snippets, caller-controlled credential grant snippets, caller-controlled SQL/query snippets, caller-controlled model-routing snippets, embedding-provider snippets, telemetry calls, trace payloads, prompt-cache calls, cache keys, cache values, training dataset calls, dataset IDs, training records, screenshot bytes, OCR text, delegated-agent calls, forwarded context snippets, memory-write snippets, caller-selected memory scope snippets, agent-config write snippets, credential-broker calls, nested-tool dispatcher calls, browser page calls, caller-selected browser target snippets, screenshot calls, visual-capture output snippets, secret-manager read calls, external service SDK calls, caller-selected external-service recipient snippets, model-provider SDK calls, privileged prompt snippets, shell/subprocess snippets, returned network-response snippets, returned secret-bearing text, dynamic-code snippets, deserialization snippets, file-read snippets, source snippets, or secret values
- rule `AGENTCSP-TOOL-013` for source-defined tools that send model-controlled or customer data externally with env-backed runtime secret authority
- rule `AGENTCSP-TOOL-014` for source-defined tools that mutate local workspace paths or host files from path-like model arguments
- rule `AGENTCSP-TOOL-015` for source-defined tools that execute shell or subprocess handlers from command-like tool arguments
- rule `AGENTCSP-TOOL-016` for source-defined tools that execute database writes from SQL or record-update tool arguments
- rule `AGENTCSP-TOOL-017` for source-defined tools that return env-backed secrets through model-visible tool output
- rule `AGENTCSP-TOOL-018` for source-defined tools that forward env-backed credentials to caller-controlled URLs through non-write network requests
- rule `AGENTCSP-TOOL-019` for source-defined tools that evaluate model-supplied code through dynamic in-process execution APIs
- rule `AGENTCSP-TOOL-020` for source-defined tools that return model-selected local file contents into model-visible tool output
- rule `AGENTCSP-TOOL-021` for source-defined tools that pass serialized model inputs into unsafe deserialization APIs
- rule `AGENTCSP-TOOL-022` for source-defined tools that fetch caller-controlled URLs and return network responses into model-visible tool output
- rule `AGENTCSP-TOOL-023` for source-defined tools that persist customer or prompt-like tool input into memory, vector, RAG, or state stores
- rule `AGENTCSP-TOOL-024` for source-defined tools that write caller or customer content into persistent agent control-plane files
- rule `AGENTCSP-TOOL-025` for source-defined tools that issue, mint, sign, broker, assume, or impersonate credentials from caller-selected subject, scope, role, audience, or customer context
- rule `AGENTCSP-TOOL-026` for source-defined tools that dispatch nested privileged tools from caller-selected tool names, argument bodies, or customer payloads
- rule `AGENTCSP-TOOL-027` for source-defined tools that drive browser pages or authenticated browser sessions from caller-selected URLs, selectors, form content, or customer payloads
- rule `AGENTCSP-TOOL-028` for source-defined tools that read secret managers, vaults, key vaults, or cloud secret stores from caller-selected paths and return credential material through model-visible tool output
- rule `AGENTCSP-TOOL-029` for source-defined tools that send caller or customer content through external collaboration, messaging, email, issue-tracker, or SaaS SDK clients
- rule `AGENTCSP-TOOL-030` for source-defined tools that forward caller or customer context into LLM or model-provider SDK calls using runtime credentials and return model output into the agent path
- rule `AGENTCSP-TOOL-031` for source-defined tools that promote caller or customer context into system/developer model prompt roles before invoking model-provider SDKs
- rule `AGENTCSP-TOOL-032` for source-defined tools that pass caller-controlled command arguments into shell or subprocess execution
- rule `AGENTCSP-TOOL-033` for source-defined tools that pass caller-controlled code arguments into dynamic in-process execution
- rule `AGENTCSP-TOOL-034` for source-defined tools that pass caller-controlled serialized payloads or derived values into unsafe deserialization
- rule `AGENTCSP-TOOL-035` for source-defined tools that pass caller-controlled path arguments or derived values into filesystem APIs
- rule `AGENTCSP-TOOL-036` for source-defined tools that pass caller-controlled secret paths or derived values into vault APIs
- rule `AGENTCSP-TOOL-037` for source-defined tools that pass caller-selected recipients, channels, destinations, or webhooks into external service SDK writes
- rule `AGENTCSP-TOOL-038` for source-defined tools that pass caller-controlled SQL, query text, statement text, or derived update inputs into database query APIs
- rule `AGENTCSP-TOOL-039` for source-defined tools that pass caller-selected namespaces, tenants, collections, indexes, or memory keys into durable memory writes
- rule `AGENTCSP-TOOL-040` for source-defined tools that pass caller-selected URLs, selectors, form inputs, or customer payloads into browser page or driver calls
- rule `AGENTCSP-TOOL-041` for source-defined tools that pass caller-selected URLs, endpoints, webhooks, or destinations into HTTP client calls
- rule `AGENTCSP-TOOL-042` for source-defined tools that pass caller-selected subjects, scopes, roles, audiences, tenants, or accounts into credential broker APIs
- rule `AGENTCSP-TOOL-043` for source-defined tools that pass caller-selected model, deployment, provider, endpoint, or base URL routing into model-provider SDK calls
- rule `AGENTCSP-TOOL-044` for source-defined tools that send caller or customer text to embedding providers and persist vectors into memory, RAG, or state stores
- rule `AGENTCSP-TOOL-045` for source-defined tools that export caller, customer, prompt, or tool-output payloads into telemetry, tracing, logging, or observability SDKs with runtime credentials
- rule `AGENTCSP-TOOL-046` for source-defined tools that write caller-controlled prompt, customer, or tool-output values into prompt, LLM, response, or semantic caches with caller-controlled cache keys and runtime credentials
- rule `AGENTCSP-TOOL-047` for source-defined tools that export caller, customer, prompt, completion, or tool-output payloads into AI training or fine-tuning datasets with runtime credentials
- rule `AGENTCSP-TOOL-048` for source-defined tools that capture authenticated browser screenshots, screen state, OCR, or visual context from caller-selected targets and return it into model-visible output with runtime credentials
- rule `AGENTCSP-TOOL-049` for source-defined tools that delegate caller or customer context to caller-selected remote agents using runtime credentials
- rule `AGENTCSP-TOOL-050` for source-defined tools that export caller/customer agent artifacts, reports, generated output, or tool output to public or shareable storage using runtime credentials
- rule `AGENTCSP-TOOL-051` for source-defined tools that send caller/customer/tool-output context into a model-mediated approval gate and automatically execute the privileged action from the approval result
- vulnerable and safe fixture coverage proving risky handlers produce critical findings while read-only source tools produce zero handler signals
- regression coverage proving raw handler syntax such as network calls, network response variables, memory-store writes, telemetry/tracing SDK calls, trace payload variables, prompt-cache calls, cache keys, cache values, training dataset calls, dataset IDs, training records, artifact export calls, public artifact URLs, object keys, bucket names, artifact return strings, approval model calls, approval decision summaries, privileged action executor calls, action payloads, agent control-plane write calls and target paths, credential-broker calls, identity-broker calls, nested-tool dispatcher calls, delegated-agent calls, forwarded context snippets, browser page calls, screenshot calls, visual-capture outputs, secret-manager read calls, caller-controlled vault path snippets, external service SDK calls, model-provider SDK calls, privileged prompt-role snippets, database driver calls, SQL strings, returned network-response text, returned secret-bearing text, filesystem read/delete calls, caller-controlled filesystem path snippets, shell/subprocess calls, command argument snippets, dynamic-code evaluation calls, dynamic code argument snippets, unsafe deserialization calls, serialized payload transformation snippets, `os.getenv`, credentialed fetch calls, and bearer-header construction stays redacted

## Initial Build Recommendation

Start with a CLI-first MVP before building the dashboard:

- local scanner
- manifest schema
- rule schema
- policy schema
- built-in rules
- blast-radius report
- JSON, Markdown, and later SARIF output
- dashboard after the data model is useful and stable

## Professional Tone

The user explicitly requested that the project not sound AI-generated. All naming, docs, UI, and positioning should feel professional, enterprise-grade, and credible to security, platform, and governance teams.
