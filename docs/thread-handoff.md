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
- authority classification for external writes, destructive actions, credential-like inputs, filesystem paths, URL inputs, browser control, memory access, and shell execution
- high-signal rules for external writes with credential-like inputs and destructive filesystem tool schemas
- fixture coverage for risky and read-only tools

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
- vulnerable fixture coverage for an OpenAI-compatible model gateway over plaintext HTTP without emitting raw endpoint URLs, model names, or secret placeholders
- rule `AGENTCSP-RUNTIME-009` for credential-backed model endpoints that send sensitive agent context over plaintext transport
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
- rule `AGENTCSP-RUNTIME-012` for SaaS connectors that combine broad credential-backed external write authority, untrusted input, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving raw OAuth scopes, webhook URLs, workspace names, channel names, customer-system labels, and secret placeholders stay redacted

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
- scanner, rule, fixture verifier, and redaction coverage proving raw mailbox names, webhook URLs, sender addresses, labels, agent names, prompt fields, and token placeholders stay redacted

## Multi-Agent Orchestration Authority Pass

The current iteration adds:

- first-class redacted metadata for CrewAI, AutoGen, LangGraph, Semantic Kernel, swarm-style, and related multi-agent orchestration configs
- vulnerable fixture coverage for a support crew where untrusted intake delegates automatically into a privileged executor with shared memory, browser/database/secret/messaging/filesystem authority, credentials, and no approval gate
- rule `AGENTCSP-RUNTIME-015` for multi-agent delegation that routes untrusted context to privileged agents
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
- scanner, rule, fixture verifier, and redaction coverage proving issuer URLs, token endpoints, service-account IDs, raw scopes, IAM roles, subject labels, tool names, data-field labels, and token placeholders stay redacted

## Agent Extension Loader Pass

The current iteration adds:

- first-class redacted metadata for remote skill, plugin, tool, prompt, MCP, marketplace, registry, catalog, and capability-loader configs
- vulnerable fixture coverage for a remote extension marketplace that auto-installs and auto-updates unpinned, unsigned skills/plugins selected from customer/retrieval/browser context with privileged tool authority and no approval gate
- rule `AGENTCSP-RUNTIME-019` for remote extension loaders that combine auto-install, unpinned references, disabled signature verification, untrusted input, privileged authority, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving registry URLs, Git URLs, package names, extension names, version strings, permission strings, selector fields, source labels, data-field labels, and token placeholders stay redacted

## Agent Self-Modification Pass

The current iteration adds:

- first-class redacted metadata for self-modifying agent, policy-writer, prompt-writer, runtime-writer, autofix, codemod, and mutation configs
- vulnerable fixture coverage for untrusted customer/retrieval/browser context that can auto-apply persistent writes to instructions, prompt templates, policy, runtime config, tool definitions, and memory, then reload agent execution without approval
- rule `AGENTCSP-RUNTIME-020` for self-modification configs that combine untrusted input, auto-applied persistent control-plane writes, instruction/policy/tool targets, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving target paths, patch-rule field names, reload commands, source labels, tool names, data-field labels, and token placeholders stay redacted

## Agent Approval-Gate Integrity Pass

The current iteration adds:

- first-class redacted metadata for agent approval, review, human-in-the-loop, model-reviewer, and decision-gate configs
- vulnerable fixture coverage for an LLM-driven approval gate where customer/retrieval/browser context shapes the approval prompt, human review is not required, default behavior approves, and privileged actions auto-execute
- rule `AGENTCSP-RUNTIME-021` for model-mediated approval gates that combine untrusted approval context, default-allow behavior, auto-executed privileged actions, credential exposure, and no required human reviewer
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
- scanner, rule, fixture verifier, and redaction coverage proving bucket names, endpoints, data-scope labels, generated outputs, and token placeholders stay redacted

## Agent Webhook Egress Boundary Pass

The current iteration adds:

- first-class redacted metadata for agent webhook, callback, outbound sink, event-sink, response-hook, reply-hook, and notification-sink configs
- vulnerable fixture coverage for model-generated callback delivery that posts prompts, completions, tool outputs, browser context, retrieval context, memory, PII, and secrets to a remote endpoint with disabled redaction, retry queues, credentials, and no approval gate
- rule `AGENTCSP-RUNTIME-025` for webhook/callback egress that combines remote delivery, model-generated or untrusted payloads, sensitive context, disabled redaction, credential exposure, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving callback endpoints, payload bodies, source labels, data-field labels, and token placeholders stay redacted

## Agent Container Isolation Boundary Pass

The current iteration adds:

- first-class redacted metadata for agent container, sandbox, Docker, Compose, runner, executor, and runtime isolation configs
- vulnerable fixture coverage for a privileged Docker agent container with Docker socket access, host-root and credential mounts, host network/PID/IPC namespaces, dangerous capabilities, untrusted inputs, credential env, and no approval gate
- rule `AGENTCSP-RUNTIME-026` for container host-escape boundaries that combine privileged mode, Docker socket, host path mounts, host networking, untrusted input, credential exposure, and missing approval
- graph-priority tuning that keeps concrete RAG-to-exfiltration and RAG-to-mutable-record paths visible as the runtime surface inventory grows
- scanner, rule, fixture verifier, and redaction coverage proving image names, host paths, Docker socket paths, credential paths, input labels, tool names, and token placeholders stay redacted

## Agent Code Interpreter Runtime Pass

The current iteration adds:

- first-class redacted metadata for agent code interpreter, notebook, Jupyter, Python REPL, kernel, and code-runner configs
- vulnerable fixture coverage for untrusted customer/retrieval/browser context that can execute model-generated code with network access, package installation, shell/filesystem access, credential mounts, output persistence, and no approval gate
- rule `AGENTCSP-RUNTIME-027` for code interpreter runtimes that combine model-driven code execution, untrusted input, network/package-install authority, filesystem access, credential exposure, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving kernel values, mounted paths, input labels, output labels, and token placeholders stay redacted

## AI Training Dataset Boundary Pass

The current iteration adds:

- first-class redacted metadata for AI training, fine-tuning, distillation, feedback-training, RLHF, and dataset-export configs
- vulnerable fixture coverage for a model-update dataset pipeline that captures raw prompts, completions, tool outputs, retrieval context, memory, browser context, PII, and secrets from untrusted customer sources, uploads to a managed provider, retains data, and has no approval gate
- rule `AGENTCSP-RUNTIME-028` for training dataset boundaries that combine model-update authority, remote upload, sensitive capture, disabled redaction, untrusted input, credential exposure, and missing approval
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
- scanner, rule, fixture verifier, and redaction coverage proving provider endpoints, model aliases, fallback labels, routing strategy values, source labels, context labels, and token placeholders stay redacted

## AI Embedding/Indexing Boundary Pass

The current iteration adds:

- first-class redacted metadata for AI embedding, indexing, vectorization, document-index, and RAG-index pipelines
- vulnerable fixture coverage for a third-party embedding pipeline that indexes documents, prompts, tool outputs, browser context, retrieval context, memory, PII, and secrets from untrusted customer sources into a vector destination with disabled redaction, raw-chunk retention, credentials, and no approval gate
- rule `AGENTCSP-RUNTIME-031` for embedding boundaries that combine third-party embedding, vector writes, sensitive capture, disabled redaction, untrusted input, credential exposure, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving embedding endpoints, model aliases, vector-store destinations, namespaces, source labels, document chunks, context labels, and token placeholders stay redacted

## Agent Package Manifest Supply-Chain Pass

The current iteration adds:

- first-class redacted metadata for agent-relevant `package.json` manifests with agent, MCP, model, RAG, vector, or browser-automation dependencies
- vulnerable fixture coverage for floating and remote agent dependency specs combined with a credentialed lifecycle script
- rule `AGENTCSP-SUPPLYCHAIN-001` for package manifests that combine risky agent dependency references, install-time execution, external dependency reach, and credential exposure
- scanner, rule, fixture verifier, and redaction coverage proving dependency names, dependency specs, remote package URLs, Git references, lifecycle commands, local script paths, and token placeholders stay redacted

## Agent Deployment Image Provenance Pass

The current iteration adds:

- first-class redacted metadata for agent deployment manifests with image provenance, digest pinning, pull policy, privileged runtime, service-account, host-mount, and credential posture
- vulnerable fixture coverage for a Kubernetes-style support agent deployed from a mutable remote image with pull-always policy, privileged root execution, host network, Docker socket and credential mounts, secret-backed env, and no approval gate
- rule `AGENTCSP-SUPPLYCHAIN-002` for deployment manifests that combine mutable remote agent images, privileged host authority, credential exposure, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving image references, registry paths, service-account names, secret names, host paths, and token placeholders stay redacted

## Cloud Control-Plane Authority Pass

The current iteration adds:

- first-class redacted metadata for cloud, IAM, IaC, Terraform, Kubernetes platform, and control-plane configs with provider, broad/admin scope, IAM, compute, storage, secret, audit-log, auto-remediation, tool-authority, untrusted-input, credential, and approval posture
- vulnerable fixture coverage for an AWS-style support agent that can run cloud/IaC remediation against broad cloud resources with untrusted customer/runbook inputs, cloud credential references, and no approval gate
- rule `AGENTCSP-RUNTIME-032` for cloud control-plane agents that combine broad credentialed write authority, IAM mutation, secret access, compute/storage mutation, untrusted input, and missing approval
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
- confidence scoring improvement so structured `parsed_*_config` metadata and write/approval actions contribute to very-high confidence when a rule is otherwise well correlated
- scanner, rule, fixture verifier, and redaction coverage proving raw policy IDs, owners, reasons, trust paths, match categories, and token placeholders stay redacted from policy-integrity surface metadata

## Remote Prompt Registry Supply Pass

The current iteration adds:

- first-class redacted metadata for remote prompt-registry posture, including registry destination categories, prompt reference counts and kinds, auto-sync, unpinned references, signature/provenance verification, untrusted selectors, privileged role injection, tool/memory/external directives, and approval posture
- vulnerable fixture coverage for a remote prompt registry that auto-syncs unpinned system and developer prompts selected by untrusted customer and retrieval context
- rule `AGENTCSP-RUNTIME-035` for prompt registries that combine remote auto-sync, unpinned prompt refs, disabled verification, untrusted selectors, privileged role injection, tool directives, and no approval gate
- scanner, rule, fixture verifier, and redaction coverage proving raw registry URLs, prompt IDs, selector fields, directive strings, data-scope labels, and token placeholders stay redacted

## Public Agent-Card Exposure Pass

The current iteration adds:

- first-class redacted metadata for public A2A and agent-card exposure, including endpoint categories, capability counts, authentication posture, anonymous external caller access, privileged authority categories, rate-limit posture, and approval posture
- vulnerable fixture coverage for a `.well-known/agent-card.json` that exposes browser, database, memory, secret, and external-response authority to anonymous external agents
- rule `AGENTCSP-RUNTIME-036` for public agent cards that combine anonymous external access, privileged tool authority, missing approval, missing rate limits, and credential exposure
- scanner, rule, fixture verifier, and redaction coverage proving raw endpoint URLs, agent names, skill IDs, tool strings, caller labels, data-scope labels, and token placeholders stay redacted

## Remote Agent Federation Pass

The current iteration adds:

- first-class redacted metadata for outbound A2A and remote-agent federation posture, including remote destination categories, agent reference counts, dynamic discovery, untrusted agent selectors, auto-delegation, context forwarding, tool-result forwarding, memory forwarding, credential forwarding, verification posture, allowlist posture, and approval posture
- vulnerable fixture coverage for an A2A federation config that dynamically selects third-party agents from untrusted customer/retrieval/browser context and forwards prompts, retrieval context, tool results, memory, and credentials without verification, allowlists, or approval
- rule `AGENTCSP-RUNTIME-037` for remote agent federation that combines dynamic discovery, untrusted peer selection, sensitive context forwarding, credential forwarding, missing identity verification, missing allowlists, and no approval
- scanner, rule, fixture verifier, and redaction coverage proving raw registry URLs, agent-card URLs, peer names, selector fields, source labels, task names, data-scope labels, and token placeholders stay redacted

## MCP OAuth Authorization Pass

The current iteration adds:

- first-class redacted metadata for MCP OAuth authorization posture, including remote authorization/resource endpoint categories, dynamic client registration, public-client/client-secret posture, PKCE/state/resource-indicator controls, scope categories, refresh-token storage, token forwarding, untrusted server selection, and approval posture
- vulnerable fixture coverage for an MCP OAuth client that dynamically registers against remote authorization metadata, requests broad and sensitive scopes, stores refresh tokens, forwards authorization headers to an untrusted MCP server, and does not require approval
- rule `AGENTCSP-RUNTIME-038` for MCP OAuth delegation that combines remote DCR, disabled PKCE/state/resource indicators, broad scopes, refresh-token storage, token forwarding, untrusted server selection, credential exposure, and no approval
- graph hardening so explicitly referenced privileged tools and MCP servers remain in bounded attack-path analysis even when newly discovered runtime surfaces increase capability volume
- scanner, rule, fixture verifier, and redaction coverage proving raw authorization endpoints, MCP URLs, OAuth scopes, selector values, token-cache paths, data-scope labels, and token placeholders stay redacted

## Tool Output Injection Boundary Pass

The current iteration adds:

- first-class redacted metadata for tool-output policy posture, including browser/shell/MCP/API/customer source categories, raw-output handling, prompt-context injection, delimiter posture, sanitization posture, prompt-injection filtering, follow-up tool authority, memory writes, shell authority, external reach, secret access, and approval posture
- vulnerable fixture coverage for raw tool observations that can enter developer prompt context, request follow-up tools, write customer records, send Slack replies, persist memory, run shell commands, and access a secret lookup tool without approval
- rule `AGENTCSP-RUNTIME-039` for tool-output injection boundaries that combine untrusted raw observations, disabled sanitization and prompt-injection filtering, privileged follow-up action authority, credential exposure, and no approval
- scanner, rule, fixture verifier, and redaction coverage proving raw observation labels, tool names, data-scope labels, and token placeholders stay redacted

## Visual Context Injection Boundary Pass

The current iteration adds:

- first-class redacted metadata for visual context policy posture, including browser screenshot, screen-capture, uploaded-image, document-image, OCR-text, raw-image handling, prompt-context injection, visual boundary posture, sanitization posture, prompt-injection filtering, follow-up tool authority, memory writes, shell authority, external reach, secret access, and approval posture
- vulnerable fixture coverage for raw screenshots and OCR text that can enter system prompt context, request follow-up tools, write customer records, submit browser forms, send Slack replies, persist memory, run shell commands, and access a secret lookup tool without approval
- rule `AGENTCSP-RUNTIME-040` for visual context injection boundaries that combine untrusted raw screenshots or OCR text, disabled visual sanitization and prompt-injection filtering, privileged follow-up action authority, credential exposure, and no approval
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
- scanner, rule, fixture verifier, and redaction coverage proving raw endpoints, model names, tool names, caller labels, recording labels, data-scope labels, and token placeholders stay redacted

## AI Feedback And RLHF Pipeline Pass

The current iteration adds:

- first-class redacted metadata for AI feedback, human review, ratings, annotations, labeling, preference, and RLHF pipelines, including remote feedback destination categories, captured prompt/completion/tool/retrieval/memory/browser/PII/secret categories, training/eval/model-update promotion posture, redaction, consent, retention, and approval controls
- vulnerable fixture coverage for a feedback loop that collects untrusted customer ratings and freeform feedback, captures raw production prompts, completions, tool outputs, retrieval context, memory, browser context, PII, and secret fields, and promotes them into training/eval/model-update paths without redaction, consent, or approval
- safe fixture coverage for a local approved feedback queue that captures only feedback labels, keeps model-update and eval promotion disabled, and keeps redaction, consent, and approval controls enabled
- rule `AGENTCSP-RUNTIME-044` for feedback/RLHF pipelines that combine untrusted sensitive capture, remote export, training promotion, disabled redaction, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving raw feedback endpoints, source labels, data-field labels, dataset names, and token placeholders stay redacted

## Agent Safety Fail-Open Posture Pass

The current iteration adds:

- first-class redacted metadata for agent safety fail-open posture, including default-allow, timeout-allow, error-allow, and monitor-only fallback categories
- vulnerable fixture coverage for an otherwise enabled guardrail policy that allows by default, allows on timeout and error, runs monitor-only, and can reach database, secret-manager, and external-response tools without approval
- safe fixture coverage for an approval-gated default-deny safety policy that blocks timeout and error paths
- rule `AGENTCSP-RUNTIME-045` for safety policies that fail open around privileged tools when untrusted input, credentials, and missing approval are present
- scanner, rule, fixture verifier, graph tie-break, and redaction coverage proving raw policy names, fallback tokens, tool names, and data-scope labels stay redacted

## Background Agent Task Queue Pass

The current iteration adds:

- first-class redacted metadata for background agent, task-queue, job-queue, worker, BullMQ, Celery, Temporal, SQS, Pub/Sub, Kafka, RabbitMQ, and similar async-agent posture
- vulnerable fixture coverage for a BullMQ support-agent queue that auto-executes untrusted customer jobs, passes prompt/tool-output context, redrives failed jobs, and can reach database, Slack, browser, and secret-manager tools without approval
- safe fixture coverage for a local in-memory internal review queue with approval required, no auto-execution, no replay, no untrusted payload, and no privileged authority
- rule `AGENTCSP-RUNTIME-046` for background agent queues that combine background consumers, auto-execution, untrusted payloads, privileged tool authority, credential exposure, and missing approval
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
- scanner, rule, fixture verifier, and redaction coverage proving raw gateway URLs, gateway names, tool names, data-scope labels, and token placeholders stay redacted

## Approval Channel Integrity Pass

The current iteration adds:

- first-class redacted metadata for human approval-channel posture, including ChatOps, webhook, email, ticket, and comment channel categories, external-channel exposure, channel authentication, approver identity verification, replay protection, broad approver scope, privileged action authority, and auto-execution posture
- vulnerable fixture coverage for a Slack-style approval webhook that accepts broad public channel approvals from unverified/requester-controlled approvers, disables signature and replay checks, and auto-executes database, browser, Slack, and secret-manager actions
- safe fixture coverage for an internal SSO/RBAC-backed review console with signature checks, replay protection, approver allowlists, no raw untrusted context, and no auto-execution
- rule `AGENTCSP-RUNTIME-052` for spoofable approval channels that combine external approval ingress, disabled channel authentication, unverified approver identity, disabled replay protection, broad approver scope, privileged action authority, and auto-execution
- scanner, rule, fixture verifier, and redaction coverage proving raw approval URLs, channel names, approver labels, action names, data-scope labels, and token placeholders stay redacted

## Live Agent Session-Sharing Pass

The current iteration adds:

- first-class redacted metadata for live agent session-sharing and collaboration posture, including public links, anonymous access, external collaborators, disabled authentication, live prompt/tool/approval control, replay and handoff behavior, sensitive capture, redaction posture, and approval boundaries
- vulnerable fixture coverage for a public shared-copilot session where anonymous external collaborators can inject messages, edit prompt context, approve actions, run tools, resume/replay the session, and capture browser, retrieval, memory, transcript, PII, and secret context without redaction or approval
- safe fixture coverage for an authenticated internal read-only review session with SSO/RBAC, no external collaborators, no live control, no capture, redaction enabled, and approval required
- rule `AGENTCSP-RUNTIME-053` for public or external shared live sessions that combine disabled authentication, live control, tool authority, sensitive context, disabled redaction, credential exposure, and missing independent approval
- scanner, rule, fixture verifier, and redaction coverage proving raw session URLs, session names, collaborator labels, tool names, source labels, data-scope labels, and token placeholders stay redacted

## Computer-Use Desktop Control Pass

The current iteration adds:

- first-class redacted metadata for computer-use, desktop automation, remote desktop, VNC/RDP, workstation, operator, and UI automation posture, including signed-in desktop sessions, screen/OCR capture, clipboard access, keyboard/mouse control, file transfer, app/terminal control, remote desktop endpoints, credential-store exposure, redaction posture, and approval boundaries
- vulnerable fixture coverage for a computer-use desktop agent that can observe a signed-in support desktop, use OCR, type/click, read/write clipboard, upload/download files, control desktop apps, and act on untrusted customer/browser context while redaction and approval are disabled
- safe fixture coverage for a local read-only desktop review config with no signed-in session, screen capture, clipboard, keyboard/mouse, file transfer, app control, credential store, or untrusted input
- rule `AGENTCSP-RUNTIME-054` for computer-use agents that combine authenticated desktop state, screen capture, keyboard/mouse control, clipboard and file authority, untrusted input, disabled redaction, credential exposure, and missing approval
- graph candidate-window hardening so the Static Blast-Radius Summary keeps earlier high-signal context-to-capability paths as the runtime posture inventory grows, while the final attack-path output remains bounded
- scanner, rule, fixture verifier, and redaction coverage proving raw remote desktop endpoints, app names, window titles, local transfer paths, data-scope labels, and token placeholders stay redacted

## Context-Window Instruction Integrity Pass

The current iteration adds:

- first-class redacted metadata for context-window, token-budget, truncation, compaction, summarization, and overflow-policy posture, including strategy categories, priority categories, privileged instruction retention or eviction, safety-policy retention or eviction, summary verification, delimiter/redaction posture, privileged tool categories, credential exposure, and approval boundaries
- vulnerable fixture coverage for a sliding-window support-agent policy that preserves untrusted customer, tool-output, retrieval, and memory context while dropping system, developer, and safety instructions, trusting summaries without verification, disabling delimiters and redaction, and allowing database, Slack, and vault tool authority without approval
- safe fixture coverage for a pinned-system-first context-window policy that preserves system, developer, and safety instructions, drops lower-trust user/tool context first, verifies summaries, keeps delimiters and redaction enabled, and requires approval
- rule `AGENTCSP-RUNTIME-055` for context-window instruction eviction that combines enabled truncation, untrusted/tool/memory priority, privileged instruction eviction, safety-policy eviction, unverified summaries, privileged tool authority, credential exposure, and missing approval
- scanner, rule, fixture verifier, and redaction coverage proving raw priority labels, summary strategy names, tool names, data-scope labels, and token placeholders stay redacted

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
