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
- graph regression coverage proving `rag/customer-note.md` can route sensitive context to `publish_summary` while keeping raw retrieval text redacted
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
