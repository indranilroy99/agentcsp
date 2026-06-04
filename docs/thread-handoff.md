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
