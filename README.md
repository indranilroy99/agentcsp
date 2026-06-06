# AgentCSP

```text
    ___                    __  __________
   /   | ____ ____  ____  / /_/ ____/ ___/____
  / /| |/ __ '/ _ \/ __ \/ __/ /    \__ \/ __ \
 / ___ / /_/ /  __/ / / / /_/ /___ ___/ / /_/ /
/_/  |_\__, /\___/_/ /_/\__/\____//____/ .___/
      /____/                           /_/

  [ context ]==>[ surface ]==>[ capability ]==>[ control ]
       trust        data class        authority       evidence
```

**Context Security Policy for AI Agents.**

AgentCSP is an open-source control plane for discovering, testing, and enforcing security policy across AI agents, tools, skills, MCP servers, RAG, memory, CI/CD, and runtime actions.

It is not a prompt filter. AgentCSP models the agent environment as a security surface: what the agent can see, what it can trust, what it can call, what it can remember, and what authority it can exercise.

```text
untrusted_context -> agent_surface -> capability -> data_class -> side_effect -> recommended_control
```

## Why AgentCSP

Modern agent systems are assembled from prompts, repo instructions, MCP servers, browser tools, shell commands, package scripts, retrieval stores, memory, logs, credentials, CI workflows, and generated state. Security teams need one view of that AI authority before they can reason about policy, blast radius, or evidence.

AgentCSP answers practical questions:

- What agent-facing context exists in this project?
- Which tools, scripts, MCP servers, and workflows expand the agent's authority?
- Where can untrusted or unknown context influence privileged action?
- Which secret references, data classes, and external systems are in scope?
- What is the static blast radius if an instruction-boundary failure succeeds?
- Which controls should be recommended before runtime enforcement exists?

## Current Status

AgentCSP is in early MVP development. The first release is a local-first CLI that scans a repository, builds a versioned agent manifest, runs an open rule pack, and produces JSON, Markdown, and SARIF evidence.

Runtime enforcement adapters, deeper graph traversal, and the dashboard are planned after the CLI data model is stable.

## Core Capabilities

- **Agent Surface Inventory**: discovers instructions, prompt templates, skills, plugins, MCP configs, package scripts, workflows, env references, RAG sources, memory surfaces, logs, and tool definitions.
- **Agent Manifest**: emits `agent-manifest.json`, an SBOM-style record for AI agent deployments.
- **Authority Signals**: classifies actions such as read, write, execute, publish, send, delete, remember, and call.
- **Instruction and Cursor Rule Signals**: records redacted instruction-file signals when repo, workspace, custom, or always-applied Cursor project rules bridge untrusted context into tools, memory, or external actions.
- **Skill Data-Flow Signals**: records redacted skill inputs and outputs when skills bridge retrieved context, tool output, memory, or prompts to external publication.
- **MCP and Tool Schema Authority**: extracts individual tool schemas and classifies package-runner MCP launchers, missing local MCP implementations, model-visible tool-description injection, tool name collisions, external writes, prompt-like content inputs, PII/customer-data inputs, local-path-to-external data flow, destructive actions, credential-like inputs, open-world arguments, read-only hint conflicts, filesystem paths, URL inputs, browser control, memory access, and shell authority.
- **Remote MCP Trust Signals**: detects remote MCP servers, redacts URLs and header values, records host/header/key metadata, classifies plaintext remote transport, and flags credential-backed third-party MCP access.
- **Runtime Posture Inventory**: parses agent runtime configs for sandbox mode, approval policy, network access, Claude-style permission allowlists, privileged tool allowlists, MCP references, auto-approved MCP tools, broad web scopes, auto-approved package scripts, AI model endpoint egress, authenticated browser-session authority, SaaS/API connector authority, secret-manager authority, database connector authority, AI telemetry export, and env key exposure.
- **Prompt Template Signals**: records redacted template variables, privileged system/developer role-boundary injection, exact references to discovered tools, and flags untrusted user/customer/context variables joined with tool, memory, external, or secret-sensitive directives.
- **RAG, Vector Store, Memory, and Generated-State Signals**: records redacted instruction-like, data-egress, explicit privileged-tool, remote vector-store connector, external-send, persistence, transcript, cached-output, and tool-output replay signals from retrieval, memory, and included log files.
- **Automation Authority**: models scheduled, manual, and externally dispatched workflows, including redacted agent package-script execution, as agent-relevant automation surfaces.
- **Trust Boundary Analysis**: tracks trusted, project, workspace, third-party, untrusted, and unknown provenance.
- **Explainable Risk Scoring**: severity includes contributing factors such as trust level, data class, reversibility, external reach, and secret exposure.
- **Finding Confidence**: each finding includes confidence and rationale so teams can separate correlated evidence from weaker static signals.
- **Triage Summary**: summarizes active findings by severity, confidence, surface type, category, recommended control, top rules, and top risk objects.
- **Baseline Comparison**: compares current findings to previous scan output so teams can separate new risk from existing debt.
- **Scan Coverage Summary**: reports indexed files, oversized files, ignored paths, skipped hidden/log directories, max-file limits, and diagnostic counts.
- **Scan Diagnostics**: emits redacted parser diagnostics when security-relevant configs cannot be parsed.
- **Evidence-Led Static Attack Paths**: connects specific context-risk signals to privileged capabilities, highlights customer-data routes into PII-capable external tools, prefers exact callable references when context names a discovered tool or MCP server, and avoids expanding those cases into broad speculative blast-radius entries.
- **Auditable Suppressions**: supports owned, reasoned, expiring accepted-risk records without deleting evidence.
- **Open Rule Packs**: constrained YAML rules operate over normalized manifest objects. Built-in rules always run; project-local rules are additive and never execute custom JavaScript.
- **Static Blast-Radius Summary**: reports reachable authority from static project metadata without claiming runtime graph traversal.
- **Evidence Reports**: outputs JSON and Markdown with redacted evidence snippets and recommended controls.

## Scanner Safety

AgentCSP is conservative by default:

- Secret values are not read or emitted.
- `.env*` files are reduced to file presence and key names only.
- Evidence snippets are redacted by default.
- Raw file contents are not dumped into the manifest.
- RAG and memory content signals are emitted as booleans and counts, not raw text.
- Large/generated folders are ignored by default.
- `.agentcspignore` is supported in the MVP.
- File traversal and object IDs are deterministic.

Default included hidden paths:

- `.codex`
- `.agents`
- `.claude`
- `.cursor`
- `.github`
- common MCP config paths

Default excluded paths:

- `.git`
- `node_modules`
- `dist`
- `build`
- `coverage`
- cache folders
- log folders unless `--include-logs` is set

## Quick Start

```bash
pnpm install
pnpm build
pnpm agentcsp scan examples/vulnerable-agent --out .agentcsp
```

The scan writes:

```text
.agentcsp/agent-manifest.json
.agentcsp/findings.json
.agentcsp/report.md
```

CLI shape:

```bash
agentcsp scan [path] --out .agentcsp
```

Relative `--out` paths are resolved from the current working directory. Absolute paths are preserved.

Useful flags:

```bash
agentcsp scan . \
  --config agentcsp.yaml \
  --format json,md,sarif \
  --fail-on critical \
  --fail-on-confidence high \
  --baseline .agentcsp/previous-findings.json \
  --fail-on-new \
  --no-hidden \
  --include-logs \
  --max-file-size 1048576 \
  --max-files 5000 \
  --quiet
```

AgentCSP exits with code `0` by default when a scan completes, even if findings exist. CI failure is opt-in through `--fail-on critical`, `--fail-on high`, `--fail-on medium`, or `--fail-on low`.

Use `--fail-on-confidence high` or `--fail-on-confidence very_high` with `--fail-on` when CI should fail only on findings that meet both impact and confidence thresholds.

Use `--baseline` with a previous `findings.json` or `agent-manifest.json` to distinguish new, existing, and resolved findings. Add `--fail-on-new` when CI should fail only on new findings that meet the configured severity and confidence thresholds.

Use `--fail-on-diagnostics` when malformed security-relevant configs should fail CI even if findings are otherwise below the configured severity gate. Malformed `agentcsp.yaml` files are reported as redacted diagnostics and scans continue with empty advisory policy so JSON, Markdown, and SARIF evidence are still emitted.

The terminal banner animates only in interactive terminals. It is suppressed by `--quiet`, disabled in CI and piped output, and can be turned off with `AGENTCSP_NO_ANIMATION=1`.

SARIF output is available for CI and code-scanning integrations:

```bash
agentcsp scan . --format json,md,sarif --out .agentcsp
```

## Repository Layout

```text
packages/core   scanner, schemas, rules, policy, risk, reporting
packages/cli    command-line interface
rules           built-in open rule packs
schemas         exported JSON schemas
examples        vulnerable/demo agent projects
docs            product, architecture, roadmap, and usage notes
```

## Manifest

The Agent Manifest is the SBOM equivalent for AI agent deployments. Core sections include:

- `metadata`
- `agents`
- `instructions`
- `skills`
- `plugins`
- `mcp_servers`
- `tools`
- `prompts`
- `rag_sources`
- `memory`
- `secrets`
- `runtime_config`
- `ci_cd`
- `automations`
- `relationships`
- `attack_paths`
- `findings`
- `evidence`
- `diagnostics`
- `triage_summary`
- `baseline_comparison`
- `scan_coverage`
- `static_blast_radius`

Findings include severity, confidence, risk factors, redacted evidence, mappings, and recommended controls. The triage summary gives downstream CI and platform consumers stable counts for active risk, suppressions, confidence, surface types, control mix, top rules, and top active risks.

## Rules

Rules are open YAML files validated by Zod. MVP rules match normalized manifest objects first; graph-edge rules are planned later.

AgentCSP always runs its built-in rule pack. If the scanned repository contains a project-local `rules/` directory, those rules are loaded additively. Malformed local rules and duplicate rule IDs are reported as redacted diagnostics and skipped so they cannot suppress built-in detections.

The built-in rule pack is packaged with `@agentcsp/core` under the compiled distribution, so installed CLI builds do not depend on a checkout-relative root `rules/` directory.

```yaml
id: AGENTCSP-MCP-001
name: MCP server exposes agent-callable authority
category: mcp_authority
severity: medium
match:
  object_type: mcp_server
  where:
    - field: side_effect
      op: equals
      value: true
recommendation:
  control: require_approval
  text: Review MCP tool schemas, auth scope, network reach, and side effects.
```

## Policy

`agentcsp.yaml` is advisory in v1. It supports trust overrides, recommended controls, and auditable suppressions. Runtime enforcement is planned for future MCP and agent-framework adapters.

If `agentcsp.yaml` is malformed, fails schema validation, or an explicitly supplied `--config` path is missing, AgentCSP records a redacted scan diagnostic and continues with empty advisory policy. Default missing policy files do not produce diagnostics.

```yaml
schema_version: "0.1"

trust_overrides:
  - path: "rag/**"
    trust_level: "untrusted"

recommended_controls:
  - id: "deny-unsandboxed-runtime"
    reason: "Organization policy forbids unsandboxed runtime without approval."
    control: "deny"
    match:
      rule_id: "AGENTCSP-RUNTIME-001"
      path: ".codex/config.toml"
```

Reports use "recommended controls" until runtime enforcement exists.

## Roadmap

- CLI scanner and manifest generator
- Built-in rule pack
- JSON and Markdown reports
- SARIF output for CI and GitHub code scanning
- Graph-based blast-radius analysis
- Red-team rule exchange
- Secure RAG and memory lab
- Local and cloud-hostable platform for manifest registry, policy governance, evidence, and AI agent security operations
- Runtime enforcement adapters
- Evidence dashboard

## Open Source Commitment

AgentCSP core is fully open source, self-hostable, local-first, vendor-neutral, and usable without paid APIs. Optional integrations may be added later, but scanning, reporting, rules, and policy evaluation must work locally.

## License

Apache License 2.0.
