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
- Add runtime posture inventory for sandbox, approval, network, tool authority, and agent safety-control posture.
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
