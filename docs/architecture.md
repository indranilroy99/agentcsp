# Architecture

This document separates the implemented v0.2 scanner from longer-term platform direction. The current product is a local, static, advisory repository scanner.

## Core Data Model

AgentCSP should model the agent environment as a graph:

- Principals: users, agents, subagents, service accounts, CI jobs
- Context sources: prompts, skills, RAG docs, memory, web pages, emails, tool outputs, logs
- Capabilities: tools, MCP functions, shell commands, API operations, filesystem access, authorization brokers
- Data classes: public, internal, confidential, secret, credential, PII
- Trust levels: trusted, project, workspace, third-party, untrusted, unknown
- Actions: read, write, execute, publish, send, delete, approve, remember
- Controls: allow, deny, require approval, redact, quarantine, sandbox, rate-limit

## v0.2 Pipeline

1. Discover surfaces.
2. Normalize metadata into an Agent Manifest.
3. Classify trust, permissions, data classes, and side effects.
4. Build static provenance and authority relationships.
5. Run constrained advisory rules over normalized manifest objects.
6. Build bounded static attack paths and a Static Blast-Radius Summary.
7. Apply advisory policy, suppressions, baselines, and explicit CI gates.
8. Produce redacted JSON, Markdown, and SARIF evidence transactionally.

The current static graph is intentionally conservative. It prioritizes file-specific context-to-capability paths only when normalized evidence shows instruction-like content, tool directives, external directives, memory-write directives, generated-state replay, exact runtime permission-to-package-script references, or explicit instruction/skill authority. When context names a concrete privileged callable, the prioritized attack-path list keeps the exact path and avoids broad speculative entries from that same source. This keeps the MVP useful for security review without implying complete runtime graph traversal.

v0.2 does not generate executable red-team scenarios, prove runtime reachability, or enforce controls at runtime. Those capabilities require separately threat-modeled adapters and are roadmap work, not implicit behavior of the static pipeline.

## Future Platform Direction

The long-term architecture may add independently deployed runtime adapters, signed evidence, fleet inventory, and organization policy. Those components must consume stable manifest and finding contracts and must not weaken the local scanner's deterministic, vendor-neutral operation.

## Manifest Concept

The Agent Manifest is an SBOM-style inventory for the AI-agent surfaces visible in a repository. It is exported as JSON and is designed to support signing in a later schema version.

Key sections:

- agents
- skills
- plugins
- mcp_servers
- tools
- prompts
- memory
- rag_sources
- secrets
- policies
- findings
- evidence

## Rule Concept

Rules should be declarative, portable, and reviewable. Think Sigma/YARA style for AI agent systems.

Initial rule categories:

- prompt injection
- indirect prompt injection
- tool poisoning
- tool shadowing
- memory poisoning
- RAG poisoning
- system prompt extraction
- secret exfiltration
- excessive agency
- unsafe code execution
- irreversible external write
- unbounded consumption
