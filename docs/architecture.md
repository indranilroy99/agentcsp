# Architecture Notes

## Core Data Model

AgentCSP should model the agent environment as a graph:

- Principals: users, agents, subagents, service accounts, CI jobs
- Context sources: prompts, skills, RAG docs, memory, web pages, emails, tool outputs, logs
- Capabilities: tools, MCP functions, shell commands, API operations, filesystem access
- Data classes: public, internal, confidential, secret, credential, PII
- Trust levels: trusted, project, workspace, third-party, untrusted, unknown
- Actions: read, write, execute, publish, send, delete, approve, remember
- Controls: allow, deny, require approval, redact, quarantine, sandbox, rate-limit

## Main Pipeline

1. Discover surfaces.
2. Normalize metadata into an Agent Manifest.
3. Classify trust, permissions, data classes, and side effects.
4. Build provenance and authority graph.
5. Run static checks and rule packs.
6. Generate red-team scenarios.
7. Simulate blast radius.
8. Produce reports and evidence.
9. Enforce policies at runtime where integrations exist.

## Manifest Concept

The Agent Manifest is the SBOM equivalent for an AI agent deployment. It should be exportable as JSON and eventually support signing.

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

