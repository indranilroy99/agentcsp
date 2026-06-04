# Agent Manifest

The Agent Manifest is the SBOM equivalent for an AI agent deployment.

It captures normalized agent-facing surfaces, authority signals, trust levels, data classes, findings, evidence, and the Static Blast-Radius Summary.

Core sections:

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
- `findings`
- `evidence`

The manifest is versioned and validated with Zod. JSON Schema exports live in `schemas/`.
