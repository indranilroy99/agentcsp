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
- `relationships`
- `attack_paths`
- `findings`
- `evidence`

The manifest is versioned and validated with Zod. JSON Schema exports live in `schemas/`.

## Relationships

`relationships` are static graph edges between normalized surfaces. They are intentionally bounded and evidence-backed.

Examples:

- `rag_source -> tool` with relation `influences`
- `secret -> mcp_server` with relation `uses_secret`
- `instruction -> ci_cd` with relation `influences`
- `memory -> tool` with relation `influences`

## Attack Paths

`attack_paths` are prioritized paths that combine relationships with findings. They are designed to show security teams how context provenance can reach authority, data classes, and side effects.

An attack path includes:

- source surface
- target surface
- relationship edges
- severity
- confidence
- risk factors
- recommended control
- redacted evidence

## Suppression State

Findings may include a `suppression` object when they match a policy suppression.

Active suppressions are excluded from CI failure gates. Expired suppressions are retained on the finding but treated as active risk.

Suppression fields:

- `id`
- `status`
- `reason`
- `owner`
- `expires_at`
- `matched_on`
- `applied_at`
