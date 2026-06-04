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

## Tool Schema Authority

Tool definition files are normalized into individual `tool` objects when AgentCSP can parse JSON or YAML tool schemas.

Tool metadata may include:

- `tool_name`
- `parsed_tool_schema`
- `authority_classes`
- `schema_properties`
- `required_properties`
- `accepts_secret_like_input`
- `accepts_path_input`
- `accepts_url_input`
- `external_write`
- `destructive_action`
- `read_only_hint`
- `idempotent_hint`
- `open_world_schema`

These fields let rules reason about concrete agent-callable authority without dumping raw tool descriptions or schemas into the manifest.

## Runtime Configuration

Runtime configuration files are normalized into `runtime_config` objects when AgentCSP can parse security-relevant JSON, YAML, or TOML config.

Runtime metadata may include:

- `parsed_runtime_config`
- `runtime_fields`
- `sandbox_mode`
- `sandbox_disabled`
- `workspace_write`
- `approval_policy`
- `approval_bypass`
- `network_access`
- `network_enabled`
- `allowed_tools`
- `disabled_tools`
- `privileged_tools_allowed`
- `privileged_tool_signals`
- `env_key_names`
- `secret_env_exposure`
- `secret_values_collected`

Secret or environment values are not emitted. AgentCSP records key names and posture signals so rules can detect risky authority without exposing credentials.

## Findings

Each finding includes:

- `severity`
- `confidence`
- `confidence_rationale`
- `risk`
- `matched_object`
- `recommended_control`
- optional `policy_control`
- `maps_to`
- `evidence`
- optional `suppression`

Confidence is separate from severity. Severity describes potential impact; confidence describes how strongly the normalized evidence supports the finding.

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
