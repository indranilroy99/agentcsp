# Agent Manifest

The Agent Manifest is the SBOM equivalent for an AI agent deployment.

It captures normalized agent-facing surfaces, authority signals, trust levels, data classes, findings, evidence, diagnostics, the Triage Summary, optional baseline comparison, scan coverage, and the Static Blast-Radius Summary.

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
- `diagnostics`
- `triage_summary`
- `baseline_comparison`
- `scan_coverage`
- `static_blast_radius`

The manifest is versioned and validated with Zod. JSON Schema exports live in `schemas/`.

## MCP Server Authority

MCP server entries are normalized into `mcp_server` objects. For remote MCP servers, AgentCSP records posture metadata without emitting raw URLs or header values.

MCP metadata may include:

- `command_name`
- `args_count`
- `transport`
- `remote`
- `remote_host`
- `remote_scheme`
- `url_redacted`
- `header_names`
- `auth_header_names`
- `env_key_names`
- `secret_ref_key_names`
- `values_collected`
- `content_redacted`

Remote third-party MCP servers are treated as external trust boundaries. Credential references and auth headers are represented as key names only.

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
- `read_only_hint_conflict`
- `open_world_authority`
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

## RAG, Memory, and Generated-State Signals

RAG and memory files are normalized into file-level `rag_source` and `memory` objects when they appear under common retrieval, vector, memory, summary, or state paths.

Content metadata may include:

- `content_redacted`
- `content_analyzed`
- `generated_state`
- `generated_state_kinds`
- `transcript_like`
- `tool_output_like`
- `cached_output_like`
- `instruction_like_content`
- `instruction_override`
- `tool_directive`
- `memory_write_directive`
- `external_directive`
- `secret_reference`
- `content_signal_count`
- `skipped_for_size`

Raw RAG, memory, transcript, and cached-output text is not emitted. AgentCSP records normalized signals so rules can reason about indirect prompt injection, generated-state replay, and cross-session contamination without publishing the content.

## Automations

GitHub workflow triggers that can run outside a normal direct code-review path are normalized into `automation` objects.

Automation metadata may include:

- `trigger_names`
- `automation_triggers`
- `scheduled`
- `manual_dispatch`
- `external_dispatch`
- `workflow_run_trigger`
- `write_permissions`
- `mentions_secrets_context`
- `has_permissions_block`
- `content_redacted`

Automation surfaces let rules reason about scheduled agents, manual dispatches, webhook-style dispatches, and background workflows that can run with secrets or write authority.

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
- optional `baseline_status`

Confidence is separate from severity. Severity describes potential impact; confidence describes how strongly the normalized evidence supports the finding.

## Triage Summary

`triage_summary` is the stable operator-facing rollup for scan results. It is generated after policy controls and suppressions are applied, so active findings exclude accepted active suppressions while expired suppressions remain visible as risk.

The summary includes:

- total, active, suppressed, and expired-suppression counts
- highest active severity
- maximum active risk score
- active findings by severity and confidence
- active findings by surface type, category, and recommended control
- top active rules
- top active risks with finding IDs, object IDs, paths, risk scores, and recommended controls

The triage summary does not include raw file contents, evidence snippets, secret values, or unredacted tool/runtime configuration values.

## Baseline Comparison

`baseline_comparison` is present when the scan is run with a previous `findings.json` or `agent-manifest.json` baseline.

The comparison includes:

- baseline path and format
- current and baseline finding counts
- new, existing, and resolved finding counts
- stable new finding IDs
- stable resolved finding IDs

Current findings include `baseline_status` set to `new` or `existing` when a baseline is loaded. Resolved findings are represented by ID in `baseline_comparison.resolved_finding_ids`; their previous raw content is not copied into the new manifest.

## Scan Coverage

`scan_coverage` records deterministic scan-scope counts so teams can review whether a scan was complete enough for CI, audit, or release decisions.

The summary includes:

- directories visited
- files seen and indexed
- files skipped because they exceeded `max_file_size_bytes`
- files and directories skipped by default ignore rules or `.agentcspignore`
- hidden directories skipped
- log directories skipped
- whether `max_files` was reached
- configured `max_files` and `max_file_size_bytes`

Coverage counts do not include raw file contents or skipped path lists.

## Diagnostics

`diagnostics` records scan health issues that may affect completeness, such as malformed MCP configs, runtime configs, package manifests, workflow files, or tool definition files.

Each diagnostic includes:

- stable diagnostic ID
- severity
- code
- file path
- parser
- reason
- `content_redacted: true`

Diagnostics do not include raw parser stack traces, raw file contents, secret values, or evidence snippets.

## Relationships

`relationships` are static graph edges between normalized surfaces. They are intentionally bounded and evidence-backed. Context-to-capability influence edges require concrete normalized signals such as instruction-like content, tool directives, external directives, memory-write directives, generated-state replay signals, or explicit instruction/skill authority. Heuristic-only RAG, memory, and log directory markers do not create influence paths by themselves.

Examples:

- `rag_source -> tool` with relation `influences`
- `secret -> mcp_server` with relation `uses_secret`
- `instruction -> ci_cd` with relation `influences`
- `memory -> tool` with relation `influences`

## Attack Paths

`attack_paths` are prioritized paths that combine relationships with findings. They are designed to show security teams how context provenance can reach authority, data classes, and side effects. The list is capped and sorted toward high-impact, high-confidence, file-specific paths.

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
