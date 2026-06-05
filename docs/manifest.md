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
- `local_command_paths`
- `local_command_path_count`
- `local_command_paths_found`
- `local_command_paths_missing`
- `local_command_paths_missing_count`
- `local_command_paths_all_found`
- `opaque_local_mcp_implementation`
- `package_runner`
- `package_runner_name`
- `package_name`
- `package_version_pinned`
- `package_reference_redacted`
- `values_collected`
- `content_redacted`

Remote third-party MCP servers are treated as external trust boundaries. Credential references and auth headers are represented as key names only. For local MCP launchers, AgentCSP records project-local implementation path references such as `tools/server.js` and whether those files were present in the scan; raw command arguments and secret placeholders remain redacted.

## Instruction Context Signals

Instruction files are normalized into `instruction` objects. AgentCSP records redacted content signals when repository, workspace, or custom instructions connect untrusted inputs to privileged agent behavior.

Instruction metadata may include:

- `content_redacted`
- `content_analyzed`
- `instruction_like_content`
- `instruction_override`
- `untrusted_context_reference`
- `tool_directive`
- `memory_write_directive`
- `external_directive`
- `secret_reference`
- `sensitive_context_reference`
- `data_egress_directive`
- `context_bridge_tool`
- `context_bridge_memory`
- `context_bridge_external`
- `context_bridge_data_egress`
- `context_bridge_privileged`
- `content_signal_count`
- `skipped_for_size`

Raw instruction text is not emitted. These fields let rules detect instruction-boundary designs where customer, user, web, support, or retrieved context can steer tools, memory, or external actions.

The same redacted context signals are used for analyzed RAG, memory, generated-state, and prompt-template files. `data_egress_directive` marks content that tries to move sensitive or internal context toward an external destination, while `context_bridge_data_egress` marks that bridge when the content is also untrusted or retrieved.

## Skill Data-Flow Signals

Skill files are normalized into `skill` objects. AgentCSP records redacted data-flow signals when skills consume agent context and produce side-effecting output.

Skill metadata may include:

- `skill_directory`
- `content_redacted`
- `content_analyzed`
- `retrieved_context_input`
- `tool_output_input`
- `memory_input`
- `prompt_input`
- `context_input_sources`
- `context_input_count`
- `external_output`
- `local_write_output`
- `context_bridge_external_output`

Raw skill text is not emitted. These fields let rules detect skills that bridge retrieved documents, tool output, memory, or prompts into external publication or local writes.

## Tool Schema Authority

Tool definition files are normalized into individual `tool` objects when AgentCSP can parse JSON or YAML tool schemas.

Tool metadata may include:

- `tool_name`
- `parsed_tool_schema`
- `authority_classes`
- `schema_properties`
- `required_properties`
- `accepts_secret_like_input`
- `accepts_content_like_input`
- `accepts_path_input`
- `accepts_url_input`
- `accepts_pii_like_input`
- `accepts_customer_data_input`
- `accepted_data_classes`
- `external_write`
- `destructive_action`
- `read_only_hint`
- `idempotent_hint`
- `read_only_hint_conflict`
- `open_world_authority`
- `open_world_schema`
- `name_collision`
- `collision_name`
- `collision_count`
- `collision_paths`
- `collision_trust_levels`
- `collision_authority_mismatch`
- `collision_has_privileged_peer`

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
- `permission_allowlist`
- `permission_denylist`
- `auto_approved_package_script_names`
- `auto_approved_mcp_servers`
- `auto_approved_mcp_tool_refs`
- `auto_approved_mcp_tool_count`
- `auto_approved_destructive_mcp_servers`
- `auto_approved_destructive_mcp_tool_refs`
- `auto_approved_destructive_mcp_tool_count`
- `auto_approved_destructive_mcp_tools`
- `auto_approved_network_tools`
- `auto_approved_network_scope_kinds`
- `auto_approved_network_scope_count`
- `auto_approved_wildcard_network_scope`
- `auto_approved_unscoped_network_tool`
- `auto_approved_broad_network_scope`
- `auto_approved_tools_redacted`
- `auto_approved_tool_count`
- `auto_approved_privileged_tool_count`
- `auto_approved_privileged_tool_signal_count`
- `auto_approved_privileged_tools`
- `auto_approved_privileged_tool_signals`
- `privileged_tools_allowed`
- `privileged_tool_signals`
- `referenced_mcp_servers`
- `referenced_mcp_count`
- `referenced_privileged_mcp_servers`
- `referenced_privileged_mcp_count`
- `referenced_secret_backed_mcp_servers`
- `referenced_secret_backed_mcp_count`
- `referenced_auto_approved_package_scripts`
- `referenced_auto_approved_package_script_count`
- `referenced_release_package_scripts`
- `referenced_release_package_script_count`
- `auto_approved_package_script_bridge`
- `auto_approved_release_package_script_bridge`
- `mcp_runtime_bridge`
- `privileged_mcp_runtime_bridge`
- `secret_backed_mcp_runtime_bridge`
- `approvalless_privileged_mcp_bridge`
- `approvalless_secret_mcp_bridge`
- `env_key_names`
- `secret_env_exposure`
- `secret_values_collected`

Network permission scopes are normalized into bounded categories such as `wildcard_domain`, `scoped_domain`, and `unscoped_network_tool`; raw runtime permission strings, domains, URLs, and argument values are not emitted.

Secret or environment values are not emitted. Permission allowlists are normalized to canonical tool names, MCP tool references, package script names, and capability classes instead of raw command patterns. AgentCSP records key names, runtime posture, explicit MCP references, and exact package-script references so rules can detect risky authority without exposing credentials or dumping runtime config values.

## Prompt Template Signals

Prompt template files are normalized into `prompt` objects when they appear under common prompt/template paths or use prompt-specific filenames.

Prompt metadata may include:

- `content_redacted`
- `content_analyzed`
- `prompt_template`
- `template_variable_names`
- `template_variable_count`
- `untrusted_template_variables`
- `untrusted_template_input`
- `template_bridge_tool`
- `template_bridge_memory`
- `template_bridge_external`
- `template_bridge_secret`
- `template_bridge_privileged`
- `instruction_like_content`
- `instruction_override`
- `tool_directive`
- `memory_write_directive`
- `external_directive`
- `secret_reference`
- `referenced_tools`
- `referenced_tool_count`
- `referenced_privileged_tools`
- `referenced_privileged_tool_count`
- `referenced_mcp_servers`
- `referenced_mcp_count`
- `referenced_privileged_mcp_servers`
- `referenced_privileged_mcp_count`
- `explicit_tool_reference`
- `explicit_mcp_reference`
- `explicit_callable_reference`
- `privileged_callable_reference`
- `content_signal_count`
- `skipped_for_size`

Raw prompt text is not emitted. AgentCSP records variable names, normalized context signals, and references to discovered callable names so rules can detect prompt templates that bridge untrusted input into specific privileged tools, MCP servers, memory, external, or secret-sensitive actions.

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
- `referenced_tools`
- `referenced_tool_count`
- `referenced_privileged_tools`
- `referenced_privileged_tool_count`
- `referenced_mcp_servers`
- `referenced_mcp_count`
- `referenced_privileged_mcp_servers`
- `referenced_privileged_mcp_count`
- `explicit_tool_reference`
- `explicit_mcp_reference`
- `explicit_callable_reference`
- `privileged_callable_reference`
- `content_signal_count`
- `skipped_for_size`

Raw RAG, memory, transcript, and cached-output text is not emitted. AgentCSP records normalized signals and exact references to already-discovered callables so rules can reason about indirect prompt injection, generated-state replay, and cross-session contamination without publishing the content.

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
- `run_commands_redacted`
- `run_command_count`
- `package_manager_run`
- `agent_run_command`
- `agent_package_script_names`
- `referenced_package_scripts`
- `referenced_package_script_count`
- `referenced_agent_package_scripts`
- `referenced_agent_package_script_count`
- `package_script_bridge`
- `agent_package_script_bridge`
- `has_permissions_block`
- `content_redacted`

Automation surfaces let rules reason about scheduled agents, manual dispatches, webhook-style dispatches, and background workflows that can run agent scripts with secrets or write authority.

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

`relationships` are static graph edges between normalized surfaces. They are intentionally bounded and evidence-backed. Context-to-capability influence edges require concrete normalized signals such as instruction-like content, tool directives, external directives, data-egress directives, memory-write directives, generated-state replay signals, or explicit instruction/skill authority. Runtime-to-package-script trigger edges require redacted permission allowlist metadata that references a concrete package script. Heuristic-only RAG, memory, and log directory markers do not create influence paths by themselves.

Examples:

- `rag_source -> tool` with relation `influences`
- `secret -> mcp_server` with relation `uses_secret`
- `instruction -> ci_cd` with relation `influences`
- `memory -> tool` with relation `influences`
- `runtime_config -> tool` with relation `triggers`

## Attack Paths

`attack_paths` are prioritized paths that combine relationships with findings. They are designed to show security teams how context provenance can reach authority, data classes, and side effects. The list is capped and sorted toward high-impact, high-confidence, file-specific paths.

Attack paths may be anchored on target findings, such as a risky tool schema, or source findings, such as retrievable content that directs sensitive context toward an external destination. Source-anchored data-egress, customer-data egress, memory replay, generated-state replay, runtime auto-approval, and untrusted-template-to-tool paths are prioritized so the Static Blast-Radius Summary preserves why the source itself is dangerous. When a context source names a discovered privileged tool or MCP server, AgentCSP prefers that exact source-to-callable path and suppresses broader speculative attack-path entries for the same source.

An attack path includes:

- source surface
- target surface
- relationship edges
- severity
- confidence
- risk factors
- recommended control
- redacted evidence

## Static Blast-Radius Summary

`static_blast_radius` is a bounded rollup of the graph, findings, and normalized surfaces. It does not claim runtime traversal; it summarizes discovered static authority and data exposure so teams can triage likely blast radius quickly.

The summary includes:

- read, write, execute, external reach, and secret-reference path counts
- sensitive-data, PII, and credential external-reach counts
- sensitive-data, PII, and credential attack-path counts
- RAG and memory surface counts
- relationship, attack-path, and critical attack-path counts
- active and expired suppression counts
- highest severity
- capped high-risk objects
- recommended controls

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
