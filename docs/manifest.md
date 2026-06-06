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
- `plaintext_remote_transport`
- `encrypted_remote_transport`
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

Remote third-party MCP servers are treated as external trust boundaries. Credential references and auth headers are represented as key names only. Plaintext remote transport is represented as a boolean posture signal without emitting the raw URL. For local MCP launchers, AgentCSP records project-local implementation path references such as `tools/server.js` and whether those files were present in the scan; raw command arguments and secret placeholders remain redacted.

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

Cursor project rules under `.cursor/rules/` are normalized as `instruction` objects with additional redacted metadata:

- `cursor_rule`
- `cursor_rule_frontmatter_present`
- `cursor_rule_frontmatter_parsed`
- `cursor_rule_body_redacted`
- `cursor_rule_description_present`
- `cursor_rule_always_apply`
- `cursor_rule_application_mode`
- `cursor_rule_glob_count`
- `cursor_rule_glob_scope_kinds`
- `cursor_rule_applies_broadly`

AgentCSP does not emit Cursor rule descriptions, glob values, or body text. Glob scopes are reduced to coarse categories such as `all_files`, `workspace`, `code`, `docs`, and `config` so rules can identify broad always-applied authority without leaking repository-specific path patterns.

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
- `model_visible_description_analyzed`
- `model_visible_description_redacted`
- `model_visible_description_instruction_like_content`
- `model_visible_description_instruction_override`
- `model_visible_description_untrusted_context_reference`
- `model_visible_description_tool_directive`
- `model_visible_description_memory_write_directive`
- `model_visible_description_external_directive`
- `model_visible_description_secret_reference`
- `model_visible_description_sensitive_context_reference`
- `model_visible_description_data_egress_directive`
- `model_visible_description_context_bridge_tool`
- `model_visible_description_context_bridge_memory`
- `model_visible_description_context_bridge_external`
- `model_visible_description_context_bridge_data_egress`
- `model_visible_description_context_bridge_privileged`
- `model_visible_description_signal_count`
- `name_collision`
- `collision_name`
- `collision_count`
- `collision_paths`
- `collision_trust_levels`
- `collision_authority_mismatch`
- `collision_has_privileged_peer`

These fields let rules reason about concrete agent-callable authority without dumping raw tool descriptions or schemas into the manifest. Model-visible descriptions are treated as prompt surface: AgentCSP records redacted instruction, untrusted-context, external, memory, secret, and data-egress signals so rules can detect poisoned tool metadata attached to side-effecting authority.

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

## Browser Session Posture

Browser, Playwright, Puppeteer, Selenium, and browser-agent session configs are also normalized into `runtime_config` objects when common browser session configuration files are discovered.

Browser session metadata may include:

- `parsed_browser_session_config`
- `browser_fields`
- `browser_provider`
- `browser_persistent_profile`
- `browser_cookie_storage`
- `browser_session_storage`
- `browser_authenticated_session`
- `browser_remote_debugging`
- `browser_untrusted_navigation`
- `browser_click_or_form_authority`
- `browser_download_upload_enabled`
- `browser_network_remote`
- `browser_broad_origin_access`
- `browser_destination_redacted`
- `browser_destination_count`
- `browser_destination_kinds`
- `browser_path_references_redacted`
- `browser_sensitive_data`
- `browser_pii_data`
- `env_key_names`
- `secret_ref_key_names`

Raw cookie files, storage-state files, profile paths, origins, browser endpoints, hostnames, and secret placeholders are not emitted. Provider names, broad-origin categories, authenticated-session booleans, untrusted-navigation signals, click/form authority, path-redaction flags, and credential key names let rules detect browser-agent account-action risk without copying browser state into the manifest.

## Inbound Agent Trigger Posture

Inbound email, chat, ticket, webhook, queue, and listener configs are also normalized into `runtime_config` objects when common inbound-agent trigger files are discovered.

Inbound trigger metadata may include:

- `parsed_inbound_trigger_config`
- `inbound_trigger_fields`
- `inbound_trigger_provider`
- `inbound_trigger_external_source`
- `inbound_trigger_source_redacted`
- `inbound_trigger_source_count`
- `inbound_trigger_source_categories`
- `inbound_trigger_payload_redacted`
- `inbound_trigger_payload_categories`
- `inbound_trigger_invokes_agent`
- `inbound_trigger_invokes_tools`
- `inbound_trigger_tool_authority_categories`
- `inbound_trigger_write_authority`
- `inbound_trigger_external_response`
- `inbound_trigger_memory_write`
- `inbound_trigger_sensitive_context`
- `inbound_trigger_pii_context`
- `inbound_trigger_attachment_context`
- `inbound_trigger_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw mailbox names, sender addresses, queue names, webhook URLs, prompt-field expressions, labels, channel names, agent names, and payload content are not emitted. Provider names, source categories, payload categories, tool-authority categories, approval posture, data-class booleans, and credential key names let rules detect direct paths from untrusted inbound messages into privileged agent execution.

## Agent Orchestration Posture

CrewAI, AutoGen, LangGraph, Semantic Kernel, swarm-style, and other multi-agent orchestration configs are also normalized into `runtime_config` objects when common orchestration configuration files are discovered.

Agent orchestration metadata may include:

- `parsed_agent_orchestration_config`
- `agent_orchestration_fields`
- `agent_orchestration_framework`
- `agent_orchestration_multi_agent`
- `agent_orchestration_agent_count`
- `agent_orchestration_agent_names_redacted`
- `agent_orchestration_delegation_enabled`
- `agent_orchestration_delegation_categories`
- `agent_orchestration_untrusted_input`
- `agent_orchestration_shared_memory`
- `agent_orchestration_memory_redacted`
- `agent_orchestration_invokes_tools`
- `agent_orchestration_tool_authority_categories`
- `agent_orchestration_privileged_agent`
- `agent_orchestration_write_authority`
- `agent_orchestration_external_authority`
- `agent_orchestration_secret_authority`
- `agent_orchestration_sensitive_data`
- `agent_orchestration_pii_data`
- `agent_orchestration_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw agent names, crew names, role prompts, task descriptions, memory namespaces, graph labels, tool lists, and secret placeholders are not emitted. Framework names, counts, redacted delegation categories, shared-memory posture, tool-authority categories, approval posture, data-class booleans, and credential key names let rules detect indirect prompt-injection paths across agent handoffs without copying orchestration content into the manifest.

## Agent Safety Control Posture

Agent safety, guardrail, moderation, validation, sanitization, and redaction configs are normalized into `runtime_config` objects when common control configuration files are discovered.

Agent safety metadata may include:

- `parsed_agent_safety_config`
- `agent_safety_fields`
- `agent_safety_framework`
- `agent_safety_controls_declared`
- `agent_safety_controls_disabled`
- `agent_safety_disabled_controls`
- `agent_safety_prompt_injection_filter_disabled`
- `agent_safety_output_validation_disabled`
- `agent_safety_tool_result_sanitization_disabled`
- `agent_safety_content_moderation_disabled`
- `agent_safety_pii_redaction_disabled`
- `agent_safety_secret_redaction_disabled`
- `agent_safety_untrusted_input`
- `agent_safety_privileged_tool_authority`
- `agent_safety_tool_authority_categories`
- `agent_safety_write_authority`
- `agent_safety_external_authority`
- `agent_safety_memory_write_authority`
- `agent_safety_secret_exposure`
- `agent_safety_sensitive_data`
- `agent_safety_pii_data`
- `agent_safety_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw policy names, source names, tool strings, action lists, data-field labels, prompt text, and secret placeholders are not emitted. Framework names, disabled-control categories, tool-authority categories, approval posture, data-class booleans, and credential key names let rules detect when weakened safety controls expose privileged agent actions without copying control policy contents into the manifest.

## AI Eval Harness Posture

AI eval, red-team, adversarial scenario, and prompt test harness configs are normalized into `runtime_config` objects when common eval configuration files are discovered.

AI eval metadata may include:

- `parsed_ai_eval_harness_config`
- `ai_eval_fields`
- `ai_eval_framework`
- `ai_eval_live_execution`
- `ai_eval_adversarial_cases`
- `ai_eval_untrusted_prompts`
- `ai_eval_dataset_redacted`
- `ai_eval_dataset_count`
- `ai_eval_invokes_agent`
- `ai_eval_invokes_tools`
- `ai_eval_tool_authority_categories`
- `ai_eval_write_authority`
- `ai_eval_external_write_authority`
- `ai_eval_remote_target`
- `ai_eval_production_target`
- `ai_eval_records_outputs`
- `ai_eval_sensitive_data`
- `ai_eval_pii_data`
- `ai_eval_secret_exposure`
- `ai_eval_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw suite names, scenario names, prompts, target URLs, agent names, tool strings, assertion values, output paths, data-field labels, and secret placeholders are not emitted. Framework names, redacted dataset counts, tool-authority categories, production/live execution posture, output retention, approval posture, data-class booleans, and credential key names let rules detect red-team harnesses that can hit real agents with real authority.

## Agent Identity Delegation Posture

Agent identity, OAuth, OIDC, service-account, workload-identity, IAM, and credential-delegation configs are also normalized into `runtime_config` objects when common identity configuration files are discovered.

Agent identity metadata may include:

- `parsed_agent_identity_config`
- `agent_identity_fields`
- `agent_identity_provider`
- `agent_identity_remote`
- `agent_identity_destination_redacted`
- `agent_identity_destination_count`
- `agent_identity_destination_kinds`
- `agent_identity_issuer_redacted`
- `agent_identity_subject_redacted`
- `agent_identity_scope_redacted`
- `agent_identity_scope_categories`
- `agent_identity_broad_scope`
- `agent_identity_admin_scope`
- `agent_identity_write_scope`
- `agent_identity_credential_issuance_enabled`
- `agent_identity_impersonation_enabled`
- `agent_identity_token_refresh_enabled`
- `agent_identity_tool_injection`
- `agent_identity_external_authority`
- `agent_identity_untrusted_input`
- `agent_identity_sensitive_data`
- `agent_identity_pii_data`
- `agent_identity_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw issuer URLs, token endpoints, service-account identifiers, OAuth scopes, IAM roles, subject mappings, tenant IDs, audience values, delegated subject labels, tool names, data-field labels, and secret placeholders are not emitted. Provider names, redacted destination categories, normalized scope categories, credential-issuance and impersonation posture, subject-redaction flags, approval posture, data-class booleans, and credential key names let rules detect over-authorized agent identity delegation without copying identity configuration values into the manifest.

## SaaS And API Connector Posture

SaaS, API, ticketing, messaging, email, CRM, and repository-service connector configs are also normalized into `runtime_config` objects when common connector configuration files are discovered.

SaaS connector metadata may include:

- `parsed_saas_connector_config`
- `saas_connector_fields`
- `saas_connector_provider`
- `saas_connector_external_reach`
- `saas_connector_destination_redacted`
- `saas_connector_destination_count`
- `saas_connector_destination_kinds`
- `saas_connector_scope_redacted`
- `saas_connector_scope_categories`
- `saas_connector_broad_scope`
- `saas_connector_admin_scope`
- `saas_connector_read_enabled`
- `saas_connector_external_write_enabled`
- `saas_connector_untrusted_input`
- `saas_connector_sensitive_data`
- `saas_connector_pii_data`
- `saas_connector_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw OAuth scopes, endpoint URLs, webhook URLs, workspace names, channel names, queue names, repository names, customer-system labels, and secret placeholders are not emitted. Provider names, redacted destination categories, normalized scope categories, write/read posture, untrusted-input booleans, approval posture, and credential key names let rules detect over-authorized SaaS connectors without copying integration configuration into the manifest.

## Secret Manager Posture

Vault, cloud secret manager, key vault, KMS, Kubernetes secret, and credential-broker configs are also normalized into `runtime_config` objects when common secret-manager configuration files are discovered.

Secret manager metadata may include:

- `parsed_secret_manager_config`
- `secret_manager_fields`
- `secret_manager_provider`
- `secret_manager_remote`
- `secret_manager_destination_redacted`
- `secret_manager_destination_count`
- `secret_manager_destination_kinds`
- `secret_manager_scope_redacted`
- `secret_manager_scope_categories`
- `secret_manager_path_references_redacted`
- `secret_manager_read_enabled`
- `secret_manager_list_enabled`
- `secret_manager_write_enabled`
- `secret_manager_broad_scope`
- `secret_manager_injects_into_tools`
- `secret_manager_untrusted_input`
- `secret_manager_sensitive_scope`
- `secret_manager_pii_scope`
- `secret_manager_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw vault URLs, secret paths, resource names, policy names, role names, project IDs, namespaces, ARNs, key names, and secret placeholders are not emitted. Provider names, redacted destination categories, normalized scope categories, read/list/write posture, tool-injection booleans, untrusted-input signals, approval posture, and credential key names let rules detect credential-broker blast radius without copying secret inventory into the manifest.

## Database Connector Posture

Database, SQL, warehouse, and datastore connector configs are also normalized into `runtime_config` objects when common database connector configuration files are discovered.

Database connector metadata may include:

- `parsed_database_connector_config`
- `database_fields`
- `database_provider`
- `database_remote`
- `database_destination_redacted`
- `database_remote_destination_count`
- `database_remote_destination_kinds`
- `database_read_enabled`
- `database_write_enabled`
- `database_delete_enabled`
- `database_query_execution_enabled`
- `database_untrusted_query_input`
- `database_sensitive_data`
- `database_pii_data`
- `database_table_names_redacted`
- `env_key_names`
- `secret_ref_key_names`

Raw database hosts, connection strings, database names, usernames, table names, query examples, and secret placeholders are not emitted. Provider names, destination categories, read/write/query posture, data-class booleans, table-name redaction flags, and credential key names let rules detect agent-controlled database authority without copying database configuration values into the manifest.

## AI Model Endpoint Posture

AI model provider, gateway, router, proxy, and inference configs are also normalized into `runtime_config` objects when common model endpoint configuration files are discovered.

Model endpoint metadata may include:

- `parsed_ai_model_config`
- `ai_model_fields`
- `ai_model_provider`
- `ai_model_remote_endpoint`
- `ai_model_custom_endpoint`
- `ai_model_destination_redacted`
- `ai_model_remote_destination_count`
- `ai_model_remote_destination_kinds`
- `ai_model_plaintext_endpoint`
- `ai_model_encrypted_endpoint`
- `ai_model_sends_prompts`
- `ai_model_sends_tool_outputs`
- `ai_model_sends_retrieval_context`
- `ai_model_sends_memory`
- `ai_model_sensitive_context`
- `ai_model_pii_context`
- `env_key_names`
- `secret_ref_key_names`

Raw model gateway URLs, model names, base URLs, request payload examples, and secret placeholders are not emitted. Provider names, redacted destination categories, transport posture, context booleans, and credential key names let rules detect risky model endpoints without copying prompts, tool outputs, memory, retrieval content, or endpoint values into the manifest.

## AI Telemetry Export

AI telemetry and trace-export configs are also normalized into `runtime_config` objects when common observability, tracing, LangSmith, Langfuse, Helicone, Braintrust, OpenTelemetry, or similar configuration files are discovered.

Telemetry metadata may include:

- `parsed_ai_telemetry_config`
- `ai_telemetry_fields`
- `ai_telemetry_provider`
- `ai_telemetry_export_enabled`
- `ai_telemetry_remote_export`
- `ai_telemetry_destination_redacted`
- `ai_telemetry_remote_destination_count`
- `ai_telemetry_remote_destination_kinds`
- `ai_telemetry_captures_prompts`
- `ai_telemetry_captures_completions`
- `ai_telemetry_captures_tool_outputs`
- `ai_telemetry_captures_retrieval`
- `ai_telemetry_captures_memory`
- `ai_telemetry_sensitive_capture`
- `ai_telemetry_pii_capture`
- `ai_telemetry_secret_capture_signal`
- `ai_telemetry_redaction_disabled`
- `ai_telemetry_retention_enabled`
- `env_key_names`
- `secret_ref_key_names`

Raw telemetry endpoints, project names, trace payloads, sampled content, and secret placeholders are not emitted. Provider names, redacted destination categories, field paths, capture booleans, retention signals, redaction posture, and credential key names let rules detect sensitive trace export without copying observability configuration values into the manifest.

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
- `privileged_prompt_role`
- `privileged_template_roles`
- `privileged_role_untrusted_variables`
- `privileged_role_untrusted_variable_count`
- `privileged_role_untrusted_template_input`
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

Raw prompt text is not emitted. AgentCSP records variable names, normalized context signals, privileged role-boundary signals, and references to discovered callable names so rules can detect prompt templates that bridge untrusted input into system/developer roles, specific privileged tools, MCP servers, memory, external, or secret-sensitive actions.

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

Agent memory-store configs are also normalized into `memory` objects when common memory, checkpoint, state, session, or long-term memory configuration files are discovered.

Memory-store metadata may include:

- `parsed_agent_memory_store_config`
- `parse_error`
- `agent_memory_store_fields`
- `agent_memory_store_provider`
- `agent_memory_store_remote`
- `agent_memory_store_destination_redacted`
- `agent_memory_store_destination_count`
- `agent_memory_store_destination_kinds`
- `agent_memory_store_persistent`
- `agent_memory_store_shared`
- `agent_memory_store_write_enabled`
- `agent_memory_store_sync_enabled`
- `agent_memory_store_untrusted_write`
- `agent_memory_store_tool_output_capture`
- `agent_memory_store_prompt_capture`
- `agent_memory_store_retrieval_capture`
- `agent_memory_store_secret_capture`
- `agent_memory_store_output_replay_enabled`
- `agent_memory_store_sensitive_data`
- `agent_memory_store_pii_data`
- `agent_memory_store_namespace_redacted`
- `agent_memory_store_approval_required`
- `env_key_names`
- `secret_ref_key_names`
- `values_collected`

Raw memory-store URLs, connection strings, collection names, namespaces, key prefixes, source labels, replay targets, data-field labels, and secret placeholders are not emitted. Provider names, redacted destination categories, capture/replay booleans, sharing and persistence posture, approval posture, data-class booleans, and credential key names let rules detect durable memory poisoning and cross-session context replay without copying memory configuration values into the manifest.

RAG and vector-store connector configs are also normalized into `rag_source` objects when common retrieval, vector, embedding, or knowledge-store configuration files are discovered.

Connector metadata may include:

- `parsed_rag_connector_config`
- `parse_error`
- `rag_connector_fields`
- `vector_store`
- `vector_store_provider`
- `vector_store_remote`
- `vector_store_destination_redacted`
- `vector_store_remote_destination_count`
- `vector_store_remote_destination_kinds`
- `vector_store_write_enabled`
- `vector_store_sync_enabled`
- `vector_store_ingests_untrusted_sources`
- `vector_store_sensitive_collection`
- `vector_store_pii_collection`
- `vector_store_namespace_redacted`
- `env_key_names`
- `secret_ref_key_names`
- `values_collected`

Raw vector-store URLs, endpoints, collection names, namespaces, source labels, and secret placeholders are not emitted. Provider names, redacted destination categories, field names, booleans, counts, and credential key names let rules detect durable retrieval poisoning and remote data exposure without copying connector values into the manifest.

## Automations

GitHub workflow triggers that can run outside a normal direct code-review path are normalized into `automation` objects.

Automation metadata may include:

- `trigger_names`
- `automation_triggers`
- `scheduled`
- `manual_dispatch`
- `external_dispatch`
- `workflow_run_trigger`
- `untrusted_event_trigger`
- `untrusted_event_triggers`
- `untrusted_event_payload_used`
- `untrusted_event_payload_sources`
- `untrusted_event_payload_source_count`
- `untrusted_event_payload_redacted`
- `untrusted_event_context_env_keys`
- `untrusted_event_context_env_key_count`
- `untrusted_event_agent_input`
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

Automation surfaces let rules reason about scheduled agents, manual dispatches, webhook-style dispatches, issue/comment-triggered agent jobs, and background workflows that can run agent scripts with secrets or write authority. GitHub event payload expressions and payload text are not emitted; AgentCSP records coarse source classes such as issue comment body, pull request text, discussion text, or repository dispatch payload plus env key names when event payloads are passed to agent jobs.

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
- diagnostic totals by severity through `diagnostics_total`, `diagnostics_errors`, `diagnostics_warnings`, and `diagnostics_info`
- whether `max_files` was reached
- configured `max_files` and `max_file_size_bytes`

Coverage counts do not include raw file contents or skipped path lists. Diagnostic counters summarize parser health; detailed redacted records remain in `diagnostics`.

## Diagnostics

`diagnostics` records scan health issues that may affect completeness, such as malformed MCP configs, runtime configs, package manifests, workflow files, policy files, project-local rule files, or tool definition files.

Each diagnostic includes:

- stable diagnostic ID
- severity
- code
- file path
- parser
- reason
- `content_redacted: true`

Diagnostics do not include raw parser stack traces, raw file contents, secret values, or evidence snippets.

Policy diagnostics include malformed `agentcsp.yaml`, schema-invalid policy files, and explicitly supplied missing `--config` paths. Scans continue with empty advisory policy in those cases so evidence is still generated; default missing policy files do not create diagnostics.

Rule diagnostics include malformed project-local rules, schema-invalid rules, and duplicate rule IDs. Built-in AgentCSP rules still run when project-local rule diagnostics are emitted.

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
