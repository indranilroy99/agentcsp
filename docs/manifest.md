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
- `mcp_env_passthrough`
- `mcp_env_passthrough_all`
- `mcp_env_passthrough_secret_risk`
- `mcp_env_passthrough_source_kinds`
- `mcp_env_passthrough_pattern_count`
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
- `mcp_roots_redacted`
- `mcp_root_count`
- `mcp_root_scope_kinds`
- `mcp_root_broad_scope`
- `mcp_sampling_enabled`
- `mcp_sampling_includes_context`
- `mcp_elicitation_enabled`
- `mcp_elicitation_sensitive_fields`
- `mcp_context_request_authority`
- `mcp_client_context_exposure`
- `mcp_tool_catalog_detected`
- `mcp_tool_catalog_enabled`
- `mcp_tool_catalog_source_redacted`
- `mcp_tool_catalog_source_count`
- `mcp_tool_catalog_source_kinds`
- `mcp_tool_catalog_dynamic`
- `mcp_tool_catalog_auto_refresh`
- `mcp_tool_catalog_model_visible_descriptions`
- `mcp_tool_catalog_remote_schema_trust`
- `mcp_tool_catalog_unpinned_tools`
- `mcp_tool_catalog_signature_verification_disabled`
- `mcp_tool_catalog_provenance_verification_disabled`
- `mcp_tool_catalog_unreviewed_tools_allowed`
- `mcp_tool_catalog_tool_authority_categories`
- `mcp_tool_catalog_privileged_tool_authority`
- `mcp_tool_catalog_write_authority`
- `mcp_tool_catalog_external_authority`
- `mcp_tool_catalog_memory_authority`
- `mcp_tool_catalog_secret_context`
- `mcp_tool_catalog_shell_authority`
- `mcp_tool_catalog_sensitive_context`
- `mcp_tool_catalog_pii_context`
- `mcp_tool_catalog_approval_required`
- `mcp_resource_subscription_detected`
- `mcp_resource_subscription_enabled`
- `mcp_resource_subscription_source_redacted`
- `mcp_resource_subscription_source_count`
- `mcp_resource_subscription_source_kinds`
- `mcp_resource_subscription_dynamic_updates`
- `mcp_resource_subscription_auto_refresh`
- `mcp_resource_subscription_auto_include_context`
- `mcp_resource_subscription_model_visible_context`
- `mcp_resource_subscription_raw_content_passthrough`
- `mcp_resource_subscription_untrusted_source`
- `mcp_resource_subscription_sanitization_disabled`
- `mcp_resource_subscription_redaction_disabled`
- `mcp_resource_subscription_prompt_injection_filter_disabled`
- `mcp_resource_subscription_provenance_verification_disabled`
- `mcp_resource_subscription_authority_categories`
- `mcp_resource_subscription_privileged_bridge`
- `mcp_resource_subscription_write_authority`
- `mcp_resource_subscription_external_authority`
- `mcp_resource_subscription_memory_authority`
- `mcp_resource_subscription_secret_context`
- `mcp_resource_subscription_shell_authority`
- `mcp_resource_subscription_sensitive_context`
- `mcp_resource_subscription_pii_context`
- `mcp_resource_subscription_approval_required`
- `values_collected`
- `content_redacted`

Remote third-party MCP servers are treated as external trust boundaries. Credential references and auth headers are represented as key names only. Plaintext remote transport is represented as a boolean posture signal without emitting the raw URL. Ambient environment inheritance is reduced to source categories such as `process_env`, `inherit_env`, `wildcard`, and `sensitive_prefix`; raw env passthrough expressions and wildcard patterns are not emitted. For local MCP launchers, AgentCSP records project-local implementation path references such as `tools/server.js` and whether those files were present in the scan; raw command arguments and secret placeholders remain redacted.

MCP client roots, sampling, and elicitation are represented as coarse posture metadata. Raw root URIs, filesystem paths, root names, sampling prompts, elicitation schemas, requested field names, and secret placeholders are not emitted. Root scopes are reduced to categories such as `workspace`, `home`, `host_root`, `credential_path`, `absolute_path`, `file_uri`, and `wildcard` so rules can detect remote servers that can request broad client context without copying sensitive client paths into evidence.

MCP tool catalogs are represented as posture metadata when an MCP server declares dynamic discovery, remote registries, tool manifests, marketplace entries, or model-visible tool descriptions. Raw catalog URLs, registry values, tool names, action names, context labels, and secret placeholders are not emitted. Source kinds such as `remote_registry`, `dynamic_discovery`, `tool_catalog`, `marketplace`, and `static_manifest`, combined with pinning, signature/provenance verification, review, approval, and authority categories, let rules distinguish risky mutable tool supply from pinned reviewed catalogs.

MCP resource subscriptions are represented as posture metadata when an MCP server declares live resource watches, streams, notifications, resource sync, or resource update feeds. Raw subscribed resource URIs, stream names, trust labels, context labels, action names, and secret placeholders are not emitted. Source kinds such as `remote_resource`, `dynamic_subscription`, `customer_stream`, `browser_output`, `tool_output`, `memory_resource`, `retrieval_resource`, `public_web`, and `filesystem_resource`, combined with model-visibility, raw-content passthrough, sanitization, redaction, prompt-injection filtering, provenance, approval, and authority categories, let rules detect live MCP context that can cross from untrusted resources into privileged tool action.

MCP prompts and resources declared in MCP configuration are normalized as `prompt` objects when their model-visible context can be inspected safely. Additional metadata may include:

- `mcp_context_surface`
- `mcp_context_kind`
- `mcp_context_source_field`
- `mcp_context_server_name`
- `mcp_context_server_remote`
- `mcp_context_server_plaintext_remote`
- `mcp_context_server_privileged`
- `mcp_context_server_secret_backed`
- `mcp_context_uri_redacted`
- `mcp_context_name_redacted`
- `mcp_context_content_analyzed`
- `env_key_names`
- `secret_ref_key_names`

Raw MCP prompt text, resource text, prompt names, descriptions, URIs, URLs, and secret placeholders are not emitted. AgentCSP records only redacted content-signal booleans and the associated MCP server posture so rules can detect server-supplied context that tries to steer privileged or secret-backed MCP authority.

## MCP Authorization Posture

MCP OAuth and authorization-client configs are normalized into `runtime_config` objects when common MCP auth configuration files are discovered.

MCP authorization metadata may include:

- `parsed_mcp_authorization_config`
- `mcp_authorization_fields`
- `mcp_authorization_provider`
- `mcp_authorization_remote`
- `mcp_authorization_destination_redacted`
- `mcp_authorization_destination_count`
- `mcp_authorization_destination_kinds`
- `mcp_authorization_dynamic_client_registration`
- `mcp_authorization_client_secret_exposure`
- `mcp_authorization_public_client`
- `mcp_authorization_pkce_disabled`
- `mcp_authorization_state_validation_disabled`
- `mcp_authorization_resource_indicator_missing`
- `mcp_authorization_scope_redacted`
- `mcp_authorization_scope_kinds`
- `mcp_authorization_broad_scope`
- `mcp_authorization_sensitive_scope`
- `mcp_authorization_pii_scope`
- `mcp_authorization_refresh_token_storage`
- `mcp_authorization_token_forwarding`
- `mcp_authorization_untrusted_server`
- `mcp_authorization_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw authorization endpoints, MCP server URLs, registration endpoints, OAuth scopes, selector values, token-cache paths, data-scope labels, and secret placeholders are not emitted. Provider names, destination categories, scope categories, DCR posture, PKCE/state/resource-indicator controls, refresh-token storage, token forwarding, untrusted server-selection posture, approval posture, and credential key names let rules detect unsafe token delegation into MCP servers without copying authorization material into the manifest.

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

OpenAPI and Swagger files imported as agent tools are also normalized into `tool` objects. Metadata may include:

- `parsed_openapi_tool_spec`
- `openapi_agent_tool_import`
- `openapi_method`
- `openapi_server_kinds`
- `openapi_remote_server`
- `openapi_security_required`
- `openapi_security_scheme_types`
- `openapi_authenticated_operation`
- `openapi_user_controlled_input`
- `openapi_request_data_categories`
- `openapi_write_operation`
- `openapi_destructive_operation`
- `openapi_external_operation`
- `openapi_broad_or_sensitive_scope`
- `openapi_approval_required`

Raw OpenAPI paths, operation IDs, summaries, descriptions, server URLs, request schemas, and request field names are not emitted. AgentCSP records redacted operation posture so rules can detect agent-imported API tools that combine authenticated external writes, user-controlled inputs, sensitive data classes, and missing approval boundaries.

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
- `browser_download_auto_accept`
- `browser_file_chooser_enabled`
- `browser_extensions_redacted`
- `browser_extension_count`
- `browser_extension_kinds`
- `browser_extension_privileged_permissions`
- `browser_extension_automation`
- `browser_password_manager_enabled`
- `browser_autofill_sensitive_data`
- `browser_download_path_redacted`
- `browser_upload_path_redacted`
- `browser_network_remote`
- `browser_broad_origin_access`
- `browser_destination_redacted`
- `browser_destination_count`
- `browser_destination_kinds`
- `browser_path_references_redacted`
- `browser_sensitive_data`
- `browser_pii_data`
- `browser_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw cookie files, storage-state files, profile paths, extension names, extension IDs, extension paths, download/upload paths, origins, browser endpoints, hostnames, autofill labels, and secret placeholders are not emitted. Provider names, broad-origin categories, authenticated-session booleans, untrusted-navigation signals, click/form authority, file-transfer posture, extension counts and categories, autofill/password-manager posture, path-redaction flags, approval posture, and credential key names let rules detect browser-agent account-action and sensitive file-transfer risk without copying browser state into the manifest.

## Computer-Use And Desktop Automation Posture

Computer-use, desktop automation, remote desktop, VNC/RDP, workstation, operator, and UI automation configs are also normalized into `runtime_config` objects when common computer-use directories or filenames are discovered.

Computer-use metadata may include:

- `parsed_agent_computer_use_config`
- `agent_computer_use_fields`
- `agent_computer_use_provider`
- `agent_computer_use_enabled`
- `agent_computer_use_remote_session`
- `agent_computer_use_destination_redacted`
- `agent_computer_use_destination_count`
- `agent_computer_use_destination_kinds`
- `agent_computer_use_authenticated_session`
- `agent_computer_use_credential_store_access`
- `agent_computer_use_screen_capture`
- `agent_computer_use_ocr_capture`
- `agent_computer_use_clipboard_access`
- `agent_computer_use_clipboard_write`
- `agent_computer_use_keyboard_input`
- `agent_computer_use_mouse_control`
- `agent_computer_use_file_transfer`
- `agent_computer_use_download_auto_accept`
- `agent_computer_use_local_path_redacted`
- `agent_computer_use_app_control`
- `agent_computer_use_terminal_control`
- `agent_computer_use_sensitive_context`
- `agent_computer_use_pii_context`
- `agent_computer_use_redaction_disabled`
- `agent_computer_use_untrusted_input`
- `agent_computer_use_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw remote desktop endpoints, hostnames, app names, window titles, screen labels, clipboard contents, upload/download paths, profile paths, source labels, data-field labels, and secret placeholders are not emitted. Provider names, redacted destination categories, signed-in-session posture, screen/OCR capture, clipboard and keyboard/mouse authority, file-transfer posture, redaction posture, approval posture, data-class booleans, and credential key names let rules detect host-desktop blast radius without copying screenshots, clipboard data, or local paths into evidence.

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

## Agent Autonomous Loop Posture

Autonomous agent, control-loop, planner-executor, and self-directed runner configs are normalized into `runtime_config` objects when common loop configuration files are discovered.

Agent autonomous loop metadata may include:

- `parsed_agent_autonomous_loop_config`
- `agent_autonomous_loop_fields`
- `agent_autonomous_loop_enabled`
- `agent_autonomous_loop_autonomous_mode`
- `agent_autonomous_loop_loop_enabled`
- `agent_autonomous_loop_auto_execute`
- `agent_autonomous_loop_goal_source_redacted`
- `agent_autonomous_loop_goal_source_categories`
- `agent_autonomous_loop_untrusted_goal`
- `agent_autonomous_loop_tool_authority_categories`
- `agent_autonomous_loop_privileged_tool_authority`
- `agent_autonomous_loop_write_authority`
- `agent_autonomous_loop_external_authority`
- `agent_autonomous_loop_secret_authority`
- `agent_autonomous_loop_shell_authority`
- `agent_autonomous_loop_memory_feedback`
- `agent_autonomous_loop_tool_output_feedback`
- `agent_autonomous_loop_unbounded_iterations`
- `agent_autonomous_loop_iteration_limit_redacted`
- `agent_autonomous_loop_iteration_limit_high`
- `agent_autonomous_loop_runtime_budget_missing`
- `agent_autonomous_loop_stop_condition_missing`
- `agent_autonomous_loop_kill_switch_disabled`
- `agent_autonomous_loop_dry_run_disabled`
- `agent_autonomous_loop_sensitive_context`
- `agent_autonomous_loop_pii_context`
- `agent_autonomous_loop_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw goals, objective text, planner prompts, tool names, action strings, observation labels, stop-condition labels, data-field labels, and secret placeholders are not emitted. Goal-source categories, tool-authority categories, loop-budget posture, tool-output feedback posture, kill-switch posture, dry-run posture, approval posture, data-class booleans, and credential key names let rules detect untrusted goals that can repeatedly drive privileged agent actions without copying loop contents into evidence.

## Hosted Assistant Definition Posture

Hosted assistant, assistant API, deployable agent, and hosted-agent definition files are normalized into `runtime_config` objects when common JSON, YAML, or TOML config files are discovered.

Hosted assistant metadata may include:

- `parsed_hosted_assistant_config`
- `hosted_assistant_fields`
- `hosted_assistant_provider`
- `hosted_assistant_definition_detected`
- `hosted_assistant_model_redacted`
- `hosted_assistant_instructions_redacted`
- `hosted_assistant_tool_names_redacted`
- `hosted_assistant_tool_count`
- `hosted_assistant_tool_categories`
- `hosted_assistant_privileged_tools`
- `hosted_assistant_privileged_tool_category_count`
- `hosted_assistant_code_interpreter_enabled`
- `hosted_assistant_file_search_enabled`
- `hosted_assistant_function_tools_enabled`
- `hosted_assistant_mcp_tools_enabled`
- `hosted_assistant_web_search_enabled`
- `hosted_assistant_computer_use_enabled`
- `hosted_assistant_tool_choice_auto`
- `hosted_assistant_parallel_tool_calls`
- `hosted_assistant_parallel_privileged_tool_fanout`
- `hosted_assistant_vector_store_redacted`
- `hosted_assistant_file_ids_redacted`
- `hosted_assistant_sensitive_context`
- `hosted_assistant_pii_context`
- `hosted_assistant_secret_context`
- `hosted_assistant_untrusted_input`
- `hosted_assistant_guardrails_disabled`
- `hosted_assistant_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw assistant IDs, assistant names, model names, instructions, tool names, tool descriptions, file IDs, vector-store IDs, thread/message content, data labels, and secret placeholders are not emitted. Provider names, redacted counts, hosted-tool categories, privileged tool fanout posture, tool-choice posture, file/vector resource posture, guardrail posture, approval posture, and credential key names let rules detect hosted assistants that auto-route untrusted thread or customer context into privileged hosted tools without copying deployable assistant contents into evidence.

## Realtime And Voice Agent Session Posture

Realtime, voice, streaming, telephony, WebRTC, WebSocket, LiveKit, Twilio, and similar session configs are normalized into `runtime_config` objects when common realtime or voice-agent JSON, YAML, or TOML files are discovered.

Realtime agent session metadata may include:

- `parsed_realtime_agent_session_config`
- `realtime_agent_fields`
- `realtime_agent_provider`
- `realtime_agent_session_detected`
- `realtime_agent_destination_redacted`
- `realtime_agent_destination_count`
- `realtime_agent_destination_kinds`
- `realtime_agent_external_caller`
- `realtime_agent_voice_or_audio_input`
- `realtime_agent_transcript_capture`
- `realtime_agent_recording_enabled`
- `realtime_agent_recording_redaction_disabled`
- `realtime_agent_transcript_sanitization_disabled`
- `realtime_agent_prompt_injection_filter_disabled`
- `realtime_agent_tool_calls_enabled`
- `realtime_agent_tool_authority_categories`
- `realtime_agent_privileged_tool_authority`
- `realtime_agent_write_authority`
- `realtime_agent_external_response`
- `realtime_agent_memory_write`
- `realtime_agent_sensitive_context`
- `realtime_agent_pii_context`
- `realtime_agent_secret_exposure`
- `realtime_agent_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw endpoints, room names, phone numbers, session IDs, model names, transcript labels, tool names, tool descriptions, recording labels, data-scope labels, and secret placeholders are not emitted. Provider names, destination categories, transcript and recording posture, prompt-injection filtering posture, tool-authority categories, approval posture, data-class booleans, and credential key names let rules detect external callers or raw audio being routed into privileged tools without copying call-session details into evidence.

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
- `agent_safety_fail_open`
- `agent_safety_fail_open_categories`
- `agent_safety_default_allow`
- `agent_safety_timeout_allows`
- `agent_safety_error_allows`
- `agent_safety_monitor_only`
- `agent_safety_model_only_enforcement`
- `agent_safety_model_only_categories`
- `agent_safety_pre_tool_enforcement_missing`
- `agent_safety_deterministic_policy_missing`
- `agent_safety_post_hoc_only`
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

Raw policy names, source names, fallback-action strings, model-reviewer labels, policy prompt labels, tool strings, action lists, data-field labels, prompt text, and secret placeholders are not emitted. Framework names, disabled-control categories, fail-open categories such as `default_allow`, `timeout_allow`, `error_allow`, and `monitor_only`, model-only enforcement categories, pre-tool and deterministic-policy posture, tool-authority categories, approval posture, data-class booleans, and credential key names let rules detect when weakened or model-only safety controls expose privileged agent actions without copying control policy contents into the manifest.

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

## Cloud Control-Plane Authority Posture

Cloud, IAM, infrastructure, Terraform/IaC, Kubernetes platform, and control-plane configs are also normalized into `runtime_config` objects when common cloud authority configuration files are discovered.

Cloud control-plane metadata may include:

- `parsed_cloud_control_plane_config`
- `cloud_control_plane_fields`
- `cloud_provider`
- `cloud_control_plane_remote`
- `cloud_control_plane_account_redacted`
- `cloud_control_plane_role_redacted`
- `cloud_control_plane_resource_references_redacted`
- `cloud_control_plane_scope_redacted`
- `cloud_control_plane_scope_categories`
- `cloud_control_plane_broad_scope`
- `cloud_control_plane_admin_scope`
- `cloud_control_plane_iam_write`
- `cloud_control_plane_secret_access`
- `cloud_control_plane_secret_write`
- `cloud_control_plane_storage_write`
- `cloud_control_plane_compute_write`
- `cloud_control_plane_delete_authority`
- `cloud_control_plane_audit_log_access`
- `cloud_control_plane_tool_authority_categories`
- `cloud_control_plane_auto_remediation`
- `cloud_control_plane_untrusted_input`
- `cloud_control_plane_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw account IDs, role ARNs, role names, policy names, action strings, resource identifiers, region values, tool names, source labels, data-field labels, and secret placeholders are not emitted. Provider names, redacted scope categories, broad/admin/write posture, tool-authority categories, approval posture, data-class booleans, and credential key names let rules detect AI agents that can modify cloud control planes without copying cloud configuration values into the scan output.

## Agent Extension Loader Posture

Remote skill, plugin, tool, prompt, MCP, extension registry, marketplace, catalog, and capability-loader configs are also normalized into `runtime_config` objects when common extension-loading configuration files are discovered.

Agent extension loader metadata may include:

- `parsed_agent_extension_loader_config`
- `agent_extension_loader_fields`
- `agent_extension_loader_provider`
- `agent_extension_loader_remote`
- `agent_extension_loader_destination_redacted`
- `agent_extension_loader_destination_count`
- `agent_extension_loader_destination_kinds`
- `agent_extension_loader_extension_refs_redacted`
- `agent_extension_loader_extension_ref_count`
- `agent_extension_loader_extension_kinds`
- `agent_extension_loader_unpinned_reference`
- `agent_extension_loader_auto_install_enabled`
- `agent_extension_loader_auto_update_enabled`
- `agent_extension_loader_signature_verification_disabled`
- `agent_extension_loader_provenance_verification_missing`
- `agent_extension_loader_untrusted_input`
- `agent_extension_loader_tool_authority_categories`
- `agent_extension_loader_privileged_authority`
- `agent_extension_loader_external_authority`
- `agent_extension_loader_sensitive_data`
- `agent_extension_loader_pii_data`
- `agent_extension_loader_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw registry URLs, Git repository URLs, package names, extension names, version strings, permission strings, context selector fields, source labels, data-field labels, and secret placeholders are not emitted. Provider names, redacted destination categories, extension-kind categories, pinning posture, signature/provenance posture, tool-authority categories, approval posture, data-class booleans, and credential key names let rules detect dynamic agent capability loading without copying extension manifests into the scan output.

## Agent Self-Modification Posture

Agent self-modification, policy-writer, prompt-writer, runtime-writer, autofix, codemod, and mutation configs are also normalized into `runtime_config` objects when common self-modification configuration files are discovered.

Agent self-modification metadata may include:

- `parsed_agent_self_modification_config`
- `agent_self_modification_fields`
- `agent_self_modification_target_redacted`
- `agent_self_modification_target_count`
- `agent_self_modification_target_categories`
- `agent_self_modification_instruction_target`
- `agent_self_modification_prompt_target`
- `agent_self_modification_policy_target`
- `agent_self_modification_tool_target`
- `agent_self_modification_runtime_target`
- `agent_self_modification_memory_target`
- `agent_self_modification_workflow_target`
- `agent_self_modification_write_enabled`
- `agent_self_modification_auto_apply`
- `agent_self_modification_persistent_change`
- `agent_self_modification_executes_after_update`
- `agent_self_modification_rollback_enabled`
- `agent_self_modification_untrusted_input`
- `agent_self_modification_authority_categories`
- `agent_self_modification_external_authority`
- `agent_self_modification_sensitive_data`
- `agent_self_modification_pii_data`
- `agent_self_modification_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw target paths, prompt or policy field names, patch rules, reload commands, source labels, tool names, data-field labels, and secret placeholders are not emitted. Target categories, authority categories, auto-apply posture, persistence posture, rollback posture, approval posture, data-class booleans, and credential key names let rules detect when untrusted agent context can mutate the control plane without copying self-modification instructions into evidence.

## Agent Approval-Gate Posture

Agent approval, review, human-in-the-loop, model-reviewer, and decision-gate configs are also normalized into `runtime_config` objects when common approval-gate configuration files are discovered.

Agent approval-gate metadata may include:

- `parsed_agent_approval_config`
- `agent_approval_fields`
- `agent_approval_prompt_redacted`
- `agent_approval_prompt_source_categories`
- `agent_approval_channel_categories`
- `agent_approval_external_channel`
- `agent_approval_channel_auth_disabled`
- `agent_approval_approver_identity_unverified`
- `agent_approval_replay_protection_disabled`
- `agent_approval_broad_approver_scope`
- `agent_approval_context_untrusted`
- `agent_approval_raw_context_included`
- `agent_approval_decision_model_driven`
- `agent_approval_uses_untrusted_summary`
- `agent_approval_human_required`
- `agent_approval_default_allow`
- `agent_approval_auto_execute_after_approval`
- `agent_approval_action_categories`
- `agent_approval_privileged_actions`
- `agent_approval_write_actions`
- `agent_approval_destructive_actions`
- `agent_approval_external_actions`
- `agent_approval_memory_write`
- `agent_approval_secret_access`
- `agent_approval_sensitive_data`
- `agent_approval_pii_data`
- `env_key_names`
- `secret_ref_key_names`

Raw approval prompts, model names, approval summaries, approval channel URLs, channel names, action names, reviewer labels, approver allowlists, source labels, data-field labels, and secret placeholders are not emitted. Prompt-source categories, approval-channel categories, channel authentication posture, approver identity posture, replay-protection posture, action-authority categories, model-driven decision posture, default-allow posture, human-review posture, auto-execution posture, data-class booleans, and credential key names let rules detect approval gates where untrusted context or spoofable approval channels can influence privileged execution.

## Agent Session-Sharing Posture

Live session-sharing, shared-copilot, collaboration, co-browse, and handoff configs are also normalized into `runtime_config` objects when common session-sharing directories or filenames are discovered.

Agent session-sharing metadata may include:

- `parsed_agent_session_sharing_config`
- `agent_session_sharing_fields`
- `agent_session_sharing_enabled`
- `agent_session_sharing_external`
- `agent_session_sharing_public_access`
- `agent_session_sharing_anonymous_access`
- `agent_session_sharing_auth_disabled`
- `agent_session_sharing_destination_redacted`
- `agent_session_sharing_destination_count`
- `agent_session_sharing_destination_kinds`
- `agent_session_sharing_collaborator_count`
- `agent_session_sharing_external_collaborators`
- `agent_session_sharing_broad_collaborator_scope`
- `agent_session_sharing_control_categories`
- `agent_session_sharing_live_control_enabled`
- `agent_session_sharing_prompt_injection_enabled`
- `agent_session_sharing_tool_control_enabled`
- `agent_session_sharing_tool_write_authority`
- `agent_session_sharing_tool_execution_authority`
- `agent_session_sharing_approval_control_enabled`
- `agent_session_sharing_resume_replay_enabled`
- `agent_session_sharing_capture_categories`
- `agent_session_sharing_transcript_capture`
- `agent_session_sharing_sensitive_context`
- `agent_session_sharing_pii_context`
- `agent_session_sharing_secret_capture`
- `agent_session_sharing_redaction_disabled`
- `agent_session_sharing_untrusted_input`
- `agent_session_sharing_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw session URLs, session names, collaborator labels, allowlist entries, tool names, source labels, data-field labels, transcript content, prompt text, and secret placeholders are not emitted. Destination categories, collaborator counts, access-control posture, live-control categories, context-capture categories, redaction posture, approval posture, data-class booleans, and credential key names let rules detect public or external live-session control without copying session content into evidence.

## Agent Context-Composer Posture

Context-composer, prompt-composer, prompt-assembly, context-router, prompt-router, message-builder, and role-map configs are also normalized into `runtime_config` objects when common context assembly configuration files are discovered.

Agent context-composer metadata may include:

- `parsed_agent_context_composer_config`
- `agent_context_composer_fields`
- `agent_context_composer_source_redacted`
- `agent_context_composer_source_categories`
- `agent_context_composer_untrusted_sources`
- `agent_context_composer_privileged_role_injection`
- `agent_context_composer_system_role`
- `agent_context_composer_developer_role`
- `agent_context_composer_role_boundary_redacted`
- `agent_context_composer_delimiter_disabled`
- `agent_context_composer_sanitization_disabled`
- `agent_context_composer_raw_context_enabled`
- `agent_context_composer_env_materialization`
- `agent_context_composer_secret_env_materialization`
- `agent_context_composer_env_materialization_target_categories`
- `agent_context_composer_env_materialization_privileged_context`
- `agent_context_composer_env_materialization_redaction_disabled`
- `agent_context_composer_untrusted_env_selector`
- `agent_context_composer_tool_authority_categories`
- `agent_context_composer_privileged_tool_authority`
- `agent_context_composer_write_authority`
- `agent_context_composer_external_authority`
- `agent_context_composer_memory_write`
- `agent_context_composer_shell_authority`
- `agent_context_composer_destructive_authority`
- `agent_context_composer_secret_access`
- `agent_context_composer_sensitive_data`
- `agent_context_composer_pii_data`
- `agent_context_composer_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw source labels, role prompt text, message templates, tool names, action strings, data-field labels, env selector labels, and secret placeholders are not emitted. Source categories, privileged-role booleans, delimiter and sanitization posture, raw-context posture, environment-materialization target categories, tool-authority categories, approval posture, data-class booleans, and credential key names let rules detect context assembly paths where untrusted content or credential-bearing environment references are promoted into system, developer, or model-visible context before privileged tool use.

## Agent Context-Window And Compaction Posture

Context-window, token-budget, truncation, compaction, summarization, message-retention, and overflow-policy configs are also normalized into `runtime_config` objects when common context-window files are discovered.

Agent context-window metadata may include:

- `parsed_agent_context_window_config`
- `agent_context_window_fields`
- `agent_context_window_enabled`
- `agent_context_window_strategy_categories`
- `agent_context_window_truncation_enabled`
- `agent_context_window_compaction_enabled`
- `agent_context_window_summarization_enabled`
- `agent_context_window_overflow_policy_redacted`
- `agent_context_window_token_budget_low`
- `agent_context_window_priority_categories`
- `agent_context_window_untrusted_priority`
- `agent_context_window_tool_output_priority`
- `agent_context_window_memory_priority`
- `agent_context_window_privileged_instruction_retention`
- `agent_context_window_privileged_instruction_eviction`
- `agent_context_window_safety_instruction_retention`
- `agent_context_window_safety_instruction_eviction`
- `agent_context_window_memory_replay`
- `agent_context_window_summary_untrusted`
- `agent_context_window_summary_verification_disabled`
- `agent_context_window_delimiter_disabled`
- `agent_context_window_redaction_disabled`
- `agent_context_window_tool_authority_categories`
- `agent_context_window_privileged_tool_authority`
- `agent_context_window_write_authority`
- `agent_context_window_external_authority`
- `agent_context_window_shell_authority`
- `agent_context_window_destructive_authority`
- `agent_context_window_secret_context`
- `agent_context_window_sensitive_context`
- `agent_context_window_pii_context`
- `agent_context_window_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw priority labels, role labels, summary text, source labels, tool names, action strings, data-field labels, token placeholders, and context content are not emitted. Strategy categories, priority categories, instruction-retention booleans, summary verification posture, delimiter/redaction posture, tool-authority categories, approval posture, data-class booleans, and credential key names let rules detect cases where long-context truncation or compaction preserves untrusted context while evicting system, developer, or safety instructions before privileged tool use.

## Agent Reasoning And Scratchpad State

Reasoning-state, scratchpad, planner-state, agent-state, run-state, chain-of-thought, and thought-log configs are also normalized into `runtime_config` objects when common agent state files are discovered.

Agent reasoning-state metadata may include:

- `parsed_agent_reasoning_state_config`
- `agent_reasoning_state_fields`
- `agent_reasoning_state_enabled`
- `agent_reasoning_state_capture_enabled`
- `agent_reasoning_state_capture_categories`
- `agent_reasoning_state_chain_of_thought_capture`
- `agent_reasoning_state_plan_capture`
- `agent_reasoning_state_tool_observation_capture`
- `agent_reasoning_state_prompt_context_capture`
- `agent_reasoning_state_retrieval_context_capture`
- `agent_reasoning_state_memory_context_capture`
- `agent_reasoning_state_secret_capture`
- `agent_reasoning_state_sensitive_capture`
- `agent_reasoning_state_pii_capture`
- `agent_reasoning_state_untrusted_input`
- `agent_reasoning_state_persistent`
- `agent_reasoning_state_shared`
- `agent_reasoning_state_remote`
- `agent_reasoning_state_public_access`
- `agent_reasoning_state_destination_redacted`
- `agent_reasoning_state_destination_count`
- `agent_reasoning_state_destination_kinds`
- `agent_reasoning_state_replay_enabled`
- `agent_reasoning_state_planner_uses_state`
- `agent_reasoning_state_redaction_disabled`
- `agent_reasoning_state_access_control_disabled`
- `agent_reasoning_state_retention_enabled`
- `agent_reasoning_state_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw reasoning text, chain-of-thought, scratchpad entries, planner traces, destination URLs, workspace names, source labels, tool names, data-field labels, and token placeholders are not emitted. Capture categories, destination categories, persistence and replay posture, planner-use posture, redaction and access-control posture, approval posture, data-class booleans, and credential key names let rules detect cases where sensitive agent reasoning state can be stored remotely and replayed into future privileged decisions.

## Agent Network Egress Posture

Network-egress, web-egress, browser-egress, fetch-policy, web-access, private-network, metadata-access, and SSRF-oriented configs are also normalized into `runtime_config` objects when common agent egress policy files are discovered.

Agent network egress metadata may include:

- `parsed_agent_network_egress_config`
- `agent_network_egress_fields`
- `agent_network_egress_enabled`
- `agent_network_egress_web_tool_authority`
- `agent_network_egress_destination_redacted`
- `agent_network_egress_destination_count`
- `agent_network_egress_destination_kinds`
- `agent_network_egress_private_network_access`
- `agent_network_egress_metadata_service_access`
- `agent_network_egress_localhost_access`
- `agent_network_egress_private_cidr_access`
- `agent_network_egress_wildcard_destination`
- `agent_network_egress_untrusted_input`
- `agent_network_egress_user_controlled_url`
- `agent_network_egress_redirects_allowed`
- `agent_network_egress_dns_rebinding_protection_disabled`
- `agent_network_egress_request_headers_forwarded`
- `agent_network_egress_credential_forwarding`
- `agent_network_egress_response_capture`
- `agent_network_egress_sensitive_response_capture`
- `agent_network_egress_pii_response_capture`
- `agent_network_egress_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw URLs, hostnames, IP addresses, CIDRs, header values, source labels, response field labels, and token placeholders are not emitted. Destination categories such as `cloud_metadata_service`, `localhost_or_cluster_service`, `private_network_range`, and `wildcard_destination`, combined with untrusted URL sources, credential-forwarding posture, redirect and DNS-rebinding posture, and approval state let rules detect model-steered SSRF paths without copying network targets into evidence.

## Agent Workspace Context Sync Posture

Workspace-context, context-sync, file-context, repository-context, and workspace-index configs are also normalized into `runtime_config` objects when common context ingestion files are discovered.

Agent workspace context metadata may include:

- `parsed_agent_workspace_context_config`
- `agent_workspace_context_fields`
- `agent_workspace_context_enabled`
- `agent_workspace_context_auto_sync_enabled`
- `agent_workspace_context_source_redacted`
- `agent_workspace_context_source_count`
- `agent_workspace_context_source_categories`
- `agent_workspace_context_sensitive_paths`
- `agent_workspace_context_secret_path_exposure`
- `agent_workspace_context_env_file_access`
- `agent_workspace_context_ssh_key_access`
- `agent_workspace_context_cloud_credential_access`
- `agent_workspace_context_kubeconfig_access`
- `agent_workspace_context_home_directory_access`
- `agent_workspace_context_git_history_access`
- `agent_workspace_context_repo_wide_access`
- `agent_workspace_context_destination_redacted`
- `agent_workspace_context_destination_count`
- `agent_workspace_context_destination_kinds`
- `agent_workspace_context_remote_sync`
- `agent_workspace_context_prompt_context`
- `agent_workspace_context_rag_indexing`
- `agent_workspace_context_memory_persistence`
- `agent_workspace_context_untrusted_input`
- `agent_workspace_context_pii_context`
- `agent_workspace_context_redaction_disabled`
- `agent_workspace_context_agentcspignore_bypassed`
- `agent_workspace_context_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw file paths, repository names, home-directory paths, credential paths, URLs, destination names, field labels, and token placeholders are not emitted. Source categories such as `env_file`, `ssh_key`, `cloud_credential`, `kubeconfig`, `git_history`, `home_directory`, `private_repo`, and `untrusted_selector`, combined with remote sync, prompt/RAG/memory sinks, redaction posture, `.agentcspignore` posture, approval state, and credential key names let rules detect unsafe workspace context ingestion without copying local secrets or private paths into evidence.

## Agent Tool Retry And Replay Posture

Tool-retry, replay, idempotency, duplicate-suppression, execution-policy, and retry-budget configs are also normalized into `runtime_config` objects when common agent tool retry configuration files are discovered.

Agent tool retry metadata may include:

- `parsed_agent_tool_retry_policy_config`
- `agent_tool_retry_fields`
- `agent_tool_retry_enabled`
- `agent_tool_retry_automatic_retry`
- `agent_tool_retry_replay_enabled`
- `agent_tool_retry_retry_on_failure`
- `agent_tool_retry_retry_on_timeout`
- `agent_tool_retry_retry_on_rate_limit`
- `agent_tool_retry_retry_on_validation_error`
- `agent_tool_retry_max_attempts_redacted`
- `agent_tool_retry_max_attempts_gt_one`
- `agent_tool_retry_unbounded_attempts`
- `agent_tool_retry_budget_missing`
- `agent_tool_retry_backoff_disabled`
- `agent_tool_retry_idempotency_required`
- `agent_tool_retry_idempotency_disabled`
- `agent_tool_retry_deduplication_disabled`
- `agent_tool_retry_exactly_once_disabled`
- `agent_tool_retry_non_idempotent_actions`
- `agent_tool_retry_untrusted_input`
- `agent_tool_retry_tool_output_replay`
- `agent_tool_retry_model_selected_retry`
- `agent_tool_retry_action_categories`
- `agent_tool_retry_privileged_tool_authority`
- `agent_tool_retry_write_authority`
- `agent_tool_retry_external_authority`
- `agent_tool_retry_memory_authority`
- `agent_tool_retry_shell_authority`
- `agent_tool_retry_destructive_authority`
- `agent_tool_retry_secret_context`
- `agent_tool_retry_sensitive_context`
- `agent_tool_retry_pii_context`
- `agent_tool_retry_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw tool names, action strings, retry argument labels, source labels, data-field labels, and token placeholders are not emitted. Retry posture, replay posture, idempotency and duplicate-suppression booleans, action categories, approval posture, data-class booleans, and credential key names let rules detect cases where an agent can automatically replay non-idempotent privileged tools from untrusted context without copying tool arguments or secret values into evidence.

## Tool Output Policy Posture

Tool-output, tool-result, observation, result-handler, output-handler, and tool-output policy configs are also normalized into `runtime_config` objects when common tool-observation handling configuration files are discovered.

Tool output policy metadata may include:

- `parsed_tool_output_policy_config`
- `tool_output_policy_fields`
- `tool_output_source_redacted`
- `tool_output_source_categories`
- `tool_output_untrusted_sources`
- `tool_output_raw_output_enabled`
- `tool_output_prompt_context`
- `tool_output_system_or_developer_context`
- `tool_output_delimiter_disabled`
- `tool_output_sanitization_disabled`
- `tool_output_prompt_injection_filter_disabled`
- `tool_output_followup_tool_calls`
- `tool_output_tool_authority_categories`
- `tool_output_write_authority`
- `tool_output_external_reach`
- `tool_output_memory_write`
- `tool_output_shell_authority`
- `tool_output_destructive_authority`
- `tool_output_approval_input`
- `tool_output_secret_capture`
- `tool_output_secret_access`
- `tool_output_sensitive_data`
- `tool_output_pii_data`
- `tool_output_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw observation labels, source names, tool names, follow-up action strings, data-field labels, and secret placeholders are not emitted. Source categories, raw-output posture, prompt-context posture, delimiter and sanitization posture, prompt-injection filter posture, authority categories, approval posture, data-class booleans, and credential key names let rules detect cases where untrusted browser, shell, MCP, API, retrieval, or customer outputs can steer privileged follow-up actions.

## Visual Context Policy Posture

Vision, visual-context, screenshot, screen-capture, OCR, multimodal, image-input, and image-observation configs are also normalized into `runtime_config` objects when common visual context handling configuration files are discovered.

Visual context policy metadata may include:

- `parsed_visual_context_policy_config`
- `visual_context_policy_fields`
- `visual_context_source_redacted`
- `visual_context_source_categories`
- `visual_context_untrusted_sources`
- `visual_context_raw_image_enabled`
- `visual_context_ocr_enabled`
- `visual_context_prompt_context`
- `visual_context_system_or_developer_context`
- `visual_context_boundary_disabled`
- `visual_context_sanitization_disabled`
- `visual_context_prompt_injection_filter_disabled`
- `visual_context_followup_tool_calls`
- `visual_context_tool_authority_categories`
- `visual_context_write_authority`
- `visual_context_external_reach`
- `visual_context_memory_write`
- `visual_context_shell_authority`
- `visual_context_destructive_authority`
- `visual_context_approval_input`
- `visual_context_secret_capture`
- `visual_context_secret_access`
- `visual_context_sensitive_data`
- `visual_context_pii_data`
- `visual_context_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw image paths, screenshot labels, OCR text, source names, tool names, action strings, data-field labels, and secret placeholders are not emitted. Source categories, raw-image posture, OCR posture, prompt-context posture, visual-boundary posture, sanitization posture, prompt-injection filter posture, authority categories, approval posture, data-class booleans, and credential key names let rules detect cases where untrusted screenshots, uploaded images, screen captures, or OCR-derived text can steer privileged agent actions.

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
- `secret_manager_injects_into_prompt_context`
- `secret_manager_prompt_context_categories`
- `secret_manager_redaction_disabled`
- `secret_manager_untrusted_input`
- `secret_manager_sensitive_scope`
- `secret_manager_pii_scope`
- `secret_manager_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw vault URLs, secret paths, resource names, policy names, role names, project IDs, namespaces, ARNs, key names, prompt target labels, model-context labels, alias names, and secret placeholders are not emitted. Provider names, redacted destination categories, normalized scope categories, read/list/write posture, tool-injection booleans, prompt-context materialization categories, redaction posture, untrusted-input signals, approval posture, and credential key names let rules detect credential-broker blast radius without copying secret inventory into the manifest.

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
- `ai_model_public_endpoint`
- `ai_model_auth_required`
- `ai_model_auth_disabled`
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
- `ai_model_untrusted_input`
- `ai_model_request_logging_enabled`
- `ai_model_redaction_disabled`
- `ai_model_tool_calling_enabled`
- `ai_model_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw model gateway URLs, model names, base URLs, request payload examples, exposed tool names, data-scope labels, and secret placeholders are not emitted. Provider names, redacted destination categories, transport posture, public/auth posture, request-logging posture, redaction posture, tool-calling posture, approval posture, context booleans, and credential key names let rules detect risky model endpoints without copying prompts, tool outputs, memory, retrieval content, or endpoint values into the manifest.

## AI Model Router Boundary

AI model router, provider-routing, fallback, failover, and gateway configs are normalized into `runtime_config` objects when router-oriented directories or filenames are discovered before generic model endpoint classification.

Model router metadata may include:

- `parsed_ai_model_router_config`
- `ai_model_router_fields`
- `ai_model_router_provider`
- `ai_model_router_enabled`
- `ai_model_router_remote_providers`
- `ai_model_router_destination_redacted`
- `ai_model_router_destination_count`
- `ai_model_router_destination_kinds`
- `ai_model_router_provider_categories`
- `ai_model_router_fallback_enabled`
- `ai_model_router_auto_fallback`
- `ai_model_router_cost_or_latency_routing`
- `ai_model_router_sends_prompts`
- `ai_model_router_sends_tool_outputs`
- `ai_model_router_sends_retrieval_context`
- `ai_model_router_sends_memory`
- `ai_model_router_sensitive_context`
- `ai_model_router_pii_context`
- `ai_model_router_secret_context`
- `ai_model_router_untrusted_input`
- `ai_model_router_redaction_disabled`
- `ai_model_router_records_outputs`
- `ai_model_router_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw provider URLs, model aliases, fallback labels, routing strategy values, source labels, prompts, tool outputs, retrieval context, memory content, and secret placeholders are not emitted. Router framework names, redacted destination categories, fallback posture, context booleans, redaction posture, approval posture, and credential key names let rules detect sensitive third-party model failover without copying routed payloads or provider endpoints into the manifest.

## AI Feedback And RLHF Pipelines

AI feedback, human review, rating, annotation, labeling, preference, and RLHF pipeline configs are normalized into `runtime_config` objects when feedback-oriented JSON, YAML, or TOML files are discovered.

Feedback pipeline metadata may include:

- `parsed_ai_feedback_pipeline_config`
- `ai_feedback_fields`
- `ai_feedback_provider`
- `ai_feedback_collection_enabled`
- `ai_feedback_remote_export`
- `ai_feedback_destination_redacted`
- `ai_feedback_destination_count`
- `ai_feedback_destination_kinds`
- `ai_feedback_capture_categories`
- `ai_feedback_prompt_capture`
- `ai_feedback_completion_capture`
- `ai_feedback_tool_output_capture`
- `ai_feedback_retrieval_capture`
- `ai_feedback_memory_capture`
- `ai_feedback_browser_capture`
- `ai_feedback_feedback_label_capture`
- `ai_feedback_secret_capture`
- `ai_feedback_sensitive_capture`
- `ai_feedback_pii_capture`
- `ai_feedback_untrusted_input`
- `ai_feedback_training_promotion_enabled`
- `ai_feedback_model_update_enabled`
- `ai_feedback_eval_set_write`
- `ai_feedback_redaction_disabled`
- `ai_feedback_consent_required`
- `ai_feedback_retention_enabled`
- `ai_feedback_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw feedback endpoints, project names, source labels, feedback labels, reviewer notes, dataset names, prompt text, completion text, tool traces, retrieval chunks, memory content, PII field labels, and secret placeholders are not emitted. Provider names, redacted destination categories, capture categories, training/eval/model-promotion posture, redaction/consent/approval posture, and credential key names let rules detect feedback loops that can convert tainted production interactions into future model behavior or evaluation data.

## Background Agent Task Queue Posture

Background agent, task-queue, job-queue, worker, Celery, BullMQ, Sidekiq, Temporal, SQS, Pub/Sub, Kafka, RabbitMQ, and similar async-agent configs are normalized into `runtime_config` objects when queue-oriented JSON, YAML, or TOML files are discovered.

Task-queue metadata may include:

- `parsed_agent_task_queue_config`
- `agent_task_queue_fields`
- `agent_task_queue_provider`
- `agent_task_queue_detected`
- `agent_task_queue_remote`
- `agent_task_queue_destination_redacted`
- `agent_task_queue_destination_count`
- `agent_task_queue_destination_kinds`
- `agent_task_queue_background_consumer`
- `agent_task_queue_asynchronous_execution`
- `agent_task_queue_auto_execute`
- `agent_task_queue_untrusted_payload`
- `agent_task_queue_payload_categories`
- `agent_task_queue_prompt_passthrough`
- `agent_task_queue_tool_output_passthrough`
- `agent_task_queue_retry_enabled`
- `agent_task_queue_dead_letter_queue`
- `agent_task_queue_replay_enabled`
- `agent_task_queue_tool_authority_categories`
- `agent_task_queue_privileged_tool_authority`
- `agent_task_queue_write_authority`
- `agent_task_queue_external_authority`
- `agent_task_queue_memory_authority`
- `agent_task_queue_secret_exposure`
- `agent_task_queue_sensitive_payload`
- `agent_task_queue_pii_payload`
- `agent_task_queue_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw queue names, queue URLs, topic names, dead-letter queue names, job labels, payload labels, tool strings, action lists, and secret placeholders are not emitted. Provider names, redacted destination categories, payload categories, tool-authority categories, replay posture, approval posture, data-class booleans, and credential key names let rules detect background agents that can replay or auto-execute untrusted queued jobs into privileged tools without copying queue payloads into evidence.

## AI Embedding Pipeline Boundary

AI embedding, indexing, vectorization, document-index, and RAG-index pipeline configs are normalized into `runtime_config` objects when embedding-oriented directories or filenames are discovered.

Embedding pipeline metadata may include:

- `parsed_ai_embedding_pipeline_config`
- `ai_embedding_fields`
- `ai_embedding_provider`
- `ai_embedding_enabled`
- `ai_embedding_remote_provider`
- `ai_embedding_destination_redacted`
- `ai_embedding_destination_count`
- `ai_embedding_destination_kinds`
- `ai_embedding_vector_write_enabled`
- `ai_embedding_batch_indexing`
- `ai_embedding_auto_sync`
- `ai_embedding_capture_categories`
- `ai_embedding_document_capture`
- `ai_embedding_prompt_capture`
- `ai_embedding_tool_output_capture`
- `ai_embedding_retrieval_capture`
- `ai_embedding_memory_capture`
- `ai_embedding_browser_capture`
- `ai_embedding_secret_capture`
- `ai_embedding_sensitive_capture`
- `ai_embedding_pii_capture`
- `ai_embedding_untrusted_input`
- `ai_embedding_redaction_disabled`
- `ai_embedding_retention_enabled`
- `ai_embedding_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw embedding endpoints, model aliases, vector-store URLs, namespaces, source labels, document chunks, prompts, tool outputs, browser context, memory content, and secret placeholders are not emitted. Provider names, redacted destination categories, capture categories, sync/write posture, redaction posture, retention posture, approval posture, and credential key names let rules detect sensitive third-party embedding and vector indexing without copying indexed text into the manifest.

## Agent Package Manifest Supply Chain

Agent-relevant `package.json` manifests are normalized into `runtime_config` objects when they include agent, MCP, model, RAG, vector, or browser-automation dependencies, lifecycle scripts, or agent-oriented package scripts. This is intentionally narrower than a general dependency audit.

Package-manifest metadata may include:

- `parsed_agent_package_manifest_config`
- `package_manifest_fields`
- `package_manifest_dependency_names_redacted`
- `package_manifest_dependency_specs_redacted`
- `package_manifest_dependency_count`
- `package_manifest_agent_dependency_count`
- `package_manifest_agent_dependency_categories`
- `package_manifest_dependency_reference_kinds`
- `package_manifest_risky_dependency_count`
- `package_manifest_unpinned_dependency`
- `package_manifest_remote_dependency`
- `package_manifest_lifecycle_script`
- `package_manifest_lifecycle_script_names`
- `package_manifest_install_script_count`
- `package_manifest_lifecycle_shell_execution`
- `package_manifest_lifecycle_network_access`
- `package_manifest_lifecycle_secret_env`
- `package_manifest_agent_script_count`
- `package_manifest_package_private`
- `env_key_names`
- `secret_ref_key_names`

Raw dependency names, dependency specs, remote package URLs, Git references, lifecycle commands, local script paths, and token placeholders are not emitted. AgentCSP records dependency categories, reference-kind categories, lifecycle-script names, command capability booleans, and credential key names so rules can detect install-time agent supply-chain risk without becoming a noisy generic SCA scanner.

## Agent Deployment Image Provenance

Agent deployment, Kubernetes, Helm, Compose, and workload manifests are normalized into `runtime_config` objects when deployment-oriented directories or filenames are discovered. This surface focuses on agent workload image provenance and runtime authority rather than general container vulnerability scanning.

Deployment metadata may include:

- `parsed_agent_deployment_config`
- `agent_deployment_fields`
- `agent_deployment_platform`
- `agent_deployment_agent_workload`
- `agent_deployment_image_references_redacted`
- `agent_deployment_image_count`
- `agent_deployment_image_reference_kinds`
- `agent_deployment_remote_image`
- `agent_deployment_unpinned_image`
- `agent_deployment_digest_pinned`
- `agent_deployment_pull_policy_always`
- `agent_deployment_privileged_container`
- `agent_deployment_root_user`
- `agent_deployment_host_network`
- `agent_deployment_host_mount`
- `agent_deployment_credential_mount`
- `agent_deployment_mounts_redacted`
- `agent_deployment_mount_kinds`
- `agent_deployment_secret_env_exposure`
- `agent_deployment_service_account_redacted`
- `agent_deployment_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw image names, registry paths, service-account names, secret names, host mount paths, and token placeholders are not emitted. Platform names, redacted image-reference categories such as `remote_registry_image`, `latest_tag`, and `missing_digest`, mount categories, service-account posture, approval posture, and credential key names let rules detect mutable agent deployment images running with credentialed host authority.

## Agent Artifact Export

Agent artifact, output, report, screenshot, recording, and generated-output export configs are normalized into `runtime_config` objects when common artifact directories or export-oriented config filenames are discovered.

Artifact export metadata may include:

- `parsed_agent_artifact_export_config`
- `agent_artifact_export_fields`
- `agent_artifact_export_provider`
- `agent_artifact_export_remote`
- `agent_artifact_export_public_access`
- `agent_artifact_export_destination_redacted`
- `agent_artifact_export_destination_count`
- `agent_artifact_export_destination_kinds`
- `agent_artifact_export_path_redacted`
- `agent_artifact_export_capture_categories`
- `agent_artifact_export_sensitive_capture`
- `agent_artifact_export_pii_capture`
- `agent_artifact_export_secret_capture`
- `agent_artifact_export_browser_capture`
- `agent_artifact_export_tool_output_capture`
- `agent_artifact_export_memory_capture`
- `agent_artifact_export_retrieval_capture`
- `agent_artifact_export_prompt_capture`
- `agent_artifact_export_write_enabled`
- `agent_artifact_export_retention_enabled`
- `agent_artifact_export_redaction_disabled`
- `agent_artifact_export_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw artifact bucket names, endpoints, paths, generated outputs, data-scope labels, and secret placeholders are not emitted. Provider names, redacted destination categories, capture categories, redaction posture, retention posture, approval posture, and credential key names let rules detect generated-output exfiltration without copying run artifacts into the manifest.

## Agent Webhook Egress

Agent webhook, callback, outbound sink, event-sink, response-hook, reply-hook, and notification-sink configs are normalized into `runtime_config` objects when common callback directories or webhook-oriented config filenames are discovered.

Webhook egress metadata may include:

- `parsed_agent_webhook_egress_config`
- `agent_webhook_egress_fields`
- `agent_webhook_egress_provider`
- `agent_webhook_egress_remote`
- `agent_webhook_egress_destination_redacted`
- `agent_webhook_egress_destination_count`
- `agent_webhook_egress_destination_kinds`
- `agent_webhook_egress_plaintext_endpoint`
- `agent_webhook_egress_auth_header_redacted`
- `agent_webhook_egress_auth_header_names`
- `agent_webhook_egress_payload_categories`
- `agent_webhook_egress_model_output_payload`
- `agent_webhook_egress_prompt_payload`
- `agent_webhook_egress_tool_output_payload`
- `agent_webhook_egress_retrieval_payload`
- `agent_webhook_egress_memory_payload`
- `agent_webhook_egress_browser_payload`
- `agent_webhook_egress_secret_payload`
- `agent_webhook_egress_sensitive_payload`
- `agent_webhook_egress_pii_payload`
- `agent_webhook_egress_external_write_enabled`
- `agent_webhook_egress_untrusted_input`
- `agent_webhook_egress_redaction_disabled`
- `agent_webhook_egress_retry_enabled`
- `agent_webhook_egress_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw callback endpoints, token placeholders, payload bodies, source labels, and data-field labels are not emitted. Provider names, redacted endpoint categories, auth-header names, payload categories, write posture, retry posture, approval posture, redaction posture, and credential key names let rules detect sensitive model-output callbacks without copying webhook payloads into the manifest.

## Agent Container Runtime

Agent container, sandbox, Docker, Compose, runner, executor, and runtime isolation configs are normalized into `runtime_config` objects when common runtime directories or container-oriented config filenames are discovered.

Container runtime metadata may include:

- `parsed_agent_container_runtime_config`
- `agent_container_runtime_fields`
- `agent_container_provider`
- `agent_container_runtime_enabled`
- `agent_container_privileged`
- `agent_container_root_user`
- `agent_container_docker_socket_mount`
- `agent_container_host_path_mount`
- `agent_container_host_root_mount`
- `agent_container_writable_host_mount`
- `agent_container_workspace_mount`
- `agent_container_credential_mount`
- `agent_container_sensitive_mount`
- `agent_container_mounts_redacted`
- `agent_container_mount_kinds`
- `agent_container_host_network`
- `agent_container_host_pid`
- `agent_container_host_ipc`
- `agent_container_network_enabled`
- `agent_container_dangerous_capability`
- `agent_container_capability_categories`
- `agent_container_tool_authority_categories`
- `agent_container_shell_authority`
- `agent_container_filesystem_authority`
- `agent_container_browser_authority`
- `agent_container_docker_authority`
- `agent_container_untrusted_input`
- `agent_container_pii_input`
- `agent_container_secret_env_exposure`
- `agent_container_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw image names, host mount paths, Docker socket paths, credential paths, input labels, tool lists, and token placeholders are not emitted. Provider names, redacted mount categories, namespace posture, capability categories, tool-authority categories, untrusted-input signals, approval posture, and credential key names let rules detect host-escape blast radius without copying container runtime details into the manifest.

## Agent Code Interpreter Runtime

Agent code interpreter, notebook, Python REPL, Jupyter, kernel, and code-runner configs are normalized into `runtime_config` objects when interpreter-oriented directories or filenames are discovered.

Code interpreter metadata may include:

- `parsed_agent_code_interpreter_config`
- `agent_code_interpreter_fields`
- `agent_code_interpreter_provider`
- `agent_code_interpreter_enabled`
- `agent_code_interpreter_executes_model_code`
- `agent_code_interpreter_untrusted_input`
- `agent_code_interpreter_network_enabled`
- `agent_code_interpreter_package_install`
- `agent_code_interpreter_shell_access`
- `agent_code_interpreter_filesystem_access`
- `agent_code_interpreter_workspace_write`
- `agent_code_interpreter_output_capture`
- `agent_code_interpreter_output_persistence`
- `agent_code_interpreter_mounts_redacted`
- `agent_code_interpreter_mount_kinds`
- `agent_code_interpreter_credential_mount`
- `agent_code_interpreter_sensitive_input`
- `agent_code_interpreter_pii_input`
- `agent_code_interpreter_secret_env_exposure`
- `agent_code_interpreter_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw kernel values, code snippets, package names, mounted paths, input labels, output labels, and token placeholders are not emitted. Provider names, redacted mount categories, execution posture, network/package-install posture, output-retention posture, approval posture, and credential key names let rules detect untrusted code execution blast radius without copying notebook runtime details into the manifest.

## AI Training Dataset Boundary

AI training, fine-tuning, distillation, feedback-training, RLHF, and dataset-export configs are normalized into `runtime_config` objects when training-oriented directories or filenames are discovered.

Training dataset metadata may include:

- `parsed_ai_training_dataset_config`
- `ai_training_dataset_fields`
- `ai_training_dataset_provider`
- `ai_training_dataset_enabled`
- `ai_training_dataset_export_enabled`
- `ai_training_dataset_model_update_enabled`
- `ai_training_dataset_remote_upload`
- `ai_training_dataset_destination_redacted`
- `ai_training_dataset_destination_count`
- `ai_training_dataset_destination_kinds`
- `ai_training_dataset_capture_categories`
- `ai_training_dataset_prompt_capture`
- `ai_training_dataset_completion_capture`
- `ai_training_dataset_tool_output_capture`
- `ai_training_dataset_retrieval_capture`
- `ai_training_dataset_memory_capture`
- `ai_training_dataset_browser_capture`
- `ai_training_dataset_secret_capture`
- `ai_training_dataset_sensitive_capture`
- `ai_training_dataset_pii_capture`
- `ai_training_dataset_untrusted_input`
- `ai_training_dataset_redaction_disabled`
- `ai_training_dataset_retention_enabled`
- `ai_training_dataset_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw training endpoints, dataset names, record labels, source labels, prompts, completions, tool outputs, retrieval context, memory content, and token placeholders are not emitted. Provider names, redacted destination categories, capture categories, redaction posture, retention posture, approval posture, and credential key names let rules detect sensitive model-update pipelines without copying training data into the manifest.

## LLM Prompt Cache Boundary

LLM prompt, response, completion, semantic, and model-cache configs are normalized into `runtime_config` objects when cache-oriented directories or filenames are discovered. Generated cache data remains excluded by default through the scanner's normal generated/cache directory ignores.

Prompt cache metadata may include:

- `parsed_llm_prompt_cache_config`
- `llm_prompt_cache_fields`
- `llm_prompt_cache_provider`
- `llm_prompt_cache_enabled`
- `llm_prompt_cache_remote`
- `llm_prompt_cache_shared`
- `llm_prompt_cache_persistent`
- `llm_prompt_cache_write_enabled`
- `llm_prompt_cache_destination_redacted`
- `llm_prompt_cache_destination_count`
- `llm_prompt_cache_destination_kinds`
- `llm_prompt_cache_capture_categories`
- `llm_prompt_cache_prompt_capture`
- `llm_prompt_cache_completion_capture`
- `llm_prompt_cache_tool_output_capture`
- `llm_prompt_cache_retrieval_capture`
- `llm_prompt_cache_memory_capture`
- `llm_prompt_cache_browser_capture`
- `llm_prompt_cache_secret_capture`
- `llm_prompt_cache_sensitive_capture`
- `llm_prompt_cache_pii_capture`
- `llm_prompt_cache_untrusted_input`
- `llm_prompt_cache_semantic_reuse_enabled`
- `llm_prompt_cache_user_controlled_key`
- `llm_prompt_cache_broad_match_threshold`
- `llm_prompt_cache_cross_tenant_replay`
- `llm_prompt_cache_tenant_isolation_disabled`
- `llm_prompt_cache_redaction_disabled`
- `llm_prompt_cache_replay_enabled`
- `llm_prompt_cache_retention_enabled`
- `llm_prompt_cache_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw cache URLs, DSNs, namespaces, cache keys, cache values, prompts, completions, source labels, record labels, tenant labels, key-scope labels, and token placeholders are not emitted. Provider names, redacted destination categories, capture categories, shared/persistent posture, semantic reuse posture, user-controlled cache-key posture, broad-match posture, tenant-isolation posture, replay posture, redaction posture, approval posture, and credential key names let rules detect sensitive prompt-cache replay and semantic-cache poisoning without copying cached content into the manifest.

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
- `ai_telemetry_public_access`
- `ai_telemetry_shared_workspace`
- `ai_telemetry_access_control_disabled`
- `ai_telemetry_retention_enabled`
- `ai_telemetry_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw telemetry endpoints, project names, workspace names, share links, viewer or collaborator labels, trace payloads, sampled content, and secret placeholders are not emitted. Provider names, redacted destination categories, field paths, capture booleans, access-control posture, retention signals, redaction posture, and credential key names let rules detect sensitive trace export and public trace-sharing risk without copying observability configuration values into the manifest.

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
- `agent_memory_store_retention_days`
- `agent_memory_store_long_retention`
- `agent_memory_store_unbounded_retention`
- `agent_memory_store_redaction_disabled`
- `agent_memory_store_sensitive_data`
- `agent_memory_store_pii_data`
- `agent_memory_store_namespace_redacted`
- `agent_memory_store_public_access`
- `agent_memory_store_cross_tenant_access`
- `agent_memory_store_access_control_disabled`
- `agent_memory_store_tenant_isolation_disabled`
- `agent_memory_store_approval_required`
- `env_key_names`
- `secret_ref_key_names`
- `values_collected`

Raw memory-store URLs, connection strings, collection names, namespaces, key prefixes, source labels, replay targets, access-control labels, tenant selectors, shared-with labels, data-field labels, and secret placeholders are not emitted. Provider names, redacted destination categories, capture/replay booleans, sharing and persistence posture, retention and redaction posture, public or cross-tenant exposure posture, access-control and tenant-isolation posture, approval posture, data-class booleans, and credential key names let rules detect durable memory poisoning, sensitive context retention, and cross-session or cross-tenant context replay without copying memory configuration values into the manifest.

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
- `vector_store_ingestion_enabled`
- `vector_store_ingestion_source_redacted`
- `vector_store_ingestion_source_categories`
- `vector_store_auto_ingest_enabled`
- `vector_store_ingestion_writes_trusted_namespace`
- `vector_store_ingestion_quarantine_disabled`
- `vector_store_ingestion_moderation_disabled`
- `vector_store_ingestion_instruction_stripping_disabled`
- `vector_store_ingestion_sanitization_disabled`
- `vector_store_ingestion_provenance_required`
- `vector_store_ingestion_approval_required`
- `vector_store_sensitive_collection`
- `vector_store_pii_collection`
- `vector_store_namespace_redacted`
- `vector_store_retrieval_enabled`
- `vector_store_user_query_input`
- `vector_store_filter_redacted`
- `vector_store_filter_count`
- `vector_store_filter_kinds`
- `vector_store_broad_retrieval_scope`
- `vector_store_acl_disabled`
- `vector_store_provenance_filter_disabled`
- `vector_store_trust_filter_disabled`
- `vector_store_prompt_injection_passthrough`
- `vector_store_raw_chunk_passthrough`
- `vector_store_tool_context_injection`
- `vector_store_approval_required`
- `env_key_names`
- `secret_ref_key_names`
- `values_collected`

Raw vector-store URLs, endpoints, collection names, namespaces, query selectors, filter values, ingestion source labels, target namespace labels, raw chunk text, and secret placeholders are not emitted. Provider names, redacted destination categories, ingestion source categories, quarantine/moderation/instruction-stripping posture, filter categories, ACL/provenance/trust-filter posture, prompt-injection passthrough posture, tool-context injection posture, booleans, counts, and credential key names let rules detect durable ingestion poisoning, unauthorized private retrieval, and remote data exposure without copying connector values into the manifest.

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

## AgentCSP Policy Integrity Posture

Project-local `agentcsp.yaml`, `agentcsp.yml`, and common AgentCSP policy config filenames are normalized into `runtime_config` objects when discovered. This models scan-control posture because advisory policy can change trust, recommended controls, suppressions, and CI failure behavior.

Policy-integrity metadata may include:

- `parsed_agentcsp_policy_config`
- `agentcsp_policy_fields`
- `agentcsp_policy_trust_override_count`
- `agentcsp_policy_trust_overrides_redacted`
- `agentcsp_policy_trust_override_kinds`
- `agentcsp_policy_marks_untrusted_context_trusted`
- `agentcsp_policy_suppression_count`
- `agentcsp_policy_suppressions_redacted`
- `agentcsp_policy_broad_suppression`
- `agentcsp_policy_high_severity_suppression`
- `agentcsp_policy_long_lived_suppression`
- `agentcsp_policy_active_suppression`
- `agentcsp_policy_suppression_match_kinds`
- `agentcsp_policy_recommended_control_count`
- `agentcsp_policy_recommended_controls_redacted`
- `agentcsp_policy_recommended_control_downgrade`
- `agentcsp_policy_recommended_control_downgrade_kinds`
- `agentcsp_policy_weakening_controls`
- `agentcsp_policy_weakens_security_controls`
- `env_key_names`
- `secret_ref_key_names`

Raw trust-override paths, suppression IDs, owners, reasons, recommended-control IDs, match values, and policy comments are not emitted as policy-integrity surface metadata. Counts, match-kind categories, weakening-control categories, and booleans let rules detect broad high-severity suppressions, permissive control downgrades, and trust elevation for untrusted context without copying the policy body into the manifest.

## Agent Prompt Registry Posture

Remote prompt registries, prompt hubs, prompt catalogs, and instruction registries are normalized into `runtime_config` objects when discovered. This models prompt supply-chain posture because registry content can become model-visible system or developer instructions.

Prompt-registry metadata may include:

- `parsed_agent_prompt_registry_config`
- `agent_prompt_registry_fields`
- `agent_prompt_registry_provider`
- `agent_prompt_registry_remote`
- `agent_prompt_registry_destination_redacted`
- `agent_prompt_registry_destination_count`
- `agent_prompt_registry_destination_kinds`
- `agent_prompt_registry_prompt_refs_redacted`
- `agent_prompt_registry_prompt_ref_count`
- `agent_prompt_registry_prompt_kinds`
- `agent_prompt_registry_auto_sync_enabled`
- `agent_prompt_registry_unpinned_reference`
- `agent_prompt_registry_signature_verification_disabled`
- `agent_prompt_registry_provenance_verification_missing`
- `agent_prompt_registry_untrusted_selector`
- `agent_prompt_registry_privileged_role_injection`
- `agent_prompt_registry_tool_directive`
- `agent_prompt_registry_memory_directive`
- `agent_prompt_registry_external_directive`
- `agent_prompt_registry_sensitive_context`
- `agent_prompt_registry_pii_context`
- `agent_prompt_registry_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw registry URLs, repository URLs, prompt IDs, prompt names, selector fields, directive strings, data-scope labels, and token placeholders are not emitted. Provider names, destination categories, prompt-kind categories, auto-sync posture, verification posture, role-injection posture, untrusted selector signals, and approval posture let rules detect remote prompt supply-chain risk without copying prompt content into the manifest.

## Agent Remote Instruction-Loader Posture

Remote instruction loaders, instruction sync configs, prompt loaders, and system or developer instruction-source configs are normalized into `runtime_config` objects when discovered. This models the path where externally refreshed instructions become model-visible agent authority without going through a formal prompt registry.

Remote instruction-loader metadata may include:

- `parsed_agent_remote_instruction_loader_config`
- `agent_remote_instruction_fields`
- `agent_remote_instruction_provider`
- `agent_remote_instruction_remote`
- `agent_remote_instruction_destination_redacted`
- `agent_remote_instruction_destination_count`
- `agent_remote_instruction_destination_kinds`
- `agent_remote_instruction_refs_redacted`
- `agent_remote_instruction_ref_count`
- `agent_remote_instruction_role_categories`
- `agent_remote_instruction_system_role`
- `agent_remote_instruction_developer_role`
- `agent_remote_instruction_auto_refresh_enabled`
- `agent_remote_instruction_unpinned_reference`
- `agent_remote_instruction_signature_verification_disabled`
- `agent_remote_instruction_provenance_verification_missing`
- `agent_remote_instruction_untrusted_selector`
- `agent_remote_instruction_privileged_role_injection`
- `agent_remote_instruction_tool_authority_categories`
- `agent_remote_instruction_privileged_tool_authority`
- `agent_remote_instruction_write_authority`
- `agent_remote_instruction_external_authority`
- `agent_remote_instruction_memory_write`
- `agent_remote_instruction_shell_authority`
- `agent_remote_instruction_secret_access`
- `agent_remote_instruction_sensitive_context`
- `agent_remote_instruction_pii_context`
- `agent_remote_instruction_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw remote instruction URLs, repository URLs, instruction IDs, instruction names, selector values, directive strings, tool names, data-scope labels, and token placeholders are not emitted. Destination categories, role categories, refresh and pinning posture, verification posture, untrusted selector posture, tool-authority categories, approval posture, data-class booleans, and credential key names let rules detect remote instruction authority without copying instruction content into evidence.

## Agent Exposure Posture

Public A2A agent cards, `.well-known` agent-card documents, agent discovery configs, and agent capability catalogs are normalized into `runtime_config` objects when discovered. This models the boundary where external agents can discover and invoke local agent capabilities.

Agent exposure metadata may include:

- `parsed_agent_exposure_config`
- `agent_exposure_fields`
- `agent_exposure_provider`
- `agent_exposure_public_discovery`
- `agent_exposure_endpoint_redacted`
- `agent_exposure_endpoint_count`
- `agent_exposure_endpoint_kinds`
- `agent_exposure_capabilities_redacted`
- `agent_exposure_capability_count`
- `agent_exposure_auth_required`
- `agent_exposure_auth_disabled`
- `agent_exposure_anonymous_access`
- `agent_exposure_external_callers`
- `agent_exposure_tool_invocation_enabled`
- `agent_exposure_tool_authority_categories`
- `agent_exposure_privileged_authority`
- `agent_exposure_write_authority`
- `agent_exposure_memory_access`
- `agent_exposure_secret_access`
- `agent_exposure_sensitive_data`
- `agent_exposure_pii_data`
- `agent_exposure_rate_limit_missing`
- `agent_exposure_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw endpoint URLs, agent names, skill IDs, skill descriptions, tool strings, caller labels, data-scope labels, and token placeholders are not emitted. Provider names, endpoint categories, capability counts, authentication posture, authority categories, rate-limit posture, approval posture, and credential key names let rules detect externally callable agent authority without publishing the agent card body.

## Public Agent Chat Ingress Posture

Public chat widgets, customer-support chat routes, chatbot endpoints, and web assistant ingress configs are normalized into `runtime_config` objects when discovered. This models the boundary where anonymous or public users can send prompt text or attachments into an agent that may call tools.

Public agent chat metadata may include:

- `parsed_public_agent_chat_config`
- `public_agent_chat_fields`
- `public_agent_chat_enabled`
- `public_agent_chat_endpoint_redacted`
- `public_agent_chat_endpoint_count`
- `public_agent_chat_endpoint_kinds`
- `public_agent_chat_public_endpoint`
- `public_agent_chat_anonymous_access`
- `public_agent_chat_auth_disabled`
- `public_agent_chat_cors_broad`
- `public_agent_chat_csrf_disabled`
- `public_agent_chat_rate_limit_missing`
- `public_agent_chat_abuse_protection_disabled`
- `public_agent_chat_file_upload_enabled`
- `public_agent_chat_untrusted_input`
- `public_agent_chat_auto_tool_invocation`
- `public_agent_chat_tool_authority_categories`
- `public_agent_chat_privileged_tool_authority`
- `public_agent_chat_write_authority`
- `public_agent_chat_external_response`
- `public_agent_chat_memory_write`
- `public_agent_chat_secret_access`
- `public_agent_chat_sensitive_context`
- `public_agent_chat_pii_context`
- `public_agent_chat_redaction_disabled`
- `public_agent_chat_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw chat endpoints, allowed origins, tool names, visitor labels, attachment labels, context field names, data-scope labels, and token placeholders are not emitted. Endpoint categories, authentication posture, CORS/CSRF/rate-limit/abuse-control posture, file-upload posture, authority categories, redaction posture, approval posture, and credential key names let rules detect public prompt-to-tool authority without copying public chat configuration values into evidence.

## Agent Debug Console Posture

Agent debug consoles, playgrounds, prompt inspectors, developer consoles, and admin inspection surfaces are normalized into `runtime_config` objects when discovered. This models the boundary where diagnostic tooling can expose system/developer prompts, raw context, traces, memory, tool schemas, impersonation, or live tool invocation.

Agent debug console metadata may include:

- `parsed_agent_debug_console_config`
- `agent_debug_console_fields`
- `agent_debug_console_enabled`
- `agent_debug_console_endpoint_redacted`
- `agent_debug_console_endpoint_count`
- `agent_debug_console_endpoint_kinds`
- `agent_debug_console_public_endpoint`
- `agent_debug_console_anonymous_access`
- `agent_debug_console_auth_disabled`
- `agent_debug_console_cors_broad`
- `agent_debug_console_prompt_view_enabled`
- `agent_debug_console_system_prompt_visible`
- `agent_debug_console_developer_prompt_visible`
- `agent_debug_console_raw_context_visible`
- `agent_debug_console_trace_view_enabled`
- `agent_debug_console_memory_view_enabled`
- `agent_debug_console_tool_schema_visible`
- `agent_debug_console_prompt_edit_enabled`
- `agent_debug_console_tool_invocation_enabled`
- `agent_debug_console_impersonation_enabled`
- `agent_debug_console_tool_authority_categories`
- `agent_debug_console_privileged_tool_authority`
- `agent_debug_console_write_authority`
- `agent_debug_console_external_authority`
- `agent_debug_console_memory_write_authority`
- `agent_debug_console_secret_context_visible`
- `agent_debug_console_sensitive_context`
- `agent_debug_console_pii_context`
- `agent_debug_console_redaction_disabled`
- `agent_debug_console_audit_logging_disabled`
- `agent_debug_console_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw console endpoints, prompt names, prompt bodies, trace names, memory labels, context field names, tool names, allowed origins, and token placeholders are not emitted. Endpoint categories, authentication posture, visible-context categories, authority categories, redaction posture, audit posture, approval posture, and credential key names let rules detect exposed diagnostic control planes without publishing the debug configuration body.

## Agent Response Exposure Posture

Agent response policies, response-stream configs, event-stream configs, public output streams, and client-visible event policies are normalized into `runtime_config` objects when discovered. This models the boundary where model internals, tool results, retrieval context, memory, or secrets can leave the runtime through client-visible responses.

Agent response exposure metadata may include:

- `parsed_agent_response_exposure_config`
- `agent_response_exposure_fields`
- `agent_response_exposure_enabled`
- `agent_response_exposure_endpoint_redacted`
- `agent_response_exposure_endpoint_count`
- `agent_response_exposure_endpoint_kinds`
- `agent_response_exposure_public_endpoint`
- `agent_response_exposure_anonymous_access`
- `agent_response_exposure_auth_disabled`
- `agent_response_exposure_cors_broad`
- `agent_response_exposure_streaming_enabled`
- `agent_response_exposure_reasoning_visible`
- `agent_response_exposure_system_prompt_visible`
- `agent_response_exposure_developer_prompt_visible`
- `agent_response_exposure_tool_output_visible`
- `agent_response_exposure_tool_argument_visible`
- `agent_response_exposure_retrieval_visible`
- `agent_response_exposure_memory_visible`
- `agent_response_exposure_secret_context_visible`
- `agent_response_exposure_sensitive_context`
- `agent_response_exposure_pii_context`
- `agent_response_exposure_redaction_disabled`
- `agent_response_exposure_external_response`
- `agent_response_exposure_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw response endpoints, event-stream URLs, output field names, reasoning labels, tool-output labels, retrieval labels, memory labels, prompt names, data-scope labels, and token placeholders are not emitted. Endpoint categories, authentication posture, visible internal-context categories, redaction posture, approval posture, and credential key names let rules detect response-stream disclosure without copying model or tool internals into evidence.

## Agent Action Router Posture

Agent action-router, command-router, tool-dispatch, model-action, output-parser, and action-DSL configs are normalized into `runtime_config` objects when discovered. This models the boundary where model output or repaired structured text is converted into tool calls, shell commands, memory writes, external responses, or secret-manager access.

Agent action router metadata may include:

- `parsed_agent_action_router_config`
- `agent_action_router_fields`
- `agent_action_router_enabled`
- `agent_action_router_model_output_input`
- `agent_action_router_untrusted_input`
- `agent_action_router_action_format_categories`
- `agent_action_router_schema_validation_disabled`
- `agent_action_router_strict_schema`
- `agent_action_router_open_action_schema`
- `agent_action_router_unknown_actions_allowed`
- `agent_action_router_json_repair_enabled`
- `agent_action_router_batch_execution_enabled`
- `agent_action_router_auto_execute`
- `agent_action_router_tool_authority_categories`
- `agent_action_router_privileged_tool_authority`
- `agent_action_router_write_authority`
- `agent_action_router_external_authority`
- `agent_action_router_memory_authority`
- `agent_action_router_secret_access`
- `agent_action_router_shell_authority`
- `agent_action_router_sensitive_context`
- `agent_action_router_pii_context`
- `agent_action_router_redaction_disabled`
- `agent_action_router_dry_run_disabled`
- `agent_action_router_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw parsed action names, command strings, input-source labels, context field names, tool arguments, credential references, and token placeholders are not emitted. Format categories, schema posture, auto-execution posture, authority categories, dry-run posture, redaction posture, approval posture, and credential key names let rules detect model-output-to-privileged-action paths without publishing action payloads.

## Agent Federation Posture

Outbound A2A clients, remote-agent federation configs, agent registries, peer-agent catalogs, and agent handoff routing configs are normalized into `runtime_config` objects when discovered. This models the boundary where a local agent delegates work or forwards context to third-party agents.

Agent federation metadata may include:

- `parsed_agent_federation_config`
- `agent_federation_fields`
- `agent_federation_provider`
- `agent_federation_remote`
- `agent_federation_destination_redacted`
- `agent_federation_destination_count`
- `agent_federation_destination_kinds`
- `agent_federation_agent_refs_redacted`
- `agent_federation_agent_ref_count`
- `agent_federation_dynamic_discovery`
- `agent_federation_untrusted_selector`
- `agent_federation_auto_delegation_enabled`
- `agent_federation_context_forwarding_enabled`
- `agent_federation_sensitive_context_forwarding`
- `agent_federation_pii_context_forwarding`
- `agent_federation_secret_forwarding`
- `agent_federation_tool_result_forwarding`
- `agent_federation_memory_forwarding`
- `agent_federation_credential_forwarding`
- `agent_federation_signature_verification_disabled`
- `agent_federation_identity_verification_missing`
- `agent_federation_allowlist_missing`
- `agent_federation_approval_required`
- `env_key_names`
- `secret_ref_key_names`

Raw registry URLs, agent-card URLs, endpoint URLs, peer names, agent IDs, task names, selector fields, forwarded source labels, tool strings, data-scope labels, and token placeholders are not emitted. Provider names, destination categories, peer counts, dynamic-discovery posture, context-forwarding categories, verification posture, allowlist posture, approval posture, and credential key names let rules detect remote-agent delegation risk without copying federation configuration values into evidence.

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
