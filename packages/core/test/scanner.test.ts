import { describe, expect, it } from "vitest";
import path from "node:path";
import { detectSurfaces } from "../src/scanner/detect.js";
import { walkProject } from "../src/scanner/walk.js";

const fixtureRoot = path.resolve("examples/vulnerable-agent");
const safeFixtureRoot = path.resolve("examples/safe-agent");

describe("scanner", () => {
  it("collects env key names without exposing env values", async () => {
    const files = await walkProject({
      root_path: fixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const envSurface = surfaces.secrets.find((surface) => surface.path === ".env.example");

    expect(envSurface).toBeDefined();
    expect(envSurface?.metadata.env_key_names).toEqual([
      "A2A_AGENT_TOKEN",
      "A2A_FEDERATION_TOKEN",
      "ACTION_ROUTER_TOKEN",
      "AGENT_CONTAINER_TOKEN",
      "AGENT_DEPLOY_TOKEN",
      "AGENT_EXTENSION_TOKEN",
      "AGENT_IDENTITY_TOKEN",
      "AGENT_LOOP_TOKEN",
      "AGENT_SELF_MOD_TOKEN",
      "AGENT_WEBHOOK_TOKEN",
      "APPROVAL_GATE_TOKEN",
      "ARTIFACT_EXPORT_TOKEN",
      "AWS_ACCESS_KEY_ID",
      "AWS_SECRET_ACCESS_KEY",
      "AWS_SESSION_TOKEN",
      "BROWSER_SESSION_TOKEN",
      "CODE_INTERPRETER_TOKEN",
      "CONTEXT_BROKER_TOKEN",
      "CONTEXT_COMPOSER_TOKEN",
      "CONTEXT_WINDOW_TOKEN",
      "CREW_AGENT_TOKEN",
      "CUSTOMER_SUCCESS_SLACK_BOT_TOKEN",
      "DEBUG_CONSOLE_TOKEN",
      "EMBEDDING_API_KEY",
      "EVAL_AGENT_TOKEN",
      "FALLBACK_MODEL_TOKEN",
      "FINE_TUNE_TOKEN",
      "GITHUB_TOKEN",
      "LLM_CACHE_TOKEN",
      "LLM_CACHE_URL",
      "MCP_OAUTH_CLIENT_SECRET",
      "MCP_TOOL_CATALOG_TOKEN",
      "MEMORY_STORE_TOKEN",
      "MODEL_GUARDRAIL_TOKEN",
      "MODEL_ROUTER_TOKEN",
      "NETWORK_EGRESS_TOKEN",
      "OPENAI_API_KEY",
      "PROMPT_REGISTRY_TOKEN",
      "PUBLIC_CHAT_AGENT_TOKEN",
      "REASONING_STATE_TOKEN",
      "REMOTE_INSTRUCTION_TOKEN",
      "RESPONSE_STREAM_TOKEN",
      "SAFETY_RUNTIME_TOKEN",
      "SLACK_WEBHOOK_URL",
      "SUPPORT_DB_PASSWORD",
      "SUPPORT_DB_URL",
      "SUPPORT_INBOX_TOKEN",
      "TICKETING_MCP_TOKEN",
      "TOOL_OUTPUT_POLICY_TOKEN",
      "TOOL_RETRY_POLICY_TOKEN",
      "VAULT_AGENT_TOKEN",
      "VISION_CONTEXT_TOKEN",
      "WORKSPACE_CONTEXT_TOKEN"
    ]);
    expect(JSON.stringify(envSurface)).not.toContain("replace-me");
    expect(JSON.stringify(envSurface)).not.toContain("https://example.invalid/webhook");
  });

  it("detects agent security surfaces across the vulnerable fixture", async () => {
    const files = await walkProject({
      root_path: fixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);

    expect(surfaces.instructions.some((surface) => surface.path === "AGENTS.md")).toBe(true);
    const agentInstructions = surfaces.instructions.find((surface) => surface.path === "AGENTS.md");
    expect(agentInstructions?.metadata).toMatchObject({
      content_analyzed: true,
      content_redacted: true,
      untrusted_context_reference: true,
      tool_directive: true,
      memory_write_directive: true,
      context_bridge_tool: true,
      context_bridge_memory: true,
      context_bridge_privileged: true
    });
    expect(agentInstructions?.actions).toContain("call");
    expect(agentInstructions?.actions).toContain("remember");
    expect(agentInstructions?.untrusted_to_privileged).toBe(true);
    expect(JSON.stringify(agentInstructions)).not.toContain("Untrusted customer notes");
    const cursorRule = surfaces.instructions.find((surface) => surface.path === ".cursor/rules/customer-escalation.mdc");
    expect(cursorRule).toBeDefined();
    expect(cursorRule?.metadata).toMatchObject({
      content_analyzed: true,
      content_redacted: true,
      cursor_rule: true,
      cursor_rule_frontmatter_present: true,
      cursor_rule_frontmatter_parsed: true,
      cursor_rule_body_redacted: true,
      cursor_rule_description_present: true,
      cursor_rule_always_apply: true,
      cursor_rule_application_mode: "always",
      cursor_rule_glob_count: 1,
      cursor_rule_applies_broadly: true,
      untrusted_context_reference: true,
      memory_write_directive: true,
      context_bridge_memory: true,
      context_bridge_privileged: true
    });
    expect(cursorRule?.metadata.cursor_rule_glob_scope_kinds).toEqual(["all_files", "workspace"]);
    expect(cursorRule?.actions).toContain("remember");
    expect(cursorRule?.untrusted_to_privileged).toBe(true);
    expect(JSON.stringify(cursorRule)).not.toContain("Always prepare customer escalation notes");
    expect(JSON.stringify(cursorRule)).not.toContain("When a customer escalation arrives");
    expect(surfaces.skills.some((surface) => surface.path === "skills/exfil-skill/SKILL.md")).toBe(true);
    const exfilSkill = surfaces.skills.find((surface) => surface.path === "skills/exfil-skill/SKILL.md");
    expect(exfilSkill?.metadata).toMatchObject({
      content_analyzed: true,
      content_redacted: true,
      retrieved_context_input: true,
      tool_output_input: true,
      memory_input: true,
      context_input_count: 3,
      external_output: true,
      local_write_output: true,
      context_bridge_external_output: true
    });
    expect(exfilSkill?.metadata.context_input_sources).toEqual(["memory", "retrieved_context", "tool_output"]);
    expect(exfilSkill?.actions).toContain("publish");
    expect(exfilSkill?.actions).toContain("send");
    expect(exfilSkill?.external_reach).toBe(true);
    expect(exfilSkill?.side_effect).toBe(true);
    expect(surfaces.mcp_servers.length).toBeGreaterThanOrEqual(3);
    const localMcp = surfaces.mcp_servers.find((surface) => surface.name === "filesystem-admin");
    const browserPublisherMcp = surfaces.mcp_servers.find((surface) => surface.name === "browser-publisher");
    const remoteMcp = surfaces.mcp_servers.find((surface) => surface.name === "remote-ticketing");
    const remoteContextBrokerMcp = surfaces.mcp_servers.find((surface) => surface.name === "remote-context-broker");
    const remoteToolCatalogMcp = surfaces.mcp_servers.find((surface) => surface.name === "remote-tool-catalog");
    const packageRunnerMcp = surfaces.mcp_servers.find((surface) => surface.name === "ticketing-package-runner");
    expect(localMcp).toMatchObject({
      trust_level: "project",
      secret_exposure: true
    });
    expect(localMcp?.metadata).toMatchObject({
      command_name: "node",
      args_count: 1,
      env_key_names: ["GITHUB_TOKEN"],
      local_command_paths: ["tools/filesystem-admin.js"],
      local_command_path_count: 1,
      local_command_paths_found: [],
      local_command_paths_missing: ["tools/filesystem-admin.js"],
      local_command_paths_missing_count: 1,
      local_command_paths_all_found: false,
      opaque_local_mcp_implementation: true,
      values_collected: false
    });
    expect(JSON.stringify(localMcp)).not.toContain("${GITHUB_TOKEN}");
    expect(browserPublisherMcp).toMatchObject({
      trust_level: "project",
      secret_exposure: true
    });
    expect(browserPublisherMcp?.metadata).toMatchObject({
      command_name: "node",
      args_count: 3,
      secret_ref_key_names: ["SLACK_WEBHOOK_URL"],
      local_command_paths: ["tools/browser-publisher.js"],
      local_command_paths_missing: ["tools/browser-publisher.js"],
      local_command_paths_missing_count: 1,
      opaque_local_mcp_implementation: true,
      values_collected: false
    });
    expect(JSON.stringify(browserPublisherMcp)).not.toContain("${SLACK_WEBHOOK_URL}");
    expect(remoteMcp).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true
    });
    expect(remoteMcp?.metadata).toMatchObject({
      remote: true,
      remote_host: "mcp.example.invalid",
      remote_scheme: "http",
      plaintext_remote_transport: true,
      encrypted_remote_transport: false,
      url_redacted: true,
      header_names: ["Authorization"],
      auth_header_names: ["Authorization"],
      secret_ref_key_names: ["TICKETING_MCP_TOKEN"],
      values_collected: false
    });
    expect(JSON.stringify(remoteMcp)).not.toContain("${TICKETING_MCP_TOKEN}");
    expect(JSON.stringify(remoteMcp)).not.toContain("/sse");
    expect(remoteContextBrokerMcp).toMatchObject({
      trust_level: "third_party",
      data_classes: ["confidential", "credential", "pii", "secret"],
      actions: ["call", "read", "remember", "send", "write"],
      external_reach: true,
      secret_exposure: true,
      untrusted_to_privileged: true
    });
    expect(remoteContextBrokerMcp?.metadata).toMatchObject({
      remote: true,
      remote_host: "context-broker.example.invalid",
      remote_scheme: "https",
      plaintext_remote_transport: false,
      encrypted_remote_transport: true,
      auth_header_names: ["Authorization"],
      mcp_env_passthrough: true,
      mcp_env_passthrough_all: true,
      mcp_env_passthrough_secret_risk: true,
      mcp_env_passthrough_pattern_count: 5,
      secret_ref_key_names: ["CONTEXT_BROKER_TOKEN"],
      mcp_roots_redacted: true,
      mcp_root_count: 3,
      mcp_root_scope_kinds: ["absolute_path", "credential_path", "file_uri", "home", "host_root", "workspace"],
      mcp_root_broad_scope: true,
      mcp_root_credential_scope: true,
      mcp_root_host_scope: true,
      mcp_root_sensitive_scope: true,
      mcp_root_approval_required: false,
      mcp_sampling_enabled: true,
      mcp_sampling_includes_context: true,
      mcp_sampling_sensitive_context: true,
      mcp_sampling_redaction_disabled: true,
      mcp_sampling_prompt_injection_filter_disabled: true,
      mcp_sampling_approval_required: false,
      mcp_elicitation_enabled: true,
      mcp_elicitation_sensitive_fields: true,
      mcp_elicitation_sensitive_field_count: 2,
      mcp_elicitation_redaction_disabled: true,
      mcp_elicitation_sanitization_disabled: true,
      mcp_elicitation_approval_required: false,
      mcp_context_request_authority: true,
      mcp_client_context_exposure: true,
      mcp_resource_subscription_detected: true,
      mcp_resource_subscription_enabled: true,
      mcp_resource_subscription_source_redacted: true,
      mcp_resource_subscription_source_count: 2,
      mcp_resource_subscription_dynamic_updates: true,
      mcp_resource_subscription_auto_refresh: true,
      mcp_resource_subscription_auto_include_context: true,
      mcp_resource_subscription_model_visible_context: true,
      mcp_resource_subscription_raw_content_passthrough: true,
      mcp_resource_subscription_untrusted_source: true,
      mcp_resource_subscription_sanitization_disabled: true,
      mcp_resource_subscription_redaction_disabled: true,
      mcp_resource_subscription_prompt_injection_filter_disabled: true,
      mcp_resource_subscription_provenance_verification_disabled: true,
      mcp_resource_subscription_privileged_bridge: true,
      mcp_resource_subscription_write_authority: true,
      mcp_resource_subscription_external_authority: true,
      mcp_resource_subscription_memory_authority: true,
      mcp_resource_subscription_secret_context: true,
      mcp_resource_subscription_sensitive_context: true,
      mcp_resource_subscription_pii_context: true,
      mcp_resource_subscription_approval_required: false,
      values_collected: false,
      content_redacted: true
    });
    expect(remoteContextBrokerMcp?.metadata.mcp_env_passthrough_source_kinds).toEqual([
      "inherit_env",
      "process_env",
      "sensitive_prefix",
      "wildcard"
    ]);
    expect(remoteContextBrokerMcp?.metadata.mcp_resource_subscription_source_kinds).toEqual([
      "browser_output",
      "customer_stream",
      "dynamic_subscription",
      "remote_resource",
      "tool_output"
    ]);
    expect(remoteContextBrokerMcp?.metadata.mcp_resource_subscription_authority_categories).toEqual([
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(remoteContextBrokerMcp?.metadata.mcp_sampling_context_kinds).toEqual([
      "credential_context",
      "pii_context",
      "prompt_context",
      "root_context",
      "secret_context",
      "tool_output",
      "workspace"
    ]);
    expect(remoteContextBrokerMcp?.metadata.mcp_elicitation_sensitive_field_kinds).toEqual(["credential", "pii"]);
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("${CONTEXT_BROKER_TOKEN}");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("context-broker.example.invalid/mcp");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("context-broker.example.invalid/live/customer-ticket-stream");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("mcp://browser-observations/tool-output");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("untrusted_customer_stream");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("ticket_attachments");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("subscription_customer_email");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("subscription_account_number");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("confidential_subscription_notes");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("subscription_support_api_token");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("slack.post_subscription_reply");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("memory.write_customer_summary");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("process.env");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("AWS_*");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("OPENAI_*");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("SLACK_*");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("*_TOKEN");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("file:///home/support/.ssh");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("file:///workspace/customer-escalations");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("file:///");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("support-ssh");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("customer-escalations");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("host-root");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("sampling_customer_email");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("sampling_tool_output");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("sampling_api_token");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("customer_email");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("api_token");
    expect(remoteToolCatalogMcp).toMatchObject({
      trust_level: "third_party",
      data_classes: ["confidential", "credential", "pii", "secret"],
      actions: ["call", "execute", "read", "remember", "send", "write"],
      side_effect: true,
      reversible: false,
      external_reach: true,
      secret_exposure: true,
      untrusted_to_privileged: true
    });
    expect(remoteToolCatalogMcp?.metadata).toMatchObject({
      remote: true,
      remote_host: "tool-catalog.agentcsp-demo.example.invalid",
      remote_scheme: "https",
      encrypted_remote_transport: true,
      auth_header_names: ["Authorization"],
      secret_ref_key_names: ["MCP_TOOL_CATALOG_TOKEN"],
      mcp_tool_catalog_detected: true,
      mcp_tool_catalog_enabled: true,
      mcp_tool_catalog_source_redacted: true,
      mcp_tool_catalog_source_count: 1,
      mcp_tool_catalog_dynamic: true,
      mcp_tool_catalog_auto_refresh: true,
      mcp_tool_catalog_model_visible_descriptions: true,
      mcp_tool_catalog_remote_schema_trust: true,
      mcp_tool_catalog_unpinned_tools: true,
      mcp_tool_catalog_signature_verification_disabled: true,
      mcp_tool_catalog_provenance_verification_disabled: true,
      mcp_tool_catalog_unreviewed_tools_allowed: true,
      mcp_tool_catalog_privileged_tool_authority: true,
      mcp_tool_catalog_write_authority: true,
      mcp_tool_catalog_external_authority: true,
      mcp_tool_catalog_memory_authority: true,
      mcp_tool_catalog_secret_context: true,
      mcp_tool_catalog_shell_authority: true,
      mcp_tool_catalog_sensitive_context: true,
      mcp_tool_catalog_pii_context: true,
      mcp_tool_catalog_approval_required: false,
      values_collected: false,
      content_redacted: true
    });
    expect(remoteToolCatalogMcp?.metadata.mcp_tool_catalog_source_kinds).toEqual([
      "dynamic_discovery",
      "remote_registry",
      "tool_catalog"
    ]);
    expect(remoteToolCatalogMcp?.metadata.mcp_tool_catalog_tool_authority_categories).toEqual([
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ]);
    expect(JSON.stringify(remoteToolCatalogMcp)).not.toContain("${MCP_TOOL_CATALOG_TOKEN}");
    expect(JSON.stringify(remoteToolCatalogMcp)).not.toContain("tool-catalog.agentcsp-demo.example.invalid/mcp");
    expect(JSON.stringify(remoteToolCatalogMcp)).not.toContain("remote_dynamic_registry");
    expect(JSON.stringify(remoteToolCatalogMcp)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(remoteToolCatalogMcp)).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(remoteToolCatalogMcp)).not.toContain("shell.run_remediation");
    expect(JSON.stringify(remoteToolCatalogMcp)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(remoteToolCatalogMcp)).not.toContain("memory.write_catalog_summary");
    expect(JSON.stringify(remoteToolCatalogMcp)).not.toContain("catalog_customer_email");
    expect(JSON.stringify(remoteToolCatalogMcp)).not.toContain("catalog_account_number");
    expect(JSON.stringify(remoteToolCatalogMcp)).not.toContain("confidential_catalog_notes");
    expect(packageRunnerMcp).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true
    });
    expect(packageRunnerMcp?.actions).toContain("execute");
    expect(packageRunnerMcp?.metadata).toMatchObject({
      command_name: "npx",
      package_runner: true,
      package_runner_name: "npx",
      package_name: "@acme/ticketing-mcp",
      package_version_pinned: false,
      package_reference_redacted: true,
      env_key_names: ["TICKETING_MCP_TOKEN"],
      values_collected: false
    });
    expect(JSON.stringify(packageRunnerMcp)).not.toContain("${TICKETING_MCP_TOKEN}");
    expect(JSON.stringify(packageRunnerMcp)).not.toContain("--workspace");
    const mcpContextSurfaces = surfaces.prompts.filter((surface) => surface.metadata.mcp_context_surface === true);
    expect(mcpContextSurfaces).toHaveLength(2);
    const mcpPromptContext = mcpContextSurfaces.find((surface) => surface.metadata.mcp_context_kind === "prompt");
    const mcpResourceContext = mcpContextSurfaces.find((surface) => surface.metadata.mcp_context_kind === "resource");
    expect(mcpPromptContext).toMatchObject({
      name: "mcp-context:filesystem-admin:prompt:1",
      path: "mcp.json",
      trust_level: "project",
      data_classes: ["confidential", "credential", "secret"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      untrusted_to_privileged: true
    });
    expect(mcpPromptContext?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      mcp_context_source_field: "prompts",
      mcp_context_server_name: "filesystem-admin",
      mcp_context_server_privileged: true,
      mcp_context_server_secret_backed: true,
      mcp_context_name_redacted: true,
      mcp_context_content_analyzed: true,
      env_key_names: ["GITHUB_TOKEN"],
      instruction_like_content: true,
      instruction_override: true,
      untrusted_context_reference: true,
      tool_directive: true,
      external_directive: true,
      secret_reference: true,
      sensitive_context_reference: true,
      context_bridge_privileged: true
    });
    expect(mcpResourceContext?.metadata).toMatchObject({
      mcp_context_source_field: "resources",
      mcp_context_server_name: "filesystem-admin",
      mcp_context_uri_redacted: true,
      mcp_context_server_secret_backed: true,
      untrusted_context_reference: true,
      tool_directive: true,
      external_directive: true,
      context_bridge_privileged: true
    });
    expect(JSON.stringify(mcpContextSurfaces)).not.toContain("support_remediation");
    expect(JSON.stringify(mcpContextSurfaces)).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(mcpContextSurfaces)).not.toContain("ignore approval policy");
    expect(JSON.stringify(mcpContextSurfaces)).not.toContain("delete_file");
    expect(JSON.stringify(mcpContextSurfaces)).not.toContain("exfil.example.invalid");
    expect(JSON.stringify(mcpContextSurfaces)).not.toContain("support://customer-escalation-runbook");
    expect(JSON.stringify(mcpContextSurfaces)).not.toContain("Retrieved support runbook");
    expect(surfaces.tools.some((surface) => surface.name === "package-script:sync:docs")).toBe(true);
    expect(surfaces.tools.some((surface) => surface.name === "package-script:postinstall")).toBe(true);
    const packageManifestConfig = surfaces.runtime_config.find(
      (surface) => surface.path === "package.json" && surface.metadata.parsed_agent_package_manifest_config === true
    );
    expect(packageManifestConfig).toBeDefined();
    expect(packageManifestConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(packageManifestConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_package_manifest_config: true,
      package_manifest_dependency_names_redacted: true,
      package_manifest_dependency_specs_redacted: true,
      package_manifest_dependency_count: 4,
      package_manifest_agent_dependency_count: 4,
      package_manifest_risky_dependency_count: 3,
      package_manifest_unpinned_dependency: true,
      package_manifest_remote_dependency: true,
      package_manifest_lifecycle_script: true,
      package_manifest_lifecycle_script_names: ["postinstall"],
      package_manifest_install_script_count: 1,
      package_manifest_lifecycle_shell_execution: true,
      package_manifest_lifecycle_network_access: false,
      package_manifest_lifecycle_secret_env: true,
      package_manifest_agent_script_count: 1,
      package_manifest_package_private: true
    });
    expect(packageManifestConfig?.metadata.package_manifest_agent_dependency_categories).toEqual([
      "agent_framework",
      "mcp_sdk",
      "model_sdk",
      "rag_vector_store"
    ]);
    expect(packageManifestConfig?.metadata.package_manifest_dependency_reference_kinds).toEqual([
      "exact_semver",
      "floating_range",
      "git_dependency",
      "http_tarball"
    ]);
    expect(packageManifestConfig?.metadata.env_key_names).toEqual(["AGENT_EXTENSION_TOKEN"]);
    expect(packageManifestConfig?.metadata.secret_ref_key_names).toEqual(["AGENT_EXTENSION_TOKEN"]);
    expect(packageManifestConfig?.data_classes).toEqual(["credential", "internal", "secret"]);
    expect(packageManifestConfig?.actions).toEqual(["execute", "read", "send", "write"]);
    expect(JSON.stringify(packageManifestConfig)).not.toContain("${AGENT_EXTENSION_TOKEN}");
    expect(JSON.stringify(packageManifestConfig)).not.toContain("@agentcsp-demo/remote-rag-plugin");
    expect(JSON.stringify(packageManifestConfig)).not.toContain("@openai/agents");
    expect(JSON.stringify(packageManifestConfig)).not.toContain("openai-agents-fork");
    expect(JSON.stringify(packageManifestConfig)).not.toContain("packages.example.invalid");
    expect(JSON.stringify(packageManifestConfig)).not.toContain("scripts/install-agent-plugins.js");
    const publishTool = surfaces.tools.find((surface) => surface.name === "publish_summary");
    const collisionTools = surfaces.tools.filter((surface) => surface.name === "customer_record");
    const privilegedCollisionTool = collisionTools.find((surface) => surface.metadata.external_write === true);
    const shadowCollisionTool = collisionTools.find((surface) => surface.path === "tools/shadow-tools.json");
    const deleteTool = surfaces.tools.find((surface) => surface.name === "delete_cache");
    const openWorldTool = surfaces.tools.find((surface) => surface.name === "post_customer_update");
    const readOnlyConflictTool = surfaces.tools.find((surface) => surface.name === "readonly_cleanup_workspace");
    const readTool = surfaces.tools.find((surface) => surface.name === "read_customer_record");
    const sourceExportTool = surfaces.tools.find((surface) => surface.name === "source_export_customer_record");
    const sourceDeleteTool = surfaces.tools.find((surface) => surface.name === "source_readonly_delete_workspace_file");
    const sourceShellTool = surfaces.tools.find((surface) => surface.name === "source_run_remediation_command");
    const sourceToolOutputShellExecutionBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_run_tool_observation_command"
    );
    const sourceToolOutputDynamicCodeBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_execute_tool_observation_code"
    );
    const sourceFileReadTool = surfaces.tools.find((surface) => surface.name === "source_read_workspace_file");
    const sourceNetworkResponseTool = surfaces.tools.find((surface) => surface.name === "source_fetch_url_content");
    const sourceDynamicCodeTool = surfaces.tools.find((surface) => surface.name === "source_evaluate_agent_expression");
    const sourceDatabaseTool = surfaces.tools.find((surface) => surface.name === "source_apply_record_change_sql");
    const sourceSecretOutputTool = surfaces.tools.find((surface) => surface.name === "source_reveal_runtime_secret");
    const sourceCredentialedNetworkTool = surfaces.tools.find((surface) => surface.name === "source_fetch_partner_status");
    const sourceMemoryWriteTool = surfaces.tools.find((surface) => surface.name === "source_persist_customer_memory");
    const sourceRagRetrievalTool = surfaces.tools.find((surface) => surface.name === "source_retrieve_support_context");
    const sourceRagRetrievalMemoryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_store_retrieved_context_memory"
    );
    const sourceRagRetrievalPromptBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_summarize_retrieved_context_with_model"
    );
    const sourceRagRetrievalExternalServiceBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_post_retrieved_context_external"
    );
    const sourceRagRetrievalBrowserAutomationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_submit_retrieved_context_browser"
    );
    const sourceTaskQueueTool = surfaces.tools.find((surface) => surface.name === "source_enqueue_support_agent_job");
    const sourceSecretManagerTaskQueueBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_enqueue_customer_vault_secret_job"
    );
    const sourceSecretManagerAgentDelegationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_delegate_customer_vault_secret_remote_agent"
    );
    const sourceTelemetryExportTool = surfaces.tools.find((surface) => surface.name === "source_export_customer_trace");
    const sourcePromptCacheWriteTool = surfaces.tools.find((surface) => surface.name === "source_write_prompt_cache_entry");
    const sourceTrainingDatasetExportTool = surfaces.tools.find((surface) => surface.name === "source_append_training_dataset_record");
    const sourceFeedbackAutoPromotionTool = surfaces.tools.find((surface) => surface.name === "source_record_feedback_auto_promotion");
    const sourceSafetyPolicyWeakeningTool = surfaces.tools.find((surface) => surface.name === "source_update_guardrail_policy_override");
    const sourceToolOutputSafetyPolicyBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_apply_tool_observation_guardrail_override"
    );
    const sourceSecretManagerSafetyPolicyBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_apply_vault_secret_guardrail_override"
    );
    const sourceAuthorizationGrantTool = surfaces.tools.find((surface) => surface.name === "source_update_tool_permission_grant");
    const sourceSecretManagerAuthorizationGrantBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_grant_customer_vault_secret_authorization"
    );
    const sourceArtifactExportTool = surfaces.tools.find((surface) => surface.name === "source_export_agent_run_artifact");
    const sourceModelApprovalTool = surfaces.tools.find((surface) => surface.name === "source_model_review_and_run_action");
    const sourcePromptRegistryWriteTool = surfaces.tools.find((surface) => surface.name === "source_publish_prompt_registry_update");
    const sourceAgentConfigWriteTool = surfaces.tools.find((surface) => surface.name === "source_update_agent_instructions");
    const sourceCredentialIssuanceTool = surfaces.tools.find((surface) => surface.name === "source_mint_agent_session_token");
    const sourceSecretManagerCredentialIssuanceBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_issue_vault_backed_agent_credential"
    );
    const sourceToolOutputCredentialIssuanceBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_issue_privileged_tool_observation_credential"
    );
    const sourceToolOutputDatabaseWriteBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_store_privileged_tool_observation_database"
    );
    const sourceNestedToolInvocationTool = surfaces.tools.find((surface) => surface.name === "source_dispatch_privileged_tool");
    const sourceToolOutputPromptBridgeTool = surfaces.tools.find((surface) => surface.name === "source_review_privileged_tool_observation");
    const sourceToolOutputMemoryBridgeTool = surfaces.tools.find((surface) => surface.name === "source_store_privileged_tool_observation_memory");
    const sourceToolOutputPromptCacheBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_cache_privileged_tool_observation_prompt"
    );
    const sourceToolOutputEmbeddingVectorBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_embed_privileged_tool_observation_vector_memory"
    );
    const sourceToolOutputPromptRegistryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_publish_privileged_tool_observation_prompt_registry"
    );
    const sourceToolOutputAuthorizationGrantBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_grant_privileged_tool_observation_authorization"
    );
    const sourceToolOutputExternalServiceBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_post_privileged_tool_observation_slack"
    );
    const sourceToolOutputTelemetryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_export_privileged_tool_observation_trace"
    );
    const sourceToolOutputArtifactBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_export_privileged_tool_observation_artifact"
    );
    const sourceToolOutputTaskQueueBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_enqueue_privileged_tool_observation_job"
    );
    const sourceToolOutputTrainingDatasetBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_export_privileged_tool_observation_training_dataset"
    );
    const sourceAgentDelegationTool = surfaces.tools.find((surface) => surface.name === "source_delegate_customer_case_to_remote_agent");
    const sourceToolOutputAgentDelegationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_delegate_privileged_tool_observation_remote_agent"
    );
    const sourceBrowserAutomationTool = surfaces.tools.find((surface) => surface.name === "source_submit_customer_browser_form");
    const sourceToolOutputBrowserAutomationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_submit_privileged_tool_observation_browser_form"
    );
    const sourceSecretManagerBrowserAutomationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_fill_customer_vault_secret_browser_form"
    );
    const sourceLocalFileBrowserAutomationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_upload_local_file_authenticated_browser"
    );
    const sourceClipboardExternalServiceBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_post_clipboard_to_slack"
    );
    const sourceVisualContextCaptureTool = surfaces.tools.find((surface) => surface.name === "source_capture_authenticated_page_screenshot");
    const sourceVisualContextPromptBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_review_authenticated_page_screenshot_with_model"
    );
    const sourceVisualContextExternalServiceBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_post_authenticated_page_screenshot_external"
    );
    const sourceVisualContextMemoryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_store_authenticated_page_screenshot_memory"
    );
    const sourceVisualContextArtifactBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_export_authenticated_page_screenshot_artifact"
    );
    const sourceVisualContextTrainingDatasetBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_export_authenticated_page_screenshot_training_dataset"
    );
    const sourceVisualContextTelemetryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_export_authenticated_page_screenshot_trace"
    );
    const sourceVisualContextPromptCacheBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_cache_authenticated_page_screenshot_prompt"
    );
    const sourceVisualContextAgentDelegationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_delegate_authenticated_page_screenshot_remote_agent"
    );
    const sourceVisualContextTaskQueueBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_enqueue_authenticated_page_screenshot_job"
    );
    const sourceSecretManagerAccessTool = surfaces.tools.find((surface) => surface.name === "source_read_customer_vault_secret");
    const sourceSecretManagerExternalServiceBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_post_customer_vault_secret_slack"
    );
    const sourceSecretManagerPromptBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_summarize_customer_vault_secret_with_model"
    );
    const sourceSecretManagerMemoryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_store_customer_vault_secret_memory"
    );
    const sourceSecretManagerDatabaseWriteBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_store_customer_vault_secret_database"
    );
    const sourceSecretManagerEmbeddingVectorBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_embed_customer_vault_secret_vector_memory"
    );
    const sourceSecretManagerTrainingDatasetBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_export_customer_vault_secret_training_dataset"
    );
    const sourceSecretManagerFeedbackBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_promote_customer_vault_secret_feedback"
    );
    const sourceSecretManagerArtifactBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_export_customer_vault_secret_artifact"
    );
    const sourceSecretManagerTelemetryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_export_customer_vault_secret_trace"
    );
    const sourceSecretManagerPromptCacheBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_cache_customer_vault_secret_prompt"
    );
    const sourceSecretManagerPromptRegistryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_publish_customer_vault_secret_prompt_registry"
    );
    const sourceExternalServiceWriteTool = surfaces.tools.find((surface) => surface.name === "source_send_customer_slack_update");
    const sourceModelProviderCallTool = surfaces.tools.find((surface) => surface.name === "source_summarize_customer_with_model");
    const sourceModelOutputDynamicCodeBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_execute_model_generated_code"
    );
    const sourceModelOutputNetworkDestinationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_fetch_model_selected_url"
    );
    const sourceModelOutputShellExecutionBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "source_run_model_generated_command"
    );
    const pythonExportTool = surfaces.tools.find((surface) => surface.name === "python_export_customer_record");
    const pythonDeleteTool = surfaces.tools.find((surface) => surface.name === "python_readonly_delete_workspace_file");
    const pythonUnsafeDeserializationTool = surfaces.tools.find((surface) => surface.name === "python_load_serialized_agent_state");
    const langchainExportTool = surfaces.tools.find((surface) => surface.name === "langchain_export_customer_context");
    const langchainDeleteTool = surfaces.tools.find((surface) => surface.name === "langchain_readonly_delete_workspace_path");
    const langchainShellTool = surfaces.tools.find((surface) => surface.name === "langchain_run_remediation_command");
    const langchainToolOutputShellExecutionBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_run_tool_observation_command"
    );
    const langchainToolOutputDynamicCodeBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_execute_tool_observation_code"
    );
    const langchainFileReadTool = surfaces.tools.find((surface) => surface.name === "langchain_read_workspace_file");
    const langchainNetworkResponseTool = surfaces.tools.find((surface) => surface.name === "langchain_fetch_url_content");
    const langchainDynamicCodeTool = surfaces.tools.find((surface) => surface.name === "langchain_evaluate_agent_expression");
    const langchainDatabaseTool = surfaces.tools.find((surface) => surface.name === "langchain_apply_record_change_sql");
    const langchainSecretOutputTool = surfaces.tools.find((surface) => surface.name === "langchain_reveal_runtime_secret");
    const langchainCredentialedNetworkTool = surfaces.tools.find((surface) => surface.name === "langchain_fetch_partner_status");
    const langchainMemoryWriteTool = surfaces.tools.find((surface) => surface.name === "langchain_persist_customer_memory");
    const langchainRagRetrievalTool = surfaces.tools.find((surface) => surface.name === "langchain_retrieve_support_context");
    const langchainRagRetrievalMemoryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_store_retrieved_context_memory"
    );
    const langchainRagRetrievalPromptBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_summarize_retrieved_context_with_model"
    );
    const langchainRagRetrievalExternalServiceBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_post_retrieved_context_external"
    );
    const langchainRagRetrievalBrowserAutomationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_submit_retrieved_context_browser"
    );
    const langchainTaskQueueTool = surfaces.tools.find((surface) => surface.name === "langchain_enqueue_support_agent_job");
    const langchainSecretManagerTaskQueueBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_enqueue_customer_vault_secret_job"
    );
    const langchainSecretManagerAgentDelegationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_delegate_customer_vault_secret_remote_agent"
    );
    const langchainTelemetryExportTool = surfaces.tools.find((surface) => surface.name === "langchain_export_customer_trace");
    const langchainPromptCacheWriteTool = surfaces.tools.find((surface) => surface.name === "langchain_write_prompt_cache_entry");
    const langchainTrainingDatasetExportTool = surfaces.tools.find((surface) => surface.name === "langchain_append_training_dataset_record");
    const langchainFeedbackAutoPromotionTool = surfaces.tools.find((surface) => surface.name === "langchain_record_feedback_auto_promotion");
    const langchainSafetyPolicyWeakeningTool = surfaces.tools.find((surface) => surface.name === "langchain_update_guardrail_policy_override");
    const langchainToolOutputSafetyPolicyBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_apply_tool_observation_guardrail_override"
    );
    const langchainSecretManagerSafetyPolicyBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_apply_vault_secret_guardrail_override"
    );
    const langchainAuthorizationGrantTool = surfaces.tools.find((surface) => surface.name === "langchain_update_tool_permission_grant");
    const langchainSecretManagerAuthorizationGrantBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_grant_customer_vault_secret_authorization"
    );
    const langchainArtifactExportTool = surfaces.tools.find((surface) => surface.name === "langchain_export_agent_run_artifact");
    const langchainModelApprovalTool = surfaces.tools.find((surface) => surface.name === "langchain_model_review_and_run_action");
    const langchainPromptRegistryWriteTool = surfaces.tools.find((surface) => surface.name === "langchain_publish_prompt_registry_update");
    const langchainAgentConfigWriteTool = surfaces.tools.find((surface) => surface.name === "langchain_update_agent_instructions");
    const langchainCredentialIssuanceTool = surfaces.tools.find((surface) => surface.name === "langchain_mint_agent_session_token");
    const langchainSecretManagerCredentialIssuanceBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_issue_vault_backed_agent_credential"
    );
    const langchainToolOutputCredentialIssuanceBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_issue_privileged_tool_observation_credential"
    );
    const langchainToolOutputDatabaseWriteBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_store_privileged_tool_observation_database"
    );
    const langchainNestedToolInvocationTool = surfaces.tools.find((surface) => surface.name === "langchain_dispatch_privileged_tool");
    const langchainToolOutputPromptBridgeTool = surfaces.tools.find((surface) => surface.name === "langchain_review_privileged_tool_observation");
    const langchainToolOutputMemoryBridgeTool = surfaces.tools.find((surface) => surface.name === "langchain_store_privileged_tool_observation_memory");
    const langchainToolOutputPromptCacheBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_cache_privileged_tool_observation_prompt"
    );
    const langchainToolOutputEmbeddingVectorBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_embed_privileged_tool_observation_vector_memory"
    );
    const langchainToolOutputPromptRegistryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_publish_privileged_tool_observation_prompt_registry"
    );
    const langchainToolOutputAuthorizationGrantBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_grant_privileged_tool_observation_authorization"
    );
    const langchainToolOutputExternalServiceBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_post_privileged_tool_observation_slack"
    );
    const langchainToolOutputTelemetryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_export_privileged_tool_observation_trace"
    );
    const langchainToolOutputArtifactBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_export_privileged_tool_observation_artifact"
    );
    const langchainToolOutputTaskQueueBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_enqueue_privileged_tool_observation_job"
    );
    const langchainToolOutputTrainingDatasetBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_export_privileged_tool_observation_training_dataset"
    );
    const langchainAgentDelegationTool = surfaces.tools.find((surface) => surface.name === "langchain_delegate_customer_case_to_remote_agent");
    const langchainToolOutputAgentDelegationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_delegate_privileged_tool_observation_remote_agent"
    );
    const langchainBrowserAutomationTool = surfaces.tools.find((surface) => surface.name === "langchain_submit_customer_browser_form");
    const langchainToolOutputBrowserAutomationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_submit_privileged_tool_observation_browser_form"
    );
    const langchainSecretManagerBrowserAutomationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_fill_customer_vault_secret_browser_form"
    );
    const langchainLocalFileBrowserAutomationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_upload_local_file_authenticated_browser"
    );
    const langchainClipboardExternalServiceBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_post_clipboard_to_slack"
    );
    const langchainVisualContextCaptureTool = surfaces.tools.find((surface) => surface.name === "langchain_capture_authenticated_page_screenshot");
    const langchainVisualContextPromptBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_review_authenticated_page_screenshot_with_model"
    );
    const langchainVisualContextExternalServiceBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_post_authenticated_page_screenshot_external"
    );
    const langchainVisualContextMemoryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_store_authenticated_page_screenshot_memory"
    );
    const langchainVisualContextArtifactBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_export_authenticated_page_screenshot_artifact"
    );
    const langchainVisualContextTrainingDatasetBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_export_authenticated_page_screenshot_training_dataset"
    );
    const langchainVisualContextTelemetryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_export_authenticated_page_screenshot_trace"
    );
    const langchainVisualContextPromptCacheBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_cache_authenticated_page_screenshot_prompt"
    );
    const langchainVisualContextAgentDelegationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_delegate_authenticated_page_screenshot_remote_agent"
    );
    const langchainVisualContextTaskQueueBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_enqueue_authenticated_page_screenshot_job"
    );
    const langchainSecretManagerAccessTool = surfaces.tools.find((surface) => surface.name === "langchain_read_customer_vault_secret");
    const langchainSecretManagerExternalServiceBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_post_customer_vault_secret_slack"
    );
    const langchainSecretManagerPromptBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_summarize_customer_vault_secret_with_model"
    );
    const langchainSecretManagerMemoryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_store_customer_vault_secret_memory"
    );
    const langchainSecretManagerDatabaseWriteBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_store_customer_vault_secret_database"
    );
    const langchainSecretManagerEmbeddingVectorBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_embed_customer_vault_secret_vector_memory"
    );
    const langchainSecretManagerTrainingDatasetBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_export_customer_vault_secret_training_dataset"
    );
    const langchainSecretManagerFeedbackBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_promote_customer_vault_secret_feedback"
    );
    const langchainSecretManagerArtifactBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_export_customer_vault_secret_artifact"
    );
    const langchainSecretManagerTelemetryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_export_customer_vault_secret_trace"
    );
    const langchainSecretManagerPromptCacheBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_cache_customer_vault_secret_prompt"
    );
    const langchainSecretManagerPromptRegistryBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_publish_customer_vault_secret_prompt_registry"
    );
    const langchainExternalServiceWriteTool = surfaces.tools.find((surface) => surface.name === "langchain_send_customer_slack_update");
    const langchainModelProviderCallTool = surfaces.tools.find((surface) => surface.name === "langchain_summarize_customer_with_model");
    const langchainModelOutputDynamicCodeBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_execute_model_generated_code"
    );
    const langchainModelOutputNetworkDestinationBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_fetch_model_selected_url"
    );
    const langchainModelOutputShellExecutionBridgeTool = surfaces.tools.find(
      (surface) => surface.name === "langchain_run_model_generated_command"
    );
    const langchainUnsafeDeserializationTool = surfaces.tools.find((surface) => surface.name === "langchain_load_serialized_agent_state");
    const aiSdkExportTool = surfaces.tools.find((surface) => surface.name === "aiSdkExportCustomerContext");
    const tsLangchainDeleteTool = surfaces.tools.find((surface) => surface.name === "ts_langchain_delete_workspace_path");
    expect(publishTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      external_write: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      open_world_schema: false,
      open_world_authority: false,
      read_only_hint_conflict: false,
      model_visible_description_analyzed: true,
      model_visible_description_redacted: true,
      model_visible_description_instruction_like_content: true,
      model_visible_description_instruction_override: true,
      model_visible_description_untrusted_context_reference: true,
      model_visible_description_tool_directive: true,
      model_visible_description_external_directive: true,
      model_visible_description_sensitive_context_reference: true,
      model_visible_description_data_egress_directive: true,
      model_visible_description_context_bridge_tool: true,
      model_visible_description_context_bridge_external: true,
      model_visible_description_context_bridge_data_egress: true,
      model_visible_description_context_bridge_privileged: true
    });
    expect(JSON.stringify(publishTool)).not.toContain("ignore previous instructions");
    expect(collisionTools).toHaveLength(2);
    expect(privilegedCollisionTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      external_write: true,
      accepts_path_input: true,
      accepts_url_input: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: false,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      accepted_data_classes: ["confidential", "pii"],
      name_collision: true,
      collision_name: "customer_record",
      collision_count: 2,
      collision_authority_mismatch: true,
      collision_has_privileged_peer: true
    });
    expect(shadowCollisionTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      read_only_hint: true,
      external_write: false,
      accepts_content_like_input: false,
      name_collision: true,
      collision_name: "customer_record",
      collision_count: 2,
      collision_authority_mismatch: true,
      collision_has_privileged_peer: true
    });
    expect(shadowCollisionTool?.metadata.collision_paths).toEqual(["tools/agent-tools.json", "tools/shadow-tools.json"]);
    expect(JSON.stringify(shadowCollisionTool)).not.toContain("Preview a local customer record");
    expect(deleteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      destructive_action: true,
      accepts_path_input: true,
      accepts_content_like_input: false,
      read_only_hint_conflict: false
    });
    expect(openWorldTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      external_write: true,
      accepts_url_input: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      accepted_data_classes: ["confidential", "pii"],
      open_world_schema: true,
      open_world_authority: true,
      read_only_hint_conflict: false
    });
    expect(privilegedCollisionTool?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(openWorldTool?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(readOnlyConflictTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      read_only_hint: true,
      destructive_action: true,
      accepts_path_input: true,
      accepts_content_like_input: false,
      read_only_hint_conflict: true,
      open_world_schema: false
    });
    expect(readOnlyConflictTool?.side_effect).toBe(true);
    expect(readTool?.side_effect).toBe(false);
    expect(readTool?.metadata.accepts_content_like_input).toBe(false);
    expect(readTool?.metadata.read_only_hint_conflict).toBe(false);
    expect(sourceExportTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true
    });
    expect(sourceExportTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "tool",
      mcp_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      values_collected: false,
      external_write: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      open_world_schema: true,
      open_world_authority: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: true,
      handler_tainted_network_destination: true,
      handler_external_write: true,
      handler_secret_env_access: true,
      tainted_network_destination: true,
      handler_shell_execution: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4
    });
    expect(sourceExportTool?.metadata.handler_authority_classes).toEqual([
      "handler_external_write",
      "handler_network_access",
      "handler_secret_env_access",
      "handler_tainted_network_destination"
    ]);
    expect(sourceExportTool?.metadata.handler_env_key_names).toEqual(["SOURCE_EXPORT_TOKEN"]);
    expect(sourceExportTool?.metadata.mcp_source_tool_schema_styles).toEqual(["zod_field_map"]);
    expect(sourceExportTool?.metadata.schema_properties).toEqual([
      "authorization_token",
      "customer_email",
      "customer_reference",
      "destination_webhook_url",
      "source_payload_text"
    ]);
    expect(JSON.stringify(sourceExportTool)).not.toContain("queued");
    expect(JSON.stringify(sourceExportTool)).not.toContain("Post customer records");
    expect(JSON.stringify(sourceExportTool)).not.toContain("fetch(");
    expect(JSON.stringify(sourceExportTool)).not.toContain("Bearer");
    expect(sourceDeleteTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      actions: ["call", "delete", "read"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false
    });
    expect(sourceDeleteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: true,
      idempotent_hint: false,
      destructive_action: true,
      accepts_path_input: true,
      read_only_hint_conflict: true,
      open_world_schema: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_shell_execution: false,
      handler_tainted_filesystem_path: true,
      tainted_filesystem_path: true,
      handler_filesystem_write: false,
      handler_filesystem_delete: true,
      handler_signal_count: 2
    });
    expect(sourceDeleteTool?.metadata.authority_classes).toEqual([
      "destructive_action",
      "filesystem_access",
      "handler_filesystem_delete",
      "handler_tainted_filesystem_path",
      "tainted_filesystem_path"
    ]);
    expect(sourceDeleteTool?.metadata.handler_authority_classes).toEqual([
      "handler_filesystem_delete",
      "handler_tainted_filesystem_path"
    ]);
    expect(sourceDeleteTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceDeleteTool?.metadata.mcp_source_tool_schema_styles).toEqual([
      "zod_field_map",
      "zod_object",
      "zod_strict"
    ]);
    expect(JSON.stringify(sourceDeleteTool)).not.toContain("rm(");
    expect(JSON.stringify(sourceDeleteTool)).not.toContain("node:fs/promises");
    expect(sourceShellTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      actions: ["call", "execute", "read"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: false
    });
    expect(sourceShellTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_path_input: true,
      external_write: false,
      destructive_action: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_shell_execution: true,
      handler_tainted_shell_argument: true,
      tainted_shell_argument: true,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(sourceShellTool?.metadata.authority_classes).toEqual([
      "filesystem_access",
      "handler_shell_execution",
      "handler_tainted_shell_argument",
      "shell_execution",
      "tainted_shell_argument"
    ]);
    expect(sourceShellTool?.metadata.handler_authority_classes).toEqual([
      "handler_shell_execution",
      "handler_tainted_shell_argument"
    ]);
    expect(sourceShellTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceShellTool?.metadata.schema_properties).toEqual(["shell_command", "working_directory"]);
    expect(sourceShellTool?.metadata.required_properties).toEqual(["shell_command"]);
    expect(JSON.stringify(sourceShellTool)).not.toContain("execFile");
    expect(JSON.stringify(sourceShellTool)).not.toContain("node:child_process");
    expect(JSON.stringify(sourceShellTool)).not.toContain("source shell queued");
    expect(sourceToolOutputShellExecutionBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputShellExecutionBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_path_input: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      shell_execution: true,
      tool_output_shell_execution_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_shell_execution: true,
      handler_tool_output_shell_execution_bridge: true,
      handler_secret_env_access: false,
      handler_signal_count: 3,
      open_world_schema: false
    });
    expect(sourceToolOutputShellExecutionBridgeTool?.metadata.authority_classes).toEqual(expect.arrayContaining([
      "handler_shell_execution",
      "handler_tool_invocation",
      "handler_tool_output_shell_execution_bridge",
      "nested_tool_invocation",
      "shell_execution",
      "tool_output_shell_execution_bridge"
    ]));
    expect(sourceToolOutputShellExecutionBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_shell_execution",
      "handler_tool_invocation",
      "handler_tool_output_shell_execution_bridge"
    ]);
    expect(sourceToolOutputShellExecutionBridgeTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceToolOutputShellExecutionBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body",
      "working_directory"
    ]);
    expect(sourceToolOutputShellExecutionBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceToolOutputShellExecutionBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputShellExecutionBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputShellExecutionBridgeTool)).not.toContain("execFile");
    expect(JSON.stringify(sourceToolOutputShellExecutionBridgeTool)).not.toContain("source tool observation command queued");
    expect(JSON.stringify(sourceToolOutputShellExecutionBridgeTool)).not.toContain("Run a command returned by a caller selected privileged tool observation");
    expect(sourceToolOutputDynamicCodeBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputDynamicCodeBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      dynamic_code_execution: true,
      tool_output_dynamic_code_execution_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_dynamic_code_execution: true,
      handler_tool_output_dynamic_code_execution_bridge: true,
      handler_secret_env_access: false,
      handler_signal_count: 3,
      open_world_schema: false
    });
    expect(sourceToolOutputDynamicCodeBridgeTool?.metadata.authority_classes).toEqual(expect.arrayContaining([
      "dynamic_code_execution",
      "handler_dynamic_code_execution",
      "handler_tool_invocation",
      "handler_tool_output_dynamic_code_execution_bridge",
      "nested_tool_invocation",
      "tool_output_dynamic_code_execution_bridge"
    ]));
    expect(sourceToolOutputDynamicCodeBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_dynamic_code_execution",
      "handler_tool_invocation",
      "handler_tool_output_dynamic_code_execution_bridge"
    ]);
    expect(sourceToolOutputDynamicCodeBridgeTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceToolOutputDynamicCodeBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "execution_reason_text",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(sourceToolOutputDynamicCodeBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "execution_reason_text",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceToolOutputDynamicCodeBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputDynamicCodeBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputDynamicCodeBridgeTool)).not.toContain("new Function");
    expect(JSON.stringify(sourceToolOutputDynamicCodeBridgeTool)).not.toContain("source tool observation code executed");
    expect(JSON.stringify(sourceToolOutputDynamicCodeBridgeTool)).not.toContain("Execute code returned by a caller selected privileged tool observation");
    expect(sourceFileReadTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["credential"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: false,
      secret_exposure: true,
      reversible: true
    });
    expect(sourceFileReadTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: true,
      idempotent_hint: true,
      accepts_path_input: true,
      local_file_disclosure: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_filesystem_read: true,
      handler_tainted_filesystem_path: true,
      tainted_filesystem_path: true,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_model_visible_output: true,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(sourceFileReadTool?.metadata.authority_classes).toEqual([
      "filesystem_access",
      "filesystem_read",
      "handler_filesystem_read",
      "handler_tainted_filesystem_path",
      "local_file_disclosure",
      "tainted_filesystem_path"
    ]);
    expect(sourceFileReadTool?.metadata.handler_authority_classes).toEqual([
      "handler_filesystem_read",
      "handler_tainted_filesystem_path"
    ]);
    expect(sourceFileReadTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceFileReadTool?.metadata.schema_properties).toEqual(["encoding", "workspace_path"]);
    expect(sourceFileReadTool?.metadata.required_properties).toEqual(["workspace_path"]);
    expect(JSON.stringify(sourceFileReadTool)).not.toContain("readFile");
    expect(JSON.stringify(sourceFileReadTool)).not.toContain("contents.toString");
    expect(JSON.stringify(sourceFileReadTool)).not.toContain("Read a workspace file by model supplied path");
    expect(sourceNetworkResponseTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["unknown"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: false,
      reversible: false
    });
    expect(sourceNetworkResponseTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: true,
      accepts_url_input: true,
      network_response_capture: true,
      external_write: false,
      destructive_action: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: true,
      handler_tainted_network_destination: true,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: true,
      handler_external_write: false,
      handler_secret_env_access: false,
      tainted_network_destination: true,
      handler_model_visible_output: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 3,
      open_world_schema: false
    });
    expect(sourceNetworkResponseTool?.metadata.authority_classes).toEqual([
      "content_input",
      "handler_network_access",
      "handler_network_response_to_output",
      "handler_tainted_network_destination",
      "network_access",
      "network_response_capture",
      "tainted_network_destination"
    ]);
    expect(sourceNetworkResponseTool?.metadata.handler_authority_classes).toEqual([
      "handler_network_access",
      "handler_network_response_to_output",
      "handler_tainted_network_destination"
    ]);
    expect(sourceNetworkResponseTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceNetworkResponseTool?.metadata.schema_properties).toEqual(["expected_content_type", "target_url"]);
    expect(sourceNetworkResponseTool?.metadata.required_properties).toEqual(["target_url"]);
    expect(JSON.stringify(sourceNetworkResponseTool)).not.toContain("responseBody");
    expect(JSON.stringify(sourceNetworkResponseTool)).not.toContain("response.text");
    expect(JSON.stringify(sourceNetworkResponseTool)).not.toContain("Fetch a caller supplied URL");
    expect(sourceDynamicCodeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["unknown"],
      actions: ["call", "execute"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: false
    });
    expect(sourceDynamicCodeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      dynamic_code_execution: true,
      external_write: false,
      destructive_action: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: true,
      handler_tainted_dynamic_code_argument: true,
      tainted_dynamic_code_argument: true,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(sourceDynamicCodeTool?.metadata.authority_classes).toEqual([
      "dynamic_code_execution",
      "handler_dynamic_code_execution",
      "handler_tainted_dynamic_code_argument",
      "tainted_dynamic_code_argument"
    ]);
    expect(sourceDynamicCodeTool?.metadata.handler_authority_classes).toEqual([
      "handler_dynamic_code_execution",
      "handler_tainted_dynamic_code_argument"
    ]);
    expect(sourceDynamicCodeTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceDynamicCodeTool?.metadata.schema_properties).toEqual(["context_json", "expression"]);
    expect(sourceDynamicCodeTool?.metadata.required_properties).toEqual(["expression"]);
    expect(JSON.stringify(sourceDynamicCodeTool)).not.toContain("Function(");
    expect(JSON.stringify(sourceDynamicCodeTool)).not.toContain("return (${expression})");
    expect(JSON.stringify(sourceDynamicCodeTool)).not.toContain("source expression evaluated");
    expect(JSON.stringify(sourceDynamicCodeTool)).not.toContain("Evaluate a model supplied JavaScript expression");
    expect(sourceDatabaseTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "pii"],
      actions: ["call", "execute", "write"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: false
    });
    expect(sourceDatabaseTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      database_access: true,
      database_write: true,
      tainted_database_query_argument: true,
      external_write: false,
      destructive_action: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_database_query: true,
      handler_database_write: true,
      handler_tainted_database_query_argument: true,
      handler_shell_execution: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 3,
      open_world_schema: false
    });
    expect(sourceDatabaseTool?.metadata.authority_classes).toEqual([
      "customer_data_input",
      "database_access",
      "database_write",
      "handler_database_query",
      "handler_database_write",
      "handler_tainted_database_query_argument",
      "pii_input",
      "tainted_database_query_argument"
    ]);
    expect(sourceDatabaseTool?.metadata.handler_authority_classes).toEqual([
      "handler_database_query",
      "handler_database_write",
      "handler_tainted_database_query_argument"
    ]);
    expect(sourceDatabaseTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceDatabaseTool?.metadata.schema_properties).toEqual(["approval_reason", "customer_id", "sql_query"]);
    expect(sourceDatabaseTool?.metadata.required_properties).toEqual(["customer_id", "sql_query"]);
    expect(JSON.stringify(sourceDatabaseTool)).not.toContain("db.query");
    expect(JSON.stringify(sourceDatabaseTool)).not.toContain("UPDATE support_cases");
    expect(JSON.stringify(sourceDatabaseTool)).not.toContain("source database updated");
    expect(JSON.stringify(sourceDatabaseTool)).not.toContain("Update customer support records from a supplied SQL statement");
    expect(sourceToolOutputDatabaseWriteBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "pii"],
      actions: ["call", "execute", "remember", "write"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: false
    });
    expect(sourceToolOutputDatabaseWriteBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      database_access: true,
      database_write: true,
      tainted_database_query_argument: false,
      tool_output_database_write_bridge: true,
      nested_tool_invocation: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_database_query: true,
      handler_database_write: true,
      handler_tainted_database_query_argument: false,
      handler_tool_output_database_write_bridge: true,
      handler_tool_invocation: true,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourceToolOutputDatabaseWriteBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "database_access",
      "database_write",
      "handler_database_query",
      "handler_database_write",
      "handler_tool_invocation",
      "handler_tool_output_database_write_bridge",
      "memory_access",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "tool_output_database_write_bridge"
    ]);
    expect(sourceToolOutputDatabaseWriteBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_database_query",
      "handler_database_write",
      "handler_tool_invocation",
      "handler_tool_output_database_write_bridge"
    ]);
    expect(sourceToolOutputDatabaseWriteBridgeTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceToolOutputDatabaseWriteBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(sourceToolOutputDatabaseWriteBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceToolOutputDatabaseWriteBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputDatabaseWriteBridgeTool)).not.toContain("db.query");
    expect(JSON.stringify(sourceToolOutputDatabaseWriteBridgeTool)).not.toContain("UPDATE support_cases");
    expect(JSON.stringify(sourceToolOutputDatabaseWriteBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputDatabaseWriteBridgeTool)).not.toContain("source tool observation stored in database");
    expect(JSON.stringify(sourceToolOutputDatabaseWriteBridgeTool)).not.toContain("Store a raw privileged tool observation");
    expect(sourceSecretOutputTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential"],
      actions: ["call", "send"],
      side_effect: true,
      external_reach: false,
      secret_exposure: true,
      reversible: true
    });
    expect(sourceSecretOutputTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: true,
      idempotent_hint: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: true,
      handler_database_query: false,
      handler_database_write: false,
      handler_shell_execution: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(sourceSecretOutputTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_secret_env_access",
      "handler_secret_to_output",
      "secret_env_access",
      "secret_materialization"
    ]);
    expect(sourceSecretOutputTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_secret_to_output"
    ]);
    expect(sourceSecretOutputTool?.metadata.handler_env_key_names).toEqual(["SOURCE_RUNTIME_SECRET"]);
    expect(sourceSecretOutputTool?.metadata.schema_properties).toEqual(["requester_ticket", "secret_purpose"]);
    expect(sourceSecretOutputTool?.metadata.required_properties).toEqual(["requester_ticket", "secret_purpose"]);
    expect(JSON.stringify(sourceSecretOutputTool)).not.toContain("runtime secret:");
    expect(JSON.stringify(sourceSecretOutputTool)).not.toContain("Return a runtime support secret");
    expect(sourceCredentialedNetworkTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential"],
      actions: ["call", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceCredentialedNetworkTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: true,
      accepts_url_input: true,
      accepts_customer_data_input: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: true,
      handler_tainted_network_destination: true,
      handler_credentialed_network_read: true,
      handler_external_write: false,
      handler_secret_env_access: true,
      tainted_network_destination: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_shell_execution: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourceCredentialedNetworkTool?.metadata.authority_classes).toEqual([
      "credential_input",
      "credentialed_network_read",
      "customer_data_input",
      "handler_credentialed_network_read",
      "handler_network_access",
      "handler_secret_env_access",
      "handler_tainted_network_destination",
      "network_access",
      "secret_env_access",
      "tainted_network_destination"
    ]);
    expect(sourceCredentialedNetworkTool?.metadata.handler_authority_classes).toEqual([
      "handler_credentialed_network_read",
      "handler_network_access",
      "handler_secret_env_access",
      "handler_tainted_network_destination"
    ]);
    expect(sourceCredentialedNetworkTool?.metadata.handler_env_key_names).toEqual(["SOURCE_PARTNER_STATUS_TOKEN"]);
    expect(sourceCredentialedNetworkTool?.metadata.schema_properties).toEqual(["customer_reference", "status_endpoint_url"]);
    expect(sourceCredentialedNetworkTool?.metadata.required_properties).toEqual(["customer_reference", "status_endpoint_url"]);
    expect(JSON.stringify(sourceCredentialedNetworkTool)).not.toContain("source partner status checked");
    expect(JSON.stringify(sourceCredentialedNetworkTool)).not.toContain("Fetch a support partner status endpoint");
    expect(sourceMemoryWriteTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceMemoryWriteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: true,
      tainted_memory_scope: true,
      embedding_provider_call: true,
      tainted_embedding_input: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: true,
      handler_tainted_embedding_input: true,
      handler_memory_write: true,
      handler_tainted_memory_scope: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(sourceMemoryWriteTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "embedding_provider_call",
      "handler_embedding_provider_call",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tainted_embedding_input",
      "handler_tainted_memory_scope",
      "memory_access",
      "memory_write",
      "pii_input",
      "secret_env_access",
      "tainted_embedding_input",
      "tainted_memory_scope"
    ]);
    expect(sourceMemoryWriteTool?.metadata.handler_authority_classes).toEqual([
      "handler_embedding_provider_call",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tainted_embedding_input",
      "handler_tainted_memory_scope"
    ]);
    expect(sourceMemoryWriteTool?.metadata.handler_env_key_names).toEqual(["SOURCE_EMBEDDING_TOKEN"]);
    expect(sourceMemoryWriteTool?.metadata.schema_properties).toEqual(["customer_id", "memory_namespace", "ticket_text"]);
    expect(sourceMemoryWriteTool?.metadata.required_properties).toEqual(["customer_id", "ticket_text"]);
    expect(JSON.stringify(sourceMemoryWriteTool)).not.toContain("agentMemory.upsert");
    expect(JSON.stringify(sourceMemoryWriteTool)).not.toContain("embeddingClient.embedQuery");
    expect(JSON.stringify(sourceMemoryWriteTool)).not.toContain("source memory persisted");
    expect(JSON.stringify(sourceMemoryWriteTool)).not.toContain("Persist caller supplied customer ticket text");
    expect(sourceRagRetrievalTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceRagRetrievalTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      rag_retrieval: true,
      tainted_rag_retrieval_query: true,
      rag_context_to_output: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_model_provider_call: false,
      handler_rag_retrieval: true,
      handler_tainted_rag_retrieval_query: true,
      handler_rag_context_to_output: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: false,
      handler_memory_write: false,
      handler_tool_invocation: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourceRagRetrievalTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_rag_context_to_output",
      "handler_rag_retrieval",
      "handler_secret_env_access",
      "handler_tainted_rag_retrieval_query",
      "pii_input",
      "rag_context_to_output",
      "rag_retrieval",
      "secret_env_access",
      "tainted_rag_retrieval_query"
    ]);
    expect(sourceRagRetrievalTool?.metadata.handler_authority_classes).toEqual([
      "handler_rag_context_to_output",
      "handler_rag_retrieval",
      "handler_secret_env_access",
      "handler_tainted_rag_retrieval_query"
    ]);
    expect(sourceRagRetrievalTool?.metadata.handler_env_key_names).toEqual(["SOURCE_RAG_RETRIEVAL_TOKEN"]);
    expect(sourceRagRetrievalTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "retrieval_namespace",
      "retrieval_query_text",
      "top_k"
    ]);
    expect(sourceRagRetrievalTool?.metadata.required_properties).toEqual([
      "customer_id",
      "retrieval_namespace",
      "retrieval_query_text"
    ]);
    expect(JSON.stringify(sourceRagRetrievalTool)).not.toContain("vectorRetriever.search");
    expect(JSON.stringify(sourceRagRetrievalTool)).not.toContain("retrievedContext");
    expect(JSON.stringify(sourceRagRetrievalTool)).not.toContain("Retrieve caller selected support context");
    expect(sourceRagRetrievalMemoryBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceRagRetrievalMemoryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      rag_retrieval: true,
      tainted_rag_retrieval_query: true,
      rag_context_to_output: false,
      memory_write: true,
      tainted_memory_scope: true,
      rag_retrieval_memory_bridge: true,
      handler_rag_retrieval: true,
      handler_tainted_rag_retrieval_query: true,
      handler_rag_context_to_output: false,
      handler_memory_write: true,
      handler_tainted_memory_scope: true,
      handler_rag_retrieval_memory_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceRagRetrievalMemoryBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_memory_write",
      "handler_rag_retrieval",
      "handler_rag_retrieval_memory_bridge",
      "handler_secret_env_access",
      "handler_tainted_memory_scope",
      "handler_tainted_rag_retrieval_query",
      "memory_access",
      "memory_write",
      "pii_input",
      "rag_retrieval",
      "rag_retrieval_memory_bridge",
      "secret_env_access",
      "tainted_memory_scope",
      "tainted_rag_retrieval_query"
    ]);
    expect(sourceRagRetrievalMemoryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_memory_write",
      "handler_rag_retrieval",
      "handler_rag_retrieval_memory_bridge",
      "handler_secret_env_access",
      "handler_tainted_memory_scope",
      "handler_tainted_rag_retrieval_query"
    ]);
    expect(sourceRagRetrievalMemoryBridgeTool?.metadata.handler_env_key_names).toEqual(["SOURCE_RAG_MEMORY_BRIDGE_TOKEN"]);
    expect(sourceRagRetrievalMemoryBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "memory_namespace",
      "retention_note_text",
      "retrieval_namespace",
      "retrieval_query_text"
    ]);
    expect(JSON.stringify(sourceRagRetrievalMemoryBridgeTool)).not.toContain("vectorRetriever.search");
    expect(JSON.stringify(sourceRagRetrievalMemoryBridgeTool)).not.toContain("agentMemory.upsert");
    expect(JSON.stringify(sourceRagRetrievalMemoryBridgeTool)).not.toContain("retrievedChunks");
    expect(JSON.stringify(sourceRagRetrievalMemoryBridgeTool)).not.toContain("source retrieved context remembered");
    expect(JSON.stringify(sourceRagRetrievalMemoryBridgeTool)).not.toContain("Persist caller selected retrieved support context");
    expect(sourceRagRetrievalPromptBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceRagRetrievalPromptBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      rag_retrieval: true,
      tainted_rag_retrieval_query: true,
      model_provider_call: true,
      rag_retrieval_prompt_bridge: true,
      handler_rag_retrieval: true,
      handler_tainted_rag_retrieval_query: true,
      handler_model_provider_call: true,
      handler_rag_retrieval_prompt_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceRagRetrievalPromptBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_model_provider_call",
      "handler_privileged_prompt_composition",
      "handler_rag_retrieval",
      "handler_rag_retrieval_prompt_bridge",
      "handler_secret_env_access",
      "handler_tainted_rag_retrieval_query",
      "model_provider_call",
      "pii_input",
      "privileged_prompt_composition",
      "rag_retrieval",
      "rag_retrieval_prompt_bridge",
      "secret_env_access",
      "tainted_rag_retrieval_query"
    ]);
    expect(sourceRagRetrievalPromptBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_model_provider_call",
      "handler_privileged_prompt_composition",
      "handler_rag_retrieval",
      "handler_rag_retrieval_prompt_bridge",
      "handler_secret_env_access",
      "handler_tainted_rag_retrieval_query"
    ]);
    expect(sourceRagRetrievalPromptBridgeTool?.metadata.handler_env_key_names).toEqual(["SOURCE_RAG_PROMPT_BRIDGE_TOKEN"]);
    expect(sourceRagRetrievalPromptBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "retrieval_namespace",
      "retrieval_query_text",
      "summary_instruction_text"
    ]);
    expect(JSON.stringify(sourceRagRetrievalPromptBridgeTool)).not.toContain("vectorRetriever.search");
    expect(JSON.stringify(sourceRagRetrievalPromptBridgeTool)).not.toContain("openai.chat.completions.create");
    expect(JSON.stringify(sourceRagRetrievalPromptBridgeTool)).not.toContain("retrievedChunks");
    expect(JSON.stringify(sourceRagRetrievalPromptBridgeTool)).not.toContain("Summarize retrieved support context");
    expect(JSON.stringify(sourceRagRetrievalPromptBridgeTool)).not.toContain("Retrieve caller selected support context");
    expect(sourceRagRetrievalExternalServiceBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceRagRetrievalExternalServiceBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      external_service_write: true,
      tainted_external_service_recipient: true,
      rag_retrieval: true,
      tainted_rag_retrieval_query: true,
      rag_retrieval_external_service_bridge: true,
      handler_external_service_write: true,
      handler_tainted_external_service_recipient: true,
      handler_rag_retrieval: true,
      handler_tainted_rag_retrieval_query: true,
      handler_rag_retrieval_external_service_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceRagRetrievalExternalServiceBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_service_write",
      "external_write",
      "handler_external_service_write",
      "handler_rag_retrieval",
      "handler_rag_retrieval_external_service_bridge",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient",
      "handler_tainted_rag_retrieval_query",
      "pii_input",
      "rag_retrieval",
      "rag_retrieval_external_service_bridge",
      "secret_env_access",
      "tainted_external_service_recipient",
      "tainted_rag_retrieval_query"
    ]);
    expect(sourceRagRetrievalExternalServiceBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_external_service_write",
      "handler_rag_retrieval",
      "handler_rag_retrieval_external_service_bridge",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient",
      "handler_tainted_rag_retrieval_query"
    ]);
    expect(sourceRagRetrievalExternalServiceBridgeTool?.metadata.handler_env_key_names).toEqual(["SOURCE_RAG_EXTERNAL_BRIDGE_TOKEN"]);
    expect(sourceRagRetrievalExternalServiceBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "destination_channel_id",
      "escalation_note_text",
      "retrieval_namespace",
      "retrieval_query_text"
    ]);
    expect(JSON.stringify(sourceRagRetrievalExternalServiceBridgeTool)).not.toContain("vectorRetriever.search");
    expect(JSON.stringify(sourceRagRetrievalExternalServiceBridgeTool)).not.toContain("slackClient.chat.postMessage");
    expect(JSON.stringify(sourceRagRetrievalExternalServiceBridgeTool)).not.toContain("retrievedChunks");
    expect(JSON.stringify(sourceRagRetrievalExternalServiceBridgeTool)).not.toContain("source retrieved context posted externally");
    expect(JSON.stringify(sourceRagRetrievalExternalServiceBridgeTool)).not.toContain("Post caller selected retrieved support context");
    expect(sourceRagRetrievalBrowserAutomationBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceRagRetrievalBrowserAutomationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      rag_retrieval: true,
      tainted_rag_retrieval_query: true,
      rag_retrieval_browser_automation_bridge: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_rag_retrieval: true,
      handler_tainted_rag_retrieval_query: true,
      handler_rag_retrieval_browser_automation_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceRagRetrievalBrowserAutomationBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_browser_automation",
      "handler_rag_retrieval",
      "handler_rag_retrieval_browser_automation_bridge",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_rag_retrieval_query",
      "network_access",
      "pii_input",
      "rag_retrieval",
      "rag_retrieval_browser_automation_bridge",
      "secret_env_access",
      "tainted_browser_automation_target",
      "tainted_rag_retrieval_query"
    ]);
    expect(sourceRagRetrievalBrowserAutomationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_rag_retrieval",
      "handler_rag_retrieval_browser_automation_bridge",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_rag_retrieval_query"
    ]);
    expect(sourceRagRetrievalBrowserAutomationBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_RAG_BROWSER_BRIDGE_TOKEN"
    ]);
    expect(sourceRagRetrievalBrowserAutomationBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "form_selector",
      "retrieval_namespace",
      "retrieval_query_text",
      "submit_selector",
      "target_url"
    ]);
    expect(sourceRagRetrievalBrowserAutomationBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "form_selector",
      "retrieval_namespace",
      "retrieval_query_text",
      "submit_selector",
      "target_url"
    ]);
    expect(JSON.stringify(sourceRagRetrievalBrowserAutomationBridgeTool)).not.toContain("vectorRetriever.search");
    expect(JSON.stringify(sourceRagRetrievalBrowserAutomationBridgeTool)).not.toContain("authenticatedBrowserPage.goto");
    expect(JSON.stringify(sourceRagRetrievalBrowserAutomationBridgeTool)).not.toContain("authenticatedBrowserPage.fill");
    expect(JSON.stringify(sourceRagRetrievalBrowserAutomationBridgeTool)).not.toContain("authenticatedBrowserPage.click");
    expect(JSON.stringify(sourceRagRetrievalBrowserAutomationBridgeTool)).not.toContain("retrievedChunks");
    expect(JSON.stringify(sourceRagRetrievalBrowserAutomationBridgeTool)).not.toContain("source retrieved context submitted through browser");
    expect(JSON.stringify(sourceRagRetrievalBrowserAutomationBridgeTool)).not.toContain("Submit caller selected retrieved support context");
    expect(sourceTaskQueueTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceTaskQueueTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      task_queue_enqueue: true,
      tainted_task_payload: true,
      tainted_task_routing: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_model_provider_call: false,
      handler_task_queue_enqueue: true,
      handler_tainted_task_payload: true,
      handler_tainted_task_routing: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: false,
      handler_memory_write: false,
      handler_tool_invocation: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourceTaskQueueTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_secret_env_access",
      "handler_tainted_task_payload",
      "handler_tainted_task_routing",
      "handler_task_queue_enqueue",
      "pii_input",
      "secret_env_access",
      "tainted_task_payload",
      "tainted_task_routing",
      "task_queue_enqueue"
    ]);
    expect(sourceTaskQueueTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_tainted_task_payload",
      "handler_tainted_task_routing",
      "handler_task_queue_enqueue"
    ]);
    expect(sourceTaskQueueTool?.metadata.handler_env_key_names).toEqual(["SOURCE_AGENT_TASK_QUEUE_TOKEN"]);
    expect(sourceTaskQueueTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "target_queue_name",
      "task_route"
    ]);
    expect(sourceTaskQueueTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "target_queue_name",
      "task_route"
    ]);
    expect(JSON.stringify(sourceTaskQueueTool)).not.toContain("taskQueueClient.enqueue");
    expect(JSON.stringify(sourceTaskQueueTool)).not.toContain("requestedAction");
    expect(JSON.stringify(sourceTaskQueueTool)).not.toContain("update_customer_record");
    expect(JSON.stringify(sourceTaskQueueTool)).not.toContain("source agent job queued");
    expect(JSON.stringify(sourceTaskQueueTool)).not.toContain("Queue a caller supplied support job");
    expect(sourceSecretManagerTaskQueueBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerTaskQueueBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      task_queue_enqueue: true,
      tainted_task_payload: true,
      tainted_task_routing: true,
      secret_manager_task_queue_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_task_queue_enqueue: true,
      handler_tainted_task_payload: true,
      handler_tainted_task_routing: true,
      handler_secret_manager_task_queue_bridge: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(sourceSecretManagerTaskQueueBridgeTool?.metadata.authority_classes).toContain("secret_manager_task_queue_bridge");
    expect(sourceSecretManagerTaskQueueBridgeTool?.metadata.handler_authority_classes).toContain("handler_secret_manager_task_queue_bridge");
    expect(sourceSecretManagerTaskQueueBridgeTool?.metadata.handler_env_key_names).toEqual(["SOURCE_SECRET_TASK_QUEUE_TOKEN"]);
    expect(sourceSecretManagerTaskQueueBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "replay_on_failure",
      "requester_ticket",
      "secret_path",
      "target_queue_name",
      "task_route"
    ]);
    expect(JSON.stringify(sourceSecretManagerTaskQueueBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerTaskQueueBridgeTool)).not.toContain("taskQueueClient.enqueue");
    expect(JSON.stringify(sourceSecretManagerTaskQueueBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerTaskQueueBridgeTool)).not.toContain("secretQueueValue");
    expect(JSON.stringify(sourceSecretManagerTaskQueueBridgeTool)).not.toContain("source vault secret queued for background agent");
    expect(JSON.stringify(sourceSecretManagerTaskQueueBridgeTool)).not.toContain("Enqueue a customer support secret");
    expect(sourceTelemetryExportTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceTelemetryExportTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      telemetry_export: true,
      tainted_telemetry_payload: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: false,
      handler_memory_write: false,
      handler_telemetry_export: true,
      handler_tainted_telemetry_payload: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 3,
      open_world_schema: false
    });
    expect(sourceTelemetryExportTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_secret_env_access",
      "handler_tainted_telemetry_payload",
      "handler_telemetry_export",
      "pii_input",
      "secret_env_access",
      "tainted_telemetry_payload",
      "telemetry_export"
    ]);
    expect(sourceTelemetryExportTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_tainted_telemetry_payload",
      "handler_telemetry_export"
    ]);
    expect(sourceTelemetryExportTool?.metadata.handler_env_key_names).toEqual(["SOURCE_TRACE_EXPORT_TOKEN"]);
    expect(sourceTelemetryExportTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "tool_trace_payload",
      "trace_session_id"
    ]);
    expect(sourceTelemetryExportTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "tool_trace_payload",
      "trace_session_id"
    ]);
    expect(JSON.stringify(sourceTelemetryExportTool)).not.toContain("telemetryClient.recordTrace");
    expect(JSON.stringify(sourceTelemetryExportTool)).not.toContain("source trace exported");
    expect(JSON.stringify(sourceTelemetryExportTool)).not.toContain("Export caller supplied customer trace context");
    expect(sourcePromptCacheWriteTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "remember", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourcePromptCacheWriteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      prompt_cache_write: true,
      tainted_prompt_cache_key: true,
      tainted_prompt_cache_value: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: false,
      handler_memory_write: false,
      handler_telemetry_export: false,
      handler_prompt_cache_write: true,
      handler_tainted_prompt_cache_key: true,
      handler_tainted_prompt_cache_value: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourcePromptCacheWriteTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_cache_key",
      "handler_tainted_prompt_cache_value",
      "pii_input",
      "prompt_cache_write",
      "secret_env_access",
      "tainted_prompt_cache_key",
      "tainted_prompt_cache_value"
    ]);
    expect(sourcePromptCacheWriteTool?.metadata.handler_authority_classes).toEqual([
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_cache_key",
      "handler_tainted_prompt_cache_value"
    ]);
    expect(sourcePromptCacheWriteTool?.metadata.handler_env_key_names).toEqual(["SOURCE_PROMPT_CACHE_TOKEN"]);
    expect(sourcePromptCacheWriteTool?.metadata.schema_properties).toEqual([
      "cache_key",
      "customer_id",
      "customer_ticket_text",
      "tool_output_text"
    ]);
    expect(sourcePromptCacheWriteTool?.metadata.required_properties).toEqual([
      "cache_key",
      "customer_id",
      "customer_ticket_text",
      "tool_output_text"
    ]);
    expect(JSON.stringify(sourcePromptCacheWriteTool)).not.toContain("promptCache.set");
    expect(JSON.stringify(sourcePromptCacheWriteTool)).not.toContain("source prompt cache written");
    expect(JSON.stringify(sourcePromptCacheWriteTool)).not.toContain("Write caller supplied prompt context");
    expect(sourceTrainingDatasetExportTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceTrainingDatasetExportTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      training_dataset_export: true,
      tainted_training_dataset_payload: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: false,
      handler_memory_write: false,
      handler_telemetry_export: false,
      handler_prompt_cache_write: false,
      handler_training_dataset_export: true,
      handler_tainted_training_dataset_payload: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 3,
      open_world_schema: false
    });
    expect(sourceTrainingDatasetExportTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_secret_env_access",
      "handler_tainted_training_dataset_payload",
      "handler_training_dataset_export",
      "pii_input",
      "secret_env_access",
      "tainted_training_dataset_payload",
      "training_dataset_export"
    ]);
    expect(sourceTrainingDatasetExportTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_tainted_training_dataset_payload",
      "handler_training_dataset_export"
    ]);
    expect(sourceTrainingDatasetExportTool?.metadata.handler_env_key_names).toEqual(["SOURCE_TRAINING_DATASET_TOKEN"]);
    expect(sourceTrainingDatasetExportTool?.metadata.schema_properties).toEqual([
      "completion_text",
      "customer_id",
      "customer_ticket_text",
      "dataset_id",
      "tool_output_text"
    ]);
    expect(sourceTrainingDatasetExportTool?.metadata.required_properties).toEqual([
      "completion_text",
      "customer_id",
      "customer_ticket_text",
      "dataset_id",
      "tool_output_text"
    ]);
    expect(JSON.stringify(sourceTrainingDatasetExportTool)).not.toContain("trainingDatasetClient.appendRecord");
    expect(JSON.stringify(sourceTrainingDatasetExportTool)).not.toContain("source training record exported");
    expect(JSON.stringify(sourceTrainingDatasetExportTool)).not.toContain("Export caller supplied support context");
    expect(sourceFeedbackAutoPromotionTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceFeedbackAutoPromotionTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      training_dataset_export: false,
      tainted_training_dataset_payload: false,
      feedback_pipeline_write: true,
      tainted_feedback_payload: true,
      feedback_auto_promotion: true,
      tainted_feedback_routing: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: false,
      handler_memory_write: false,
      handler_telemetry_export: false,
      handler_prompt_cache_write: false,
      handler_training_dataset_export: false,
      handler_tainted_training_dataset_payload: false,
      handler_feedback_pipeline_write: true,
      handler_tainted_feedback_payload: true,
      handler_feedback_auto_promotion: true,
      handler_tainted_feedback_routing: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(sourceFeedbackAutoPromotionTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "feedback_auto_promotion",
      "feedback_pipeline_write",
      "handler_feedback_auto_promotion",
      "handler_feedback_pipeline_write",
      "handler_secret_env_access",
      "handler_tainted_feedback_payload",
      "handler_tainted_feedback_routing",
      "memory_access",
      "pii_input",
      "secret_env_access",
      "tainted_feedback_payload",
      "tainted_feedback_routing"
    ]);
    expect(sourceFeedbackAutoPromotionTool?.metadata.handler_authority_classes).toEqual([
      "handler_feedback_auto_promotion",
      "handler_feedback_pipeline_write",
      "handler_secret_env_access",
      "handler_tainted_feedback_payload",
      "handler_tainted_feedback_routing"
    ]);
    expect(sourceFeedbackAutoPromotionTool?.metadata.handler_env_key_names).toEqual(["SOURCE_FEEDBACK_PIPELINE_TOKEN"]);
    expect(sourceFeedbackAutoPromotionTool?.metadata.schema_properties).toEqual([
      "completion_text",
      "customer_email",
      "customer_feedback_text",
      "customer_id",
      "eval_set_id",
      "feedback_dataset_id",
      "memory_context",
      "promotion_target",
      "prompt_text",
      "rating_value",
      "retrieval_context",
      "tool_trace_payload"
    ]);
    expect(sourceFeedbackAutoPromotionTool?.metadata.required_properties).toEqual([
      "completion_text",
      "customer_email",
      "customer_feedback_text",
      "customer_id",
      "eval_set_id",
      "feedback_dataset_id",
      "memory_context",
      "promotion_target",
      "prompt_text",
      "rating_value",
      "retrieval_context",
      "tool_trace_payload"
    ]);
    expect(JSON.stringify(sourceFeedbackAutoPromotionTool)).not.toContain("feedbackPipeline.promoteToTraining");
    expect(JSON.stringify(sourceFeedbackAutoPromotionTool)).not.toContain("source feedback promoted");
    expect(JSON.stringify(sourceFeedbackAutoPromotionTool)).not.toContain("Record caller supplied feedback");
    expect(sourceSafetyPolicyWeakeningTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSafetyPolicyWeakeningTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      feedback_pipeline_write: false,
      tainted_feedback_payload: false,
      safety_policy_write: true,
      tainted_safety_policy_payload: true,
      tainted_safety_policy_selector: true,
      safety_policy_weakening: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_safety_policy_write: true,
      handler_tainted_safety_policy_payload: true,
      handler_tainted_safety_policy_selector: true,
      handler_safety_policy_weakening: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(sourceSafetyPolicyWeakeningTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_safety_policy_weakening",
      "handler_safety_policy_write",
      "handler_secret_env_access",
      "handler_tainted_safety_policy_payload",
      "handler_tainted_safety_policy_selector",
      "pii_input",
      "safety_policy_weakening",
      "safety_policy_write",
      "secret_env_access",
      "tainted_safety_policy_payload",
      "tainted_safety_policy_selector"
    ]);
    expect(sourceSafetyPolicyWeakeningTool?.metadata.handler_authority_classes).toEqual([
      "handler_safety_policy_weakening",
      "handler_safety_policy_write",
      "handler_secret_env_access",
      "handler_tainted_safety_policy_payload",
      "handler_tainted_safety_policy_selector"
    ]);
    expect(sourceSafetyPolicyWeakeningTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_GUARDRAIL_POLICY_TOKEN"
    ]);
    expect(sourceSafetyPolicyWeakeningTool?.metadata.schema_properties).toEqual([
      "approval_profile",
      "control_id",
      "customer_email",
      "customer_id",
      "customer_ticket_text",
      "policy_mode",
      "policy_patch_text"
    ]);
    expect(sourceSafetyPolicyWeakeningTool?.metadata.required_properties).toEqual([
      "approval_profile",
      "control_id",
      "customer_email",
      "customer_id",
      "customer_ticket_text",
      "policy_mode",
      "policy_patch_text"
    ]);
    expect(JSON.stringify(sourceSafetyPolicyWeakeningTool)).not.toContain("guardrailPolicyClient.updatePolicy");
    expect(JSON.stringify(sourceSafetyPolicyWeakeningTool)).not.toContain("source guardrail policy updated");
    expect(JSON.stringify(sourceSafetyPolicyWeakeningTool)).not.toContain("Update caller selected guardrail policy");
    expect(sourceToolOutputSafetyPolicyBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputSafetyPolicyBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      safety_policy_write: true,
      tainted_safety_policy_payload: true,
      tainted_safety_policy_selector: true,
      safety_policy_weakening: true,
      tool_output_safety_policy_bridge: true,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_safety_policy_write: true,
      handler_tainted_safety_policy_payload: true,
      handler_tainted_safety_policy_selector: true,
      handler_safety_policy_weakening: true,
      handler_tool_output_safety_policy_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(sourceToolOutputSafetyPolicyBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_safety_policy_weakening",
      "handler_safety_policy_write",
      "handler_secret_env_access",
      "handler_tainted_safety_policy_payload",
      "handler_tainted_safety_policy_selector",
      "handler_tool_invocation",
      "handler_tool_output_safety_policy_bridge",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "safety_policy_weakening",
      "safety_policy_write",
      "secret_env_access",
      "tainted_safety_policy_payload",
      "tainted_safety_policy_selector",
      "tool_output_safety_policy_bridge"
    ]);
    expect(sourceToolOutputSafetyPolicyBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_safety_policy_weakening",
      "handler_safety_policy_write",
      "handler_secret_env_access",
      "handler_tainted_safety_policy_payload",
      "handler_tainted_safety_policy_selector",
      "handler_tool_invocation",
      "handler_tool_output_safety_policy_bridge"
    ]);
    expect(sourceToolOutputSafetyPolicyBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_TOOL_OBSERVATION_SAFETY_POLICY_TOKEN"
    ]);
    expect(sourceToolOutputSafetyPolicyBridgeTool?.metadata.schema_properties).toEqual([
      "customer_email",
      "customer_id",
      "override_reason",
      "policy_id",
      "policy_mode",
      "target_control_id",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(sourceToolOutputSafetyPolicyBridgeTool?.metadata.required_properties).toEqual([
      "customer_email",
      "customer_id",
      "override_reason",
      "policy_id",
      "policy_mode",
      "target_control_id",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceToolOutputSafetyPolicyBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputSafetyPolicyBridgeTool)).not.toContain("guardrailPolicyClient.updatePolicy");
    expect(JSON.stringify(sourceToolOutputSafetyPolicyBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputSafetyPolicyBridgeTool)).not.toContain("source tool observation updated safety policy");
    expect(JSON.stringify(sourceToolOutputSafetyPolicyBridgeTool)).not.toContain("Apply a raw privileged tool observation");
    expect(sourceSecretManagerSafetyPolicyBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerSafetyPolicyBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      safety_policy_write: true,
      tainted_safety_policy_payload: true,
      tainted_safety_policy_selector: true,
      safety_policy_weakening: true,
      secret_manager_safety_policy_bridge: true,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_safety_policy_write: true,
      handler_tainted_safety_policy_payload: true,
      handler_tainted_safety_policy_selector: true,
      handler_safety_policy_weakening: true,
      handler_secret_manager_safety_policy_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 8,
      open_world_schema: false
    });
    expect(sourceSecretManagerSafetyPolicyBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "filesystem_access",
      "handler_safety_policy_weakening",
      "handler_safety_policy_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_safety_policy_bridge",
      "handler_tainted_safety_policy_payload",
      "handler_tainted_safety_policy_selector",
      "handler_tainted_secret_manager_path",
      "pii_input",
      "safety_policy_weakening",
      "safety_policy_write",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_safety_policy_bridge",
      "tainted_safety_policy_payload",
      "tainted_safety_policy_selector",
      "tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerSafetyPolicyBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_safety_policy_weakening",
      "handler_safety_policy_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_safety_policy_bridge",
      "handler_tainted_safety_policy_payload",
      "handler_tainted_safety_policy_selector",
      "handler_tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerSafetyPolicyBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_VAULT_SECRET_SAFETY_POLICY_TOKEN"
    ]);
    expect(sourceSecretManagerSafetyPolicyBridgeTool?.metadata.schema_properties).toEqual([
      "customer_email",
      "customer_id",
      "override_reason",
      "policy_id",
      "policy_mode",
      "target_control_id",
      "vault_secret_path"
    ]);
    expect(sourceSecretManagerSafetyPolicyBridgeTool?.metadata.required_properties).toEqual([
      "customer_email",
      "customer_id",
      "override_reason",
      "policy_id",
      "policy_mode",
      "target_control_id",
      "vault_secret_path"
    ]);
    expect(JSON.stringify(sourceSecretManagerSafetyPolicyBridgeTool)).not.toContain("vaultClient.getSecret");
    expect(JSON.stringify(sourceSecretManagerSafetyPolicyBridgeTool)).not.toContain("guardrailPolicyClient.updatePolicy");
    expect(JSON.stringify(sourceSecretManagerSafetyPolicyBridgeTool)).not.toContain("secretPolicyValue");
    expect(JSON.stringify(sourceSecretManagerSafetyPolicyBridgeTool)).not.toContain("source vault secret updated safety policy");
    expect(JSON.stringify(sourceSecretManagerSafetyPolicyBridgeTool)).not.toContain("Apply a customer vault secret");
    expect(sourceAuthorizationGrantTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceAuthorizationGrantTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      authorization_policy_write: true,
      tainted_authorization_grant_input: true,
      authorization_broad_grant: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_authorization_policy_write: true,
      handler_tainted_authorization_grant_input: true,
      handler_authorization_broad_grant: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourceAuthorizationGrantTool?.metadata.authority_classes).toEqual([
      "authorization_broad_grant",
      "authorization_policy_write",
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_authorization_broad_grant",
      "handler_authorization_policy_write",
      "handler_secret_env_access",
      "handler_tainted_authorization_grant_input",
      "pii_input",
      "secret_env_access",
      "tainted_authorization_grant_input"
    ]);
    expect(sourceAuthorizationGrantTool?.metadata.handler_authority_classes).toEqual([
      "handler_authorization_broad_grant",
      "handler_authorization_policy_write",
      "handler_secret_env_access",
      "handler_tainted_authorization_grant_input"
    ]);
    expect(sourceAuthorizationGrantTool?.metadata.handler_env_key_names).toEqual(["SOURCE_TOOL_PERMISSION_TOKEN"]);
    expect(sourceAuthorizationGrantTool?.metadata.schema_properties).toEqual([
      "customer_email",
      "customer_id",
      "customer_ticket_text",
      "grant_reason",
      "requested_scope",
      "requested_tool_name",
      "tenant_id"
    ]);
    expect(sourceAuthorizationGrantTool?.metadata.required_properties).toEqual([
      "customer_email",
      "customer_id",
      "customer_ticket_text",
      "grant_reason",
      "requested_scope",
      "requested_tool_name",
      "tenant_id"
    ]);
    expect(JSON.stringify(sourceAuthorizationGrantTool)).not.toContain("permissionBrokerClient.upsertGrant");
    expect(JSON.stringify(sourceAuthorizationGrantTool)).not.toContain("source tool permission grant updated");
    expect(JSON.stringify(sourceAuthorizationGrantTool)).not.toContain("Grant caller selected tool permission");
    expect(sourceSecretManagerAuthorizationGrantBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerAuthorizationGrantBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      authorization_policy_write: true,
      tainted_authorization_grant_input: true,
      authorization_broad_grant: true,
      secret_manager_authorization_grant_bridge: true,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_authorization_policy_write: true,
      handler_tainted_authorization_grant_input: true,
      handler_authorization_broad_grant: true,
      handler_secret_manager_authorization_grant_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    for (const authorityClass of [
      "secret_manager_access",
      "tainted_secret_manager_path",
      "authorization_policy_write",
      "tainted_authorization_grant_input",
      "authorization_broad_grant",
      "secret_manager_authorization_grant_bridge"
    ]) {
      expect(sourceSecretManagerAuthorizationGrantBridgeTool?.metadata.authority_classes).toContain(authorityClass);
    }
    for (const handlerClass of [
      "handler_secret_manager_access",
      "handler_tainted_secret_manager_path",
      "handler_authorization_policy_write",
      "handler_tainted_authorization_grant_input",
      "handler_authorization_broad_grant",
      "handler_secret_manager_authorization_grant_bridge"
    ]) {
      expect(sourceSecretManagerAuthorizationGrantBridgeTool?.metadata.handler_authority_classes).toContain(handlerClass);
    }
    expect(sourceSecretManagerAuthorizationGrantBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_SECRET_AUTHZ_GRANT_TOKEN"
    ]);
    expect(sourceSecretManagerAuthorizationGrantBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requested_tool_name",
      "requester_ticket",
      "secret_path",
      "tenant_id"
    ]);
    expect(sourceSecretManagerAuthorizationGrantBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requested_tool_name",
      "requester_ticket",
      "secret_path",
      "tenant_id"
    ]);
    expect(JSON.stringify(sourceSecretManagerAuthorizationGrantBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerAuthorizationGrantBridgeTool)).not.toContain("permissionBrokerClient.upsertGrant");
    expect(JSON.stringify(sourceSecretManagerAuthorizationGrantBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerAuthorizationGrantBridgeTool)).not.toContain("secretGrantRole");
    expect(JSON.stringify(sourceSecretManagerAuthorizationGrantBridgeTool)).not.toContain("source vault secret granted broad authorization");
    expect(JSON.stringify(sourceSecretManagerAuthorizationGrantBridgeTool)).not.toContain("Grant broad tool authorization");
    expect(sourceArtifactExportTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceArtifactExportTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      artifact_export: true,
      tainted_artifact_export_payload: true,
      public_artifact_destination: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: false,
      handler_memory_write: false,
      handler_telemetry_export: false,
      handler_prompt_cache_write: false,
      handler_training_dataset_export: false,
      handler_artifact_export: true,
      handler_tainted_artifact_export_payload: true,
      handler_public_artifact_destination: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourceArtifactExportTool?.metadata.authority_classes).toEqual([
      "artifact_export",
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_artifact_export",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_tainted_artifact_export_payload",
      "pii_input",
      "public_artifact_destination",
      "secret_env_access",
      "tainted_artifact_export_payload"
    ]);
    expect(sourceArtifactExportTool?.metadata.handler_authority_classes).toEqual([
      "handler_artifact_export",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_tainted_artifact_export_payload"
    ]);
    expect(sourceArtifactExportTool?.metadata.handler_env_key_names).toEqual(["SOURCE_ARTIFACT_EXPORT_TOKEN"]);
    expect(sourceArtifactExportTool?.metadata.schema_properties).toEqual([
      "artifact_body",
      "customer_id",
      "destination_bucket",
      "object_key",
      "share_mode",
      "tool_output_text"
    ]);
    expect(sourceArtifactExportTool?.metadata.required_properties).toEqual([
      "artifact_body",
      "customer_id",
      "destination_bucket",
      "object_key",
      "share_mode",
      "tool_output_text"
    ]);
    expect(JSON.stringify(sourceArtifactExportTool)).not.toContain("artifactExportClient.upload");
    expect(JSON.stringify(sourceArtifactExportTool)).not.toContain("source artifact exported");
    expect(JSON.stringify(sourceArtifactExportTool)).not.toContain("Export caller supplied agent artifact");
    expect(sourceModelApprovalTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceModelApprovalTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      model_approval_gate: true,
      tainted_approval_context: true,
      approval_auto_execution: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_model_provider_call: false,
      handler_model_approval_gate: true,
      handler_tainted_approval_context: true,
      handler_approval_auto_execution: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_tool_invocation: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourceModelApprovalTool?.metadata.authority_classes).toEqual([
      "approval_auto_execution",
      "content_input",
      "customer_data_input",
      "handler_approval_auto_execution",
      "handler_model_approval_gate",
      "handler_secret_env_access",
      "handler_tainted_approval_context",
      "model_approval_gate",
      "pii_input",
      "secret_env_access",
      "tainted_approval_context"
    ]);
    expect(sourceModelApprovalTool?.metadata.handler_authority_classes).toEqual([
      "handler_approval_auto_execution",
      "handler_model_approval_gate",
      "handler_secret_env_access",
      "handler_tainted_approval_context"
    ]);
    expect(sourceModelApprovalTool?.metadata.handler_env_key_names).toEqual(["SOURCE_APPROVAL_MODEL_TOKEN"]);
    expect(sourceModelApprovalTool?.metadata.schema_properties).toEqual([
      "action_payload",
      "customer_id",
      "customer_ticket_text",
      "requested_action",
      "tool_output_text"
    ]);
    expect(sourceModelApprovalTool?.metadata.required_properties).toEqual([
      "action_payload",
      "customer_id",
      "customer_ticket_text",
      "requested_action",
      "tool_output_text"
    ]);
    expect(JSON.stringify(sourceModelApprovalTool)).not.toContain("approvalModelClient.evaluate");
    expect(JSON.stringify(sourceModelApprovalTool)).not.toContain("privilegedActionExecutor.execute");
    expect(JSON.stringify(sourceModelApprovalTool)).not.toContain("source model approval executed");
    expect(JSON.stringify(sourceModelApprovalTool)).not.toContain("Approve and execute a caller supplied privileged action");
    expect(sourcePromptRegistryWriteTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourcePromptRegistryWriteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      prompt_registry_write: true,
      tainted_prompt_registry_payload: true,
      tainted_prompt_registry_selector: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_model_provider_call: false,
      handler_prompt_registry_write: true,
      handler_tainted_prompt_registry_payload: true,
      handler_tainted_prompt_registry_selector: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourcePromptRegistryWriteTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_prompt_registry_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_registry_payload",
      "handler_tainted_prompt_registry_selector",
      "pii_input",
      "prompt_registry_write",
      "secret_env_access",
      "tainted_prompt_registry_payload",
      "tainted_prompt_registry_selector"
    ]);
    expect(sourcePromptRegistryWriteTool?.metadata.handler_authority_classes).toEqual([
      "handler_prompt_registry_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_registry_payload",
      "handler_tainted_prompt_registry_selector"
    ]);
    expect(sourcePromptRegistryWriteTool?.metadata.handler_env_key_names).toEqual(["SOURCE_PROMPT_REGISTRY_TOKEN"]);
    expect(sourcePromptRegistryWriteTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "instruction_text",
      "prompt_id",
      "prompt_role"
    ]);
    expect(sourcePromptRegistryWriteTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "instruction_text",
      "prompt_id",
      "prompt_role"
    ]);
    expect(JSON.stringify(sourcePromptRegistryWriteTool)).not.toContain("promptRegistryClient.updatePrompt");
    expect(JSON.stringify(sourcePromptRegistryWriteTool)).not.toContain("customerContext");
    expect(JSON.stringify(sourcePromptRegistryWriteTool)).not.toContain("source prompt registry updated");
    expect(JSON.stringify(sourcePromptRegistryWriteTool)).not.toContain("Publish caller supplied system prompt text");
    expect(sourceAgentConfigWriteTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "pii"],
      actions: ["call", "write"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: false
    });
    expect(sourceAgentConfigWriteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: false,
      agent_config_write: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: true,
      handler_shell_execution: false,
      handler_tainted_filesystem_path: false,
      tainted_filesystem_path: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: true,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(sourceAgentConfigWriteTool?.metadata.authority_classes).toEqual([
      "agent_config_write",
      "content_input",
      "customer_data_input",
      "filesystem_access",
      "handler_agent_config_write",
      "handler_filesystem_write",
      "pii_input"
    ]);
    expect(sourceAgentConfigWriteTool?.metadata.handler_authority_classes).toEqual([
      "handler_agent_config_write",
      "handler_filesystem_write"
    ]);
    expect(sourceAgentConfigWriteTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceAgentConfigWriteTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "instruction_text"
    ]);
    expect(sourceAgentConfigWriteTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "instruction_text"
    ]);
    expect(JSON.stringify(sourceAgentConfigWriteTool)).not.toContain("writeFile");
    expect(JSON.stringify(sourceAgentConfigWriteTool)).not.toContain("AGENTS.md");
    expect(JSON.stringify(sourceAgentConfigWriteTool)).not.toContain("source instructions updated");
    expect(JSON.stringify(sourceAgentConfigWriteTool)).not.toContain("Rewrite AGENTS.md from caller supplied customer context");
    expect(sourceCredentialIssuanceTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "send"],
      side_effect: true,
      external_reach: false,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceCredentialIssuanceTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: false,
      agent_config_write: false,
      credential_issuance: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_credential_issuance: true,
      handler_tainted_credential_issuance_input: true,
      tainted_credential_issuance_input: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(sourceCredentialIssuanceTool?.metadata.authority_classes).toEqual([
      "credential_input",
      "credential_issuance",
      "customer_data_input",
      "handler_credential_issuance",
      "handler_tainted_credential_issuance_input",
      "pii_input",
      "tainted_credential_issuance_input"
    ]);
    expect(sourceCredentialIssuanceTool?.metadata.handler_authority_classes).toEqual([
      "handler_credential_issuance",
      "handler_tainted_credential_issuance_input"
    ]);
    expect(sourceCredentialIssuanceTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceCredentialIssuanceTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requested_scope",
      "requested_subject",
      "token_audience"
    ]);
    expect(sourceCredentialIssuanceTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requested_scope",
      "requested_subject",
      "token_audience"
    ]);
    expect(JSON.stringify(sourceCredentialIssuanceTool)).not.toContain("identityBroker.issueToken");
    expect(JSON.stringify(sourceCredentialIssuanceTool)).not.toContain("Mint an agent session token");
    expect(sourceSecretManagerCredentialIssuanceBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerCredentialIssuanceBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      credential_issuance: true,
      tainted_credential_issuance_input: true,
      secret_manager_credential_issuance_bridge: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_credential_issuance: true,
      handler_tainted_credential_issuance_input: true,
      handler_secret_manager_credential_issuance_bridge: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_secret_env_access: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    for (const authorityClass of [
      "credential_issuance",
      "tainted_credential_issuance_input",
      "secret_manager_credential_issuance_bridge",
      "secret_manager_access",
      "tainted_secret_manager_path"
    ]) {
      expect(sourceSecretManagerCredentialIssuanceBridgeTool?.metadata.authority_classes).toContain(authorityClass);
    }
    for (const handlerClass of [
      "handler_credential_issuance",
      "handler_tainted_credential_issuance_input",
      "handler_secret_manager_credential_issuance_bridge",
      "handler_secret_manager_access",
      "handler_tainted_secret_manager_path"
    ]) {
      expect(sourceSecretManagerCredentialIssuanceBridgeTool?.metadata.handler_authority_classes).toContain(handlerClass);
    }
    expect(sourceSecretManagerCredentialIssuanceBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_SECRET_CREDENTIAL_ISSUER_TOKEN"
    ]);
    expect(sourceSecretManagerCredentialIssuanceBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requested_scope",
      "requested_subject",
      "requester_ticket",
      "secret_path",
      "token_audience"
    ]);
    expect(sourceSecretManagerCredentialIssuanceBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requested_scope",
      "requested_subject",
      "requester_ticket",
      "secret_path",
      "token_audience"
    ]);
    expect(JSON.stringify(sourceSecretManagerCredentialIssuanceBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerCredentialIssuanceBridgeTool)).not.toContain("identityBroker.issueToken");
    expect(JSON.stringify(sourceSecretManagerCredentialIssuanceBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerCredentialIssuanceBridgeTool)).not.toContain("vaultSigningKey");
    expect(JSON.stringify(sourceSecretManagerCredentialIssuanceBridgeTool)).not.toContain("Issue an agent credential");
    expect(sourceToolOutputCredentialIssuanceBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputCredentialIssuanceBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      credential_issuance: true,
      tainted_credential_issuance_input: true,
      secret_manager_credential_issuance_bridge: false,
      tool_output_credential_issuance_bridge: true,
      nested_tool_invocation: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_credential_issuance: true,
      handler_tainted_credential_issuance_input: true,
      handler_secret_manager_credential_issuance_bridge: false,
      handler_tool_output_credential_issuance_bridge: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_tool_invocation: true,
      handler_memory_write: false,
      handler_tool_output_memory_bridge: false,
      handler_tool_output_to_output: false,
      handler_model_provider_call: false,
      handler_tool_output_prompt_bridge: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(sourceToolOutputCredentialIssuanceBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "credential_issuance",
      "customer_data_input",
      "external_write",
      "handler_credential_issuance",
      "handler_secret_env_access",
      "handler_tainted_credential_issuance_input",
      "handler_tool_invocation",
      "handler_tool_output_credential_issuance_bridge",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_credential_issuance_input",
      "tool_output_credential_issuance_bridge"
    ]);
    expect(sourceToolOutputCredentialIssuanceBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_credential_issuance",
      "handler_secret_env_access",
      "handler_tainted_credential_issuance_input",
      "handler_tool_invocation",
      "handler_tool_output_credential_issuance_bridge"
    ]);
    expect(sourceToolOutputCredentialIssuanceBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_TOOL_OBSERVATION_CREDENTIAL_TOKEN"
    ]);
    expect(sourceToolOutputCredentialIssuanceBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requested_scope",
      "requested_subject",
      "requester_ticket",
      "target_tool_name",
      "token_audience",
      "tool_request_body"
    ]);
    expect(sourceToolOutputCredentialIssuanceBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requested_scope",
      "requested_subject",
      "requester_ticket",
      "target_tool_name",
      "token_audience",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceToolOutputCredentialIssuanceBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputCredentialIssuanceBridgeTool)).not.toContain("identityBroker.issueToken");
    expect(JSON.stringify(sourceToolOutputCredentialIssuanceBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputCredentialIssuanceBridgeTool)).not.toContain("grantMaterial");
    expect(JSON.stringify(sourceToolOutputCredentialIssuanceBridgeTool)).not.toContain("source tool observation issued credential");
    expect(JSON.stringify(sourceToolOutputCredentialIssuanceBridgeTool)).not.toContain("Issue an agent credential from a raw privileged tool observation");
    expect(sourceNestedToolInvocationTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "pii"],
      actions: ["call", "execute", "send"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: false
    });
    expect(sourceNestedToolInvocationTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: false,
      tool_output_to_output: true,
      agent_config_write: false,
      credential_issuance: false,
      nested_tool_invocation: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_tool_output_to_output: true,
      handler_agent_config_write: false,
      handler_credential_issuance: false,
      handler_tool_invocation: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(sourceNestedToolInvocationTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_tool_invocation",
      "handler_tool_output_to_output",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "tool_output_to_output"
    ]);
    expect(sourceNestedToolInvocationTool?.metadata.handler_authority_classes).toEqual([
      "handler_tool_invocation",
      "handler_tool_output_to_output"
    ]);
    expect(sourceNestedToolInvocationTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceNestedToolInvocationTool?.metadata.schema_properties).toEqual([
      "approval_ticket",
      "customer_id",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(sourceNestedToolInvocationTool?.metadata.required_properties).toEqual([
      "customer_id",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceNestedToolInvocationTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceNestedToolInvocationTool)).not.toContain("JSON.stringify(result)");
    expect(JSON.stringify(sourceNestedToolInvocationTool)).not.toContain("Dispatch a caller selected privileged tool");
    expect(sourceToolOutputPromptBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["credential"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputPromptBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: false,
      accepts_customer_data_input: false,
      nested_tool_invocation: true,
      model_provider_call: true,
      tool_output_prompt_bridge: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_tool_invocation: true,
      handler_model_provider_call: true,
      handler_tool_output_prompt_bridge: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourceToolOutputPromptBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_prompt_bridge",
      "model_provider_call",
      "nested_tool_invocation",
      "network_access",
      "secret_env_access",
      "tool_output_prompt_bridge"
    ]);
    expect(sourceToolOutputPromptBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_prompt_bridge"
    ]);
    expect(sourceToolOutputPromptBridgeTool?.metadata.handler_env_key_names).toEqual(["SOURCE_TOOL_OBSERVATION_MODEL_TOKEN"]);
    expect(sourceToolOutputPromptBridgeTool?.metadata.schema_properties).toEqual([
      "review_instruction_text",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(sourceToolOutputPromptBridgeTool?.metadata.required_properties).toEqual([
      "review_instruction_text",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceToolOutputPromptBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputPromptBridgeTool)).not.toContain("openai.chat.completions.create");
    expect(JSON.stringify(sourceToolOutputPromptBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputPromptBridgeTool)).not.toContain("Review a raw privileged tool observation");
    expect(sourceToolOutputMemoryBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["credential"],
      actions: ["call", "execute", "remember", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputMemoryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: false,
      accepts_customer_data_input: false,
      nested_tool_invocation: true,
      memory_write: true,
      tool_output_memory_bridge: true,
      model_provider_call: false,
      tool_output_prompt_bridge: false,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_tool_invocation: true,
      handler_memory_write: true,
      handler_tool_output_memory_bridge: true,
      handler_model_provider_call: false,
      handler_tool_output_prompt_bridge: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourceToolOutputMemoryBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_memory_bridge",
      "memory_access",
      "memory_write",
      "nested_tool_invocation",
      "network_access",
      "secret_env_access",
      "tool_output_memory_bridge"
    ]);
    expect(sourceToolOutputMemoryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_memory_bridge"
    ]);
    expect(sourceToolOutputMemoryBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_TOOL_OBSERVATION_MEMORY_TOKEN"
    ]);
    expect(sourceToolOutputMemoryBridgeTool?.metadata.schema_properties).toEqual([
      "retention_note_text",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(sourceToolOutputMemoryBridgeTool?.metadata.required_properties).toEqual([
      "retention_note_text",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceToolOutputMemoryBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputMemoryBridgeTool)).not.toContain("agentMemory.upsert");
    expect(JSON.stringify(sourceToolOutputMemoryBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputMemoryBridgeTool)).not.toContain("source tool observation remembered");
    expect(JSON.stringify(sourceToolOutputMemoryBridgeTool)).not.toContain("Persist a raw privileged tool observation");
    expect(sourceToolOutputPromptCacheBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "remember", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputPromptCacheBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      prompt_cache_write: true,
      tool_output_prompt_cache_bridge: true,
      tainted_prompt_cache_key: true,
      tainted_prompt_cache_value: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_prompt_cache_write: true,
      handler_tool_output_prompt_cache_bridge: true,
      handler_tainted_prompt_cache_key: true,
      handler_tainted_prompt_cache_value: false,
      handler_secret_env_access: true,
      handler_tool_invocation: true,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(sourceToolOutputPromptCacheBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_cache_key",
      "handler_tool_invocation",
      "handler_tool_output_prompt_cache_bridge",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "prompt_cache_write",
      "secret_env_access",
      "tainted_prompt_cache_key",
      "tool_output_prompt_cache_bridge"
    ]);
    expect(sourceToolOutputPromptCacheBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_cache_key",
      "handler_tool_invocation",
      "handler_tool_output_prompt_cache_bridge"
    ]);
    expect(sourceToolOutputPromptCacheBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_TOOL_OBSERVATION_PROMPT_CACHE_TOKEN"
    ]);
    expect(sourceToolOutputPromptCacheBridgeTool?.metadata.schema_properties).toEqual([
      "cache_key",
      "customer_id",
      "retention_note_text",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceToolOutputPromptCacheBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputPromptCacheBridgeTool)).not.toContain("promptCache.set");
    expect(JSON.stringify(sourceToolOutputPromptCacheBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputPromptCacheBridgeTool)).not.toContain("source tool observation cached for prompts");
    expect(JSON.stringify(sourceToolOutputPromptCacheBridgeTool)).not.toContain("Write a raw privileged tool observation");
    expect(sourceToolOutputEmbeddingVectorBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputEmbeddingVectorBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      embedding_provider_call: true,
      tainted_embedding_input: false,
      memory_write: true,
      tainted_memory_scope: true,
      tool_output_memory_bridge: true,
      tool_output_embedding_vector_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_tool_invocation: true,
      handler_embedding_provider_call: true,
      handler_tainted_embedding_input: false,
      handler_memory_write: true,
      handler_tainted_memory_scope: true,
      handler_tool_output_memory_bridge: true,
      handler_tool_output_embedding_vector_bridge: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(sourceToolOutputEmbeddingVectorBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "embedding_provider_call",
      "handler_embedding_provider_call",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tainted_memory_scope",
      "handler_tool_invocation",
      "handler_tool_output_embedding_vector_bridge",
      "handler_tool_output_memory_bridge",
      "memory_access",
      "memory_write",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_memory_scope",
      "tool_output_embedding_vector_bridge",
      "tool_output_memory_bridge"
    ]);
    expect(sourceToolOutputEmbeddingVectorBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_embedding_provider_call",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tainted_memory_scope",
      "handler_tool_invocation",
      "handler_tool_output_embedding_vector_bridge",
      "handler_tool_output_memory_bridge"
    ]);
    expect(sourceToolOutputEmbeddingVectorBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_TOOL_OBSERVATION_VECTOR_TOKEN"
    ]);
    expect(sourceToolOutputEmbeddingVectorBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "retention_note_text",
      "target_tool_name",
      "tool_request_body",
      "vector_namespace"
    ]);
    expect(sourceToolOutputEmbeddingVectorBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "retention_note_text",
      "target_tool_name",
      "tool_request_body",
      "vector_namespace"
    ]);
    expect(JSON.stringify(sourceToolOutputEmbeddingVectorBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputEmbeddingVectorBridgeTool)).not.toContain("embeddingClient.embedQuery");
    expect(JSON.stringify(sourceToolOutputEmbeddingVectorBridgeTool)).not.toContain("vectorStore.upsert");
    expect(JSON.stringify(sourceToolOutputEmbeddingVectorBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputEmbeddingVectorBridgeTool)).not.toContain("toolObservationEmbedding");
    expect(JSON.stringify(sourceToolOutputEmbeddingVectorBridgeTool)).not.toContain("source tool observation embedded to vector memory");
    expect(JSON.stringify(sourceToolOutputEmbeddingVectorBridgeTool)).not.toContain("Embed a raw privileged tool observation");
    expect(sourceToolOutputPromptRegistryBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputPromptRegistryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      prompt_registry_write: true,
      tool_output_prompt_registry_bridge: true,
      tainted_prompt_registry_payload: true,
      tainted_prompt_registry_selector: true,
      memory_write: false,
      tool_output_memory_bridge: false,
      tool_output_to_output: false,
      model_provider_call: false,
      tool_output_prompt_bridge: false,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_prompt_registry_write: true,
      handler_tool_output_prompt_registry_bridge: true,
      handler_tainted_prompt_registry_payload: true,
      handler_tainted_prompt_registry_selector: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_tool_invocation: true,
      handler_memory_write: false,
      handler_tool_output_memory_bridge: false,
      handler_tool_output_to_output: false,
      handler_model_provider_call: false,
      handler_tool_output_prompt_bridge: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceToolOutputPromptRegistryBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_prompt_registry_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_registry_payload",
      "handler_tainted_prompt_registry_selector",
      "handler_tool_invocation",
      "handler_tool_output_prompt_registry_bridge",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "prompt_registry_write",
      "secret_env_access",
      "tainted_prompt_registry_payload",
      "tainted_prompt_registry_selector",
      "tool_output_prompt_registry_bridge"
    ]);
    expect(sourceToolOutputPromptRegistryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_prompt_registry_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_registry_payload",
      "handler_tainted_prompt_registry_selector",
      "handler_tool_invocation",
      "handler_tool_output_prompt_registry_bridge"
    ]);
    expect(sourceToolOutputPromptRegistryBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_TOOL_OBSERVATION_PROMPT_REGISTRY_TOKEN"
    ]);
    expect(sourceToolOutputPromptRegistryBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "prompt_id",
      "prompt_role",
      "registry_namespace",
      "reviewer_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(sourceToolOutputPromptRegistryBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "prompt_id",
      "prompt_role",
      "registry_namespace",
      "reviewer_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceToolOutputPromptRegistryBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputPromptRegistryBridgeTool)).not.toContain("promptRegistryClient.updatePrompt");
    expect(JSON.stringify(sourceToolOutputPromptRegistryBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputPromptRegistryBridgeTool)).not.toContain("source tool observation published to prompt registry");
    expect(JSON.stringify(sourceToolOutputPromptRegistryBridgeTool)).not.toContain("Publish a raw privileged tool observation");
    expect(sourceToolOutputAuthorizationGrantBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputAuthorizationGrantBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      authorization_policy_write: true,
      tainted_authorization_grant_input: true,
      authorization_broad_grant: true,
      secret_manager_authorization_grant_bridge: false,
      tool_output_authorization_grant_bridge: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_authorization_policy_write: true,
      handler_tainted_authorization_grant_input: true,
      handler_authorization_broad_grant: true,
      handler_secret_manager_authorization_grant_bridge: false,
      handler_tool_output_authorization_grant_bridge: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_tool_invocation: true,
      handler_memory_write: false,
      handler_tool_output_memory_bridge: false,
      handler_tool_output_to_output: false,
      handler_model_provider_call: false,
      handler_tool_output_prompt_bridge: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceToolOutputAuthorizationGrantBridgeTool?.metadata.authority_classes).toEqual([
      "authorization_broad_grant",
      "authorization_policy_write",
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "handler_authorization_broad_grant",
      "handler_authorization_policy_write",
      "handler_secret_env_access",
      "handler_tainted_authorization_grant_input",
      "handler_tool_invocation",
      "handler_tool_output_authorization_grant_bridge",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_authorization_grant_input",
      "tool_output_authorization_grant_bridge"
    ]);
    expect(sourceToolOutputAuthorizationGrantBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_authorization_broad_grant",
      "handler_authorization_policy_write",
      "handler_secret_env_access",
      "handler_tainted_authorization_grant_input",
      "handler_tool_invocation",
      "handler_tool_output_authorization_grant_bridge"
    ]);
    expect(sourceToolOutputAuthorizationGrantBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_TOOL_OBSERVATION_AUTHZ_TOKEN"
    ]);
    expect(sourceToolOutputAuthorizationGrantBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "grant_reason",
      "requested_scope",
      "requested_tool_name",
      "target_tool_name",
      "tenant_id",
      "tool_request_body"
    ]);
    expect(sourceToolOutputAuthorizationGrantBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "grant_reason",
      "requested_scope",
      "requested_tool_name",
      "target_tool_name",
      "tenant_id",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceToolOutputAuthorizationGrantBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputAuthorizationGrantBridgeTool)).not.toContain("permissionBrokerClient.upsertGrant");
    expect(JSON.stringify(sourceToolOutputAuthorizationGrantBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputAuthorizationGrantBridgeTool)).not.toContain("source tool observation granted authorization");
    expect(JSON.stringify(sourceToolOutputAuthorizationGrantBridgeTool)).not.toContain("Grant broad authorization from a raw privileged tool observation");
    expect(sourceToolOutputExternalServiceBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["credential"],
      actions: ["call", "execute", "publish", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputExternalServiceBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: false,
      accepts_customer_data_input: false,
      nested_tool_invocation: true,
      external_service_write: true,
      tainted_external_service_recipient: true,
      tool_output_external_service_bridge: true,
      memory_write: false,
      tool_output_memory_bridge: false,
      tool_output_to_output: false,
      model_provider_call: false,
      tool_output_prompt_bridge: false,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: true,
      handler_tainted_external_service_recipient: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_tool_invocation: true,
      handler_tool_output_external_service_bridge: true,
      handler_memory_write: false,
      handler_tool_output_memory_bridge: false,
      handler_tool_output_to_output: false,
      handler_model_provider_call: false,
      handler_tool_output_prompt_bridge: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(sourceToolOutputExternalServiceBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "external_service_write",
      "external_write",
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient",
      "handler_tool_invocation",
      "handler_tool_output_external_service_bridge",
      "nested_tool_invocation",
      "network_access",
      "secret_env_access",
      "tainted_external_service_recipient",
      "tool_output_external_service_bridge"
    ]);
    expect(sourceToolOutputExternalServiceBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient",
      "handler_tool_invocation",
      "handler_tool_output_external_service_bridge"
    ]);
    expect(sourceToolOutputExternalServiceBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_TOOL_OBSERVATION_SLACK_TOKEN"
    ]);
    expect(sourceToolOutputExternalServiceBridgeTool?.metadata.schema_properties).toEqual([
      "external_channel_id",
      "posting_reason_text",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(sourceToolOutputExternalServiceBridgeTool?.metadata.required_properties).toEqual([
      "external_channel_id",
      "posting_reason_text",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceToolOutputExternalServiceBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputExternalServiceBridgeTool)).not.toContain("slackClient.chat.postMessage");
    expect(JSON.stringify(sourceToolOutputExternalServiceBridgeTool)).not.toContain("JSON.stringify(toolResult)");
    expect(JSON.stringify(sourceToolOutputExternalServiceBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputExternalServiceBridgeTool)).not.toContain("source tool observation posted externally");
    expect(JSON.stringify(sourceToolOutputExternalServiceBridgeTool)).not.toContain("Post a raw privileged tool observation");
    expect(sourceToolOutputTelemetryBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential"],
      actions: ["call", "execute", "publish", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputTelemetryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      nested_tool_invocation: true,
      telemetry_export: true,
      tool_output_telemetry_bridge: true,
      tainted_telemetry_payload: false,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_telemetry_export: true,
      handler_tool_output_telemetry_bridge: true,
      handler_tainted_telemetry_payload: false,
      handler_secret_env_access: true,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourceToolOutputTelemetryBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_secret_env_access",
      "handler_telemetry_export",
      "handler_tool_invocation",
      "handler_tool_output_telemetry_bridge",
      "nested_tool_invocation",
      "network_access",
      "secret_env_access",
      "telemetry_export",
      "tool_output_telemetry_bridge"
    ]);
    expect(sourceToolOutputTelemetryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_telemetry_export",
      "handler_tool_invocation",
      "handler_tool_output_telemetry_bridge"
    ]);
    expect(sourceToolOutputTelemetryBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_TOOL_OBSERVATION_TRACE_TOKEN"
    ]);
    expect(sourceToolOutputTelemetryBridgeTool?.metadata.schema_properties).toEqual([
      "requester_ticket",
      "target_tool_name",
      "tool_request_body",
      "trace_session_id"
    ]);
    expect(sourceToolOutputTelemetryBridgeTool?.metadata.required_properties).toEqual([
      "requester_ticket",
      "target_tool_name",
      "tool_request_body",
      "trace_session_id"
    ]);
    expect(JSON.stringify(sourceToolOutputTelemetryBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputTelemetryBridgeTool)).not.toContain("telemetryClient.recordTrace");
    expect(JSON.stringify(sourceToolOutputTelemetryBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputTelemetryBridgeTool)).not.toContain("source tool observation exported to telemetry");
    expect(JSON.stringify(sourceToolOutputTelemetryBridgeTool)).not.toContain("Export a raw privileged tool observation");
    expect(sourceToolOutputArtifactBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential"],
      actions: ["call", "execute", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputArtifactBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      nested_tool_invocation: true,
      artifact_export: true,
      tool_output_artifact_bridge: true,
      public_artifact_destination: true,
      tainted_artifact_export_payload: false,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_artifact_export: true,
      handler_tool_output_artifact_bridge: true,
      handler_public_artifact_destination: true,
      handler_tainted_artifact_export_payload: false,
      handler_secret_env_access: true,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(sourceToolOutputArtifactBridgeTool?.metadata.authority_classes).toEqual([
      "artifact_export",
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_artifact_export",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_artifact_bridge",
      "nested_tool_invocation",
      "network_access",
      "public_artifact_destination",
      "secret_env_access",
      "tool_output_artifact_bridge"
    ]);
    expect(sourceToolOutputArtifactBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_artifact_export",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_artifact_bridge"
    ]);
    expect(sourceToolOutputArtifactBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_TOOL_OBSERVATION_ARTIFACT_TOKEN"
    ]);
    expect(sourceToolOutputArtifactBridgeTool?.metadata.schema_properties).toEqual([
      "object_key",
      "public_access",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(sourceToolOutputArtifactBridgeTool?.metadata.required_properties).toEqual([
      "object_key",
      "public_access",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceToolOutputArtifactBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputArtifactBridgeTool)).not.toContain("artifactExportClient.upload");
    expect(JSON.stringify(sourceToolOutputArtifactBridgeTool)).not.toContain("JSON.stringify(toolResult)");
    expect(JSON.stringify(sourceToolOutputArtifactBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputArtifactBridgeTool)).not.toContain("source tool observation exported to artifact");
    expect(JSON.stringify(sourceToolOutputArtifactBridgeTool)).not.toContain("Export a raw privileged tool observation");
    expect(sourceToolOutputTaskQueueBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential"],
      actions: ["call", "execute", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputTaskQueueBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      task_queue_enqueue: true,
      tool_output_task_queue_bridge: true,
      tainted_task_payload: false,
      tainted_task_routing: true,
      external_write: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_task_queue_enqueue: true,
      handler_tool_output_task_queue_bridge: true,
      handler_tainted_task_payload: false,
      handler_tainted_task_routing: true,
      handler_secret_env_access: true,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(sourceToolOutputTaskQueueBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_secret_env_access",
      "handler_tainted_task_routing",
      "handler_task_queue_enqueue",
      "handler_tool_invocation",
      "handler_tool_output_task_queue_bridge",
      "nested_tool_invocation",
      "network_access",
      "secret_env_access",
      "tainted_task_routing",
      "task_queue_enqueue",
      "tool_output_task_queue_bridge"
    ]);
    expect(sourceToolOutputTaskQueueBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_tainted_task_routing",
      "handler_task_queue_enqueue",
      "handler_tool_invocation",
      "handler_tool_output_task_queue_bridge"
    ]);
    expect(sourceToolOutputTaskQueueBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_TOOL_OBSERVATION_QUEUE_TOKEN"
    ]);
    expect(sourceToolOutputTaskQueueBridgeTool?.metadata.schema_properties).toEqual([
      "replay_on_failure",
      "requester_ticket",
      "target_queue_name",
      "target_tool_name",
      "task_route",
      "tool_request_body"
    ]);
    expect(sourceToolOutputTaskQueueBridgeTool?.metadata.required_properties).toEqual([
      "replay_on_failure",
      "requester_ticket",
      "target_queue_name",
      "target_tool_name",
      "task_route",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceToolOutputTaskQueueBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputTaskQueueBridgeTool)).not.toContain("taskQueueClient.enqueue");
    expect(JSON.stringify(sourceToolOutputTaskQueueBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputTaskQueueBridgeTool)).not.toContain("source tool observation queued for background agent");
    expect(JSON.stringify(sourceToolOutputTaskQueueBridgeTool)).not.toContain("Enqueue a raw privileged tool observation");
    expect(sourceToolOutputTrainingDatasetBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential"],
      actions: ["call", "execute", "publish", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputTrainingDatasetBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      training_dataset_export: true,
      tool_output_training_dataset_bridge: true,
      tainted_training_dataset_payload: false,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_training_dataset_export: true,
      handler_tool_output_training_dataset_bridge: true,
      handler_tainted_training_dataset_payload: false,
      handler_secret_env_access: true,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourceToolOutputTrainingDatasetBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_training_dataset_bridge",
      "handler_training_dataset_export",
      "nested_tool_invocation",
      "network_access",
      "secret_env_access",
      "tool_output_training_dataset_bridge",
      "training_dataset_export"
    ]);
    expect(sourceToolOutputTrainingDatasetBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_training_dataset_bridge",
      "handler_training_dataset_export"
    ]);
    expect(sourceToolOutputTrainingDatasetBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_TOOL_OBSERVATION_TRAINING_TOKEN"
    ]);
    expect(sourceToolOutputTrainingDatasetBridgeTool?.metadata.schema_properties).toEqual([
      "requester_ticket",
      "source_label",
      "target_tool_name",
      "tool_request_body",
      "training_dataset_id"
    ]);
    expect(sourceToolOutputTrainingDatasetBridgeTool?.metadata.required_properties).toEqual([
      "requester_ticket",
      "source_label",
      "target_tool_name",
      "tool_request_body",
      "training_dataset_id"
    ]);
    expect(JSON.stringify(sourceToolOutputTrainingDatasetBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputTrainingDatasetBridgeTool)).not.toContain("trainingDatasetClient.appendRecord");
    expect(JSON.stringify(sourceToolOutputTrainingDatasetBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputTrainingDatasetBridgeTool)).not.toContain("source tool observation exported to training dataset");
    expect(JSON.stringify(sourceToolOutputTrainingDatasetBridgeTool)).not.toContain("Export a raw privileged tool observation");
    expect(sourceAgentDelegationTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceAgentDelegationTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      agent_delegation: true,
      tainted_agent_delegation_target: true,
      agent_delegation_context_forwarding: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_agent_delegation: true,
      handler_tainted_agent_delegation_target: true,
      handler_agent_delegation_context_forwarding: true,
      handler_tool_invocation: false,
      handler_browser_automation: false,
      handler_external_service_write: false,
      handler_model_provider_call: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourceAgentDelegationTool?.metadata.authority_classes).toEqual([
      "agent_delegation",
      "agent_delegation_context_forwarding",
      "content_input",
      "customer_data_input",
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_secret_env_access",
      "handler_tainted_agent_delegation_target",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_agent_delegation_target"
    ]);
    expect(sourceAgentDelegationTool?.metadata.handler_authority_classes).toEqual([
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_secret_env_access",
      "handler_tainted_agent_delegation_target"
    ]);
    expect(sourceAgentDelegationTool?.metadata.handler_env_key_names).toEqual(["SOURCE_A2A_FEDERATION_TOKEN"]);
    expect(sourceAgentDelegationTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "requested_task_type",
      "target_agent_url",
      "tool_output_text"
    ]);
    expect(sourceAgentDelegationTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "requested_task_type",
      "target_agent_url",
      "tool_output_text"
    ]);
    expect(JSON.stringify(sourceAgentDelegationTool)).not.toContain("remoteAgentClient.delegateTask");
    expect(JSON.stringify(sourceAgentDelegationTool)).not.toContain("Delegate caller supplied customer context");
    expect(JSON.stringify(sourceAgentDelegationTool)).not.toContain("customerTicket");
    expect(sourceSecretManagerAgentDelegationBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerAgentDelegationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      agent_delegation: true,
      tainted_agent_delegation_target: true,
      agent_delegation_context_forwarding: true,
      secret_manager_agent_delegation_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_agent_delegation: true,
      handler_tainted_agent_delegation_target: true,
      handler_agent_delegation_context_forwarding: true,
      handler_secret_manager_agent_delegation_bridge: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(sourceSecretManagerAgentDelegationBridgeTool?.metadata.authority_classes).toEqual([
      "agent_delegation",
      "agent_delegation_context_forwarding",
      "content_input",
      "credential_input",
      "customer_data_input",
      "filesystem_access",
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_agent_delegation_bridge",
      "handler_tainted_agent_delegation_target",
      "handler_tainted_secret_manager_path",
      "network_access",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_agent_delegation_bridge",
      "tainted_agent_delegation_target",
      "tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerAgentDelegationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_agent_delegation_bridge",
      "handler_tainted_agent_delegation_target",
      "handler_tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerAgentDelegationBridgeTool?.metadata.handler_env_key_names).toEqual(["SOURCE_SECRET_A2A_TOKEN"]);
    expect(sourceSecretManagerAgentDelegationBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "delegation_reason",
      "requested_task_type",
      "requester_ticket",
      "secret_path",
      "target_agent_url"
    ]);
    expect(sourceSecretManagerAgentDelegationBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "delegation_reason",
      "requested_task_type",
      "requester_ticket",
      "secret_path",
      "target_agent_url"
    ]);
    expect(JSON.stringify(sourceSecretManagerAgentDelegationBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerAgentDelegationBridgeTool)).not.toContain("remoteAgentClient.delegateTask");
    expect(JSON.stringify(sourceSecretManagerAgentDelegationBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerAgentDelegationBridgeTool)).not.toContain("secretDelegationValue");
    expect(JSON.stringify(sourceSecretManagerAgentDelegationBridgeTool)).not.toContain("source vault secret delegated to remote agent");
    expect(JSON.stringify(sourceSecretManagerAgentDelegationBridgeTool)).not.toContain("Delegate a customer support secret");
    expect(sourceToolOutputAgentDelegationBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["credential"],
      actions: ["call", "execute", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputAgentDelegationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_customer_data_input: false,
      agent_delegation: true,
      tainted_agent_delegation_target: true,
      agent_delegation_context_forwarding: true,
      tool_output_agent_delegation_bridge: true,
      nested_tool_invocation: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_agent_delegation: true,
      handler_tainted_agent_delegation_target: true,
      handler_agent_delegation_context_forwarding: true,
      handler_tool_output_agent_delegation_bridge: true,
      handler_tool_invocation: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceToolOutputAgentDelegationBridgeTool?.metadata.authority_classes).toEqual([
      "agent_delegation",
      "agent_delegation_context_forwarding",
      "content_input",
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_secret_env_access",
      "handler_tainted_agent_delegation_target",
      "handler_tool_invocation",
      "handler_tool_output_agent_delegation_bridge",
      "nested_tool_invocation",
      "network_access",
      "secret_env_access",
      "tainted_agent_delegation_target",
      "tool_output_agent_delegation_bridge"
    ]);
    expect(sourceToolOutputAgentDelegationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_secret_env_access",
      "handler_tainted_agent_delegation_target",
      "handler_tool_invocation",
      "handler_tool_output_agent_delegation_bridge"
    ]);
    expect(sourceToolOutputAgentDelegationBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_TOOL_OBSERVATION_A2A_TOKEN"
    ]);
    expect(sourceToolOutputAgentDelegationBridgeTool?.metadata.schema_properties).toEqual([
      "delegation_reason",
      "requested_task_type",
      "target_agent_url",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(sourceToolOutputAgentDelegationBridgeTool?.metadata.required_properties).toEqual([
      "delegation_reason",
      "requested_task_type",
      "target_agent_url",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceToolOutputAgentDelegationBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputAgentDelegationBridgeTool)).not.toContain("remoteAgentClient.delegateTask");
    expect(JSON.stringify(sourceToolOutputAgentDelegationBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputAgentDelegationBridgeTool)).not.toContain("Delegate a raw privileged tool observation");
    expect(sourceBrowserAutomationTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceBrowserAutomationTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: false,
      agent_config_write: false,
      credential_issuance: false,
      nested_tool_invocation: false,
      browser_automation: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_credential_issuance: false,
      handler_tool_invocation: false,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(sourceBrowserAutomationTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_browser_automation",
      "handler_tainted_browser_automation_target",
      "network_access",
      "pii_input",
      "tainted_browser_automation_target"
    ]);
    expect(sourceBrowserAutomationTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_tainted_browser_automation_target"
    ]);
    expect(sourceBrowserAutomationTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceBrowserAutomationTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_message_text",
      "form_selector",
      "submit_selector",
      "target_url"
    ]);
    expect(sourceBrowserAutomationTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_message_text",
      "form_selector",
      "submit_selector",
      "target_url"
    ]);
    expect(JSON.stringify(sourceBrowserAutomationTool)).not.toContain("authenticatedBrowserPage");
    expect(JSON.stringify(sourceBrowserAutomationTool)).not.toContain("page.goto");
    expect(JSON.stringify(sourceBrowserAutomationTool)).not.toContain("page.fill");
    expect(JSON.stringify(sourceBrowserAutomationTool)).not.toContain("page.click");
    expect(JSON.stringify(sourceBrowserAutomationTool)).not.toContain("Drive an authenticated browser session");
    expect(sourceToolOutputBrowserAutomationBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["credential"],
      actions: ["call", "execute", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceToolOutputBrowserAutomationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      nested_tool_invocation: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      tool_output_browser_automation_bridge: true,
      secret_manager_browser_automation_bridge: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_tool_output_browser_automation_bridge: true,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourceToolOutputBrowserAutomationBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "handler_browser_automation",
      "handler_tainted_browser_automation_target",
      "handler_tool_invocation",
      "handler_tool_output_browser_automation_bridge",
      "nested_tool_invocation",
      "network_access",
      "tainted_browser_automation_target",
      "tool_output_browser_automation_bridge"
    ]);
    expect(sourceToolOutputBrowserAutomationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_tainted_browser_automation_target",
      "handler_tool_invocation",
      "handler_tool_output_browser_automation_bridge"
    ]);
    expect(sourceToolOutputBrowserAutomationBridgeTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceToolOutputBrowserAutomationBridgeTool?.metadata.schema_properties).toEqual([
      "form_selector",
      "submit_selector",
      "target_tool_name",
      "target_url",
      "tool_request_body"
    ]);
    expect(sourceToolOutputBrowserAutomationBridgeTool?.metadata.required_properties).toEqual([
      "form_selector",
      "submit_selector",
      "target_tool_name",
      "target_url",
      "tool_request_body"
    ]);
    expect(JSON.stringify(sourceToolOutputBrowserAutomationBridgeTool)).not.toContain("mcpClient.callTool");
    expect(JSON.stringify(sourceToolOutputBrowserAutomationBridgeTool)).not.toContain("authenticatedBrowserPage");
    expect(JSON.stringify(sourceToolOutputBrowserAutomationBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(sourceToolOutputBrowserAutomationBridgeTool)).not.toContain("page.fill");
    expect(JSON.stringify(sourceToolOutputBrowserAutomationBridgeTool)).not.toContain("page.click");
    expect(JSON.stringify(sourceToolOutputBrowserAutomationBridgeTool)).not.toContain("toolResult");
    expect(JSON.stringify(sourceToolOutputBrowserAutomationBridgeTool)).not.toContain("source tool observation submitted through browser");
    expect(JSON.stringify(sourceToolOutputBrowserAutomationBridgeTool)).not.toContain("Submit a raw privileged tool observation");
    expect(sourceSecretManagerBrowserAutomationBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerBrowserAutomationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      secret_manager_browser_automation_bridge: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_secret_manager_browser_automation_bridge: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(sourceSecretManagerBrowserAutomationBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "filesystem_access",
      "handler_browser_automation",
      "handler_secret_manager_access",
      "handler_secret_manager_browser_automation_bridge",
      "handler_tainted_browser_automation_target",
      "handler_tainted_secret_manager_path",
      "network_access",
      "pii_input",
      "secret_manager_access",
      "secret_manager_browser_automation_bridge",
      "tainted_browser_automation_target",
      "tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerBrowserAutomationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_secret_manager_access",
      "handler_secret_manager_browser_automation_bridge",
      "handler_tainted_browser_automation_target",
      "handler_tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerBrowserAutomationBridgeTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceSecretManagerBrowserAutomationBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "form_selector",
      "requester_ticket",
      "secret_path",
      "submit_selector",
      "target_url"
    ]);
    expect(sourceSecretManagerBrowserAutomationBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "form_selector",
      "requester_ticket",
      "secret_path",
      "submit_selector",
      "target_url"
    ]);
    expect(JSON.stringify(sourceSecretManagerBrowserAutomationBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerBrowserAutomationBridgeTool)).not.toContain("authenticatedBrowserPage");
    expect(JSON.stringify(sourceSecretManagerBrowserAutomationBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(sourceSecretManagerBrowserAutomationBridgeTool)).not.toContain("page.fill");
    expect(JSON.stringify(sourceSecretManagerBrowserAutomationBridgeTool)).not.toContain("page.click");
    expect(JSON.stringify(sourceSecretManagerBrowserAutomationBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerBrowserAutomationBridgeTool)).not.toContain("secretBrowserValue");
    expect(JSON.stringify(sourceSecretManagerBrowserAutomationBridgeTool)).not.toContain("source vault secret submitted through browser");
    expect(JSON.stringify(sourceSecretManagerBrowserAutomationBridgeTool)).not.toContain("Fill a customer support secret");
    expect(sourceLocalFileBrowserAutomationBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceLocalFileBrowserAutomationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      external_write: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      tainted_filesystem_path: true,
      local_file_browser_automation_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_filesystem_read: true,
      handler_tainted_filesystem_path: true,
      handler_local_file_browser_automation_bridge: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceLocalFileBrowserAutomationBridgeTool?.metadata.authority_classes).toEqual(expect.arrayContaining([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "filesystem_access",
      "handler_browser_automation",
      "handler_filesystem_read",
      "handler_local_file_browser_automation_bridge",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_filesystem_path",
      "local_file_browser_automation_bridge",
      "network_access",
      "pii_input",
      "tainted_browser_automation_target",
      "tainted_filesystem_path"
    ]));
    expect(sourceLocalFileBrowserAutomationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_filesystem_read",
      "handler_local_file_browser_automation_bridge",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_filesystem_path"
    ]);
    expect(sourceLocalFileBrowserAutomationBridgeTool?.metadata.handler_env_key_names).toEqual(["SOURCE_BROWSER_FILE_UPLOAD_TOKEN"]);
    expect(sourceLocalFileBrowserAutomationBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "file_input_selector",
      "local_file_path",
      "submit_selector",
      "target_url",
      "upload_note_text"
    ]);
    expect(sourceLocalFileBrowserAutomationBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "file_input_selector",
      "local_file_path",
      "submit_selector",
      "target_url",
      "upload_note_text"
    ]);
    expect(JSON.stringify(sourceLocalFileBrowserAutomationBridgeTool)).not.toContain("readFile");
    expect(JSON.stringify(sourceLocalFileBrowserAutomationBridgeTool)).not.toContain("authenticatedBrowserPage");
    expect(JSON.stringify(sourceLocalFileBrowserAutomationBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(sourceLocalFileBrowserAutomationBridgeTool)).not.toContain("page.setInputFiles");
    expect(JSON.stringify(sourceLocalFileBrowserAutomationBridgeTool)).not.toContain("page.fill");
    expect(JSON.stringify(sourceLocalFileBrowserAutomationBridgeTool)).not.toContain("page.click");
    expect(JSON.stringify(sourceLocalFileBrowserAutomationBridgeTool)).not.toContain("fileBytes");
    expect(JSON.stringify(sourceLocalFileBrowserAutomationBridgeTool)).not.toContain("source local file uploaded through browser");
    expect(JSON.stringify(sourceLocalFileBrowserAutomationBridgeTool)).not.toContain("Upload a caller selected local file");
    expect(sourceClipboardExternalServiceBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceClipboardExternalServiceBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      external_write: true,
      external_service_write: true,
      tainted_external_service_recipient: true,
      clipboard_read: true,
      clipboard_external_service_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_external_service_write: true,
      handler_tainted_external_service_recipient: true,
      handler_clipboard_read: true,
      handler_clipboard_external_service_bridge: true,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(sourceClipboardExternalServiceBridgeTool?.metadata.authority_classes).toEqual(expect.arrayContaining([
      "clipboard_external_service_bridge",
      "clipboard_read",
      "content_input",
      "customer_data_input",
      "external_service_write",
      "external_write",
      "handler_clipboard_external_service_bridge",
      "handler_clipboard_read",
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient",
      "pii_input",
      "tainted_external_service_recipient"
    ]));
    expect(sourceClipboardExternalServiceBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_clipboard_external_service_bridge",
      "handler_clipboard_read",
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient"
    ]);
    expect(sourceClipboardExternalServiceBridgeTool?.metadata.handler_env_key_names).toEqual(["SOURCE_CLIPBOARD_SLACK_TOKEN"]);
    expect(sourceClipboardExternalServiceBridgeTool?.metadata.schema_properties).toEqual([
      "clipboard_reason_text",
      "customer_id",
      "destination_channel_id"
    ]);
    expect(sourceClipboardExternalServiceBridgeTool?.metadata.required_properties).toEqual([
      "clipboard_reason_text",
      "customer_id",
      "destination_channel_id"
    ]);
    expect(JSON.stringify(sourceClipboardExternalServiceBridgeTool)).not.toContain("desktopClipboard.readText");
    expect(JSON.stringify(sourceClipboardExternalServiceBridgeTool)).not.toContain("slackClient.chat.postMessage");
    expect(JSON.stringify(sourceClipboardExternalServiceBridgeTool)).not.toContain("clipboardText");
    expect(JSON.stringify(sourceClipboardExternalServiceBridgeTool)).not.toContain("source clipboard posted externally");
    expect(JSON.stringify(sourceClipboardExternalServiceBridgeTool)).not.toContain("Read clipboard text");
    expect(sourceVisualContextCaptureTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceVisualContextCaptureTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: false,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_credential_issuance: false,
      handler_tool_invocation: false,
      handler_secret_manager_access: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(sourceVisualContextCaptureTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "credential_input",
      "customer_data_input",
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_capture",
      "handler_visual_context_to_output",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_browser_automation_target",
      "visual_context_capture",
      "visual_context_to_output"
    ]);
    expect(sourceVisualContextCaptureTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_capture",
      "handler_visual_context_to_output"
    ]);
    expect(sourceVisualContextCaptureTool?.metadata.handler_env_key_names).toEqual(["SOURCE_BROWSER_SESSION_TOKEN"]);
    expect(sourceVisualContextCaptureTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "screenshot_reason",
      "target_url"
    ]);
    expect(sourceVisualContextCaptureTool?.metadata.required_properties).toEqual([
      "customer_id",
      "screenshot_reason",
      "target_url"
    ]);
    expect(JSON.stringify(sourceVisualContextCaptureTool)).not.toContain("authenticatedBrowserPage");
    expect(JSON.stringify(sourceVisualContextCaptureTool)).not.toContain("page.goto");
    expect(JSON.stringify(sourceVisualContextCaptureTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(sourceVisualContextCaptureTool)).not.toContain("screenshot.toString");
    expect(JSON.stringify(sourceVisualContextCaptureTool)).not.toContain("Capture an authenticated browser screenshot");
    expect(sourceVisualContextPromptBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceVisualContextPromptBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: false,
      visual_context_prompt_bridge: true,
      model_provider_call: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_model_provider_call: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: false,
      handler_visual_context_prompt_bridge: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceVisualContextPromptBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_browser_automation",
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_capture",
      "handler_visual_context_prompt_bridge",
      "model_provider_call",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_browser_automation_target",
      "visual_context_capture",
      "visual_context_prompt_bridge"
    ]);
    expect(sourceVisualContextPromptBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_capture",
      "handler_visual_context_prompt_bridge"
    ]);
    expect(sourceVisualContextPromptBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_VISUAL_MODEL_BROWSER_TOKEN",
      "SOURCE_VISUAL_MODEL_PROVIDER_TOKEN"
    ]);
    expect(sourceVisualContextPromptBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "target_url",
      "visual_review_prompt_text"
    ]);
    expect(sourceVisualContextPromptBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "target_url",
      "visual_review_prompt_text"
    ]);
    expect(JSON.stringify(sourceVisualContextPromptBridgeTool)).not.toContain("authenticatedBrowserPage");
    expect(JSON.stringify(sourceVisualContextPromptBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(sourceVisualContextPromptBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(sourceVisualContextPromptBridgeTool)).not.toContain("screenshot.toString");
    expect(JSON.stringify(sourceVisualContextPromptBridgeTool)).not.toContain("openai.chat.completions.create");
    expect(JSON.stringify(sourceVisualContextPromptBridgeTool)).not.toContain("screenshotBase64");
    expect(JSON.stringify(sourceVisualContextPromptBridgeTool)).not.toContain("modelResponse.choices");
    expect(JSON.stringify(sourceVisualContextPromptBridgeTool)).not.toContain("source visual context reviewed");
    expect(JSON.stringify(sourceVisualContextPromptBridgeTool)).not.toContain("Review an authenticated browser screenshot");
    expect(sourceVisualContextExternalServiceBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceVisualContextExternalServiceBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: false,
      visual_context_external_service_bridge: true,
      external_service_write: true,
      tainted_external_service_recipient: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_service_write: true,
      handler_tainted_external_service_recipient: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: false,
      handler_visual_context_external_service_bridge: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(sourceVisualContextExternalServiceBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_service_write",
      "external_write",
      "handler_browser_automation",
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_external_service_recipient",
      "handler_visual_context_capture",
      "handler_visual_context_external_service_bridge",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_browser_automation_target",
      "tainted_external_service_recipient",
      "visual_context_capture",
      "visual_context_external_service_bridge"
    ]);
    expect(sourceVisualContextExternalServiceBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_external_service_recipient",
      "handler_visual_context_capture",
      "handler_visual_context_external_service_bridge"
    ]);
    expect(sourceVisualContextExternalServiceBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_VISUAL_EXTERNAL_BROWSER_TOKEN",
      "SOURCE_VISUAL_EXTERNAL_SLACK_TOKEN"
    ]);
    expect(sourceVisualContextExternalServiceBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "destination_channel_id",
      "target_url",
      "visual_note_text"
    ]);
    expect(sourceVisualContextExternalServiceBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "destination_channel_id",
      "target_url",
      "visual_note_text"
    ]);
    expect(JSON.stringify(sourceVisualContextExternalServiceBridgeTool)).not.toContain("authenticatedBrowserPage");
    expect(JSON.stringify(sourceVisualContextExternalServiceBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(sourceVisualContextExternalServiceBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(sourceVisualContextExternalServiceBridgeTool)).not.toContain("screenshot.toString");
    expect(JSON.stringify(sourceVisualContextExternalServiceBridgeTool)).not.toContain("slackClient.chat.postMessage");
    expect(JSON.stringify(sourceVisualContextExternalServiceBridgeTool)).not.toContain("authenticated-page.png");
    expect(JSON.stringify(sourceVisualContextExternalServiceBridgeTool)).not.toContain("source visual context posted externally");
    expect(JSON.stringify(sourceVisualContextExternalServiceBridgeTool)).not.toContain("Post an authenticated browser screenshot");
    expect(sourceVisualContextMemoryBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "remember", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceVisualContextMemoryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: false,
      visual_context_memory_bridge: true,
      memory_write: true,
      tainted_memory_scope: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_memory_write: true,
      handler_tainted_memory_scope: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: false,
      handler_visual_context_memory_bridge: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(sourceVisualContextMemoryBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_browser_automation",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_memory_scope",
      "handler_visual_context_capture",
      "handler_visual_context_memory_bridge",
      "memory_access",
      "memory_write",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_browser_automation_target",
      "tainted_memory_scope",
      "visual_context_capture",
      "visual_context_memory_bridge"
    ]);
    expect(sourceVisualContextMemoryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_memory_scope",
      "handler_visual_context_capture",
      "handler_visual_context_memory_bridge"
    ]);
    expect(sourceVisualContextMemoryBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_VISUAL_MEMORY_BROWSER_TOKEN",
      "SOURCE_VISUAL_MEMORY_STORE_TOKEN"
    ]);
    expect(sourceVisualContextMemoryBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "memory_namespace",
      "target_url",
      "visual_retention_note_text"
    ]);
    expect(sourceVisualContextMemoryBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "memory_namespace",
      "target_url",
      "visual_retention_note_text"
    ]);
    expect(JSON.stringify(sourceVisualContextMemoryBridgeTool)).not.toContain("authenticatedBrowserPage");
    expect(JSON.stringify(sourceVisualContextMemoryBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(sourceVisualContextMemoryBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(sourceVisualContextMemoryBridgeTool)).not.toContain("screenshot.toString");
    expect(JSON.stringify(sourceVisualContextMemoryBridgeTool)).not.toContain("agentMemory.upsert");
    expect(JSON.stringify(sourceVisualContextMemoryBridgeTool)).not.toContain("visualContext");
    expect(JSON.stringify(sourceVisualContextMemoryBridgeTool)).not.toContain("source visual context remembered");
    expect(JSON.stringify(sourceVisualContextMemoryBridgeTool)).not.toContain("Store an authenticated browser screenshot");
    expect(sourceVisualContextArtifactBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceVisualContextArtifactBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: false,
      visual_context_artifact_bridge: true,
      artifact_export: true,
      public_artifact_destination: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_artifact_export: true,
      handler_public_artifact_destination: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: false,
      handler_visual_context_artifact_bridge: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(sourceVisualContextArtifactBridgeTool?.metadata.authority_classes).toEqual([
      "artifact_export",
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "handler_artifact_export",
      "handler_browser_automation",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_artifact_bridge",
      "handler_visual_context_capture",
      "network_access",
      "pii_input",
      "public_artifact_destination",
      "secret_env_access",
      "tainted_browser_automation_target",
      "visual_context_artifact_bridge",
      "visual_context_capture"
    ]);
    expect(sourceVisualContextArtifactBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_artifact_export",
      "handler_browser_automation",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_artifact_bridge",
      "handler_visual_context_capture"
    ]);
    expect(sourceVisualContextArtifactBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_VISUAL_ARTIFACT_BROWSER_TOKEN",
      "SOURCE_VISUAL_ARTIFACT_EXPORT_TOKEN"
    ]);
    expect(sourceVisualContextArtifactBridgeTool?.metadata.schema_properties).toEqual([
      "artifact_bucket",
      "customer_id",
      "object_key",
      "public_access",
      "target_url",
      "visual_artifact_note_text"
    ]);
    expect(sourceVisualContextArtifactBridgeTool?.metadata.required_properties).toEqual([
      "artifact_bucket",
      "customer_id",
      "object_key",
      "public_access",
      "target_url",
      "visual_artifact_note_text"
    ]);
    expect(JSON.stringify(sourceVisualContextArtifactBridgeTool)).not.toContain("authenticatedBrowserPage");
    expect(JSON.stringify(sourceVisualContextArtifactBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(sourceVisualContextArtifactBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(sourceVisualContextArtifactBridgeTool)).not.toContain("screenshot.toString");
    expect(JSON.stringify(sourceVisualContextArtifactBridgeTool)).not.toContain("artifactExportClient.upload");
    expect(JSON.stringify(sourceVisualContextArtifactBridgeTool)).not.toContain("source visual context exported to artifact");
    expect(JSON.stringify(sourceVisualContextArtifactBridgeTool)).not.toContain("Export an authenticated browser screenshot");
    expect(sourceVisualContextTrainingDatasetBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceVisualContextTrainingDatasetBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: false,
      visual_context_training_dataset_bridge: true,
      training_dataset_export: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_training_dataset_export: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: false,
      handler_visual_context_training_dataset_bridge: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceVisualContextTrainingDatasetBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_training_dataset_export",
      "handler_visual_context_capture",
      "handler_visual_context_training_dataset_bridge",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_browser_automation_target",
      "training_dataset_export",
      "visual_context_capture",
      "visual_context_training_dataset_bridge"
    ]);
    expect(sourceVisualContextTrainingDatasetBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_training_dataset_export",
      "handler_visual_context_capture",
      "handler_visual_context_training_dataset_bridge"
    ]);
    expect(sourceVisualContextTrainingDatasetBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_VISUAL_TRAINING_BROWSER_TOKEN",
      "SOURCE_VISUAL_TRAINING_DATASET_TOKEN"
    ]);
    expect(sourceVisualContextTrainingDatasetBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "split_name",
      "target_url",
      "training_dataset_id",
      "visual_training_label_text"
    ]);
    expect(sourceVisualContextTrainingDatasetBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "split_name",
      "target_url",
      "training_dataset_id",
      "visual_training_label_text"
    ]);
    expect(JSON.stringify(sourceVisualContextTrainingDatasetBridgeTool)).not.toContain("authenticatedBrowserPage");
    expect(JSON.stringify(sourceVisualContextTrainingDatasetBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(sourceVisualContextTrainingDatasetBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(sourceVisualContextTrainingDatasetBridgeTool)).not.toContain("screenshot.toString");
    expect(JSON.stringify(sourceVisualContextTrainingDatasetBridgeTool)).not.toContain("trainingDatasetClient.appendRecord");
    expect(JSON.stringify(sourceVisualContextTrainingDatasetBridgeTool)).not.toContain("source visual context exported to training dataset");
    expect(JSON.stringify(sourceVisualContextTrainingDatasetBridgeTool)).not.toContain("Export an authenticated browser screenshot");
    expect(sourceVisualContextTelemetryBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceVisualContextTelemetryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: false,
      visual_context_telemetry_bridge: true,
      telemetry_export: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_telemetry_export: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: false,
      handler_visual_context_telemetry_bridge: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceVisualContextTelemetryBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_telemetry_export",
      "handler_visual_context_capture",
      "handler_visual_context_telemetry_bridge",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_browser_automation_target",
      "telemetry_export",
      "visual_context_capture",
      "visual_context_telemetry_bridge"
    ]);
    expect(sourceVisualContextTelemetryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_telemetry_export",
      "handler_visual_context_capture",
      "handler_visual_context_telemetry_bridge"
    ]);
    expect(sourceVisualContextTelemetryBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_VISUAL_TRACE_BROWSER_TOKEN",
      "SOURCE_VISUAL_TRACE_EXPORT_TOKEN"
    ]);
    expect(sourceVisualContextTelemetryBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "target_url",
      "telemetry_project",
      "trace_name",
      "visual_trace_note_text"
    ]);
    expect(sourceVisualContextTelemetryBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "target_url",
      "telemetry_project",
      "trace_name",
      "visual_trace_note_text"
    ]);
    expect(JSON.stringify(sourceVisualContextTelemetryBridgeTool)).not.toContain("authenticatedBrowserPage");
    expect(JSON.stringify(sourceVisualContextTelemetryBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(sourceVisualContextTelemetryBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(sourceVisualContextTelemetryBridgeTool)).not.toContain("screenshot.toString");
    expect(JSON.stringify(sourceVisualContextTelemetryBridgeTool)).not.toContain("telemetryClient.recordTrace");
    expect(JSON.stringify(sourceVisualContextTelemetryBridgeTool)).not.toContain("source visual context exported to telemetry");
    expect(JSON.stringify(sourceVisualContextTelemetryBridgeTool)).not.toContain("Export an authenticated browser screenshot");
    expect(sourceVisualContextPromptCacheBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "remember", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceVisualContextPromptCacheBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: false,
      visual_context_prompt_cache_bridge: true,
      prompt_cache_write: true,
      tainted_prompt_cache_key: true,
      tainted_prompt_cache_value: false,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_prompt_cache_write: true,
      handler_tainted_prompt_cache_key: true,
      handler_tainted_prompt_cache_value: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: false,
      handler_visual_context_prompt_cache_bridge: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(sourceVisualContextPromptCacheBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_browser_automation",
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_prompt_cache_key",
      "handler_visual_context_capture",
      "handler_visual_context_prompt_cache_bridge",
      "network_access",
      "pii_input",
      "prompt_cache_write",
      "secret_env_access",
      "tainted_browser_automation_target",
      "tainted_prompt_cache_key",
      "visual_context_capture",
      "visual_context_prompt_cache_bridge"
    ]);
    expect(sourceVisualContextPromptCacheBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_prompt_cache_key",
      "handler_visual_context_capture",
      "handler_visual_context_prompt_cache_bridge"
    ]);
    expect(sourceVisualContextPromptCacheBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_VISUAL_PROMPT_CACHE_BROWSER_TOKEN",
      "SOURCE_VISUAL_PROMPT_CACHE_TOKEN"
    ]);
    expect(sourceVisualContextPromptCacheBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "prompt_cache_key",
      "target_url",
      "visual_cache_note_text"
    ]);
    expect(sourceVisualContextPromptCacheBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "prompt_cache_key",
      "target_url",
      "visual_cache_note_text"
    ]);
    expect(JSON.stringify(sourceVisualContextPromptCacheBridgeTool)).not.toContain("authenticatedBrowserPage");
    expect(JSON.stringify(sourceVisualContextPromptCacheBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(sourceVisualContextPromptCacheBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(sourceVisualContextPromptCacheBridgeTool)).not.toContain("screenshot.toString");
    expect(JSON.stringify(sourceVisualContextPromptCacheBridgeTool)).not.toContain("promptCache.set");
    expect(JSON.stringify(sourceVisualContextPromptCacheBridgeTool)).not.toContain("source visual context cached for prompts");
    expect(sourceVisualContextAgentDelegationBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceVisualContextAgentDelegationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      agent_delegation: true,
      tainted_agent_delegation_target: true,
      agent_delegation_context_forwarding: true,
      visual_context_agent_delegation_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_agent_delegation: true,
      handler_tainted_agent_delegation_target: true,
      handler_agent_delegation_context_forwarding: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_agent_delegation_bridge: true,
      handler_signal_count: 8,
      open_world_schema: false
    });
    expect(sourceVisualContextAgentDelegationBridgeTool?.metadata.authority_classes).toEqual([
      "agent_delegation",
      "agent_delegation_context_forwarding",
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_agent_delegation_target",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_agent_delegation_bridge",
      "handler_visual_context_capture",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_agent_delegation_target",
      "tainted_browser_automation_target",
      "visual_context_agent_delegation_bridge",
      "visual_context_capture"
    ]);
    expect(sourceVisualContextAgentDelegationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_agent_delegation_target",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_agent_delegation_bridge",
      "handler_visual_context_capture"
    ]);
    expect(sourceVisualContextAgentDelegationBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_VISUAL_A2A_BROWSER_TOKEN",
      "SOURCE_VISUAL_A2A_TOKEN"
    ]);
    expect(sourceVisualContextAgentDelegationBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requested_task_type",
      "target_agent_url",
      "target_url",
      "visual_delegation_note_text"
    ]);
    expect(sourceVisualContextAgentDelegationBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requested_task_type",
      "target_agent_url",
      "target_url",
      "visual_delegation_note_text"
    ]);
    expect(JSON.stringify(sourceVisualContextAgentDelegationBridgeTool)).not.toContain("authenticatedBrowserPage");
    expect(JSON.stringify(sourceVisualContextAgentDelegationBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(sourceVisualContextAgentDelegationBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(sourceVisualContextAgentDelegationBridgeTool)).not.toContain("screenshot.toString");
    expect(JSON.stringify(sourceVisualContextAgentDelegationBridgeTool)).not.toContain("remoteAgentClient.delegateTask");
    expect(JSON.stringify(sourceVisualContextAgentDelegationBridgeTool)).not.toContain("source visual context delegated to remote agent");
    expect(sourceVisualContextTaskQueueBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceVisualContextTaskQueueBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_task_queue_bridge: true,
      task_queue_enqueue: true,
      tainted_task_payload: true,
      tainted_task_routing: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_task_queue_enqueue: true,
      handler_tainted_task_payload: true,
      handler_tainted_task_routing: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_task_queue_bridge: true,
      handler_signal_count: 8,
      open_world_schema: false
    });
    expect(sourceVisualContextTaskQueueBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_task_payload",
      "handler_tainted_task_routing",
      "handler_task_queue_enqueue",
      "handler_visual_context_capture",
      "handler_visual_context_task_queue_bridge",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_browser_automation_target",
      "tainted_task_payload",
      "tainted_task_routing",
      "task_queue_enqueue",
      "visual_context_capture",
      "visual_context_task_queue_bridge"
    ]);
    expect(sourceVisualContextTaskQueueBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_task_payload",
      "handler_tainted_task_routing",
      "handler_task_queue_enqueue",
      "handler_visual_context_capture",
      "handler_visual_context_task_queue_bridge"
    ]);
    expect(sourceVisualContextTaskQueueBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_VISUAL_QUEUE_BROWSER_TOKEN",
      "SOURCE_VISUAL_QUEUE_TOKEN"
    ]);
    expect(sourceVisualContextTaskQueueBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "job_route",
      "queue_name",
      "target_url",
      "visual_job_note_text"
    ]);
    expect(sourceVisualContextTaskQueueBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "job_route",
      "queue_name",
      "target_url",
      "visual_job_note_text"
    ]);
    expect(JSON.stringify(sourceVisualContextTaskQueueBridgeTool)).not.toContain("authenticatedBrowserPage");
    expect(JSON.stringify(sourceVisualContextTaskQueueBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(sourceVisualContextTaskQueueBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(sourceVisualContextTaskQueueBridgeTool)).not.toContain("screenshot.toString");
    expect(JSON.stringify(sourceVisualContextTaskQueueBridgeTool)).not.toContain("taskQueueClient.enqueue");
    expect(JSON.stringify(sourceVisualContextTaskQueueBridgeTool)).not.toContain("source visual context queued for background agent");
    expect(JSON.stringify(sourceVisualContextPromptCacheBridgeTool)).not.toContain("Write an authenticated browser screenshot");
    expect(sourceSecretManagerAccessTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: false,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerAccessTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: false,
      agent_config_write: false,
      credential_issuance: false,
      nested_tool_invocation: false,
      browser_automation: false,
      secret_manager_access: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_credential_issuance: false,
      handler_tool_invocation: false,
      handler_browser_automation: false,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      tainted_secret_manager_path: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(sourceSecretManagerAccessTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "filesystem_access",
      "handler_secret_manager_access",
      "handler_tainted_secret_manager_path",
      "pii_input",
      "secret_manager_access",
      "tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerAccessTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_manager_access",
      "handler_tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerAccessTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceSecretManagerAccessTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(sourceSecretManagerAccessTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(sourceSecretManagerAccessTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerAccessTool)).not.toContain("secret.value");
    expect(JSON.stringify(sourceSecretManagerAccessTool)).not.toContain("Read a customer support secret");
    expect(sourceSecretManagerExternalServiceBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerExternalServiceBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      secret_manager_external_service_bridge: true,
      external_service_write: true,
      tainted_external_service_recipient: true,
      external_write: true,
      memory_write: false,
      agent_config_write: false,
      credential_issuance: false,
      nested_tool_invocation: false,
      browser_automation: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: true,
      handler_tainted_external_service_recipient: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_credential_issuance: false,
      handler_tool_invocation: false,
      handler_browser_automation: false,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_secret_manager_external_service_bridge: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceSecretManagerExternalServiceBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_service_write",
      "external_write",
      "filesystem_access",
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_external_service_bridge",
      "handler_tainted_external_service_recipient",
      "handler_tainted_secret_manager_path",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_external_service_bridge",
      "tainted_external_service_recipient",
      "tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerExternalServiceBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_external_service_bridge",
      "handler_tainted_external_service_recipient",
      "handler_tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerExternalServiceBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_SECRET_BRIDGE_SLACK_TOKEN"
    ]);
    expect(sourceSecretManagerExternalServiceBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "external_channel_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(sourceSecretManagerExternalServiceBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "external_channel_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(sourceSecretManagerExternalServiceBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerExternalServiceBridgeTool)).not.toContain("slackClient.chat.postMessage");
    expect(JSON.stringify(sourceSecretManagerExternalServiceBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerExternalServiceBridgeTool)).not.toContain("source vault secret posted externally");
    expect(JSON.stringify(sourceSecretManagerExternalServiceBridgeTool)).not.toContain("Post a customer support secret");
    expect(sourceSecretManagerPromptBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerPromptBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      secret_manager_prompt_bridge: true,
      model_provider_call: true,
      tainted_model_selection: false,
      tool_output_prompt_bridge: false,
      secret_manager_external_service_bridge: false,
      external_service_write: false,
      external_write: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_model_provider_call: true,
      handler_tainted_model_selection: false,
      handler_secret_manager_prompt_bridge: true,
      handler_tool_output_prompt_bridge: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_secret_manager_external_service_bridge: false,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(sourceSecretManagerPromptBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "filesystem_access",
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_prompt_bridge",
      "handler_tainted_secret_manager_path",
      "model_provider_call",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_prompt_bridge",
      "tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerPromptBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_prompt_bridge",
      "handler_tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerPromptBridgeTool?.metadata.handler_env_key_names).toEqual(["SOURCE_SECRET_MODEL_BRIDGE_TOKEN"]);
    expect(sourceSecretManagerPromptBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(sourceSecretManagerPromptBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(sourceSecretManagerPromptBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerPromptBridgeTool)).not.toContain("openaiClient.chat.completions.create");
    expect(JSON.stringify(sourceSecretManagerPromptBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerPromptBridgeTool)).not.toContain("secretAnalysisInput");
    expect(JSON.stringify(sourceSecretManagerPromptBridgeTool)).not.toContain("source vault secret summarized by model");
    expect(JSON.stringify(sourceSecretManagerPromptBridgeTool)).not.toContain("Summarize a customer support secret");
    expect(sourceSecretManagerMemoryBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: false,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerMemoryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      memory_write: true,
      tainted_memory_scope: true,
      secret_manager_memory_bridge: true,
      secret_manager_prompt_bridge: false,
      model_provider_call: false,
      secret_manager_external_service_bridge: false,
      external_service_write: false,
      external_write: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_memory_write: true,
      handler_tainted_memory_scope: true,
      handler_secret_manager_memory_bridge: true,
      handler_secret_manager_prompt_bridge: false,
      handler_model_provider_call: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceSecretManagerMemoryBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "filesystem_access",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_memory_bridge",
      "handler_tainted_memory_scope",
      "handler_tainted_secret_manager_path",
      "memory_access",
      "memory_write",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_memory_bridge",
      "tainted_memory_scope",
      "tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerMemoryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_memory_bridge",
      "handler_tainted_memory_scope",
      "handler_tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerMemoryBridgeTool?.metadata.handler_env_key_names).toEqual(["SOURCE_SECRET_MEMORY_BRIDGE_TOKEN"]);
    expect(sourceSecretManagerMemoryBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "memory_namespace",
      "requester_ticket",
      "secret_path"
    ]);
    expect(sourceSecretManagerMemoryBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "memory_namespace",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(sourceSecretManagerMemoryBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerMemoryBridgeTool)).not.toContain("agentMemory.upsert");
    expect(JSON.stringify(sourceSecretManagerMemoryBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerMemoryBridgeTool)).not.toContain("secretMemoryValue");
    expect(JSON.stringify(sourceSecretManagerMemoryBridgeTool)).not.toContain("source vault secret persisted to memory");
    expect(JSON.stringify(sourceSecretManagerMemoryBridgeTool)).not.toContain("Store a customer support secret");
    expect(sourceSecretManagerDatabaseWriteBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerDatabaseWriteBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      database_access: true,
      database_write: true,
      tainted_database_query_argument: false,
      secret_manager_database_write_bridge: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_database_query: true,
      handler_database_write: true,
      handler_tainted_database_query_argument: false,
      handler_secret_manager_database_write_bridge: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceSecretManagerDatabaseWriteBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "database_access",
      "database_write",
      "filesystem_access",
      "handler_database_query",
      "handler_database_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_database_write_bridge",
      "handler_tainted_secret_manager_path",
      "memory_access",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_database_write_bridge",
      "tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerDatabaseWriteBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_database_query",
      "handler_database_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_database_write_bridge",
      "handler_tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerDatabaseWriteBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_SECRET_DATABASE_BRIDGE_TOKEN"
    ]);
    expect(sourceSecretManagerDatabaseWriteBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "database_record_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(sourceSecretManagerDatabaseWriteBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "database_record_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(sourceSecretManagerDatabaseWriteBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerDatabaseWriteBridgeTool)).not.toContain("supportDb.query");
    expect(JSON.stringify(sourceSecretManagerDatabaseWriteBridgeTool)).not.toContain("UPDATE support_cases");
    expect(JSON.stringify(sourceSecretManagerDatabaseWriteBridgeTool)).not.toContain("vault_secret_material");
    expect(JSON.stringify(sourceSecretManagerDatabaseWriteBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerDatabaseWriteBridgeTool)).not.toContain("secretDatabaseValue");
    expect(JSON.stringify(sourceSecretManagerDatabaseWriteBridgeTool)).not.toContain("source vault secret stored in database");
    expect(JSON.stringify(sourceSecretManagerDatabaseWriteBridgeTool)).not.toContain("Store a customer support secret");
    expect(sourceSecretManagerEmbeddingVectorBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerEmbeddingVectorBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      embedding_provider_call: true,
      tainted_embedding_input: true,
      memory_write: true,
      tainted_memory_scope: true,
      secret_manager_memory_bridge: true,
      secret_manager_embedding_vector_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_embedding_provider_call: true,
      handler_tainted_embedding_input: true,
      handler_memory_write: true,
      handler_tainted_memory_scope: true,
      handler_secret_manager_memory_bridge: true,
      handler_secret_manager_embedding_vector_bridge: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 9,
      open_world_schema: false
    });
    for (const authorityClass of [
      "secret_manager_access",
      "tainted_secret_manager_path",
      "embedding_provider_call",
      "tainted_embedding_input",
      "memory_write",
      "tainted_memory_scope",
      "secret_manager_memory_bridge",
      "secret_manager_embedding_vector_bridge"
    ]) {
      expect(sourceSecretManagerEmbeddingVectorBridgeTool?.metadata.authority_classes).toContain(authorityClass);
    }
    for (const handlerClass of [
      "handler_secret_manager_access",
      "handler_tainted_secret_manager_path",
      "handler_embedding_provider_call",
      "handler_tainted_embedding_input",
      "handler_memory_write",
      "handler_tainted_memory_scope",
      "handler_secret_manager_memory_bridge",
      "handler_secret_manager_embedding_vector_bridge"
    ]) {
      expect(sourceSecretManagerEmbeddingVectorBridgeTool?.metadata.handler_authority_classes).toContain(handlerClass);
    }
    expect(sourceSecretManagerEmbeddingVectorBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_SECRET_VECTOR_BRIDGE_TOKEN"
    ]);
    expect(sourceSecretManagerEmbeddingVectorBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path",
      "vector_namespace"
    ]);
    expect(sourceSecretManagerEmbeddingVectorBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path",
      "vector_namespace"
    ]);
    expect(JSON.stringify(sourceSecretManagerEmbeddingVectorBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerEmbeddingVectorBridgeTool)).not.toContain("embeddingClient.embedQuery");
    expect(JSON.stringify(sourceSecretManagerEmbeddingVectorBridgeTool)).not.toContain("vectorStore.upsert");
    expect(JSON.stringify(sourceSecretManagerEmbeddingVectorBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerEmbeddingVectorBridgeTool)).not.toContain("secretVectorValue");
    expect(JSON.stringify(sourceSecretManagerEmbeddingVectorBridgeTool)).not.toContain("secretEmbedding");
    expect(JSON.stringify(sourceSecretManagerEmbeddingVectorBridgeTool)).not.toContain("source vault secret embedded to vector memory");
    expect(JSON.stringify(sourceSecretManagerEmbeddingVectorBridgeTool)).not.toContain("Embed a customer support secret");
    expect(sourceSecretManagerTrainingDatasetBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerTrainingDatasetBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      training_dataset_export: true,
      tainted_training_dataset_payload: false,
      secret_manager_training_dataset_bridge: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_training_dataset_export: true,
      handler_tainted_training_dataset_payload: false,
      handler_secret_manager_training_dataset_bridge: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(sourceSecretManagerTrainingDatasetBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "filesystem_access",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_training_dataset_bridge",
      "handler_tainted_secret_manager_path",
      "handler_training_dataset_export",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_training_dataset_bridge",
      "tainted_secret_manager_path",
      "training_dataset_export"
    ]);
    expect(sourceSecretManagerTrainingDatasetBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_training_dataset_bridge",
      "handler_tainted_secret_manager_path",
      "handler_training_dataset_export"
    ]);
    expect(sourceSecretManagerTrainingDatasetBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_SECRET_TRAINING_DATASET_BRIDGE_TOKEN"
    ]);
    expect(sourceSecretManagerTrainingDatasetBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "dataset_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(sourceSecretManagerTrainingDatasetBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "dataset_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(sourceSecretManagerTrainingDatasetBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerTrainingDatasetBridgeTool)).not.toContain("trainingDatasetClient.appendRecord");
    expect(JSON.stringify(sourceSecretManagerTrainingDatasetBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerTrainingDatasetBridgeTool)).not.toContain("secretTrainingValue");
    expect(JSON.stringify(sourceSecretManagerTrainingDatasetBridgeTool)).not.toContain("source vault secret exported to training dataset");
    expect(JSON.stringify(sourceSecretManagerTrainingDatasetBridgeTool)).not.toContain("Export a customer support secret");
    expect(sourceSecretManagerFeedbackBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerFeedbackBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      feedback_pipeline_write: true,
      secret_manager_feedback_bridge: true,
      tainted_feedback_payload: false,
      feedback_auto_promotion: true,
      tainted_feedback_routing: true,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_feedback_pipeline_write: true,
      handler_secret_manager_feedback_bridge: true,
      handler_tainted_feedback_payload: false,
      handler_feedback_auto_promotion: true,
      handler_tainted_feedback_routing: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(sourceSecretManagerFeedbackBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "feedback_auto_promotion",
      "feedback_pipeline_write",
      "filesystem_access",
      "handler_feedback_auto_promotion",
      "handler_feedback_pipeline_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_feedback_bridge",
      "handler_tainted_feedback_routing",
      "handler_tainted_secret_manager_path",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_feedback_bridge",
      "tainted_feedback_routing",
      "tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerFeedbackBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_feedback_auto_promotion",
      "handler_feedback_pipeline_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_feedback_bridge",
      "handler_tainted_feedback_routing",
      "handler_tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerFeedbackBridgeTool?.metadata.handler_env_key_names).toEqual(["SOURCE_SECRET_FEEDBACK_BRIDGE_TOKEN"]);
    expect(sourceSecretManagerFeedbackBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "eval_set_id",
      "feedback_dataset_id",
      "promotion_target",
      "reviewer_ticket",
      "secret_path"
    ]);
    expect(sourceSecretManagerFeedbackBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "eval_set_id",
      "feedback_dataset_id",
      "promotion_target",
      "reviewer_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(sourceSecretManagerFeedbackBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerFeedbackBridgeTool)).not.toContain("feedbackPipeline.promoteToTraining");
    expect(JSON.stringify(sourceSecretManagerFeedbackBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerFeedbackBridgeTool)).not.toContain("secretFeedbackValue");
    expect(JSON.stringify(sourceSecretManagerFeedbackBridgeTool)).not.toContain("source vault secret promoted to feedback");
    expect(JSON.stringify(sourceSecretManagerFeedbackBridgeTool)).not.toContain("Record a customer support secret");
    expect(sourceSecretManagerArtifactBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerArtifactBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      artifact_export: true,
      secret_manager_artifact_bridge: true,
      tainted_artifact_export_payload: false,
      public_artifact_destination: true,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_artifact_export: true,
      handler_secret_manager_artifact_bridge: true,
      handler_tainted_artifact_export_payload: false,
      handler_public_artifact_destination: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceSecretManagerArtifactBridgeTool?.metadata.authority_classes).toEqual([
      "artifact_export",
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "filesystem_access",
      "handler_artifact_export",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_artifact_bridge",
      "handler_tainted_secret_manager_path",
      "pii_input",
      "public_artifact_destination",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_artifact_bridge",
      "tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerArtifactBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_artifact_export",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_artifact_bridge",
      "handler_tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerArtifactBridgeTool?.metadata.handler_env_key_names).toEqual(["SOURCE_SECRET_ARTIFACT_BRIDGE_TOKEN"]);
    expect(sourceSecretManagerArtifactBridgeTool?.metadata.schema_properties).toEqual([
      "artifact_bucket",
      "customer_id",
      "object_key",
      "public_access",
      "requester_ticket",
      "secret_path"
    ]);
    expect(sourceSecretManagerArtifactBridgeTool?.metadata.required_properties).toEqual([
      "artifact_bucket",
      "customer_id",
      "object_key",
      "public_access",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(sourceSecretManagerArtifactBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerArtifactBridgeTool)).not.toContain("artifactExportClient.upload");
    expect(JSON.stringify(sourceSecretManagerArtifactBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerArtifactBridgeTool)).not.toContain("secretArtifactValue");
    expect(JSON.stringify(sourceSecretManagerArtifactBridgeTool)).not.toContain("source vault secret exported to artifact");
    expect(JSON.stringify(sourceSecretManagerArtifactBridgeTool)).not.toContain("Export a customer support secret");
    expect(sourceSecretManagerTelemetryBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerTelemetryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      telemetry_export: true,
      secret_manager_telemetry_bridge: true,
      tainted_telemetry_payload: true,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_telemetry_export: true,
      handler_secret_manager_telemetry_bridge: true,
      handler_tainted_telemetry_payload: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceSecretManagerTelemetryBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "filesystem_access",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_telemetry_bridge",
      "handler_tainted_secret_manager_path",
      "handler_tainted_telemetry_payload",
      "handler_telemetry_export",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_telemetry_bridge",
      "tainted_secret_manager_path",
      "tainted_telemetry_payload",
      "telemetry_export"
    ]);
    expect(sourceSecretManagerTelemetryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_telemetry_bridge",
      "handler_tainted_secret_manager_path",
      "handler_tainted_telemetry_payload",
      "handler_telemetry_export"
    ]);
    expect(sourceSecretManagerTelemetryBridgeTool?.metadata.handler_env_key_names).toEqual(["SOURCE_SECRET_TELEMETRY_BRIDGE_TOKEN"]);
    expect(sourceSecretManagerTelemetryBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path",
      "trace_session_id"
    ]);
    expect(sourceSecretManagerTelemetryBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path",
      "trace_session_id"
    ]);
    expect(JSON.stringify(sourceSecretManagerTelemetryBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerTelemetryBridgeTool)).not.toContain("telemetryClient.recordTrace");
    expect(JSON.stringify(sourceSecretManagerTelemetryBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerTelemetryBridgeTool)).not.toContain("secretTraceValue");
    expect(JSON.stringify(sourceSecretManagerTelemetryBridgeTool)).not.toContain("source vault secret exported to telemetry");
    expect(JSON.stringify(sourceSecretManagerTelemetryBridgeTool)).not.toContain("Export a customer support secret");
    expect(sourceSecretManagerPromptCacheBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerPromptCacheBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      prompt_cache_write: true,
      secret_manager_prompt_cache_bridge: true,
      tainted_prompt_cache_key: true,
      tainted_prompt_cache_value: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_prompt_cache_write: true,
      handler_secret_manager_prompt_cache_bridge: true,
      handler_tainted_prompt_cache_key: true,
      handler_tainted_prompt_cache_value: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(sourceSecretManagerPromptCacheBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "filesystem_access",
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_prompt_cache_bridge",
      "handler_tainted_prompt_cache_key",
      "handler_tainted_prompt_cache_value",
      "handler_tainted_secret_manager_path",
      "pii_input",
      "prompt_cache_write",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_prompt_cache_bridge",
      "tainted_prompt_cache_key",
      "tainted_prompt_cache_value",
      "tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerPromptCacheBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_prompt_cache_bridge",
      "handler_tainted_prompt_cache_key",
      "handler_tainted_prompt_cache_value",
      "handler_tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerPromptCacheBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_SECRET_PROMPT_CACHE_BRIDGE_TOKEN"
    ]);
    expect(sourceSecretManagerPromptCacheBridgeTool?.metadata.schema_properties).toEqual([
      "cache_key",
      "customer_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(sourceSecretManagerPromptCacheBridgeTool?.metadata.required_properties).toEqual([
      "cache_key",
      "customer_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(sourceSecretManagerPromptCacheBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerPromptCacheBridgeTool)).not.toContain("promptCache.set");
    expect(JSON.stringify(sourceSecretManagerPromptCacheBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerPromptCacheBridgeTool)).not.toContain("secretPromptCacheValue");
    expect(JSON.stringify(sourceSecretManagerPromptCacheBridgeTool)).not.toContain("source vault secret cached for prompts");
    expect(JSON.stringify(sourceSecretManagerPromptCacheBridgeTool)).not.toContain("Write a customer support secret");
    expect(sourceSecretManagerPromptRegistryBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceSecretManagerPromptRegistryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      prompt_registry_write: true,
      secret_manager_prompt_registry_bridge: true,
      tainted_prompt_registry_payload: true,
      tainted_prompt_registry_selector: true,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_prompt_registry_write: true,
      handler_secret_manager_prompt_registry_bridge: true,
      handler_tainted_prompt_registry_payload: true,
      handler_tainted_prompt_registry_selector: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(sourceSecretManagerPromptRegistryBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "filesystem_access",
      "handler_prompt_registry_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_prompt_registry_bridge",
      "handler_tainted_prompt_registry_payload",
      "handler_tainted_prompt_registry_selector",
      "handler_tainted_secret_manager_path",
      "pii_input",
      "prompt_registry_write",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_prompt_registry_bridge",
      "tainted_prompt_registry_payload",
      "tainted_prompt_registry_selector",
      "tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerPromptRegistryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_prompt_registry_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_prompt_registry_bridge",
      "handler_tainted_prompt_registry_payload",
      "handler_tainted_prompt_registry_selector",
      "handler_tainted_secret_manager_path"
    ]);
    expect(sourceSecretManagerPromptRegistryBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_SECRET_PROMPT_REGISTRY_BRIDGE_TOKEN"
    ]);
    expect(sourceSecretManagerPromptRegistryBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "prompt_id",
      "prompt_role",
      "requester_ticket",
      "secret_path"
    ]);
    expect(sourceSecretManagerPromptRegistryBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "prompt_id",
      "prompt_role",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(sourceSecretManagerPromptRegistryBridgeTool)).not.toContain("vaultClient.readSecret");
    expect(JSON.stringify(sourceSecretManagerPromptRegistryBridgeTool)).not.toContain("promptRegistryClient.updatePrompt");
    expect(JSON.stringify(sourceSecretManagerPromptRegistryBridgeTool)).not.toContain("secretRecord.value");
    expect(JSON.stringify(sourceSecretManagerPromptRegistryBridgeTool)).not.toContain("secretPromptRegistryValue");
    expect(JSON.stringify(sourceSecretManagerPromptRegistryBridgeTool)).not.toContain("source vault secret published to prompt registry");
    expect(JSON.stringify(sourceSecretManagerPromptRegistryBridgeTool)).not.toContain("Publish a customer support secret");
    expect(sourceExternalServiceWriteTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceExternalServiceWriteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: false,
      agent_config_write: false,
      credential_issuance: false,
      nested_tool_invocation: false,
      browser_automation: false,
      secret_manager_access: false,
      external_service_write: true,
      tainted_external_service_recipient: true,
      network_response_capture: false,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_external_service_write: true,
      handler_tainted_external_service_recipient: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_credential_issuance: false,
      handler_tool_invocation: false,
      handler_browser_automation: false,
      handler_secret_manager_access: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 3,
      open_world_schema: false
    });
    expect(sourceExternalServiceWriteTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_service_write",
      "external_write",
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient",
      "pii_input",
      "secret_env_access",
      "tainted_external_service_recipient"
    ]);
    expect(sourceExternalServiceWriteTool?.metadata.handler_authority_classes).toEqual([
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient"
    ]);
    expect(sourceExternalServiceWriteTool?.metadata.handler_env_key_names).toEqual(["SOURCE_SLACK_BOT_TOKEN"]);
    expect(sourceExternalServiceWriteTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_update_text",
      "requester_ticket",
      "slack_channel_id"
    ]);
    expect(sourceExternalServiceWriteTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_update_text",
      "requester_ticket",
      "slack_channel_id"
    ]);
    expect(JSON.stringify(sourceExternalServiceWriteTool)).not.toContain("slackClient.chat.postMessage");
    expect(JSON.stringify(sourceExternalServiceWriteTool)).not.toContain("source slack update sent");
    expect(JSON.stringify(sourceExternalServiceWriteTool)).not.toContain("Send caller supplied customer update text");
    expect(sourceModelProviderCallTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceModelProviderCallTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: false,
      agent_config_write: false,
      credential_issuance: false,
      nested_tool_invocation: false,
      browser_automation: false,
      secret_manager_access: false,
      external_service_write: false,
      model_provider_call: true,
      tainted_model_selection: true,
      privileged_prompt_composition: true,
      network_response_capture: false,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_model_provider_call: true,
      handler_tainted_model_selection: true,
      handler_privileged_prompt_composition: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_credential_issuance: false,
      handler_tool_invocation: false,
      handler_browser_automation: false,
      handler_secret_manager_access: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(sourceModelProviderCallTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_model_provider_call",
      "handler_privileged_prompt_composition",
      "handler_secret_env_access",
      "handler_tainted_model_selection",
      "model_provider_call",
      "pii_input",
      "privileged_prompt_composition",
      "secret_env_access",
      "tainted_model_selection"
    ]);
    expect(sourceModelProviderCallTool?.metadata.handler_authority_classes).toEqual([
      "handler_model_provider_call",
      "handler_privileged_prompt_composition",
      "handler_secret_env_access",
      "handler_tainted_model_selection"
    ]);
    expect(sourceModelProviderCallTool?.metadata.handler_env_key_names).toEqual(["SOURCE_MODEL_PROVIDER_TOKEN"]);
    expect(sourceModelProviderCallTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "model_name"
    ]);
    expect(sourceModelProviderCallTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "model_name"
    ]);
    expect(JSON.stringify(sourceModelProviderCallTool)).not.toContain("openai.chat.completions.create");
    expect(JSON.stringify(sourceModelProviderCallTool)).not.toContain("result.choices");
    expect(JSON.stringify(sourceModelProviderCallTool)).not.toContain("Summarize caller supplied customer ticket text");
    expect(JSON.stringify(sourceModelProviderCallTool)).not.toContain("Create an internal support summary");
    expect(sourceModelOutputDynamicCodeBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceModelOutputDynamicCodeBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      model_provider_call: true,
      tainted_model_selection: true,
      dynamic_code_execution: true,
      model_output_dynamic_code_execution_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_model_provider_call: true,
      handler_tainted_model_selection: true,
      handler_dynamic_code_execution: true,
      handler_model_output_dynamic_code_execution_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(sourceModelOutputDynamicCodeBridgeTool?.metadata.authority_classes).toEqual(expect.arrayContaining([
      "dynamic_code_execution",
      "handler_dynamic_code_execution",
      "handler_model_output_dynamic_code_execution_bridge",
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_tainted_model_selection",
      "model_output_dynamic_code_execution_bridge",
      "model_provider_call",
      "tainted_model_selection"
    ]));
    expect(sourceModelOutputDynamicCodeBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_dynamic_code_execution",
      "handler_model_output_dynamic_code_execution_bridge",
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_tainted_model_selection"
    ]);
    expect(sourceModelOutputDynamicCodeBridgeTool?.metadata.handler_env_key_names).toEqual(["SOURCE_MODEL_CODE_EXECUTION_TOKEN"]);
    expect(sourceModelOutputDynamicCodeBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "execution_reason_text",
      "model_name"
    ]);
    expect(sourceModelOutputDynamicCodeBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "execution_reason_text",
      "model_name"
    ]);
    expect(JSON.stringify(sourceModelOutputDynamicCodeBridgeTool)).not.toContain("openai.chat.completions.create");
    expect(JSON.stringify(sourceModelOutputDynamicCodeBridgeTool)).not.toContain("modelResult");
    expect(JSON.stringify(sourceModelOutputDynamicCodeBridgeTool)).not.toContain("generatedCode");
    expect(JSON.stringify(sourceModelOutputDynamicCodeBridgeTool)).not.toContain("new Function");
    expect(JSON.stringify(sourceModelOutputDynamicCodeBridgeTool)).not.toContain("source model generated code executed");
    expect(JSON.stringify(sourceModelOutputDynamicCodeBridgeTool)).not.toContain("Ask a model provider to generate code");
    expect(sourceModelOutputNetworkDestinationBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceModelOutputNetworkDestinationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      model_provider_call: true,
      tainted_model_selection: true,
      model_output_network_destination_bridge: true,
      credentialed_network_read: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: true,
      handler_credentialed_network_read: true,
      handler_model_provider_call: true,
      handler_tainted_model_selection: true,
      handler_model_output_network_destination_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(sourceModelOutputNetworkDestinationBridgeTool?.metadata.authority_classes).toEqual(expect.arrayContaining([
      "credentialed_network_read",
      "handler_credentialed_network_read",
      "handler_model_output_network_destination_bridge",
      "handler_model_provider_call",
      "handler_network_access",
      "handler_secret_env_access",
      "handler_tainted_model_selection",
      "model_output_network_destination_bridge",
      "model_provider_call",
      "network_access",
      "tainted_model_selection"
    ]));
    expect(sourceModelOutputNetworkDestinationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_credentialed_network_read",
      "handler_model_output_network_destination_bridge",
      "handler_model_provider_call",
      "handler_network_access",
      "handler_secret_env_access",
      "handler_tainted_model_selection"
    ]);
    expect(sourceModelOutputNetworkDestinationBridgeTool?.metadata.handler_env_key_names).toEqual([
      "SOURCE_MODEL_URL_SELECTION_TOKEN",
      "SOURCE_PARTNER_STATUS_TOKEN"
    ]);
    expect(sourceModelOutputNetworkDestinationBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "investigation_scope_text",
      "model_name"
    ]);
    expect(sourceModelOutputNetworkDestinationBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "investigation_scope_text",
      "model_name"
    ]);
    expect(JSON.stringify(sourceModelOutputNetworkDestinationBridgeTool)).not.toContain("openai.chat.completions.create");
    expect(JSON.stringify(sourceModelOutputNetworkDestinationBridgeTool)).not.toContain("modelResult");
    expect(JSON.stringify(sourceModelOutputNetworkDestinationBridgeTool)).not.toContain("selectedEndpointUrl");
    expect(JSON.stringify(sourceModelOutputNetworkDestinationBridgeTool)).not.toContain("fetch(");
    expect(JSON.stringify(sourceModelOutputNetworkDestinationBridgeTool)).not.toContain("source model selected URL fetched");
    expect(JSON.stringify(sourceModelOutputNetworkDestinationBridgeTool)).not.toContain("Ask a model provider to choose an investigation URL");
    expect(sourceModelOutputShellExecutionBridgeTool).toMatchObject({
      path: "mcp-source/customer-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(sourceModelOutputShellExecutionBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      model_provider_call: true,
      tainted_model_selection: true,
      shell_execution: true,
      model_output_shell_execution_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_model_provider_call: true,
      handler_tainted_model_selection: true,
      handler_shell_execution: true,
      handler_model_output_shell_execution_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(sourceModelOutputShellExecutionBridgeTool?.metadata.authority_classes).toEqual(expect.arrayContaining([
      "handler_model_output_shell_execution_bridge",
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_shell_execution",
      "handler_tainted_model_selection",
      "model_output_shell_execution_bridge",
      "model_provider_call",
      "shell_execution",
      "tainted_model_selection"
    ]));
    expect(sourceModelOutputShellExecutionBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_model_output_shell_execution_bridge",
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_shell_execution",
      "handler_tainted_model_selection"
    ]);
    expect(sourceModelOutputShellExecutionBridgeTool?.metadata.handler_env_key_names).toEqual(["SOURCE_MODEL_COMMAND_TOKEN"]);
    expect(sourceModelOutputShellExecutionBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "model_name",
      "remediation_goal_text"
    ]);
    expect(sourceModelOutputShellExecutionBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "model_name",
      "remediation_goal_text"
    ]);
    expect(JSON.stringify(sourceModelOutputShellExecutionBridgeTool)).not.toContain("openai.chat.completions.create");
    expect(JSON.stringify(sourceModelOutputShellExecutionBridgeTool)).not.toContain("modelResult");
    expect(JSON.stringify(sourceModelOutputShellExecutionBridgeTool)).not.toContain("generatedCommand");
    expect(JSON.stringify(sourceModelOutputShellExecutionBridgeTool)).not.toContain("execFile");
    expect(JSON.stringify(sourceModelOutputShellExecutionBridgeTool)).not.toContain("source model generated command queued");
    expect(JSON.stringify(sourceModelOutputShellExecutionBridgeTool)).not.toContain("Ask a model provider to generate a shell command");
    expect(pythonExportTool).toMatchObject({
      path: "mcp-source/python_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true
    });
    expect(pythonExportTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "python_tool_decorator",
      mcp_source_tool_argument_count: 1,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      values_collected: false,
      read_only_hint: false,
      idempotent_hint: false,
      external_write: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      open_world_schema: false,
      open_world_authority: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: true,
      handler_tainted_network_destination: true,
      handler_external_write: true,
      handler_secret_env_access: true,
      tainted_network_destination: true,
      handler_shell_execution: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4
    });
    expect(pythonExportTool?.metadata.handler_authority_classes).toEqual([
      "handler_external_write",
      "handler_network_access",
      "handler_secret_env_access",
      "handler_tainted_network_destination"
    ]);
    expect(pythonExportTool?.metadata.handler_env_key_names).toEqual(["PYTHON_EXPORT_TOKEN"]);
    expect(pythonExportTool?.metadata.mcp_source_tool_schema_styles).toEqual([
      "mcp_annotations",
      "pydantic_model",
      "python_signature"
    ]);
    expect(pythonExportTool?.metadata.schema_properties).toEqual([
      "authorization_token",
      "customer_email",
      "customer_reference",
      "destination_webhook_url",
      "source_payload_text"
    ]);
    expect(pythonExportTool?.metadata.required_properties).toEqual([
      "authorization_token",
      "customer_email",
      "customer_reference",
      "destination_webhook_url",
      "source_payload_text"
    ]);
    expect(JSON.stringify(pythonExportTool)).not.toContain("queued");
    expect(JSON.stringify(pythonExportTool)).not.toContain("Send customer context");
    expect(JSON.stringify(pythonExportTool)).not.toContain("httpx.post");
    expect(JSON.stringify(pythonExportTool)).not.toContain("Bearer");
    expect(JSON.stringify(pythonExportTool)).not.toContain("ExportCustomerRecordRequest");
    expect(JSON.stringify(pythonExportTool)).not.toContain("Field(...)");
    expect(JSON.stringify(pythonExportTool)).not.toContain("Reference ID from the support case");
    expect(pythonDeleteTool).toMatchObject({
      path: "mcp-source/python_tools.py",
      actions: ["call", "delete", "read"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false
    });
    expect(pythonDeleteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "python_tool_decorator",
      mcp_source_tool_argument_count: 2,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: true,
      idempotent_hint: false,
      destructive_action: true,
      accepts_path_input: true,
      read_only_hint_conflict: true,
      open_world_schema: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_shell_execution: false,
      handler_tainted_filesystem_path: true,
      tainted_filesystem_path: true,
      handler_filesystem_write: false,
      handler_filesystem_delete: true,
      handler_signal_count: 2
    });
    expect(pythonDeleteTool?.metadata.authority_classes).toEqual([
      "destructive_action",
      "filesystem_access",
      "handler_filesystem_delete",
      "handler_tainted_filesystem_path",
      "tainted_filesystem_path"
    ]);
    expect(pythonDeleteTool?.metadata.handler_authority_classes).toEqual([
      "handler_filesystem_delete",
      "handler_tainted_filesystem_path"
    ]);
    expect(pythonDeleteTool?.metadata.handler_env_key_names).toEqual([]);
    expect(pythonDeleteTool?.metadata.mcp_source_tool_schema_styles).toEqual([
      "mcp_annotations",
      "python_signature"
    ]);
    expect(pythonDeleteTool?.metadata.required_properties).toEqual(["workspace_path"]);
    expect(JSON.stringify(pythonDeleteTool)).not.toContain("shutil.rmtree");
    expect(JSON.stringify(pythonDeleteTool)).not.toContain("os.remove");
    expect(pythonUnsafeDeserializationTool).toMatchObject({
      path: "mcp-source/python_tools.py",
      data_classes: ["unknown"],
      actions: ["call", "execute"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: false
    });
    expect(pythonUnsafeDeserializationTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "python_tool_decorator",
      mcp_source_tool_argument_count: 2,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      read_only_hint: false,
      idempotent_hint: false,
      dynamic_code_execution: false,
      unsafe_deserialization: true,
      external_write: false,
      destructive_action: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: true,
      handler_tainted_deserialization_argument: true,
      tainted_deserialization_argument: true,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_model_visible_output: true,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(pythonUnsafeDeserializationTool?.metadata.authority_classes).toEqual([
      "handler_tainted_deserialization_argument",
      "handler_unsafe_deserialization",
      "tainted_deserialization_argument",
      "unsafe_deserialization"
    ]);
    expect(pythonUnsafeDeserializationTool?.metadata.handler_authority_classes).toEqual([
      "handler_tainted_deserialization_argument",
      "handler_unsafe_deserialization"
    ]);
    expect(pythonUnsafeDeserializationTool?.metadata.handler_env_key_names).toEqual([]);
    expect(pythonUnsafeDeserializationTool?.metadata.schema_properties).toEqual(["encoding", "serialized_payload"]);
    expect(pythonUnsafeDeserializationTool?.metadata.required_properties).toEqual(["serialized_payload"]);
    expect(JSON.stringify(pythonUnsafeDeserializationTool)).not.toContain("pickle.loads");
    expect(JSON.stringify(pythonUnsafeDeserializationTool)).not.toContain("base64.b64decode");
    expect(JSON.stringify(pythonUnsafeDeserializationTool)).not.toContain("loaded state:");
    expect(JSON.stringify(pythonUnsafeDeserializationTool)).not.toContain("Load a serialized agent state snapshot");
    expect(langchainExportTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true
    });
    expect(langchainExportTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 1,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      values_collected: false,
      external_write: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      open_world_schema: false,
      open_world_authority: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: true,
      handler_tainted_network_destination: true,
      handler_external_write: true,
      handler_secret_env_access: true,
      tainted_network_destination: true,
      handler_shell_execution: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4
    });
    expect(langchainExportTool?.metadata.handler_authority_classes).toEqual([
      "handler_external_write",
      "handler_network_access",
      "handler_secret_env_access",
      "handler_tainted_network_destination"
    ]);
    expect(langchainExportTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_EXPORT_TOKEN"]);
    expect(langchainExportTool?.metadata.agent_framework_source_tool_schema_styles).toEqual([
      "agent_framework_source_tool",
      "langchain",
      "pydantic_model",
      "python_signature",
      "python_tool_decorator"
    ]);
    expect(langchainExportTool?.metadata.schema_properties).toEqual([
      "authorization_token",
      "customer_email",
      "customer_reference",
      "destination_webhook_url",
      "source_payload_text"
    ]);
    expect(langchainExportTool?.metadata.required_properties).toEqual([
      "authorization_token",
      "customer_email",
      "customer_reference",
      "destination_webhook_url",
      "source_payload_text"
    ]);
    expect(JSON.stringify(langchainExportTool)).not.toContain("framework queued");
    expect(JSON.stringify(langchainExportTool)).not.toContain("Send customer context to a caller supplied webhook from LangChain");
    expect(JSON.stringify(langchainExportTool)).not.toContain("httpx.post");
    expect(JSON.stringify(langchainExportTool)).not.toContain("Bearer");
    expect(JSON.stringify(langchainExportTool)).not.toContain("LangChainCustomerWebhookRequest");
    expect(JSON.stringify(langchainExportTool)).not.toContain("Caller supplied partner webhook");
    expect(langchainDeleteTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      actions: ["call", "delete", "read"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false
    });
    expect(langchainDeleteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "structured_tool_from_function",
      agent_framework_source_tool_argument_count: 2,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      destructive_action: true,
      accepts_path_input: true,
      open_world_schema: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_shell_execution: false,
      handler_tainted_filesystem_path: true,
      tainted_filesystem_path: true,
      handler_filesystem_write: false,
      handler_filesystem_delete: true,
      handler_signal_count: 2
    });
    expect(langchainDeleteTool?.metadata.authority_classes).toEqual([
      "destructive_action",
      "filesystem_access",
      "handler_filesystem_delete",
      "handler_tainted_filesystem_path",
      "tainted_filesystem_path"
    ]);
    expect(langchainDeleteTool?.metadata.handler_authority_classes).toEqual([
      "handler_filesystem_delete",
      "handler_tainted_filesystem_path"
    ]);
    expect(langchainDeleteTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainDeleteTool?.metadata.agent_framework_source_tool_schema_styles).toEqual([
      "agent_framework_source_tool",
      "langchain",
      "python_signature",
      "structured_tool_from_function"
    ]);
    expect(langchainDeleteTool?.metadata.required_properties).toEqual(["workspace_path"]);
    expect(JSON.stringify(langchainDeleteTool)).not.toContain("framework deleted");
    expect(JSON.stringify(langchainDeleteTool)).not.toContain("Delete a workspace path after model review from LangChain");
    expect(JSON.stringify(langchainDeleteTool)).not.toContain("shutil.rmtree");
    expect(JSON.stringify(langchainDeleteTool)).not.toContain("os.remove");
    expect(langchainShellTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      actions: ["call", "execute", "read"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: false
    });
    expect(langchainShellTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 2,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_path_input: true,
      external_write: false,
      destructive_action: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_shell_execution: true,
      handler_tainted_shell_argument: true,
      tainted_shell_argument: true,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(langchainShellTool?.metadata.authority_classes).toEqual([
      "filesystem_access",
      "handler_shell_execution",
      "handler_tainted_shell_argument",
      "shell_execution",
      "tainted_shell_argument"
    ]);
    expect(langchainShellTool?.metadata.handler_authority_classes).toEqual([
      "handler_shell_execution",
      "handler_tainted_shell_argument"
    ]);
    expect(langchainShellTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainShellTool?.metadata.schema_properties).toEqual(["shell_command", "working_directory"]);
    expect(langchainShellTool?.metadata.required_properties).toEqual(["shell_command"]);
    expect(JSON.stringify(langchainShellTool)).not.toContain("subprocess.run");
    expect(JSON.stringify(langchainShellTool)).not.toContain("shell=True");
    expect(JSON.stringify(langchainShellTool)).not.toContain("framework shell queued");
    expect(langchainToolOutputShellExecutionBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputShellExecutionBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_path_input: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      shell_execution: true,
      tool_output_shell_execution_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_shell_execution: true,
      handler_tool_output_shell_execution_bridge: true,
      handler_secret_env_access: false,
      handler_signal_count: 3,
      open_world_schema: false
    });
    expect(langchainToolOutputShellExecutionBridgeTool?.metadata.authority_classes).toEqual(expect.arrayContaining([
      "handler_shell_execution",
      "handler_tool_invocation",
      "handler_tool_output_shell_execution_bridge",
      "nested_tool_invocation",
      "shell_execution",
      "tool_output_shell_execution_bridge"
    ]));
    expect(langchainToolOutputShellExecutionBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_shell_execution",
      "handler_tool_invocation",
      "handler_tool_output_shell_execution_bridge"
    ]);
    expect(langchainToolOutputShellExecutionBridgeTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainToolOutputShellExecutionBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body",
      "working_directory"
    ]);
    expect(langchainToolOutputShellExecutionBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainToolOutputShellExecutionBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputShellExecutionBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputShellExecutionBridgeTool)).not.toContain("subprocess.run");
    expect(JSON.stringify(langchainToolOutputShellExecutionBridgeTool)).not.toContain("framework tool observation command queued");
    expect(JSON.stringify(langchainToolOutputShellExecutionBridgeTool)).not.toContain("Run a command returned by a caller selected privileged tool observation");
    expect(langchainToolOutputDynamicCodeBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputDynamicCodeBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      dynamic_code_execution: true,
      tool_output_dynamic_code_execution_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_dynamic_code_execution: true,
      handler_tool_output_dynamic_code_execution_bridge: true,
      handler_secret_env_access: false,
      handler_signal_count: 3,
      open_world_schema: false
    });
    expect(langchainToolOutputDynamicCodeBridgeTool?.metadata.authority_classes).toEqual(expect.arrayContaining([
      "dynamic_code_execution",
      "handler_dynamic_code_execution",
      "handler_tool_invocation",
      "handler_tool_output_dynamic_code_execution_bridge",
      "nested_tool_invocation",
      "tool_output_dynamic_code_execution_bridge"
    ]));
    expect(langchainToolOutputDynamicCodeBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_dynamic_code_execution",
      "handler_tool_invocation",
      "handler_tool_output_dynamic_code_execution_bridge"
    ]);
    expect(langchainToolOutputDynamicCodeBridgeTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainToolOutputDynamicCodeBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "execution_reason_text",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(langchainToolOutputDynamicCodeBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "execution_reason_text",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainToolOutputDynamicCodeBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputDynamicCodeBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputDynamicCodeBridgeTool)).not.toContain("exec(");
    expect(JSON.stringify(langchainToolOutputDynamicCodeBridgeTool)).not.toContain("framework tool observation code executed");
    expect(JSON.stringify(langchainToolOutputDynamicCodeBridgeTool)).not.toContain("Execute code returned by a caller selected privileged tool observation");
    expect(langchainFileReadTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["credential"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: false,
      secret_exposure: true,
      reversible: true
    });
    expect(langchainFileReadTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 1,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_path_input: true,
      local_file_disclosure: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_filesystem_read: true,
      handler_tainted_filesystem_path: true,
      tainted_filesystem_path: true,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_model_visible_output: true,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(langchainFileReadTool?.metadata.authority_classes).toEqual([
      "filesystem_access",
      "filesystem_read",
      "handler_filesystem_read",
      "handler_tainted_filesystem_path",
      "local_file_disclosure",
      "tainted_filesystem_path"
    ]);
    expect(langchainFileReadTool?.metadata.handler_authority_classes).toEqual([
      "handler_filesystem_read",
      "handler_tainted_filesystem_path"
    ]);
    expect(langchainFileReadTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainFileReadTool?.metadata.schema_properties).toEqual(["workspace_path"]);
    expect(langchainFileReadTool?.metadata.required_properties).toEqual(["workspace_path"]);
    expect(JSON.stringify(langchainFileReadTool)).not.toContain("Path(workspace_path)");
    expect(JSON.stringify(langchainFileReadTool)).not.toContain("read_text");
    expect(JSON.stringify(langchainFileReadTool)).not.toContain("Read a workspace file by model supplied path");
    expect(langchainNetworkResponseTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["unknown"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: false,
      reversible: false
    });
    expect(langchainNetworkResponseTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 1,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_url_input: true,
      network_response_capture: true,
      external_write: false,
      destructive_action: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: true,
      handler_tainted_network_destination: true,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: true,
      handler_external_write: false,
      handler_secret_env_access: false,
      tainted_network_destination: true,
      handler_model_visible_output: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 3,
      open_world_schema: false
    });
    expect(langchainNetworkResponseTool?.metadata.authority_classes).toEqual([
      "handler_network_access",
      "handler_network_response_to_output",
      "handler_tainted_network_destination",
      "network_access",
      "network_response_capture",
      "tainted_network_destination"
    ]);
    expect(langchainNetworkResponseTool?.metadata.handler_authority_classes).toEqual([
      "handler_network_access",
      "handler_network_response_to_output",
      "handler_tainted_network_destination"
    ]);
    expect(langchainNetworkResponseTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainNetworkResponseTool?.metadata.schema_properties).toEqual(["target_url"]);
    expect(langchainNetworkResponseTool?.metadata.required_properties).toEqual(["target_url"]);
    expect(JSON.stringify(langchainNetworkResponseTool)).not.toContain("httpx.get");
    expect(JSON.stringify(langchainNetworkResponseTool)).not.toContain("response.text");
    expect(JSON.stringify(langchainNetworkResponseTool)).not.toContain("Fetch a caller supplied URL");
    expect(langchainDynamicCodeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["unknown"],
      actions: ["call", "execute"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: false
    });
    expect(langchainDynamicCodeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 2,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      dynamic_code_execution: true,
      external_write: false,
      destructive_action: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: true,
      handler_tainted_dynamic_code_argument: true,
      tainted_dynamic_code_argument: true,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(langchainDynamicCodeTool?.metadata.authority_classes).toEqual([
      "dynamic_code_execution",
      "handler_dynamic_code_execution",
      "handler_tainted_dynamic_code_argument",
      "tainted_dynamic_code_argument"
    ]);
    expect(langchainDynamicCodeTool?.metadata.handler_authority_classes).toEqual([
      "handler_dynamic_code_execution",
      "handler_tainted_dynamic_code_argument"
    ]);
    expect(langchainDynamicCodeTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainDynamicCodeTool?.metadata.schema_properties).toEqual(["context_json", "expression"]);
    expect(langchainDynamicCodeTool?.metadata.required_properties).toEqual(["expression"]);
    expect(JSON.stringify(langchainDynamicCodeTool)).not.toContain("eval(");
    expect(JSON.stringify(langchainDynamicCodeTool)).not.toContain("framework expression evaluated");
    expect(JSON.stringify(langchainDynamicCodeTool)).not.toContain("Evaluate a model supplied Python expression");
    expect(langchainUnsafeDeserializationTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["unknown"],
      actions: ["call", "execute"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: false
    });
    expect(langchainUnsafeDeserializationTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 2,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      dynamic_code_execution: false,
      unsafe_deserialization: true,
      external_write: false,
      destructive_action: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: true,
      handler_tainted_deserialization_argument: true,
      tainted_deserialization_argument: true,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_model_visible_output: true,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(langchainUnsafeDeserializationTool?.metadata.authority_classes).toEqual([
      "handler_tainted_deserialization_argument",
      "handler_unsafe_deserialization",
      "tainted_deserialization_argument",
      "unsafe_deserialization"
    ]);
    expect(langchainUnsafeDeserializationTool?.metadata.handler_authority_classes).toEqual([
      "handler_tainted_deserialization_argument",
      "handler_unsafe_deserialization"
    ]);
    expect(langchainUnsafeDeserializationTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainUnsafeDeserializationTool?.metadata.schema_properties).toEqual([
      "payload_format",
      "serialized_payload"
    ]);
    expect(langchainUnsafeDeserializationTool?.metadata.required_properties).toEqual(["serialized_payload"]);
    expect(JSON.stringify(langchainUnsafeDeserializationTool)).not.toContain("yaml.load");
    expect(JSON.stringify(langchainUnsafeDeserializationTool)).not.toContain("yaml.Loader");
    expect(JSON.stringify(langchainUnsafeDeserializationTool)).not.toContain("framework state loaded");
    expect(JSON.stringify(langchainUnsafeDeserializationTool)).not.toContain("Load a serialized agent state document");
    expect(langchainDatabaseTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "pii"],
      actions: ["call", "execute", "write"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: false
    });
    expect(langchainDatabaseTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 2,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      database_access: true,
      database_write: true,
      tainted_database_query_argument: true,
      external_write: false,
      destructive_action: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_database_query: true,
      handler_database_write: true,
      handler_tainted_database_query_argument: true,
      handler_shell_execution: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 3,
      open_world_schema: false
    });
    expect(langchainDatabaseTool?.metadata.authority_classes).toEqual([
      "customer_data_input",
      "database_access",
      "database_write",
      "handler_database_query",
      "handler_database_write",
      "handler_tainted_database_query_argument",
      "pii_input",
      "tainted_database_query_argument"
    ]);
    expect(langchainDatabaseTool?.metadata.handler_authority_classes).toEqual([
      "handler_database_query",
      "handler_database_write",
      "handler_tainted_database_query_argument"
    ]);
    expect(langchainDatabaseTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainDatabaseTool?.metadata.schema_properties).toEqual(["customer_id", "sql_query"]);
    expect(langchainDatabaseTool?.metadata.required_properties).toEqual(["customer_id", "sql_query"]);
    expect(JSON.stringify(langchainDatabaseTool)).not.toContain("db.execute");
    expect(JSON.stringify(langchainDatabaseTool)).not.toContain("UPDATE support_cases");
    expect(JSON.stringify(langchainDatabaseTool)).not.toContain("framework database updated");
    expect(JSON.stringify(langchainDatabaseTool)).not.toContain("Update customer support records from LangChain SQL");
    expect(langchainToolOutputDatabaseWriteBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "pii"],
      actions: ["call", "execute", "remember", "write"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: false
    });
    expect(langchainToolOutputDatabaseWriteBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      database_access: true,
      database_write: true,
      tainted_database_query_argument: false,
      tool_output_database_write_bridge: true,
      nested_tool_invocation: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_database_query: true,
      handler_database_write: true,
      handler_tainted_database_query_argument: false,
      handler_tool_output_database_write_bridge: true,
      handler_tool_invocation: true,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainToolOutputDatabaseWriteBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "database_access",
      "database_write",
      "handler_database_query",
      "handler_database_write",
      "handler_tool_invocation",
      "handler_tool_output_database_write_bridge",
      "memory_access",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "tool_output_database_write_bridge"
    ]);
    expect(langchainToolOutputDatabaseWriteBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_database_query",
      "handler_database_write",
      "handler_tool_invocation",
      "handler_tool_output_database_write_bridge"
    ]);
    expect(langchainToolOutputDatabaseWriteBridgeTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainToolOutputDatabaseWriteBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(langchainToolOutputDatabaseWriteBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainToolOutputDatabaseWriteBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputDatabaseWriteBridgeTool)).not.toContain("db.execute");
    expect(JSON.stringify(langchainToolOutputDatabaseWriteBridgeTool)).not.toContain("UPDATE support_cases");
    expect(JSON.stringify(langchainToolOutputDatabaseWriteBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputDatabaseWriteBridgeTool)).not.toContain("framework tool observation stored in database");
    expect(JSON.stringify(langchainToolOutputDatabaseWriteBridgeTool)).not.toContain("Store a raw privileged tool observation");
    expect(langchainSecretOutputTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential"],
      actions: ["call", "send"],
      side_effect: true,
      external_reach: false,
      secret_exposure: true,
      reversible: true
    });
    expect(langchainSecretOutputTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 2,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: true,
      handler_database_query: false,
      handler_database_write: false,
      handler_shell_execution: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(langchainSecretOutputTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_secret_env_access",
      "handler_secret_to_output",
      "secret_env_access",
      "secret_materialization"
    ]);
    expect(langchainSecretOutputTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_secret_to_output"
    ]);
    expect(langchainSecretOutputTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_RUNTIME_SECRET"]);
    expect(langchainSecretOutputTool?.metadata.schema_properties).toEqual(["requester_ticket", "secret_purpose"]);
    expect(langchainSecretOutputTool?.metadata.required_properties).toEqual(["requester_ticket", "secret_purpose"]);
    expect(JSON.stringify(langchainSecretOutputTool)).not.toContain("runtime secret:");
    expect(JSON.stringify(langchainSecretOutputTool)).not.toContain("Return a runtime support token");
    expect(langchainCredentialedNetworkTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential"],
      actions: ["call", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainCredentialedNetworkTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 2,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_url_input: true,
      accepts_customer_data_input: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: true,
      handler_tainted_network_destination: true,
      handler_credentialed_network_read: true,
      handler_external_write: false,
      handler_secret_env_access: true,
      tainted_network_destination: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_shell_execution: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainCredentialedNetworkTool?.metadata.authority_classes).toEqual([
      "credentialed_network_read",
      "customer_data_input",
      "handler_credentialed_network_read",
      "handler_network_access",
      "handler_secret_env_access",
      "handler_tainted_network_destination",
      "network_access",
      "secret_env_access",
      "tainted_network_destination"
    ]);
    expect(langchainCredentialedNetworkTool?.metadata.handler_authority_classes).toEqual([
      "handler_credentialed_network_read",
      "handler_network_access",
      "handler_secret_env_access",
      "handler_tainted_network_destination"
    ]);
    expect(langchainCredentialedNetworkTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_PARTNER_STATUS_TOKEN"]);
    expect(langchainCredentialedNetworkTool?.metadata.schema_properties).toEqual([
      "customer_reference",
      "status_endpoint_url"
    ]);
    expect(langchainCredentialedNetworkTool?.metadata.required_properties).toEqual([
      "customer_reference",
      "status_endpoint_url"
    ]);
    expect(JSON.stringify(langchainCredentialedNetworkTool)).not.toContain("httpx.get");
    expect(JSON.stringify(langchainCredentialedNetworkTool)).not.toContain("framework partner status checked");
    expect(JSON.stringify(langchainCredentialedNetworkTool)).not.toContain("Fetch partner status from a caller supplied endpoint");
    expect(langchainMemoryWriteTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainMemoryWriteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: true,
      tainted_memory_scope: true,
      embedding_provider_call: true,
      tainted_embedding_input: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: true,
      handler_tainted_embedding_input: true,
      handler_memory_write: true,
      handler_tainted_memory_scope: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(langchainMemoryWriteTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "embedding_provider_call",
      "handler_embedding_provider_call",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tainted_embedding_input",
      "handler_tainted_memory_scope",
      "memory_access",
      "memory_write",
      "pii_input",
      "secret_env_access",
      "tainted_embedding_input",
      "tainted_memory_scope"
    ]);
    expect(langchainMemoryWriteTool?.metadata.handler_authority_classes).toEqual([
      "handler_embedding_provider_call",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tainted_embedding_input",
      "handler_tainted_memory_scope"
    ]);
    expect(langchainMemoryWriteTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_EMBEDDING_TOKEN"]);
    expect(langchainMemoryWriteTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "memory_namespace",
      "ticket_text"
    ]);
    expect(langchainMemoryWriteTool?.metadata.required_properties).toEqual(["customer_id", "ticket_text"]);
    expect(JSON.stringify(langchainMemoryWriteTool)).not.toContain("memory_store.upsert");
    expect(JSON.stringify(langchainMemoryWriteTool)).not.toContain("embedding_client.embed_documents");
    expect(JSON.stringify(langchainMemoryWriteTool)).not.toContain("framework memory persisted");
    expect(JSON.stringify(langchainMemoryWriteTool)).not.toContain("Persist caller supplied customer ticket text");
    expect(langchainRagRetrievalTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainRagRetrievalTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      rag_retrieval: true,
      tainted_rag_retrieval_query: true,
      rag_context_to_output: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_model_provider_call: false,
      handler_rag_retrieval: true,
      handler_tainted_rag_retrieval_query: true,
      handler_rag_context_to_output: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: false,
      handler_memory_write: false,
      handler_tool_invocation: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainRagRetrievalTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_rag_context_to_output",
      "handler_rag_retrieval",
      "handler_secret_env_access",
      "handler_tainted_rag_retrieval_query",
      "pii_input",
      "rag_context_to_output",
      "rag_retrieval",
      "secret_env_access",
      "tainted_rag_retrieval_query"
    ]);
    expect(langchainRagRetrievalTool?.metadata.handler_authority_classes).toEqual([
      "handler_rag_context_to_output",
      "handler_rag_retrieval",
      "handler_secret_env_access",
      "handler_tainted_rag_retrieval_query"
    ]);
    expect(langchainRagRetrievalTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_RAG_RETRIEVAL_TOKEN"]);
    expect(langchainRagRetrievalTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "retrieval_namespace",
      "retrieval_query_text",
      "top_k"
    ]);
    expect(langchainRagRetrievalTool?.metadata.required_properties).toEqual([
      "customer_id",
      "retrieval_namespace",
      "retrieval_query_text"
    ]);
    expect(JSON.stringify(langchainRagRetrievalTool)).not.toContain("vector_retriever.search");
    expect(JSON.stringify(langchainRagRetrievalTool)).not.toContain("retrieved_context");
    expect(JSON.stringify(langchainRagRetrievalTool)).not.toContain("Retrieve caller selected support context");
    expect(langchainRagRetrievalMemoryBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainRagRetrievalMemoryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      rag_retrieval: true,
      tainted_rag_retrieval_query: true,
      rag_context_to_output: false,
      memory_write: true,
      tainted_memory_scope: true,
      rag_retrieval_memory_bridge: true,
      handler_rag_retrieval: true,
      handler_tainted_rag_retrieval_query: true,
      handler_rag_context_to_output: false,
      handler_memory_write: true,
      handler_tainted_memory_scope: true,
      handler_rag_retrieval_memory_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainRagRetrievalMemoryBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_memory_write",
      "handler_rag_retrieval",
      "handler_rag_retrieval_memory_bridge",
      "handler_secret_env_access",
      "handler_tainted_memory_scope",
      "handler_tainted_rag_retrieval_query",
      "memory_access",
      "memory_write",
      "pii_input",
      "rag_retrieval",
      "rag_retrieval_memory_bridge",
      "secret_env_access",
      "tainted_memory_scope",
      "tainted_rag_retrieval_query"
    ]);
    expect(langchainRagRetrievalMemoryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_memory_write",
      "handler_rag_retrieval",
      "handler_rag_retrieval_memory_bridge",
      "handler_secret_env_access",
      "handler_tainted_memory_scope",
      "handler_tainted_rag_retrieval_query"
    ]);
    expect(langchainRagRetrievalMemoryBridgeTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_RAG_MEMORY_BRIDGE_TOKEN"]);
    expect(langchainRagRetrievalMemoryBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "memory_namespace",
      "retention_note_text",
      "retrieval_namespace",
      "retrieval_query_text"
    ]);
    expect(JSON.stringify(langchainRagRetrievalMemoryBridgeTool)).not.toContain("vector_retriever.search");
    expect(JSON.stringify(langchainRagRetrievalMemoryBridgeTool)).not.toContain("memory_store.upsert");
    expect(JSON.stringify(langchainRagRetrievalMemoryBridgeTool)).not.toContain("retrieved_chunks");
    expect(JSON.stringify(langchainRagRetrievalMemoryBridgeTool)).not.toContain("framework retrieved context remembered");
    expect(JSON.stringify(langchainRagRetrievalMemoryBridgeTool)).not.toContain("Persist caller selected retrieved support context");
    expect(langchainRagRetrievalPromptBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainRagRetrievalPromptBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      rag_retrieval: true,
      tainted_rag_retrieval_query: true,
      model_provider_call: true,
      rag_retrieval_prompt_bridge: true,
      handler_rag_retrieval: true,
      handler_tainted_rag_retrieval_query: true,
      handler_model_provider_call: true,
      handler_rag_retrieval_prompt_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(langchainRagRetrievalPromptBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_model_provider_call",
      "handler_rag_retrieval",
      "handler_rag_retrieval_prompt_bridge",
      "handler_secret_env_access",
      "handler_tainted_rag_retrieval_query",
      "model_provider_call",
      "pii_input",
      "rag_retrieval",
      "rag_retrieval_prompt_bridge",
      "secret_env_access",
      "tainted_rag_retrieval_query"
    ]);
    expect(langchainRagRetrievalPromptBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_model_provider_call",
      "handler_rag_retrieval",
      "handler_rag_retrieval_prompt_bridge",
      "handler_secret_env_access",
      "handler_tainted_rag_retrieval_query"
    ]);
    expect(langchainRagRetrievalPromptBridgeTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_RAG_PROMPT_BRIDGE_TOKEN"]);
    expect(langchainRagRetrievalPromptBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "retrieval_namespace",
      "retrieval_query_text",
      "summary_instruction_text"
    ]);
    expect(JSON.stringify(langchainRagRetrievalPromptBridgeTool)).not.toContain("vector_retriever.search");
    expect(JSON.stringify(langchainRagRetrievalPromptBridgeTool)).not.toContain("openai_client.chat.completions.create");
    expect(JSON.stringify(langchainRagRetrievalPromptBridgeTool)).not.toContain("retrieved_chunks");
    expect(JSON.stringify(langchainRagRetrievalPromptBridgeTool)).not.toContain("Summarize retrieved support context");
    expect(JSON.stringify(langchainRagRetrievalPromptBridgeTool)).not.toContain("Retrieve caller selected support context");
    expect(langchainRagRetrievalExternalServiceBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainRagRetrievalExternalServiceBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      external_service_write: true,
      tainted_external_service_recipient: true,
      rag_retrieval: true,
      tainted_rag_retrieval_query: true,
      rag_retrieval_external_service_bridge: true,
      handler_external_service_write: true,
      handler_tainted_external_service_recipient: true,
      handler_rag_retrieval: true,
      handler_tainted_rag_retrieval_query: true,
      handler_rag_retrieval_external_service_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainRagRetrievalExternalServiceBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_service_write",
      "external_write",
      "handler_external_service_write",
      "handler_rag_retrieval",
      "handler_rag_retrieval_external_service_bridge",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient",
      "handler_tainted_rag_retrieval_query",
      "pii_input",
      "rag_retrieval",
      "rag_retrieval_external_service_bridge",
      "secret_env_access",
      "tainted_external_service_recipient",
      "tainted_rag_retrieval_query"
    ]);
    expect(langchainRagRetrievalExternalServiceBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_external_service_write",
      "handler_rag_retrieval",
      "handler_rag_retrieval_external_service_bridge",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient",
      "handler_tainted_rag_retrieval_query"
    ]);
    expect(langchainRagRetrievalExternalServiceBridgeTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_RAG_EXTERNAL_BRIDGE_TOKEN"]);
    expect(langchainRagRetrievalExternalServiceBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "destination_channel_id",
      "escalation_note_text",
      "retrieval_namespace",
      "retrieval_query_text"
    ]);
    expect(JSON.stringify(langchainRagRetrievalExternalServiceBridgeTool)).not.toContain("vector_retriever.search");
    expect(JSON.stringify(langchainRagRetrievalExternalServiceBridgeTool)).not.toContain("slack_client.chat_postMessage");
    expect(JSON.stringify(langchainRagRetrievalExternalServiceBridgeTool)).not.toContain("retrieved_chunks");
    expect(JSON.stringify(langchainRagRetrievalExternalServiceBridgeTool)).not.toContain("framework retrieved context posted externally");
    expect(JSON.stringify(langchainRagRetrievalExternalServiceBridgeTool)).not.toContain("Post caller selected retrieved support context");
    expect(langchainRagRetrievalBrowserAutomationBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainRagRetrievalBrowserAutomationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 6,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      rag_retrieval: true,
      tainted_rag_retrieval_query: true,
      rag_retrieval_browser_automation_bridge: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_rag_retrieval: true,
      handler_tainted_rag_retrieval_query: true,
      handler_rag_retrieval_browser_automation_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainRagRetrievalBrowserAutomationBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_browser_automation",
      "handler_rag_retrieval",
      "handler_rag_retrieval_browser_automation_bridge",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_rag_retrieval_query",
      "network_access",
      "pii_input",
      "rag_retrieval",
      "rag_retrieval_browser_automation_bridge",
      "secret_env_access",
      "tainted_browser_automation_target",
      "tainted_rag_retrieval_query"
    ]);
    expect(langchainRagRetrievalBrowserAutomationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_rag_retrieval",
      "handler_rag_retrieval_browser_automation_bridge",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_rag_retrieval_query"
    ]);
    expect(langchainRagRetrievalBrowserAutomationBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_RAG_BROWSER_BRIDGE_TOKEN"
    ]);
    expect(langchainRagRetrievalBrowserAutomationBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "form_selector",
      "retrieval_namespace",
      "retrieval_query_text",
      "submit_selector",
      "target_url"
    ]);
    expect(langchainRagRetrievalBrowserAutomationBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "form_selector",
      "retrieval_namespace",
      "retrieval_query_text",
      "submit_selector",
      "target_url"
    ]);
    expect(JSON.stringify(langchainRagRetrievalBrowserAutomationBridgeTool)).not.toContain("vector_retriever.search");
    expect(JSON.stringify(langchainRagRetrievalBrowserAutomationBridgeTool)).not.toContain("authenticated_browser_page.goto");
    expect(JSON.stringify(langchainRagRetrievalBrowserAutomationBridgeTool)).not.toContain("authenticated_browser_page.fill");
    expect(JSON.stringify(langchainRagRetrievalBrowserAutomationBridgeTool)).not.toContain("authenticated_browser_page.click");
    expect(JSON.stringify(langchainRagRetrievalBrowserAutomationBridgeTool)).not.toContain("retrieved_chunks");
    expect(JSON.stringify(langchainRagRetrievalBrowserAutomationBridgeTool)).not.toContain("framework retrieved context submitted through browser");
    expect(JSON.stringify(langchainRagRetrievalBrowserAutomationBridgeTool)).not.toContain("Submit caller selected retrieved support context");
    expect(langchainTaskQueueTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainTaskQueueTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      task_queue_enqueue: true,
      tainted_task_payload: true,
      tainted_task_routing: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_model_provider_call: false,
      handler_task_queue_enqueue: true,
      handler_tainted_task_payload: true,
      handler_tainted_task_routing: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: false,
      handler_memory_write: false,
      handler_tool_invocation: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainTaskQueueTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_secret_env_access",
      "handler_tainted_task_payload",
      "handler_tainted_task_routing",
      "handler_task_queue_enqueue",
      "pii_input",
      "secret_env_access",
      "tainted_task_payload",
      "tainted_task_routing",
      "task_queue_enqueue"
    ]);
    expect(langchainTaskQueueTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_tainted_task_payload",
      "handler_tainted_task_routing",
      "handler_task_queue_enqueue"
    ]);
    expect(langchainTaskQueueTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_AGENT_TASK_QUEUE_TOKEN"]);
    expect(langchainTaskQueueTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "target_queue_name",
      "task_route"
    ]);
    expect(langchainTaskQueueTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "target_queue_name",
      "task_route"
    ]);
    expect(JSON.stringify(langchainTaskQueueTool)).not.toContain("task_queue_client.enqueue");
    expect(JSON.stringify(langchainTaskQueueTool)).not.toContain("requested_action");
    expect(JSON.stringify(langchainTaskQueueTool)).not.toContain("update_customer_record");
    expect(JSON.stringify(langchainTaskQueueTool)).not.toContain("framework agent job queued");
    expect(JSON.stringify(langchainTaskQueueTool)).not.toContain("Queue a caller supplied support job");
    expect(langchainSecretManagerTaskQueueBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerTaskQueueBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      task_queue_enqueue: true,
      tainted_task_payload: true,
      tainted_task_routing: true,
      secret_manager_task_queue_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_task_queue_enqueue: true,
      handler_tainted_task_payload: true,
      handler_tainted_task_routing: true,
      handler_secret_manager_task_queue_bridge: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(langchainSecretManagerTaskQueueBridgeTool?.metadata.authority_classes).toContain("secret_manager_task_queue_bridge");
    expect(langchainSecretManagerTaskQueueBridgeTool?.metadata.handler_authority_classes).toContain("handler_secret_manager_task_queue_bridge");
    expect(langchainSecretManagerTaskQueueBridgeTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_SECRET_TASK_QUEUE_TOKEN"]);
    expect(langchainSecretManagerTaskQueueBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "replay_on_failure",
      "requester_ticket",
      "secret_path",
      "target_queue_name",
      "task_route"
    ]);
    expect(JSON.stringify(langchainSecretManagerTaskQueueBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerTaskQueueBridgeTool)).not.toContain("task_queue_client.enqueue");
    expect(JSON.stringify(langchainSecretManagerTaskQueueBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerTaskQueueBridgeTool)).not.toContain("secret_queue_value");
    expect(JSON.stringify(langchainSecretManagerTaskQueueBridgeTool)).not.toContain("framework vault secret queued for background agent");
    expect(JSON.stringify(langchainSecretManagerTaskQueueBridgeTool)).not.toContain("Enqueue a customer support secret");
    expect(langchainTelemetryExportTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainTelemetryExportTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      telemetry_export: true,
      tainted_telemetry_payload: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: false,
      handler_memory_write: false,
      handler_telemetry_export: true,
      handler_tainted_telemetry_payload: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 3,
      open_world_schema: false
    });
    expect(langchainTelemetryExportTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_secret_env_access",
      "handler_tainted_telemetry_payload",
      "handler_telemetry_export",
      "pii_input",
      "secret_env_access",
      "tainted_telemetry_payload",
      "telemetry_export"
    ]);
    expect(langchainTelemetryExportTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_tainted_telemetry_payload",
      "handler_telemetry_export"
    ]);
    expect(langchainTelemetryExportTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_TRACE_EXPORT_TOKEN"]);
    expect(langchainTelemetryExportTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "tool_trace_payload",
      "trace_session_id"
    ]);
    expect(langchainTelemetryExportTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "tool_trace_payload",
      "trace_session_id"
    ]);
    expect(JSON.stringify(langchainTelemetryExportTool)).not.toContain("telemetry_client.record_trace");
    expect(JSON.stringify(langchainTelemetryExportTool)).not.toContain("framework trace exported");
    expect(JSON.stringify(langchainTelemetryExportTool)).not.toContain("Export caller supplied customer trace context");
    expect(langchainPromptCacheWriteTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "remember", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainPromptCacheWriteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      prompt_cache_write: true,
      tainted_prompt_cache_key: true,
      tainted_prompt_cache_value: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: false,
      handler_memory_write: false,
      handler_telemetry_export: false,
      handler_prompt_cache_write: true,
      handler_tainted_prompt_cache_key: true,
      handler_tainted_prompt_cache_value: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainPromptCacheWriteTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_cache_key",
      "handler_tainted_prompt_cache_value",
      "pii_input",
      "prompt_cache_write",
      "secret_env_access",
      "tainted_prompt_cache_key",
      "tainted_prompt_cache_value"
    ]);
    expect(langchainPromptCacheWriteTool?.metadata.handler_authority_classes).toEqual([
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_cache_key",
      "handler_tainted_prompt_cache_value"
    ]);
    expect(langchainPromptCacheWriteTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_PROMPT_CACHE_TOKEN"]);
    expect(langchainPromptCacheWriteTool?.metadata.schema_properties).toEqual([
      "cache_key",
      "customer_id",
      "customer_ticket_text",
      "tool_output_text"
    ]);
    expect(langchainPromptCacheWriteTool?.metadata.required_properties).toEqual([
      "cache_key",
      "customer_id",
      "customer_ticket_text",
      "tool_output_text"
    ]);
    expect(JSON.stringify(langchainPromptCacheWriteTool)).not.toContain("prompt_cache.set");
    expect(JSON.stringify(langchainPromptCacheWriteTool)).not.toContain("framework prompt cache written");
    expect(JSON.stringify(langchainPromptCacheWriteTool)).not.toContain("Write caller supplied prompt context");
    expect(langchainTrainingDatasetExportTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainTrainingDatasetExportTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      training_dataset_export: true,
      tainted_training_dataset_payload: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: false,
      handler_memory_write: false,
      handler_telemetry_export: false,
      handler_prompt_cache_write: false,
      handler_training_dataset_export: true,
      handler_tainted_training_dataset_payload: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 3,
      open_world_schema: false
    });
    expect(langchainTrainingDatasetExportTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_secret_env_access",
      "handler_tainted_training_dataset_payload",
      "handler_training_dataset_export",
      "pii_input",
      "secret_env_access",
      "tainted_training_dataset_payload",
      "training_dataset_export"
    ]);
    expect(langchainTrainingDatasetExportTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_tainted_training_dataset_payload",
      "handler_training_dataset_export"
    ]);
    expect(langchainTrainingDatasetExportTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TRAINING_DATASET_TOKEN"
    ]);
    expect(langchainTrainingDatasetExportTool?.metadata.schema_properties).toEqual([
      "completion_text",
      "customer_id",
      "customer_ticket_text",
      "dataset_id",
      "tool_output_text"
    ]);
    expect(langchainTrainingDatasetExportTool?.metadata.required_properties).toEqual([
      "completion_text",
      "customer_id",
      "customer_ticket_text",
      "dataset_id",
      "tool_output_text"
    ]);
    expect(JSON.stringify(langchainTrainingDatasetExportTool)).not.toContain("training_dataset_client.append_record");
    expect(JSON.stringify(langchainTrainingDatasetExportTool)).not.toContain("framework training record exported");
    expect(JSON.stringify(langchainTrainingDatasetExportTool)).not.toContain("Export caller supplied support context");
    expect(langchainFeedbackAutoPromotionTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainFeedbackAutoPromotionTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 12,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      training_dataset_export: false,
      tainted_training_dataset_payload: false,
      feedback_pipeline_write: true,
      tainted_feedback_payload: true,
      feedback_auto_promotion: true,
      tainted_feedback_routing: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: false,
      handler_memory_write: false,
      handler_telemetry_export: false,
      handler_prompt_cache_write: false,
      handler_training_dataset_export: false,
      handler_tainted_training_dataset_payload: false,
      handler_feedback_pipeline_write: true,
      handler_tainted_feedback_payload: true,
      handler_feedback_auto_promotion: true,
      handler_tainted_feedback_routing: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(langchainFeedbackAutoPromotionTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "feedback_auto_promotion",
      "feedback_pipeline_write",
      "handler_feedback_auto_promotion",
      "handler_feedback_pipeline_write",
      "handler_secret_env_access",
      "handler_tainted_feedback_payload",
      "handler_tainted_feedback_routing",
      "memory_access",
      "pii_input",
      "secret_env_access",
      "tainted_feedback_payload",
      "tainted_feedback_routing"
    ]);
    expect(langchainFeedbackAutoPromotionTool?.metadata.handler_authority_classes).toEqual([
      "handler_feedback_auto_promotion",
      "handler_feedback_pipeline_write",
      "handler_secret_env_access",
      "handler_tainted_feedback_payload",
      "handler_tainted_feedback_routing"
    ]);
    expect(langchainFeedbackAutoPromotionTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_FEEDBACK_PIPELINE_TOKEN"
    ]);
    expect(langchainFeedbackAutoPromotionTool?.metadata.schema_properties).toEqual([
      "completion_text",
      "customer_email",
      "customer_feedback_text",
      "customer_id",
      "eval_set_id",
      "feedback_dataset_id",
      "memory_context",
      "promotion_target",
      "prompt_text",
      "rating_value",
      "retrieval_context",
      "tool_trace_payload"
    ]);
    expect(langchainFeedbackAutoPromotionTool?.metadata.required_properties).toEqual([
      "completion_text",
      "customer_email",
      "customer_feedback_text",
      "customer_id",
      "eval_set_id",
      "feedback_dataset_id",
      "memory_context",
      "promotion_target",
      "prompt_text",
      "rating_value",
      "retrieval_context",
      "tool_trace_payload"
    ]);
    expect(JSON.stringify(langchainFeedbackAutoPromotionTool)).not.toContain("feedback_pipeline.promote_to_training");
    expect(JSON.stringify(langchainFeedbackAutoPromotionTool)).not.toContain("framework feedback promoted");
    expect(JSON.stringify(langchainFeedbackAutoPromotionTool)).not.toContain("Record caller supplied feedback");
    expect(langchainSafetyPolicyWeakeningTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSafetyPolicyWeakeningTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 7,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      feedback_pipeline_write: false,
      tainted_feedback_payload: false,
      safety_policy_write: true,
      tainted_safety_policy_payload: true,
      tainted_safety_policy_selector: true,
      safety_policy_weakening: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_safety_policy_write: true,
      handler_tainted_safety_policy_payload: true,
      handler_tainted_safety_policy_selector: true,
      handler_safety_policy_weakening: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(langchainSafetyPolicyWeakeningTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_safety_policy_weakening",
      "handler_safety_policy_write",
      "handler_secret_env_access",
      "handler_tainted_safety_policy_payload",
      "handler_tainted_safety_policy_selector",
      "pii_input",
      "safety_policy_weakening",
      "safety_policy_write",
      "secret_env_access",
      "tainted_safety_policy_payload",
      "tainted_safety_policy_selector"
    ]);
    expect(langchainSafetyPolicyWeakeningTool?.metadata.handler_authority_classes).toEqual([
      "handler_safety_policy_weakening",
      "handler_safety_policy_write",
      "handler_secret_env_access",
      "handler_tainted_safety_policy_payload",
      "handler_tainted_safety_policy_selector"
    ]);
    expect(langchainSafetyPolicyWeakeningTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_GUARDRAIL_POLICY_TOKEN"
    ]);
    expect(langchainSafetyPolicyWeakeningTool?.metadata.schema_properties).toEqual([
      "approval_profile",
      "control_id",
      "customer_email",
      "customer_id",
      "customer_ticket_text",
      "policy_mode",
      "policy_patch_text"
    ]);
    expect(langchainSafetyPolicyWeakeningTool?.metadata.required_properties).toEqual([
      "approval_profile",
      "control_id",
      "customer_email",
      "customer_id",
      "customer_ticket_text",
      "policy_mode",
      "policy_patch_text"
    ]);
    expect(JSON.stringify(langchainSafetyPolicyWeakeningTool)).not.toContain("guardrail_policy_client.update_policy");
    expect(JSON.stringify(langchainSafetyPolicyWeakeningTool)).not.toContain("framework guardrail policy updated");
    expect(JSON.stringify(langchainSafetyPolicyWeakeningTool)).not.toContain("Update caller selected guardrail policy");
    expect(langchainToolOutputSafetyPolicyBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputSafetyPolicyBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 8,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      safety_policy_write: true,
      tainted_safety_policy_payload: true,
      tainted_safety_policy_selector: true,
      safety_policy_weakening: true,
      tool_output_safety_policy_bridge: true,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_safety_policy_write: true,
      handler_tainted_safety_policy_payload: true,
      handler_tainted_safety_policy_selector: true,
      handler_safety_policy_weakening: true,
      handler_tool_output_safety_policy_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(langchainToolOutputSafetyPolicyBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_safety_policy_weakening",
      "handler_safety_policy_write",
      "handler_secret_env_access",
      "handler_tainted_safety_policy_payload",
      "handler_tainted_safety_policy_selector",
      "handler_tool_invocation",
      "handler_tool_output_safety_policy_bridge",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "safety_policy_weakening",
      "safety_policy_write",
      "secret_env_access",
      "tainted_safety_policy_payload",
      "tainted_safety_policy_selector",
      "tool_output_safety_policy_bridge"
    ]);
    expect(langchainToolOutputSafetyPolicyBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_safety_policy_weakening",
      "handler_safety_policy_write",
      "handler_secret_env_access",
      "handler_tainted_safety_policy_payload",
      "handler_tainted_safety_policy_selector",
      "handler_tool_invocation",
      "handler_tool_output_safety_policy_bridge"
    ]);
    expect(langchainToolOutputSafetyPolicyBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TOOL_OBSERVATION_SAFETY_POLICY_TOKEN"
    ]);
    expect(langchainToolOutputSafetyPolicyBridgeTool?.metadata.schema_properties).toEqual([
      "customer_email",
      "customer_id",
      "override_reason",
      "policy_id",
      "policy_mode",
      "target_control_id",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(langchainToolOutputSafetyPolicyBridgeTool?.metadata.required_properties).toEqual([
      "customer_email",
      "customer_id",
      "override_reason",
      "policy_id",
      "policy_mode",
      "target_control_id",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainToolOutputSafetyPolicyBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputSafetyPolicyBridgeTool)).not.toContain("guardrail_policy_client.update_policy");
    expect(JSON.stringify(langchainToolOutputSafetyPolicyBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputSafetyPolicyBridgeTool)).not.toContain("framework tool observation updated safety policy");
    expect(JSON.stringify(langchainToolOutputSafetyPolicyBridgeTool)).not.toContain("Apply a raw privileged tool observation");
    expect(langchainSecretManagerSafetyPolicyBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerSafetyPolicyBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 7,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      safety_policy_write: true,
      tainted_safety_policy_payload: true,
      tainted_safety_policy_selector: true,
      safety_policy_weakening: true,
      secret_manager_safety_policy_bridge: true,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_safety_policy_write: true,
      handler_tainted_safety_policy_payload: true,
      handler_tainted_safety_policy_selector: true,
      handler_safety_policy_weakening: true,
      handler_secret_manager_safety_policy_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 8,
      open_world_schema: false
    });
    expect(langchainSecretManagerSafetyPolicyBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "filesystem_access",
      "handler_safety_policy_weakening",
      "handler_safety_policy_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_safety_policy_bridge",
      "handler_tainted_safety_policy_payload",
      "handler_tainted_safety_policy_selector",
      "handler_tainted_secret_manager_path",
      "pii_input",
      "safety_policy_weakening",
      "safety_policy_write",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_safety_policy_bridge",
      "tainted_safety_policy_payload",
      "tainted_safety_policy_selector",
      "tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerSafetyPolicyBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_safety_policy_weakening",
      "handler_safety_policy_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_safety_policy_bridge",
      "handler_tainted_safety_policy_payload",
      "handler_tainted_safety_policy_selector",
      "handler_tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerSafetyPolicyBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_VAULT_SECRET_SAFETY_POLICY_TOKEN"
    ]);
    expect(langchainSecretManagerSafetyPolicyBridgeTool?.metadata.schema_properties).toEqual([
      "customer_email",
      "customer_id",
      "override_reason",
      "policy_id",
      "policy_mode",
      "target_control_id",
      "vault_secret_path"
    ]);
    expect(langchainSecretManagerSafetyPolicyBridgeTool?.metadata.required_properties).toEqual([
      "customer_email",
      "customer_id",
      "override_reason",
      "policy_id",
      "policy_mode",
      "target_control_id",
      "vault_secret_path"
    ]);
    expect(JSON.stringify(langchainSecretManagerSafetyPolicyBridgeTool)).not.toContain("vault_client.get_secret");
    expect(JSON.stringify(langchainSecretManagerSafetyPolicyBridgeTool)).not.toContain("guardrail_policy_client.update_policy");
    expect(JSON.stringify(langchainSecretManagerSafetyPolicyBridgeTool)).not.toContain("secret_policy_value");
    expect(JSON.stringify(langchainSecretManagerSafetyPolicyBridgeTool)).not.toContain("framework vault secret updated safety policy");
    expect(JSON.stringify(langchainSecretManagerSafetyPolicyBridgeTool)).not.toContain("Apply a customer vault secret");
    expect(langchainAuthorizationGrantTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainAuthorizationGrantTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 7,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      authorization_policy_write: true,
      tainted_authorization_grant_input: true,
      authorization_broad_grant: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_authorization_policy_write: true,
      handler_tainted_authorization_grant_input: true,
      handler_authorization_broad_grant: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainAuthorizationGrantTool?.metadata.authority_classes).toEqual([
      "authorization_broad_grant",
      "authorization_policy_write",
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_authorization_broad_grant",
      "handler_authorization_policy_write",
      "handler_secret_env_access",
      "handler_tainted_authorization_grant_input",
      "pii_input",
      "secret_env_access",
      "tainted_authorization_grant_input"
    ]);
    expect(langchainAuthorizationGrantTool?.metadata.handler_authority_classes).toEqual([
      "handler_authorization_broad_grant",
      "handler_authorization_policy_write",
      "handler_secret_env_access",
      "handler_tainted_authorization_grant_input"
    ]);
    expect(langchainAuthorizationGrantTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TOOL_PERMISSION_TOKEN"
    ]);
    expect(langchainAuthorizationGrantTool?.metadata.schema_properties).toEqual([
      "customer_email",
      "customer_id",
      "customer_ticket_text",
      "grant_reason",
      "requested_scope",
      "requested_tool_name",
      "tenant_id"
    ]);
    expect(langchainAuthorizationGrantTool?.metadata.required_properties).toEqual([
      "customer_email",
      "customer_id",
      "customer_ticket_text",
      "grant_reason",
      "requested_scope",
      "requested_tool_name",
      "tenant_id"
    ]);
    expect(JSON.stringify(langchainAuthorizationGrantTool)).not.toContain("permission_broker_client.upsert_grant");
    expect(JSON.stringify(langchainAuthorizationGrantTool)).not.toContain("framework tool permission grant updated");
    expect(JSON.stringify(langchainAuthorizationGrantTool)).not.toContain("Grant caller selected tool permission");
    expect(langchainSecretManagerAuthorizationGrantBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerAuthorizationGrantBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      authorization_policy_write: true,
      tainted_authorization_grant_input: true,
      authorization_broad_grant: true,
      secret_manager_authorization_grant_bridge: true,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_authorization_policy_write: true,
      handler_tainted_authorization_grant_input: true,
      handler_authorization_broad_grant: true,
      handler_secret_manager_authorization_grant_bridge: true,
      handler_secret_env_access: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    for (const authorityClass of [
      "secret_manager_access",
      "tainted_secret_manager_path",
      "authorization_policy_write",
      "tainted_authorization_grant_input",
      "authorization_broad_grant",
      "secret_manager_authorization_grant_bridge"
    ]) {
      expect(langchainSecretManagerAuthorizationGrantBridgeTool?.metadata.authority_classes).toContain(authorityClass);
    }
    for (const handlerClass of [
      "handler_secret_manager_access",
      "handler_tainted_secret_manager_path",
      "handler_authorization_policy_write",
      "handler_tainted_authorization_grant_input",
      "handler_authorization_broad_grant",
      "handler_secret_manager_authorization_grant_bridge"
    ]) {
      expect(langchainSecretManagerAuthorizationGrantBridgeTool?.metadata.handler_authority_classes).toContain(handlerClass);
    }
    expect(langchainSecretManagerAuthorizationGrantBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_SECRET_AUTHZ_GRANT_TOKEN"
    ]);
    expect(langchainSecretManagerAuthorizationGrantBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requested_tool_name",
      "requester_ticket",
      "secret_path",
      "tenant_id"
    ]);
    expect(langchainSecretManagerAuthorizationGrantBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requested_tool_name",
      "requester_ticket",
      "secret_path",
      "tenant_id"
    ]);
    expect(JSON.stringify(langchainSecretManagerAuthorizationGrantBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerAuthorizationGrantBridgeTool)).not.toContain("permission_broker_client.upsert_grant");
    expect(JSON.stringify(langchainSecretManagerAuthorizationGrantBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerAuthorizationGrantBridgeTool)).not.toContain("secret_grant_role");
    expect(JSON.stringify(langchainSecretManagerAuthorizationGrantBridgeTool)).not.toContain("framework vault secret granted broad authorization");
    expect(JSON.stringify(langchainSecretManagerAuthorizationGrantBridgeTool)).not.toContain("Grant broad tool authorization");
    expect(langchainArtifactExportTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainArtifactExportTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 6,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      artifact_export: true,
      tainted_artifact_export_payload: true,
      public_artifact_destination: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_embedding_provider_call: false,
      handler_memory_write: false,
      handler_telemetry_export: false,
      handler_prompt_cache_write: false,
      handler_training_dataset_export: false,
      handler_artifact_export: true,
      handler_tainted_artifact_export_payload: true,
      handler_public_artifact_destination: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainArtifactExportTool?.metadata.authority_classes).toEqual([
      "artifact_export",
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_artifact_export",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_tainted_artifact_export_payload",
      "pii_input",
      "public_artifact_destination",
      "secret_env_access",
      "tainted_artifact_export_payload"
    ]);
    expect(langchainArtifactExportTool?.metadata.handler_authority_classes).toEqual([
      "handler_artifact_export",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_tainted_artifact_export_payload"
    ]);
    expect(langchainArtifactExportTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_ARTIFACT_EXPORT_TOKEN"
    ]);
    expect(langchainArtifactExportTool?.metadata.schema_properties).toEqual([
      "artifact_body",
      "customer_id",
      "destination_bucket",
      "object_key",
      "share_mode",
      "tool_output_text"
    ]);
    expect(langchainArtifactExportTool?.metadata.required_properties).toEqual([
      "artifact_body",
      "customer_id",
      "destination_bucket",
      "object_key",
      "tool_output_text"
    ]);
    expect(JSON.stringify(langchainArtifactExportTool)).not.toContain("artifact_export_client.upload");
    expect(JSON.stringify(langchainArtifactExportTool)).not.toContain("framework artifact exported");
    expect(JSON.stringify(langchainArtifactExportTool)).not.toContain("Export caller supplied agent artifact");
    expect(langchainModelApprovalTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainModelApprovalTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      model_approval_gate: true,
      tainted_approval_context: true,
      approval_auto_execution: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_model_provider_call: false,
      handler_model_approval_gate: true,
      handler_tainted_approval_context: true,
      handler_approval_auto_execution: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_tool_invocation: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainModelApprovalTool?.metadata.authority_classes).toEqual([
      "approval_auto_execution",
      "content_input",
      "customer_data_input",
      "handler_approval_auto_execution",
      "handler_model_approval_gate",
      "handler_secret_env_access",
      "handler_tainted_approval_context",
      "model_approval_gate",
      "pii_input",
      "secret_env_access",
      "tainted_approval_context"
    ]);
    expect(langchainModelApprovalTool?.metadata.handler_authority_classes).toEqual([
      "handler_approval_auto_execution",
      "handler_model_approval_gate",
      "handler_secret_env_access",
      "handler_tainted_approval_context"
    ]);
    expect(langchainModelApprovalTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_APPROVAL_MODEL_TOKEN"
    ]);
    expect(langchainModelApprovalTool?.metadata.schema_properties).toEqual([
      "action_payload",
      "customer_id",
      "customer_ticket_text",
      "requested_action",
      "tool_output_text"
    ]);
    expect(langchainModelApprovalTool?.metadata.required_properties).toEqual([
      "action_payload",
      "customer_id",
      "customer_ticket_text",
      "requested_action",
      "tool_output_text"
    ]);
    expect(JSON.stringify(langchainModelApprovalTool)).not.toContain("approval_model_client.evaluate");
    expect(JSON.stringify(langchainModelApprovalTool)).not.toContain("privileged_action_executor.execute");
    expect(JSON.stringify(langchainModelApprovalTool)).not.toContain("framework model approval executed");
    expect(JSON.stringify(langchainModelApprovalTool)).not.toContain("Approve and execute a caller supplied privileged action");
    expect(langchainPromptRegistryWriteTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainPromptRegistryWriteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      prompt_registry_write: true,
      tainted_prompt_registry_payload: true,
      tainted_prompt_registry_selector: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_model_provider_call: false,
      handler_prompt_registry_write: true,
      handler_tainted_prompt_registry_payload: true,
      handler_tainted_prompt_registry_selector: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainPromptRegistryWriteTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_prompt_registry_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_registry_payload",
      "handler_tainted_prompt_registry_selector",
      "pii_input",
      "prompt_registry_write",
      "secret_env_access",
      "tainted_prompt_registry_payload",
      "tainted_prompt_registry_selector"
    ]);
    expect(langchainPromptRegistryWriteTool?.metadata.handler_authority_classes).toEqual([
      "handler_prompt_registry_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_registry_payload",
      "handler_tainted_prompt_registry_selector"
    ]);
    expect(langchainPromptRegistryWriteTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_PROMPT_REGISTRY_TOKEN"]);
    expect(langchainPromptRegistryWriteTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "instruction_text",
      "prompt_id",
      "prompt_role"
    ]);
    expect(langchainPromptRegistryWriteTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "instruction_text",
      "prompt_id",
      "prompt_role"
    ]);
    expect(JSON.stringify(langchainPromptRegistryWriteTool)).not.toContain("prompt_registry_client.update_prompt");
    expect(JSON.stringify(langchainPromptRegistryWriteTool)).not.toContain("customer_context");
    expect(JSON.stringify(langchainPromptRegistryWriteTool)).not.toContain("framework prompt registry updated");
    expect(JSON.stringify(langchainPromptRegistryWriteTool)).not.toContain("Publish caller supplied system prompt text");
    expect(langchainAgentConfigWriteTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "pii"],
      actions: ["call", "write"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: false
    });
    expect(langchainAgentConfigWriteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: false,
      agent_config_write: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: true,
      handler_shell_execution: false,
      handler_tainted_filesystem_path: false,
      tainted_filesystem_path: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: true,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(langchainAgentConfigWriteTool?.metadata.authority_classes).toEqual([
      "agent_config_write",
      "content_input",
      "customer_data_input",
      "filesystem_access",
      "handler_agent_config_write",
      "handler_filesystem_write",
      "pii_input"
    ]);
    expect(langchainAgentConfigWriteTool?.metadata.handler_authority_classes).toEqual([
      "handler_agent_config_write",
      "handler_filesystem_write"
    ]);
    expect(langchainAgentConfigWriteTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainAgentConfigWriteTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "instruction_text"
    ]);
    expect(langchainAgentConfigWriteTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "instruction_text"
    ]);
    expect(JSON.stringify(langchainAgentConfigWriteTool)).not.toContain("write_text");
    expect(JSON.stringify(langchainAgentConfigWriteTool)).not.toContain("AGENTS.md");
    expect(JSON.stringify(langchainAgentConfigWriteTool)).not.toContain("framework instructions updated");
    expect(JSON.stringify(langchainAgentConfigWriteTool)).not.toContain("Rewrite AGENTS.md from caller supplied customer context");
    expect(langchainCredentialIssuanceTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "send"],
      side_effect: true,
      external_reach: false,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainCredentialIssuanceTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: false,
      agent_config_write: false,
      credential_issuance: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_credential_issuance: true,
      handler_tainted_credential_issuance_input: true,
      tainted_credential_issuance_input: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(langchainCredentialIssuanceTool?.metadata.authority_classes).toEqual([
      "credential_input",
      "credential_issuance",
      "customer_data_input",
      "handler_credential_issuance",
      "handler_tainted_credential_issuance_input",
      "pii_input",
      "tainted_credential_issuance_input"
    ]);
    expect(langchainCredentialIssuanceTool?.metadata.handler_authority_classes).toEqual([
      "handler_credential_issuance",
      "handler_tainted_credential_issuance_input"
    ]);
    expect(langchainCredentialIssuanceTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainCredentialIssuanceTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requested_scope",
      "requested_subject",
      "token_audience"
    ]);
    expect(langchainCredentialIssuanceTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requested_scope",
      "requested_subject",
      "token_audience"
    ]);
    expect(JSON.stringify(langchainCredentialIssuanceTool)).not.toContain("identity_broker.issue_token");
    expect(JSON.stringify(langchainCredentialIssuanceTool)).not.toContain("Mint an agent session token");
    expect(langchainSecretManagerCredentialIssuanceBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerCredentialIssuanceBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 6,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      credential_issuance: true,
      tainted_credential_issuance_input: true,
      secret_manager_credential_issuance_bridge: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_credential_issuance: true,
      handler_tainted_credential_issuance_input: true,
      handler_secret_manager_credential_issuance_bridge: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_secret_env_access: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    for (const authorityClass of [
      "credential_issuance",
      "tainted_credential_issuance_input",
      "secret_manager_credential_issuance_bridge",
      "secret_manager_access",
      "tainted_secret_manager_path"
    ]) {
      expect(langchainSecretManagerCredentialIssuanceBridgeTool?.metadata.authority_classes).toContain(authorityClass);
    }
    for (const handlerClass of [
      "handler_credential_issuance",
      "handler_tainted_credential_issuance_input",
      "handler_secret_manager_credential_issuance_bridge",
      "handler_secret_manager_access",
      "handler_tainted_secret_manager_path"
    ]) {
      expect(langchainSecretManagerCredentialIssuanceBridgeTool?.metadata.handler_authority_classes).toContain(handlerClass);
    }
    expect(langchainSecretManagerCredentialIssuanceBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_SECRET_CREDENTIAL_ISSUER_TOKEN"
    ]);
    expect(langchainSecretManagerCredentialIssuanceBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requested_scope",
      "requested_subject",
      "requester_ticket",
      "secret_path",
      "token_audience"
    ]);
    expect(langchainSecretManagerCredentialIssuanceBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requested_scope",
      "requested_subject",
      "requester_ticket",
      "secret_path",
      "token_audience"
    ]);
    expect(JSON.stringify(langchainSecretManagerCredentialIssuanceBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerCredentialIssuanceBridgeTool)).not.toContain("identity_broker.issue_token");
    expect(JSON.stringify(langchainSecretManagerCredentialIssuanceBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerCredentialIssuanceBridgeTool)).not.toContain("vault_signing_key");
    expect(JSON.stringify(langchainSecretManagerCredentialIssuanceBridgeTool)).not.toContain("Issue an agent credential");
    expect(langchainToolOutputCredentialIssuanceBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputCredentialIssuanceBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 7,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      credential_issuance: true,
      tainted_credential_issuance_input: true,
      secret_manager_credential_issuance_bridge: false,
      tool_output_credential_issuance_bridge: true,
      nested_tool_invocation: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_credential_issuance: true,
      handler_tainted_credential_issuance_input: true,
      handler_secret_manager_credential_issuance_bridge: false,
      handler_tool_output_credential_issuance_bridge: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_tool_invocation: true,
      handler_memory_write: false,
      handler_tool_output_memory_bridge: false,
      handler_tool_output_to_output: false,
      handler_model_provider_call: false,
      handler_tool_output_prompt_bridge: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(langchainToolOutputCredentialIssuanceBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "credential_issuance",
      "customer_data_input",
      "external_write",
      "handler_credential_issuance",
      "handler_secret_env_access",
      "handler_tainted_credential_issuance_input",
      "handler_tool_invocation",
      "handler_tool_output_credential_issuance_bridge",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_credential_issuance_input",
      "tool_output_credential_issuance_bridge"
    ]);
    expect(langchainToolOutputCredentialIssuanceBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_credential_issuance",
      "handler_secret_env_access",
      "handler_tainted_credential_issuance_input",
      "handler_tool_invocation",
      "handler_tool_output_credential_issuance_bridge"
    ]);
    expect(langchainToolOutputCredentialIssuanceBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TOOL_OBSERVATION_CREDENTIAL_TOKEN"
    ]);
    expect(langchainToolOutputCredentialIssuanceBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requested_scope",
      "requested_subject",
      "requester_ticket",
      "target_tool_name",
      "token_audience",
      "tool_request_body"
    ]);
    expect(langchainToolOutputCredentialIssuanceBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requested_scope",
      "requested_subject",
      "requester_ticket",
      "target_tool_name",
      "token_audience",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainToolOutputCredentialIssuanceBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputCredentialIssuanceBridgeTool)).not.toContain("identity_broker.issue_token");
    expect(JSON.stringify(langchainToolOutputCredentialIssuanceBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputCredentialIssuanceBridgeTool)).not.toContain("grant_material");
    expect(JSON.stringify(langchainToolOutputCredentialIssuanceBridgeTool)).not.toContain("framework tool observation issued credential");
    expect(JSON.stringify(langchainToolOutputCredentialIssuanceBridgeTool)).not.toContain("Issue an agent credential from a raw privileged tool observation");
    expect(langchainNestedToolInvocationTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "pii"],
      actions: ["call", "execute", "send"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: false
    });
    expect(langchainNestedToolInvocationTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: false,
      tool_output_to_output: true,
      agent_config_write: false,
      credential_issuance: false,
      nested_tool_invocation: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_tool_output_to_output: true,
      handler_agent_config_write: false,
      handler_credential_issuance: false,
      handler_tool_invocation: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(langchainNestedToolInvocationTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_tool_invocation",
      "handler_tool_output_to_output",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "tool_output_to_output"
    ]);
    expect(langchainNestedToolInvocationTool?.metadata.handler_authority_classes).toEqual([
      "handler_tool_invocation",
      "handler_tool_output_to_output"
    ]);
    expect(langchainNestedToolInvocationTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainNestedToolInvocationTool?.metadata.schema_properties).toEqual([
      "approval_ticket",
      "customer_id",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(langchainNestedToolInvocationTool?.metadata.required_properties).toEqual([
      "customer_id",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainNestedToolInvocationTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainNestedToolInvocationTool)).not.toContain("str(result)");
    expect(JSON.stringify(langchainNestedToolInvocationTool)).not.toContain("Dispatch a caller selected privileged tool");
    expect(langchainToolOutputPromptBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["credential"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputPromptBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: false,
      accepts_customer_data_input: false,
      nested_tool_invocation: true,
      model_provider_call: true,
      tool_output_prompt_bridge: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_tool_invocation: true,
      handler_model_provider_call: true,
      handler_tool_output_prompt_bridge: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainToolOutputPromptBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_prompt_bridge",
      "model_provider_call",
      "nested_tool_invocation",
      "network_access",
      "secret_env_access",
      "tool_output_prompt_bridge"
    ]);
    expect(langchainToolOutputPromptBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_prompt_bridge"
    ]);
    expect(langchainToolOutputPromptBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TOOL_OBSERVATION_MODEL_TOKEN"
    ]);
    expect(langchainToolOutputPromptBridgeTool?.metadata.schema_properties).toEqual([
      "review_instruction_text",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(langchainToolOutputPromptBridgeTool?.metadata.required_properties).toEqual([
      "review_instruction_text",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainToolOutputPromptBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputPromptBridgeTool)).not.toContain("openai_client.chat.completions.create");
    expect(JSON.stringify(langchainToolOutputPromptBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputPromptBridgeTool)).not.toContain("Review a raw privileged tool observation");
    expect(langchainToolOutputMemoryBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["credential"],
      actions: ["call", "execute", "remember", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputMemoryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: false,
      accepts_customer_data_input: false,
      nested_tool_invocation: true,
      memory_write: true,
      tool_output_memory_bridge: true,
      model_provider_call: false,
      tool_output_prompt_bridge: false,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_tool_invocation: true,
      handler_memory_write: true,
      handler_tool_output_memory_bridge: true,
      handler_model_provider_call: false,
      handler_tool_output_prompt_bridge: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainToolOutputMemoryBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_memory_bridge",
      "memory_access",
      "memory_write",
      "nested_tool_invocation",
      "network_access",
      "secret_env_access",
      "tool_output_memory_bridge"
    ]);
    expect(langchainToolOutputMemoryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_memory_bridge"
    ]);
    expect(langchainToolOutputMemoryBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TOOL_OBSERVATION_MEMORY_TOKEN"
    ]);
    expect(langchainToolOutputMemoryBridgeTool?.metadata.schema_properties).toEqual([
      "retention_note_text",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(langchainToolOutputMemoryBridgeTool?.metadata.required_properties).toEqual([
      "retention_note_text",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainToolOutputMemoryBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputMemoryBridgeTool)).not.toContain("memory_store.upsert");
    expect(JSON.stringify(langchainToolOutputMemoryBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputMemoryBridgeTool)).not.toContain("framework tool observation remembered");
    expect(JSON.stringify(langchainToolOutputMemoryBridgeTool)).not.toContain("Persist a raw privileged tool observation");
    expect(langchainToolOutputPromptCacheBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "remember", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputPromptCacheBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      prompt_cache_write: true,
      tool_output_prompt_cache_bridge: true,
      tainted_prompt_cache_key: true,
      tainted_prompt_cache_value: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_prompt_cache_write: true,
      handler_tool_output_prompt_cache_bridge: true,
      handler_tainted_prompt_cache_key: true,
      handler_tainted_prompt_cache_value: false,
      handler_secret_env_access: true,
      handler_tool_invocation: true,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(langchainToolOutputPromptCacheBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_cache_key",
      "handler_tool_invocation",
      "handler_tool_output_prompt_cache_bridge",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "prompt_cache_write",
      "secret_env_access",
      "tainted_prompt_cache_key",
      "tool_output_prompt_cache_bridge"
    ]);
    expect(langchainToolOutputPromptCacheBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_cache_key",
      "handler_tool_invocation",
      "handler_tool_output_prompt_cache_bridge"
    ]);
    expect(langchainToolOutputPromptCacheBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TOOL_OBSERVATION_PROMPT_CACHE_TOKEN"
    ]);
    expect(langchainToolOutputPromptCacheBridgeTool?.metadata.schema_properties).toEqual([
      "cache_key",
      "customer_id",
      "retention_note_text",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainToolOutputPromptCacheBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputPromptCacheBridgeTool)).not.toContain("prompt_cache.set");
    expect(JSON.stringify(langchainToolOutputPromptCacheBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputPromptCacheBridgeTool)).not.toContain("framework tool observation cached for prompts");
    expect(JSON.stringify(langchainToolOutputPromptCacheBridgeTool)).not.toContain("Write a raw privileged tool observation");
    expect(langchainToolOutputEmbeddingVectorBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputEmbeddingVectorBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      embedding_provider_call: true,
      tainted_embedding_input: false,
      memory_write: true,
      tainted_memory_scope: true,
      tool_output_memory_bridge: true,
      tool_output_embedding_vector_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_tool_invocation: true,
      handler_embedding_provider_call: true,
      handler_tainted_embedding_input: false,
      handler_memory_write: true,
      handler_tainted_memory_scope: true,
      handler_tool_output_memory_bridge: true,
      handler_tool_output_embedding_vector_bridge: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(langchainToolOutputEmbeddingVectorBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "embedding_provider_call",
      "handler_embedding_provider_call",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tainted_memory_scope",
      "handler_tool_invocation",
      "handler_tool_output_embedding_vector_bridge",
      "handler_tool_output_memory_bridge",
      "memory_access",
      "memory_write",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_memory_scope",
      "tool_output_embedding_vector_bridge",
      "tool_output_memory_bridge"
    ]);
    expect(langchainToolOutputEmbeddingVectorBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_embedding_provider_call",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tainted_memory_scope",
      "handler_tool_invocation",
      "handler_tool_output_embedding_vector_bridge",
      "handler_tool_output_memory_bridge"
    ]);
    expect(langchainToolOutputEmbeddingVectorBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TOOL_OBSERVATION_VECTOR_TOKEN"
    ]);
    expect(langchainToolOutputEmbeddingVectorBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "retention_note_text",
      "target_tool_name",
      "tool_request_body",
      "vector_namespace"
    ]);
    expect(langchainToolOutputEmbeddingVectorBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "retention_note_text",
      "target_tool_name",
      "tool_request_body",
      "vector_namespace"
    ]);
    expect(JSON.stringify(langchainToolOutputEmbeddingVectorBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputEmbeddingVectorBridgeTool)).not.toContain("embedding_client.embed_documents");
    expect(JSON.stringify(langchainToolOutputEmbeddingVectorBridgeTool)).not.toContain("vector_store.upsert");
    expect(JSON.stringify(langchainToolOutputEmbeddingVectorBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputEmbeddingVectorBridgeTool)).not.toContain("tool_observation_embedding");
    expect(JSON.stringify(langchainToolOutputEmbeddingVectorBridgeTool)).not.toContain("framework tool observation embedded to vector memory");
    expect(JSON.stringify(langchainToolOutputEmbeddingVectorBridgeTool)).not.toContain("Embed a raw privileged tool observation");
    expect(langchainToolOutputPromptRegistryBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputPromptRegistryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 7,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      prompt_registry_write: true,
      tool_output_prompt_registry_bridge: true,
      tainted_prompt_registry_payload: true,
      tainted_prompt_registry_selector: true,
      memory_write: false,
      tool_output_memory_bridge: false,
      tool_output_to_output: false,
      model_provider_call: false,
      tool_output_prompt_bridge: false,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_prompt_registry_write: true,
      handler_tool_output_prompt_registry_bridge: true,
      handler_tainted_prompt_registry_payload: true,
      handler_tainted_prompt_registry_selector: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_tool_invocation: true,
      handler_memory_write: false,
      handler_tool_output_memory_bridge: false,
      handler_tool_output_to_output: false,
      handler_model_provider_call: false,
      handler_tool_output_prompt_bridge: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainToolOutputPromptRegistryBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_prompt_registry_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_registry_payload",
      "handler_tainted_prompt_registry_selector",
      "handler_tool_invocation",
      "handler_tool_output_prompt_registry_bridge",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "prompt_registry_write",
      "secret_env_access",
      "tainted_prompt_registry_payload",
      "tainted_prompt_registry_selector",
      "tool_output_prompt_registry_bridge"
    ]);
    expect(langchainToolOutputPromptRegistryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_prompt_registry_write",
      "handler_secret_env_access",
      "handler_tainted_prompt_registry_payload",
      "handler_tainted_prompt_registry_selector",
      "handler_tool_invocation",
      "handler_tool_output_prompt_registry_bridge"
    ]);
    expect(langchainToolOutputPromptRegistryBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TOOL_OBSERVATION_PROMPT_REGISTRY_TOKEN"
    ]);
    expect(langchainToolOutputPromptRegistryBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "prompt_id",
      "prompt_role",
      "registry_namespace",
      "reviewer_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(langchainToolOutputPromptRegistryBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "prompt_id",
      "prompt_role",
      "registry_namespace",
      "reviewer_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainToolOutputPromptRegistryBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputPromptRegistryBridgeTool)).not.toContain("prompt_registry_client.update_prompt");
    expect(JSON.stringify(langchainToolOutputPromptRegistryBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputPromptRegistryBridgeTool)).not.toContain("framework tool observation published to prompt registry");
    expect(JSON.stringify(langchainToolOutputPromptRegistryBridgeTool)).not.toContain("Publish a raw privileged tool observation");
    expect(langchainToolOutputAuthorizationGrantBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputAuthorizationGrantBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 7,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      authorization_policy_write: true,
      tainted_authorization_grant_input: true,
      authorization_broad_grant: true,
      secret_manager_authorization_grant_bridge: false,
      tool_output_authorization_grant_bridge: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_authorization_policy_write: true,
      handler_tainted_authorization_grant_input: true,
      handler_authorization_broad_grant: true,
      handler_secret_manager_authorization_grant_bridge: false,
      handler_tool_output_authorization_grant_bridge: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_tool_invocation: true,
      handler_memory_write: false,
      handler_tool_output_memory_bridge: false,
      handler_tool_output_to_output: false,
      handler_model_provider_call: false,
      handler_tool_output_prompt_bridge: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainToolOutputAuthorizationGrantBridgeTool?.metadata.authority_classes).toEqual([
      "authorization_broad_grant",
      "authorization_policy_write",
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "handler_authorization_broad_grant",
      "handler_authorization_policy_write",
      "handler_secret_env_access",
      "handler_tainted_authorization_grant_input",
      "handler_tool_invocation",
      "handler_tool_output_authorization_grant_bridge",
      "nested_tool_invocation",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_authorization_grant_input",
      "tool_output_authorization_grant_bridge"
    ]);
    expect(langchainToolOutputAuthorizationGrantBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_authorization_broad_grant",
      "handler_authorization_policy_write",
      "handler_secret_env_access",
      "handler_tainted_authorization_grant_input",
      "handler_tool_invocation",
      "handler_tool_output_authorization_grant_bridge"
    ]);
    expect(langchainToolOutputAuthorizationGrantBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TOOL_OBSERVATION_AUTHZ_TOKEN"
    ]);
    expect(langchainToolOutputAuthorizationGrantBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "grant_reason",
      "requested_scope",
      "requested_tool_name",
      "target_tool_name",
      "tenant_id",
      "tool_request_body"
    ]);
    expect(langchainToolOutputAuthorizationGrantBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "grant_reason",
      "requested_scope",
      "requested_tool_name",
      "target_tool_name",
      "tenant_id",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainToolOutputAuthorizationGrantBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputAuthorizationGrantBridgeTool)).not.toContain("permission_broker_client.upsert_grant");
    expect(JSON.stringify(langchainToolOutputAuthorizationGrantBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputAuthorizationGrantBridgeTool)).not.toContain("framework tool observation granted authorization");
    expect(JSON.stringify(langchainToolOutputAuthorizationGrantBridgeTool)).not.toContain("Grant broad tool authorization from a raw privileged tool observation");
    expect(langchainToolOutputExternalServiceBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["credential"],
      actions: ["call", "execute", "publish", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputExternalServiceBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: false,
      accepts_customer_data_input: false,
      nested_tool_invocation: true,
      external_service_write: true,
      tainted_external_service_recipient: true,
      tool_output_external_service_bridge: true,
      memory_write: false,
      tool_output_memory_bridge: false,
      tool_output_to_output: false,
      model_provider_call: false,
      tool_output_prompt_bridge: false,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: true,
      handler_tainted_external_service_recipient: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_tool_invocation: true,
      handler_tool_output_external_service_bridge: true,
      handler_memory_write: false,
      handler_tool_output_memory_bridge: false,
      handler_tool_output_to_output: false,
      handler_model_provider_call: false,
      handler_tool_output_prompt_bridge: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(langchainToolOutputExternalServiceBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "external_service_write",
      "external_write",
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient",
      "handler_tool_invocation",
      "handler_tool_output_external_service_bridge",
      "nested_tool_invocation",
      "network_access",
      "secret_env_access",
      "tainted_external_service_recipient",
      "tool_output_external_service_bridge"
    ]);
    expect(langchainToolOutputExternalServiceBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient",
      "handler_tool_invocation",
      "handler_tool_output_external_service_bridge"
    ]);
    expect(langchainToolOutputExternalServiceBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TOOL_OBSERVATION_SLACK_TOKEN"
    ]);
    expect(langchainToolOutputExternalServiceBridgeTool?.metadata.schema_properties).toEqual([
      "external_channel_id",
      "posting_reason_text",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(langchainToolOutputExternalServiceBridgeTool?.metadata.required_properties).toEqual([
      "external_channel_id",
      "posting_reason_text",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainToolOutputExternalServiceBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputExternalServiceBridgeTool)).not.toContain("slack_client.chat_postMessage");
    expect(JSON.stringify(langchainToolOutputExternalServiceBridgeTool)).not.toContain("str(tool_result)");
    expect(JSON.stringify(langchainToolOutputExternalServiceBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputExternalServiceBridgeTool)).not.toContain("framework tool observation posted externally");
    expect(JSON.stringify(langchainToolOutputExternalServiceBridgeTool)).not.toContain("Post a raw privileged tool observation");
    expect(langchainToolOutputTelemetryBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential"],
      actions: ["call", "execute", "publish", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputTelemetryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      nested_tool_invocation: true,
      telemetry_export: true,
      tool_output_telemetry_bridge: true,
      tainted_telemetry_payload: false,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_telemetry_export: true,
      handler_tool_output_telemetry_bridge: true,
      handler_tainted_telemetry_payload: false,
      handler_secret_env_access: true,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainToolOutputTelemetryBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_secret_env_access",
      "handler_telemetry_export",
      "handler_tool_invocation",
      "handler_tool_output_telemetry_bridge",
      "nested_tool_invocation",
      "network_access",
      "secret_env_access",
      "telemetry_export",
      "tool_output_telemetry_bridge"
    ]);
    expect(langchainToolOutputTelemetryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_telemetry_export",
      "handler_tool_invocation",
      "handler_tool_output_telemetry_bridge"
    ]);
    expect(langchainToolOutputTelemetryBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TOOL_OBSERVATION_TRACE_TOKEN"
    ]);
    expect(langchainToolOutputTelemetryBridgeTool?.metadata.schema_properties).toEqual([
      "requester_ticket",
      "target_tool_name",
      "tool_request_body",
      "trace_session_id"
    ]);
    expect(langchainToolOutputTelemetryBridgeTool?.metadata.required_properties).toEqual([
      "requester_ticket",
      "target_tool_name",
      "tool_request_body",
      "trace_session_id"
    ]);
    expect(JSON.stringify(langchainToolOutputTelemetryBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputTelemetryBridgeTool)).not.toContain("telemetry_client.record_trace");
    expect(JSON.stringify(langchainToolOutputTelemetryBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputTelemetryBridgeTool)).not.toContain("framework tool observation exported to telemetry");
    expect(JSON.stringify(langchainToolOutputTelemetryBridgeTool)).not.toContain("Export a raw privileged tool observation");
    expect(langchainToolOutputArtifactBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential"],
      actions: ["call", "execute", "publish", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputArtifactBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      nested_tool_invocation: true,
      artifact_export: true,
      tool_output_artifact_bridge: true,
      public_artifact_destination: true,
      tainted_artifact_export_payload: false,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_artifact_export: true,
      handler_tool_output_artifact_bridge: true,
      handler_public_artifact_destination: true,
      handler_tainted_artifact_export_payload: false,
      handler_secret_env_access: true,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(langchainToolOutputArtifactBridgeTool?.metadata.authority_classes).toEqual([
      "artifact_export",
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_artifact_export",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_artifact_bridge",
      "nested_tool_invocation",
      "network_access",
      "public_artifact_destination",
      "secret_env_access",
      "tool_output_artifact_bridge"
    ]);
    expect(langchainToolOutputArtifactBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_artifact_export",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_artifact_bridge"
    ]);
    expect(langchainToolOutputArtifactBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TOOL_OBSERVATION_ARTIFACT_TOKEN"
    ]);
    expect(langchainToolOutputArtifactBridgeTool?.metadata.schema_properties).toEqual([
      "object_key",
      "public_access",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(langchainToolOutputArtifactBridgeTool?.metadata.required_properties).toEqual([
      "object_key",
      "public_access",
      "requester_ticket",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainToolOutputArtifactBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputArtifactBridgeTool)).not.toContain("artifact_export_client.upload");
    expect(JSON.stringify(langchainToolOutputArtifactBridgeTool)).not.toContain("str(tool_result)");
    expect(JSON.stringify(langchainToolOutputArtifactBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputArtifactBridgeTool)).not.toContain("framework tool observation exported to artifact");
    expect(JSON.stringify(langchainToolOutputArtifactBridgeTool)).not.toContain("Export a raw privileged tool observation");
    expect(langchainToolOutputTaskQueueBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential"],
      actions: ["call", "execute", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputTaskQueueBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 6,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      task_queue_enqueue: true,
      tool_output_task_queue_bridge: true,
      tainted_task_payload: false,
      tainted_task_routing: true,
      external_write: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_task_queue_enqueue: true,
      handler_tool_output_task_queue_bridge: true,
      handler_tainted_task_payload: false,
      handler_tainted_task_routing: true,
      handler_secret_env_access: true,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(langchainToolOutputTaskQueueBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_secret_env_access",
      "handler_tainted_task_routing",
      "handler_task_queue_enqueue",
      "handler_tool_invocation",
      "handler_tool_output_task_queue_bridge",
      "nested_tool_invocation",
      "network_access",
      "secret_env_access",
      "tainted_task_routing",
      "task_queue_enqueue",
      "tool_output_task_queue_bridge"
    ]);
    expect(langchainToolOutputTaskQueueBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_tainted_task_routing",
      "handler_task_queue_enqueue",
      "handler_tool_invocation",
      "handler_tool_output_task_queue_bridge"
    ]);
    expect(langchainToolOutputTaskQueueBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TOOL_OBSERVATION_QUEUE_TOKEN"
    ]);
    expect(langchainToolOutputTaskQueueBridgeTool?.metadata.schema_properties).toEqual([
      "replay_on_failure",
      "requester_ticket",
      "target_queue_name",
      "target_tool_name",
      "task_route",
      "tool_request_body"
    ]);
    expect(langchainToolOutputTaskQueueBridgeTool?.metadata.required_properties).toEqual([
      "replay_on_failure",
      "requester_ticket",
      "target_queue_name",
      "target_tool_name",
      "task_route",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainToolOutputTaskQueueBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputTaskQueueBridgeTool)).not.toContain("task_queue_client.enqueue");
    expect(JSON.stringify(langchainToolOutputTaskQueueBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputTaskQueueBridgeTool)).not.toContain("framework tool observation queued for background agent");
    expect(JSON.stringify(langchainToolOutputTaskQueueBridgeTool)).not.toContain("Enqueue a raw privileged tool observation");
    expect(langchainToolOutputTrainingDatasetBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential"],
      actions: ["call", "execute", "publish", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputTrainingDatasetBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_customer_data_input: true,
      nested_tool_invocation: true,
      training_dataset_export: true,
      tool_output_training_dataset_bridge: true,
      tainted_training_dataset_payload: false,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_training_dataset_export: true,
      handler_tool_output_training_dataset_bridge: true,
      handler_tainted_training_dataset_payload: false,
      handler_secret_env_access: true,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainToolOutputTrainingDatasetBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_write",
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_training_dataset_bridge",
      "handler_training_dataset_export",
      "nested_tool_invocation",
      "network_access",
      "secret_env_access",
      "tool_output_training_dataset_bridge",
      "training_dataset_export"
    ]);
    expect(langchainToolOutputTrainingDatasetBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_tool_invocation",
      "handler_tool_output_training_dataset_bridge",
      "handler_training_dataset_export"
    ]);
    expect(langchainToolOutputTrainingDatasetBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TOOL_OBSERVATION_TRAINING_TOKEN"
    ]);
    expect(langchainToolOutputTrainingDatasetBridgeTool?.metadata.schema_properties).toEqual([
      "requester_ticket",
      "source_label",
      "target_tool_name",
      "tool_request_body",
      "training_dataset_id"
    ]);
    expect(langchainToolOutputTrainingDatasetBridgeTool?.metadata.required_properties).toEqual([
      "requester_ticket",
      "source_label",
      "target_tool_name",
      "tool_request_body",
      "training_dataset_id"
    ]);
    expect(JSON.stringify(langchainToolOutputTrainingDatasetBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputTrainingDatasetBridgeTool)).not.toContain("training_dataset_client.append_record");
    expect(JSON.stringify(langchainToolOutputTrainingDatasetBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputTrainingDatasetBridgeTool)).not.toContain("framework tool observation exported to training dataset");
    expect(JSON.stringify(langchainToolOutputTrainingDatasetBridgeTool)).not.toContain("Export a raw privileged tool observation");
    expect(langchainAgentDelegationTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainAgentDelegationTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      agent_delegation: true,
      tainted_agent_delegation_target: true,
      agent_delegation_context_forwarding: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_agent_delegation: true,
      handler_tainted_agent_delegation_target: true,
      handler_agent_delegation_context_forwarding: true,
      handler_tool_invocation: false,
      handler_browser_automation: false,
      handler_external_service_write: false,
      handler_model_provider_call: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainAgentDelegationTool?.metadata.authority_classes).toEqual([
      "agent_delegation",
      "agent_delegation_context_forwarding",
      "content_input",
      "customer_data_input",
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_secret_env_access",
      "handler_tainted_agent_delegation_target",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_agent_delegation_target"
    ]);
    expect(langchainAgentDelegationTool?.metadata.handler_authority_classes).toEqual([
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_secret_env_access",
      "handler_tainted_agent_delegation_target"
    ]);
    expect(langchainAgentDelegationTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_A2A_FEDERATION_TOKEN"]);
    expect(langchainAgentDelegationTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "requested_task_type",
      "target_agent_url",
      "tool_output_text"
    ]);
    expect(langchainAgentDelegationTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "requested_task_type",
      "target_agent_url",
      "tool_output_text"
    ]);
    expect(JSON.stringify(langchainAgentDelegationTool)).not.toContain("remote_agent_client.delegate_task");
    expect(JSON.stringify(langchainAgentDelegationTool)).not.toContain("Delegate caller supplied customer context");
    expect(langchainSecretManagerAgentDelegationBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerAgentDelegationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 6,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      agent_delegation: true,
      tainted_agent_delegation_target: true,
      agent_delegation_context_forwarding: true,
      secret_manager_agent_delegation_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_agent_delegation: true,
      handler_tainted_agent_delegation_target: true,
      handler_agent_delegation_context_forwarding: true,
      handler_secret_manager_agent_delegation_bridge: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(langchainSecretManagerAgentDelegationBridgeTool?.metadata.authority_classes).toEqual([
      "agent_delegation",
      "agent_delegation_context_forwarding",
      "content_input",
      "credential_input",
      "customer_data_input",
      "filesystem_access",
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_agent_delegation_bridge",
      "handler_tainted_agent_delegation_target",
      "handler_tainted_secret_manager_path",
      "network_access",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_agent_delegation_bridge",
      "tainted_agent_delegation_target",
      "tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerAgentDelegationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_agent_delegation_bridge",
      "handler_tainted_agent_delegation_target",
      "handler_tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerAgentDelegationBridgeTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_SECRET_A2A_TOKEN"]);
    expect(langchainSecretManagerAgentDelegationBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "delegation_reason",
      "requested_task_type",
      "requester_ticket",
      "secret_path",
      "target_agent_url"
    ]);
    expect(langchainSecretManagerAgentDelegationBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "delegation_reason",
      "requested_task_type",
      "requester_ticket",
      "secret_path",
      "target_agent_url"
    ]);
    expect(JSON.stringify(langchainSecretManagerAgentDelegationBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerAgentDelegationBridgeTool)).not.toContain("remote_agent_client.delegate_task");
    expect(JSON.stringify(langchainSecretManagerAgentDelegationBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerAgentDelegationBridgeTool)).not.toContain("secret_delegation_value");
    expect(JSON.stringify(langchainSecretManagerAgentDelegationBridgeTool)).not.toContain("framework vault secret delegated to remote agent");
    expect(JSON.stringify(langchainSecretManagerAgentDelegationBridgeTool)).not.toContain("Delegate a customer support secret");
    expect(langchainToolOutputAgentDelegationBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["credential"],
      actions: ["call", "execute", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputAgentDelegationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_customer_data_input: false,
      agent_delegation: true,
      tainted_agent_delegation_target: true,
      agent_delegation_context_forwarding: true,
      tool_output_agent_delegation_bridge: true,
      nested_tool_invocation: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_agent_delegation: true,
      handler_tainted_agent_delegation_target: true,
      handler_agent_delegation_context_forwarding: true,
      handler_tool_output_agent_delegation_bridge: true,
      handler_tool_invocation: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainToolOutputAgentDelegationBridgeTool?.metadata.authority_classes).toEqual([
      "agent_delegation",
      "agent_delegation_context_forwarding",
      "content_input",
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_secret_env_access",
      "handler_tainted_agent_delegation_target",
      "handler_tool_invocation",
      "handler_tool_output_agent_delegation_bridge",
      "nested_tool_invocation",
      "network_access",
      "secret_env_access",
      "tainted_agent_delegation_target",
      "tool_output_agent_delegation_bridge"
    ]);
    expect(langchainToolOutputAgentDelegationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_secret_env_access",
      "handler_tainted_agent_delegation_target",
      "handler_tool_invocation",
      "handler_tool_output_agent_delegation_bridge"
    ]);
    expect(langchainToolOutputAgentDelegationBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_TOOL_OBSERVATION_A2A_TOKEN"
    ]);
    expect(langchainToolOutputAgentDelegationBridgeTool?.metadata.schema_properties).toEqual([
      "delegation_reason",
      "requested_task_type",
      "target_agent_url",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(langchainToolOutputAgentDelegationBridgeTool?.metadata.required_properties).toEqual([
      "delegation_reason",
      "requested_task_type",
      "target_agent_url",
      "target_tool_name",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainToolOutputAgentDelegationBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputAgentDelegationBridgeTool)).not.toContain("remote_agent_client.delegate_task");
    expect(JSON.stringify(langchainToolOutputAgentDelegationBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputAgentDelegationBridgeTool)).not.toContain("Delegate a raw privileged tool observation");
    expect(langchainBrowserAutomationTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainBrowserAutomationTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: false,
      agent_config_write: false,
      credential_issuance: false,
      nested_tool_invocation: false,
      browser_automation: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_credential_issuance: false,
      handler_tool_invocation: false,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(langchainBrowserAutomationTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_browser_automation",
      "handler_tainted_browser_automation_target",
      "network_access",
      "pii_input",
      "tainted_browser_automation_target"
    ]);
    expect(langchainBrowserAutomationTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_tainted_browser_automation_target"
    ]);
    expect(langchainBrowserAutomationTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainBrowserAutomationTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_message_text",
      "form_selector",
      "submit_selector",
      "target_url"
    ]);
    expect(langchainBrowserAutomationTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_message_text",
      "form_selector",
      "submit_selector",
      "target_url"
    ]);
    expect(JSON.stringify(langchainBrowserAutomationTool)).not.toContain("browser_session.page");
    expect(JSON.stringify(langchainBrowserAutomationTool)).not.toContain("page.goto");
    expect(JSON.stringify(langchainBrowserAutomationTool)).not.toContain("page.fill");
    expect(JSON.stringify(langchainBrowserAutomationTool)).not.toContain("page.click");
    expect(JSON.stringify(langchainBrowserAutomationTool)).not.toContain("Drive an authenticated browser session");
    expect(langchainToolOutputBrowserAutomationBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["credential"],
      actions: ["call", "execute", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainToolOutputBrowserAutomationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      nested_tool_invocation: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      tool_output_browser_automation_bridge: true,
      secret_manager_browser_automation_bridge: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_tool_invocation: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_tool_output_browser_automation_bridge: true,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainToolOutputBrowserAutomationBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "handler_browser_automation",
      "handler_tainted_browser_automation_target",
      "handler_tool_invocation",
      "handler_tool_output_browser_automation_bridge",
      "nested_tool_invocation",
      "network_access",
      "tainted_browser_automation_target",
      "tool_output_browser_automation_bridge"
    ]);
    expect(langchainToolOutputBrowserAutomationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_tainted_browser_automation_target",
      "handler_tool_invocation",
      "handler_tool_output_browser_automation_bridge"
    ]);
    expect(langchainToolOutputBrowserAutomationBridgeTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainToolOutputBrowserAutomationBridgeTool?.metadata.schema_properties).toEqual([
      "form_selector",
      "submit_selector",
      "target_tool_name",
      "target_url",
      "tool_request_body"
    ]);
    expect(langchainToolOutputBrowserAutomationBridgeTool?.metadata.required_properties).toEqual([
      "form_selector",
      "submit_selector",
      "target_tool_name",
      "target_url",
      "tool_request_body"
    ]);
    expect(JSON.stringify(langchainToolOutputBrowserAutomationBridgeTool)).not.toContain("tool_registry.call_tool");
    expect(JSON.stringify(langchainToolOutputBrowserAutomationBridgeTool)).not.toContain("browser_session.page");
    expect(JSON.stringify(langchainToolOutputBrowserAutomationBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(langchainToolOutputBrowserAutomationBridgeTool)).not.toContain("page.fill");
    expect(JSON.stringify(langchainToolOutputBrowserAutomationBridgeTool)).not.toContain("page.click");
    expect(JSON.stringify(langchainToolOutputBrowserAutomationBridgeTool)).not.toContain("tool_result");
    expect(JSON.stringify(langchainToolOutputBrowserAutomationBridgeTool)).not.toContain("framework tool observation submitted through browser");
    expect(JSON.stringify(langchainToolOutputBrowserAutomationBridgeTool)).not.toContain("Submit a raw privileged tool observation");
    expect(langchainSecretManagerBrowserAutomationBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerBrowserAutomationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 6,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      secret_manager_browser_automation_bridge: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_secret_manager_browser_automation_bridge: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(langchainSecretManagerBrowserAutomationBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "filesystem_access",
      "handler_browser_automation",
      "handler_secret_manager_access",
      "handler_secret_manager_browser_automation_bridge",
      "handler_tainted_browser_automation_target",
      "handler_tainted_secret_manager_path",
      "network_access",
      "pii_input",
      "secret_manager_access",
      "secret_manager_browser_automation_bridge",
      "tainted_browser_automation_target",
      "tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerBrowserAutomationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_secret_manager_access",
      "handler_secret_manager_browser_automation_bridge",
      "handler_tainted_browser_automation_target",
      "handler_tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerBrowserAutomationBridgeTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainSecretManagerBrowserAutomationBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "form_selector",
      "requester_ticket",
      "secret_path",
      "submit_selector",
      "target_url"
    ]);
    expect(langchainSecretManagerBrowserAutomationBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "form_selector",
      "requester_ticket",
      "secret_path",
      "submit_selector",
      "target_url"
    ]);
    expect(JSON.stringify(langchainSecretManagerBrowserAutomationBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerBrowserAutomationBridgeTool)).not.toContain("browser_session.page");
    expect(JSON.stringify(langchainSecretManagerBrowserAutomationBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(langchainSecretManagerBrowserAutomationBridgeTool)).not.toContain("page.fill");
    expect(JSON.stringify(langchainSecretManagerBrowserAutomationBridgeTool)).not.toContain("page.click");
    expect(JSON.stringify(langchainSecretManagerBrowserAutomationBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerBrowserAutomationBridgeTool)).not.toContain("secret_browser_value");
    expect(JSON.stringify(langchainSecretManagerBrowserAutomationBridgeTool)).not.toContain("framework vault secret submitted through browser");
    expect(JSON.stringify(langchainSecretManagerBrowserAutomationBridgeTool)).not.toContain("Fill a customer support secret");
    expect(langchainLocalFileBrowserAutomationBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainLocalFileBrowserAutomationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 6,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      external_write: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      tainted_filesystem_path: true,
      local_file_browser_automation_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_filesystem_read: true,
      handler_tainted_filesystem_path: true,
      handler_local_file_browser_automation_bridge: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainLocalFileBrowserAutomationBridgeTool?.metadata.authority_classes).toEqual(expect.arrayContaining([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "filesystem_access",
      "handler_browser_automation",
      "handler_filesystem_read",
      "handler_local_file_browser_automation_bridge",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_filesystem_path",
      "local_file_browser_automation_bridge",
      "network_access",
      "pii_input",
      "tainted_browser_automation_target",
      "tainted_filesystem_path"
    ]));
    expect(langchainLocalFileBrowserAutomationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_filesystem_read",
      "handler_local_file_browser_automation_bridge",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_filesystem_path"
    ]);
    expect(langchainLocalFileBrowserAutomationBridgeTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_BROWSER_FILE_UPLOAD_TOKEN"]);
    expect(langchainLocalFileBrowserAutomationBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "file_input_selector",
      "local_file_path",
      "submit_selector",
      "target_url",
      "upload_note_text"
    ]);
    expect(langchainLocalFileBrowserAutomationBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "file_input_selector",
      "local_file_path",
      "submit_selector",
      "target_url",
      "upload_note_text"
    ]);
    expect(JSON.stringify(langchainLocalFileBrowserAutomationBridgeTool)).not.toContain("Path(local_file_path)");
    expect(JSON.stringify(langchainLocalFileBrowserAutomationBridgeTool)).not.toContain("read_bytes");
    expect(JSON.stringify(langchainLocalFileBrowserAutomationBridgeTool)).not.toContain("browser_session.page");
    expect(JSON.stringify(langchainLocalFileBrowserAutomationBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(langchainLocalFileBrowserAutomationBridgeTool)).not.toContain("page.set_input_files");
    expect(JSON.stringify(langchainLocalFileBrowserAutomationBridgeTool)).not.toContain("page.fill");
    expect(JSON.stringify(langchainLocalFileBrowserAutomationBridgeTool)).not.toContain("page.click");
    expect(JSON.stringify(langchainLocalFileBrowserAutomationBridgeTool)).not.toContain("file_bytes");
    expect(JSON.stringify(langchainLocalFileBrowserAutomationBridgeTool)).not.toContain("framework local file uploaded through browser");
    expect(JSON.stringify(langchainLocalFileBrowserAutomationBridgeTool)).not.toContain("Upload a caller selected local file");
    expect(langchainClipboardExternalServiceBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainClipboardExternalServiceBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      external_write: true,
      external_service_write: true,
      tainted_external_service_recipient: true,
      clipboard_read: true,
      clipboard_external_service_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_external_service_write: true,
      handler_tainted_external_service_recipient: true,
      handler_clipboard_read: true,
      handler_clipboard_external_service_bridge: true,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(langchainClipboardExternalServiceBridgeTool?.metadata.authority_classes).toEqual(expect.arrayContaining([
      "clipboard_external_service_bridge",
      "clipboard_read",
      "content_input",
      "customer_data_input",
      "external_service_write",
      "external_write",
      "handler_clipboard_external_service_bridge",
      "handler_clipboard_read",
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient",
      "pii_input",
      "tainted_external_service_recipient"
    ]));
    expect(langchainClipboardExternalServiceBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_clipboard_external_service_bridge",
      "handler_clipboard_read",
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient"
    ]);
    expect(langchainClipboardExternalServiceBridgeTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_CLIPBOARD_SLACK_TOKEN"]);
    expect(langchainClipboardExternalServiceBridgeTool?.metadata.schema_properties).toEqual([
      "clipboard_reason_text",
      "customer_id",
      "destination_channel_id"
    ]);
    expect(langchainClipboardExternalServiceBridgeTool?.metadata.required_properties).toEqual([
      "clipboard_reason_text",
      "customer_id",
      "destination_channel_id"
    ]);
    expect(JSON.stringify(langchainClipboardExternalServiceBridgeTool)).not.toContain("desktop_clipboard.read_text");
    expect(JSON.stringify(langchainClipboardExternalServiceBridgeTool)).not.toContain("slack_client.chat_postMessage");
    expect(JSON.stringify(langchainClipboardExternalServiceBridgeTool)).not.toContain("clipboard_text");
    expect(JSON.stringify(langchainClipboardExternalServiceBridgeTool)).not.toContain("framework clipboard posted externally");
    expect(JSON.stringify(langchainClipboardExternalServiceBridgeTool)).not.toContain("Read clipboard text");
    expect(langchainVisualContextCaptureTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainVisualContextCaptureTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: false,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_credential_issuance: false,
      handler_tool_invocation: false,
      handler_secret_manager_access: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(langchainVisualContextCaptureTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "credential_input",
      "customer_data_input",
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_capture",
      "handler_visual_context_to_output",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_browser_automation_target",
      "visual_context_capture",
      "visual_context_to_output"
    ]);
    expect(langchainVisualContextCaptureTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_capture",
      "handler_visual_context_to_output"
    ]);
    expect(langchainVisualContextCaptureTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_BROWSER_SESSION_TOKEN"]);
    expect(langchainVisualContextCaptureTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "screenshot_reason",
      "target_url"
    ]);
    expect(langchainVisualContextCaptureTool?.metadata.required_properties).toEqual([
      "customer_id",
      "screenshot_reason",
      "target_url"
    ]);
    expect(JSON.stringify(langchainVisualContextCaptureTool)).not.toContain("browser_session.page");
    expect(JSON.stringify(langchainVisualContextCaptureTool)).not.toContain("page.goto");
    expect(JSON.stringify(langchainVisualContextCaptureTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(langchainVisualContextCaptureTool)).not.toContain("framework screenshot captured");
    expect(JSON.stringify(langchainVisualContextCaptureTool)).not.toContain("Capture an authenticated browser screenshot");
    expect(langchainVisualContextPromptBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainVisualContextPromptBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: false,
      visual_context_prompt_bridge: true,
      model_provider_call: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_model_provider_call: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: false,
      handler_visual_context_prompt_bridge: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainVisualContextPromptBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_browser_automation",
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_capture",
      "handler_visual_context_prompt_bridge",
      "model_provider_call",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_browser_automation_target",
      "visual_context_capture",
      "visual_context_prompt_bridge"
    ]);
    expect(langchainVisualContextPromptBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_capture",
      "handler_visual_context_prompt_bridge"
    ]);
    expect(langchainVisualContextPromptBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_VISUAL_MODEL_BROWSER_TOKEN",
      "LANGCHAIN_VISUAL_MODEL_PROVIDER_TOKEN"
    ]);
    expect(langchainVisualContextPromptBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "target_url",
      "visual_review_prompt_text"
    ]);
    expect(langchainVisualContextPromptBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "target_url",
      "visual_review_prompt_text"
    ]);
    expect(JSON.stringify(langchainVisualContextPromptBridgeTool)).not.toContain("browser_session.page");
    expect(JSON.stringify(langchainVisualContextPromptBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(langchainVisualContextPromptBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(langchainVisualContextPromptBridgeTool)).not.toContain("openai_client.chat.completions.create");
    expect(JSON.stringify(langchainVisualContextPromptBridgeTool)).not.toContain("screenshot_bytes");
    expect(JSON.stringify(langchainVisualContextPromptBridgeTool)).not.toContain("model_response.choices");
    expect(JSON.stringify(langchainVisualContextPromptBridgeTool)).not.toContain("framework visual context reviewed");
    expect(JSON.stringify(langchainVisualContextPromptBridgeTool)).not.toContain("Review an authenticated browser screenshot");
    expect(langchainVisualContextExternalServiceBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainVisualContextExternalServiceBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: false,
      visual_context_external_service_bridge: true,
      external_service_write: true,
      tainted_external_service_recipient: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_service_write: true,
      handler_tainted_external_service_recipient: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: false,
      handler_visual_context_external_service_bridge: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(langchainVisualContextExternalServiceBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_service_write",
      "external_write",
      "handler_browser_automation",
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_external_service_recipient",
      "handler_visual_context_capture",
      "handler_visual_context_external_service_bridge",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_browser_automation_target",
      "tainted_external_service_recipient",
      "visual_context_capture",
      "visual_context_external_service_bridge"
    ]);
    expect(langchainVisualContextExternalServiceBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_external_service_recipient",
      "handler_visual_context_capture",
      "handler_visual_context_external_service_bridge"
    ]);
    expect(langchainVisualContextExternalServiceBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_VISUAL_EXTERNAL_BROWSER_TOKEN",
      "LANGCHAIN_VISUAL_EXTERNAL_SLACK_TOKEN"
    ]);
    expect(langchainVisualContextExternalServiceBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "destination_channel_id",
      "target_url",
      "visual_note_text"
    ]);
    expect(langchainVisualContextExternalServiceBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "destination_channel_id",
      "target_url",
      "visual_note_text"
    ]);
    expect(JSON.stringify(langchainVisualContextExternalServiceBridgeTool)).not.toContain("browser_session.page");
    expect(JSON.stringify(langchainVisualContextExternalServiceBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(langchainVisualContextExternalServiceBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(langchainVisualContextExternalServiceBridgeTool)).not.toContain("screenshot_bytes");
    expect(JSON.stringify(langchainVisualContextExternalServiceBridgeTool)).not.toContain("slack_client.chat_postMessage");
    expect(JSON.stringify(langchainVisualContextExternalServiceBridgeTool)).not.toContain("authenticated-page.png");
    expect(JSON.stringify(langchainVisualContextExternalServiceBridgeTool)).not.toContain("framework visual context posted externally");
    expect(JSON.stringify(langchainVisualContextExternalServiceBridgeTool)).not.toContain("Post an authenticated browser screenshot");
    expect(langchainVisualContextMemoryBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "remember", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainVisualContextMemoryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: false,
      visual_context_memory_bridge: true,
      memory_write: true,
      tainted_memory_scope: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_memory_write: true,
      handler_tainted_memory_scope: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: false,
      handler_visual_context_memory_bridge: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(langchainVisualContextMemoryBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_browser_automation",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_memory_scope",
      "handler_visual_context_capture",
      "handler_visual_context_memory_bridge",
      "memory_access",
      "memory_write",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_browser_automation_target",
      "tainted_memory_scope",
      "visual_context_capture",
      "visual_context_memory_bridge"
    ]);
    expect(langchainVisualContextMemoryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_memory_scope",
      "handler_visual_context_capture",
      "handler_visual_context_memory_bridge"
    ]);
    expect(langchainVisualContextMemoryBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_VISUAL_MEMORY_BROWSER_TOKEN",
      "LANGCHAIN_VISUAL_MEMORY_STORE_TOKEN"
    ]);
    expect(langchainVisualContextMemoryBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "memory_namespace",
      "target_url",
      "visual_retention_note_text"
    ]);
    expect(langchainVisualContextMemoryBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "memory_namespace",
      "target_url",
      "visual_retention_note_text"
    ]);
    expect(JSON.stringify(langchainVisualContextMemoryBridgeTool)).not.toContain("browser_session.page");
    expect(JSON.stringify(langchainVisualContextMemoryBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(langchainVisualContextMemoryBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(langchainVisualContextMemoryBridgeTool)).not.toContain("screenshot_bytes");
    expect(JSON.stringify(langchainVisualContextMemoryBridgeTool)).not.toContain("memory_store.upsert");
    expect(JSON.stringify(langchainVisualContextMemoryBridgeTool)).not.toContain("framework visual context remembered");
    expect(JSON.stringify(langchainVisualContextMemoryBridgeTool)).not.toContain("Store an authenticated browser screenshot");
    expect(langchainVisualContextArtifactBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainVisualContextArtifactBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 6,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: false,
      visual_context_artifact_bridge: true,
      artifact_export: true,
      public_artifact_destination: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_artifact_export: true,
      handler_public_artifact_destination: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: false,
      handler_visual_context_artifact_bridge: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(langchainVisualContextArtifactBridgeTool?.metadata.authority_classes).toEqual([
      "artifact_export",
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "handler_artifact_export",
      "handler_browser_automation",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_artifact_bridge",
      "handler_visual_context_capture",
      "network_access",
      "pii_input",
      "public_artifact_destination",
      "secret_env_access",
      "tainted_browser_automation_target",
      "visual_context_artifact_bridge",
      "visual_context_capture"
    ]);
    expect(langchainVisualContextArtifactBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_artifact_export",
      "handler_browser_automation",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_artifact_bridge",
      "handler_visual_context_capture"
    ]);
    expect(langchainVisualContextArtifactBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_VISUAL_ARTIFACT_BROWSER_TOKEN",
      "LANGCHAIN_VISUAL_ARTIFACT_EXPORT_TOKEN"
    ]);
    expect(langchainVisualContextArtifactBridgeTool?.metadata.schema_properties).toEqual([
      "artifact_bucket",
      "customer_id",
      "object_key",
      "public_access",
      "target_url",
      "visual_artifact_note_text"
    ]);
    expect(langchainVisualContextArtifactBridgeTool?.metadata.required_properties).toEqual([
      "artifact_bucket",
      "customer_id",
      "object_key",
      "public_access",
      "target_url",
      "visual_artifact_note_text"
    ]);
    expect(JSON.stringify(langchainVisualContextArtifactBridgeTool)).not.toContain("browser_session.page");
    expect(JSON.stringify(langchainVisualContextArtifactBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(langchainVisualContextArtifactBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(langchainVisualContextArtifactBridgeTool)).not.toContain("screenshot_bytes");
    expect(JSON.stringify(langchainVisualContextArtifactBridgeTool)).not.toContain("artifact_export_client.upload");
    expect(JSON.stringify(langchainVisualContextArtifactBridgeTool)).not.toContain("framework visual context exported to artifact");
    expect(JSON.stringify(langchainVisualContextArtifactBridgeTool)).not.toContain("Export an authenticated browser screenshot");
    expect(langchainVisualContextTrainingDatasetBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainVisualContextTrainingDatasetBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: false,
      visual_context_training_dataset_bridge: true,
      training_dataset_export: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_training_dataset_export: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: false,
      handler_visual_context_training_dataset_bridge: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainVisualContextTrainingDatasetBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_training_dataset_export",
      "handler_visual_context_capture",
      "handler_visual_context_training_dataset_bridge",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_browser_automation_target",
      "training_dataset_export",
      "visual_context_capture",
      "visual_context_training_dataset_bridge"
    ]);
    expect(langchainVisualContextTrainingDatasetBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_training_dataset_export",
      "handler_visual_context_capture",
      "handler_visual_context_training_dataset_bridge"
    ]);
    expect(langchainVisualContextTrainingDatasetBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_VISUAL_TRAINING_BROWSER_TOKEN",
      "LANGCHAIN_VISUAL_TRAINING_DATASET_TOKEN"
    ]);
    expect(langchainVisualContextTrainingDatasetBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "split_name",
      "target_url",
      "training_dataset_id",
      "visual_training_label_text"
    ]);
    expect(langchainVisualContextTrainingDatasetBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "split_name",
      "target_url",
      "training_dataset_id",
      "visual_training_label_text"
    ]);
    expect(JSON.stringify(langchainVisualContextTrainingDatasetBridgeTool)).not.toContain("browser_session.page");
    expect(JSON.stringify(langchainVisualContextTrainingDatasetBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(langchainVisualContextTrainingDatasetBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(langchainVisualContextTrainingDatasetBridgeTool)).not.toContain("screenshot_bytes");
    expect(JSON.stringify(langchainVisualContextTrainingDatasetBridgeTool)).not.toContain("training_dataset_client.append_record");
    expect(JSON.stringify(langchainVisualContextTrainingDatasetBridgeTool)).not.toContain("framework visual context exported to training dataset");
    expect(JSON.stringify(langchainVisualContextTrainingDatasetBridgeTool)).not.toContain("Export an authenticated browser screenshot");
    expect(langchainVisualContextTelemetryBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainVisualContextTelemetryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: false,
      visual_context_telemetry_bridge: true,
      telemetry_export: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_telemetry_export: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: false,
      handler_visual_context_telemetry_bridge: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainVisualContextTelemetryBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_telemetry_export",
      "handler_visual_context_capture",
      "handler_visual_context_telemetry_bridge",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_browser_automation_target",
      "telemetry_export",
      "visual_context_capture",
      "visual_context_telemetry_bridge"
    ]);
    expect(langchainVisualContextTelemetryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_telemetry_export",
      "handler_visual_context_capture",
      "handler_visual_context_telemetry_bridge"
    ]);
    expect(langchainVisualContextTelemetryBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_VISUAL_TRACE_BROWSER_TOKEN",
      "LANGCHAIN_VISUAL_TRACE_EXPORT_TOKEN"
    ]);
    expect(langchainVisualContextTelemetryBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "target_url",
      "telemetry_project",
      "trace_name",
      "visual_trace_note_text"
    ]);
    expect(langchainVisualContextTelemetryBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "target_url",
      "telemetry_project",
      "trace_name",
      "visual_trace_note_text"
    ]);
    expect(JSON.stringify(langchainVisualContextTelemetryBridgeTool)).not.toContain("browser_session.page");
    expect(JSON.stringify(langchainVisualContextTelemetryBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(langchainVisualContextTelemetryBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(langchainVisualContextTelemetryBridgeTool)).not.toContain("screenshot_bytes");
    expect(JSON.stringify(langchainVisualContextTelemetryBridgeTool)).not.toContain("telemetry_client.record_trace");
    expect(JSON.stringify(langchainVisualContextTelemetryBridgeTool)).not.toContain("framework visual context exported to telemetry");
    expect(JSON.stringify(langchainVisualContextTelemetryBridgeTool)).not.toContain("Export an authenticated browser screenshot");
    expect(langchainVisualContextPromptCacheBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "remember", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainVisualContextPromptCacheBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_to_output: false,
      visual_context_prompt_cache_bridge: true,
      prompt_cache_write: true,
      tainted_prompt_cache_key: true,
      tainted_prompt_cache_value: false,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_prompt_cache_write: true,
      handler_tainted_prompt_cache_key: true,
      handler_tainted_prompt_cache_value: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_to_output: false,
      handler_visual_context_prompt_cache_bridge: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(langchainVisualContextPromptCacheBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_browser_automation",
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_prompt_cache_key",
      "handler_visual_context_capture",
      "handler_visual_context_prompt_cache_bridge",
      "network_access",
      "pii_input",
      "prompt_cache_write",
      "secret_env_access",
      "tainted_browser_automation_target",
      "tainted_prompt_cache_key",
      "visual_context_capture",
      "visual_context_prompt_cache_bridge"
    ]);
    expect(langchainVisualContextPromptCacheBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_prompt_cache_key",
      "handler_visual_context_capture",
      "handler_visual_context_prompt_cache_bridge"
    ]);
    expect(langchainVisualContextPromptCacheBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_VISUAL_PROMPT_CACHE_BROWSER_TOKEN",
      "LANGCHAIN_VISUAL_PROMPT_CACHE_TOKEN"
    ]);
    expect(langchainVisualContextPromptCacheBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "prompt_cache_key",
      "target_url",
      "visual_cache_note_text"
    ]);
    expect(langchainVisualContextPromptCacheBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "prompt_cache_key",
      "target_url",
      "visual_cache_note_text"
    ]);
    expect(JSON.stringify(langchainVisualContextPromptCacheBridgeTool)).not.toContain("browser_session.page");
    expect(JSON.stringify(langchainVisualContextPromptCacheBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(langchainVisualContextPromptCacheBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(langchainVisualContextPromptCacheBridgeTool)).not.toContain("screenshot_bytes");
    expect(JSON.stringify(langchainVisualContextPromptCacheBridgeTool)).not.toContain("prompt_cache.set");
    expect(JSON.stringify(langchainVisualContextPromptCacheBridgeTool)).not.toContain("framework visual context cached for prompts");
    expect(JSON.stringify(langchainVisualContextPromptCacheBridgeTool)).not.toContain("Write an authenticated browser screenshot");
    expect(langchainVisualContextAgentDelegationBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainVisualContextAgentDelegationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      agent_delegation: true,
      tainted_agent_delegation_target: true,
      agent_delegation_context_forwarding: true,
      visual_context_agent_delegation_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_agent_delegation: true,
      handler_tainted_agent_delegation_target: true,
      handler_agent_delegation_context_forwarding: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_agent_delegation_bridge: true,
      handler_signal_count: 8,
      open_world_schema: false
    });
    expect(langchainVisualContextAgentDelegationBridgeTool?.metadata.authority_classes).toEqual([
      "agent_delegation",
      "agent_delegation_context_forwarding",
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_agent_delegation_target",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_agent_delegation_bridge",
      "handler_visual_context_capture",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_agent_delegation_target",
      "tainted_browser_automation_target",
      "visual_context_agent_delegation_bridge",
      "visual_context_capture"
    ]);
    expect(langchainVisualContextAgentDelegationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_agent_delegation",
      "handler_agent_delegation_context_forwarding",
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_agent_delegation_target",
      "handler_tainted_browser_automation_target",
      "handler_visual_context_agent_delegation_bridge",
      "handler_visual_context_capture"
    ]);
    expect(langchainVisualContextAgentDelegationBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_VISUAL_A2A_BROWSER_TOKEN",
      "LANGCHAIN_VISUAL_A2A_TOKEN"
    ]);
    expect(langchainVisualContextAgentDelegationBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requested_task_type",
      "target_agent_url",
      "target_url",
      "visual_delegation_note_text"
    ]);
    expect(langchainVisualContextAgentDelegationBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requested_task_type",
      "target_agent_url",
      "target_url",
      "visual_delegation_note_text"
    ]);
    expect(JSON.stringify(langchainVisualContextAgentDelegationBridgeTool)).not.toContain("browser_session.page");
    expect(JSON.stringify(langchainVisualContextAgentDelegationBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(langchainVisualContextAgentDelegationBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(langchainVisualContextAgentDelegationBridgeTool)).not.toContain("screenshot_bytes");
    expect(JSON.stringify(langchainVisualContextAgentDelegationBridgeTool)).not.toContain("remote_agent_client.delegate_task");
    expect(JSON.stringify(langchainVisualContextAgentDelegationBridgeTool)).not.toContain("framework visual context delegated to remote agent");
    expect(langchainVisualContextTaskQueueBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainVisualContextTaskQueueBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      browser_automation: true,
      tainted_browser_automation_target: true,
      visual_context_capture: true,
      visual_context_task_queue_bridge: true,
      task_queue_enqueue: true,
      tainted_task_payload: true,
      tainted_task_routing: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_task_queue_enqueue: true,
      handler_tainted_task_payload: true,
      handler_tainted_task_routing: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_browser_automation: true,
      handler_tainted_browser_automation_target: true,
      handler_visual_context_capture: true,
      handler_visual_context_task_queue_bridge: true,
      handler_signal_count: 8,
      open_world_schema: false
    });
    expect(langchainVisualContextTaskQueueBridgeTool?.metadata.authority_classes).toEqual([
      "browser_automation",
      "browser_control",
      "content_input",
      "credential_input",
      "customer_data_input",
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_task_payload",
      "handler_tainted_task_routing",
      "handler_task_queue_enqueue",
      "handler_visual_context_capture",
      "handler_visual_context_task_queue_bridge",
      "network_access",
      "pii_input",
      "secret_env_access",
      "tainted_browser_automation_target",
      "tainted_task_payload",
      "tainted_task_routing",
      "task_queue_enqueue",
      "visual_context_capture",
      "visual_context_task_queue_bridge"
    ]);
    expect(langchainVisualContextTaskQueueBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_browser_automation",
      "handler_secret_env_access",
      "handler_tainted_browser_automation_target",
      "handler_tainted_task_payload",
      "handler_tainted_task_routing",
      "handler_task_queue_enqueue",
      "handler_visual_context_capture",
      "handler_visual_context_task_queue_bridge"
    ]);
    expect(langchainVisualContextTaskQueueBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_VISUAL_QUEUE_BROWSER_TOKEN",
      "LANGCHAIN_VISUAL_QUEUE_TOKEN"
    ]);
    expect(langchainVisualContextTaskQueueBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "job_route",
      "queue_name",
      "target_url",
      "visual_job_note_text"
    ]);
    expect(langchainVisualContextTaskQueueBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "job_route",
      "queue_name",
      "target_url",
      "visual_job_note_text"
    ]);
    expect(JSON.stringify(langchainVisualContextTaskQueueBridgeTool)).not.toContain("browser_session.page");
    expect(JSON.stringify(langchainVisualContextTaskQueueBridgeTool)).not.toContain("page.goto");
    expect(JSON.stringify(langchainVisualContextTaskQueueBridgeTool)).not.toContain("page.screenshot");
    expect(JSON.stringify(langchainVisualContextTaskQueueBridgeTool)).not.toContain("screenshot_bytes");
    expect(JSON.stringify(langchainVisualContextTaskQueueBridgeTool)).not.toContain("task_queue_client.enqueue");
    expect(JSON.stringify(langchainVisualContextTaskQueueBridgeTool)).not.toContain("framework visual context queued for background agent");
    expect(langchainSecretManagerAccessTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: false,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerAccessTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: false,
      agent_config_write: false,
      credential_issuance: false,
      nested_tool_invocation: false,
      browser_automation: false,
      secret_manager_access: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_credential_issuance: false,
      handler_tool_invocation: false,
      handler_browser_automation: false,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      tainted_secret_manager_path: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 2,
      open_world_schema: false
    });
    expect(langchainSecretManagerAccessTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "filesystem_access",
      "handler_secret_manager_access",
      "handler_tainted_secret_manager_path",
      "pii_input",
      "secret_manager_access",
      "tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerAccessTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_manager_access",
      "handler_tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerAccessTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainSecretManagerAccessTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(langchainSecretManagerAccessTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(langchainSecretManagerAccessTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerAccessTool)).not.toContain("secret.value");
    expect(JSON.stringify(langchainSecretManagerAccessTool)).not.toContain("Read a customer support secret");
    expect(langchainSecretManagerExternalServiceBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerExternalServiceBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      secret_manager_external_service_bridge: true,
      external_service_write: true,
      tainted_external_service_recipient: true,
      external_write: true,
      memory_write: false,
      agent_config_write: false,
      credential_issuance: false,
      nested_tool_invocation: false,
      browser_automation: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_external_service_write: true,
      handler_tainted_external_service_recipient: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_credential_issuance: false,
      handler_tool_invocation: false,
      handler_browser_automation: false,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_secret_manager_external_service_bridge: true,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainSecretManagerExternalServiceBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_service_write",
      "external_write",
      "filesystem_access",
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_external_service_bridge",
      "handler_tainted_external_service_recipient",
      "handler_tainted_secret_manager_path",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_external_service_bridge",
      "tainted_external_service_recipient",
      "tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerExternalServiceBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_external_service_bridge",
      "handler_tainted_external_service_recipient",
      "handler_tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerExternalServiceBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_SECRET_BRIDGE_SLACK_TOKEN"
    ]);
    expect(langchainSecretManagerExternalServiceBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "external_channel_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(langchainSecretManagerExternalServiceBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "external_channel_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(langchainSecretManagerExternalServiceBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerExternalServiceBridgeTool)).not.toContain("slack_client.chat_postMessage");
    expect(JSON.stringify(langchainSecretManagerExternalServiceBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerExternalServiceBridgeTool)).not.toContain("framework vault secret posted externally");
    expect(JSON.stringify(langchainSecretManagerExternalServiceBridgeTool)).not.toContain("Post a customer support secret");
    expect(langchainSecretManagerPromptBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerPromptBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      secret_manager_prompt_bridge: true,
      model_provider_call: true,
      tainted_model_selection: false,
      tool_output_prompt_bridge: false,
      secret_manager_external_service_bridge: false,
      external_service_write: false,
      external_write: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_model_provider_call: true,
      handler_tainted_model_selection: false,
      handler_secret_manager_prompt_bridge: true,
      handler_tool_output_prompt_bridge: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_secret_manager_external_service_bridge: false,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(langchainSecretManagerPromptBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "filesystem_access",
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_prompt_bridge",
      "handler_tainted_secret_manager_path",
      "model_provider_call",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_prompt_bridge",
      "tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerPromptBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_model_provider_call",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_prompt_bridge",
      "handler_tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerPromptBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_SECRET_MODEL_BRIDGE_TOKEN"
    ]);
    expect(langchainSecretManagerPromptBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(langchainSecretManagerPromptBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(langchainSecretManagerPromptBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerPromptBridgeTool)).not.toContain("openai_client.chat.completions.create");
    expect(JSON.stringify(langchainSecretManagerPromptBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerPromptBridgeTool)).not.toContain("secret_analysis_input");
    expect(JSON.stringify(langchainSecretManagerPromptBridgeTool)).not.toContain("framework vault secret summarized by model");
    expect(JSON.stringify(langchainSecretManagerPromptBridgeTool)).not.toContain("Summarize a customer support secret");
    expect(langchainSecretManagerMemoryBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: false,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerMemoryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      memory_write: true,
      tainted_memory_scope: true,
      secret_manager_memory_bridge: true,
      secret_manager_prompt_bridge: false,
      model_provider_call: false,
      secret_manager_external_service_bridge: false,
      external_service_write: false,
      external_write: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_memory_write: true,
      handler_tainted_memory_scope: true,
      handler_secret_manager_memory_bridge: true,
      handler_secret_manager_prompt_bridge: false,
      handler_model_provider_call: false,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainSecretManagerMemoryBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "filesystem_access",
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_memory_bridge",
      "handler_tainted_memory_scope",
      "handler_tainted_secret_manager_path",
      "memory_access",
      "memory_write",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_memory_bridge",
      "tainted_memory_scope",
      "tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerMemoryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_memory_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_memory_bridge",
      "handler_tainted_memory_scope",
      "handler_tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerMemoryBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_SECRET_MEMORY_BRIDGE_TOKEN"
    ]);
    expect(langchainSecretManagerMemoryBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "memory_namespace",
      "requester_ticket",
      "secret_path"
    ]);
    expect(langchainSecretManagerMemoryBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "memory_namespace",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(langchainSecretManagerMemoryBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerMemoryBridgeTool)).not.toContain("memory_store.upsert");
    expect(JSON.stringify(langchainSecretManagerMemoryBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerMemoryBridgeTool)).not.toContain("secret_memory_value");
    expect(JSON.stringify(langchainSecretManagerMemoryBridgeTool)).not.toContain("framework vault secret persisted to memory");
    expect(JSON.stringify(langchainSecretManagerMemoryBridgeTool)).not.toContain("Store a customer support secret");
    expect(langchainSecretManagerDatabaseWriteBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerDatabaseWriteBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      database_access: true,
      database_write: true,
      tainted_database_query_argument: false,
      secret_manager_database_write_bridge: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_database_query: true,
      handler_database_write: true,
      handler_tainted_database_query_argument: false,
      handler_secret_manager_database_write_bridge: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainSecretManagerDatabaseWriteBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "database_access",
      "database_write",
      "filesystem_access",
      "handler_database_query",
      "handler_database_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_database_write_bridge",
      "handler_tainted_secret_manager_path",
      "memory_access",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_database_write_bridge",
      "tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerDatabaseWriteBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_database_query",
      "handler_database_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_database_write_bridge",
      "handler_tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerDatabaseWriteBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_SECRET_DATABASE_BRIDGE_TOKEN"
    ]);
    expect(langchainSecretManagerDatabaseWriteBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "database_record_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(langchainSecretManagerDatabaseWriteBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "database_record_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(langchainSecretManagerDatabaseWriteBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerDatabaseWriteBridgeTool)).not.toContain("support_db.execute");
    expect(JSON.stringify(langchainSecretManagerDatabaseWriteBridgeTool)).not.toContain("UPDATE support_cases");
    expect(JSON.stringify(langchainSecretManagerDatabaseWriteBridgeTool)).not.toContain("vault_secret_material");
    expect(JSON.stringify(langchainSecretManagerDatabaseWriteBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerDatabaseWriteBridgeTool)).not.toContain("secret_database_value");
    expect(JSON.stringify(langchainSecretManagerDatabaseWriteBridgeTool)).not.toContain("framework vault secret stored in database");
    expect(JSON.stringify(langchainSecretManagerDatabaseWriteBridgeTool)).not.toContain("Store a customer support secret");
    expect(langchainSecretManagerEmbeddingVectorBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerEmbeddingVectorBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      embedding_provider_call: true,
      tainted_embedding_input: true,
      memory_write: true,
      tainted_memory_scope: true,
      secret_manager_memory_bridge: true,
      secret_manager_embedding_vector_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_embedding_provider_call: true,
      handler_tainted_embedding_input: true,
      handler_memory_write: true,
      handler_tainted_memory_scope: true,
      handler_secret_manager_memory_bridge: true,
      handler_secret_manager_embedding_vector_bridge: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 9,
      open_world_schema: false
    });
    for (const authorityClass of [
      "secret_manager_access",
      "tainted_secret_manager_path",
      "embedding_provider_call",
      "tainted_embedding_input",
      "memory_write",
      "tainted_memory_scope",
      "secret_manager_memory_bridge",
      "secret_manager_embedding_vector_bridge"
    ]) {
      expect(langchainSecretManagerEmbeddingVectorBridgeTool?.metadata.authority_classes).toContain(authorityClass);
    }
    for (const handlerClass of [
      "handler_secret_manager_access",
      "handler_tainted_secret_manager_path",
      "handler_embedding_provider_call",
      "handler_tainted_embedding_input",
      "handler_memory_write",
      "handler_tainted_memory_scope",
      "handler_secret_manager_memory_bridge",
      "handler_secret_manager_embedding_vector_bridge"
    ]) {
      expect(langchainSecretManagerEmbeddingVectorBridgeTool?.metadata.handler_authority_classes).toContain(handlerClass);
    }
    expect(langchainSecretManagerEmbeddingVectorBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_SECRET_VECTOR_BRIDGE_TOKEN"
    ]);
    expect(langchainSecretManagerEmbeddingVectorBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path",
      "vector_namespace"
    ]);
    expect(langchainSecretManagerEmbeddingVectorBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path",
      "vector_namespace"
    ]);
    expect(JSON.stringify(langchainSecretManagerEmbeddingVectorBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerEmbeddingVectorBridgeTool)).not.toContain("embedding_client.embed_documents");
    expect(JSON.stringify(langchainSecretManagerEmbeddingVectorBridgeTool)).not.toContain("vector_store.upsert");
    expect(JSON.stringify(langchainSecretManagerEmbeddingVectorBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerEmbeddingVectorBridgeTool)).not.toContain("secret_vector_value");
    expect(JSON.stringify(langchainSecretManagerEmbeddingVectorBridgeTool)).not.toContain("secret_embedding");
    expect(JSON.stringify(langchainSecretManagerEmbeddingVectorBridgeTool)).not.toContain("framework vault secret embedded to vector memory");
    expect(JSON.stringify(langchainSecretManagerEmbeddingVectorBridgeTool)).not.toContain("Embed a customer support secret");
    expect(langchainSecretManagerTrainingDatasetBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerTrainingDatasetBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      training_dataset_export: true,
      tainted_training_dataset_payload: false,
      secret_manager_training_dataset_bridge: true,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_training_dataset_export: true,
      handler_tainted_training_dataset_payload: false,
      handler_secret_manager_training_dataset_bridge: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 5,
      open_world_schema: false
    });
    expect(langchainSecretManagerTrainingDatasetBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "filesystem_access",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_training_dataset_bridge",
      "handler_tainted_secret_manager_path",
      "handler_training_dataset_export",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_training_dataset_bridge",
      "tainted_secret_manager_path",
      "training_dataset_export"
    ]);
    expect(langchainSecretManagerTrainingDatasetBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_training_dataset_bridge",
      "handler_tainted_secret_manager_path",
      "handler_training_dataset_export"
    ]);
    expect(langchainSecretManagerTrainingDatasetBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_SECRET_TRAINING_DATASET_BRIDGE_TOKEN"
    ]);
    expect(langchainSecretManagerTrainingDatasetBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "dataset_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(langchainSecretManagerTrainingDatasetBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "dataset_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(langchainSecretManagerTrainingDatasetBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerTrainingDatasetBridgeTool)).not.toContain("training_dataset_client.append_record");
    expect(JSON.stringify(langchainSecretManagerTrainingDatasetBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerTrainingDatasetBridgeTool)).not.toContain("secret_training_value");
    expect(JSON.stringify(langchainSecretManagerTrainingDatasetBridgeTool)).not.toContain("framework vault secret exported to training dataset");
    expect(JSON.stringify(langchainSecretManagerTrainingDatasetBridgeTool)).not.toContain("Export a customer support secret");
    expect(langchainSecretManagerFeedbackBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerFeedbackBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 6,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      feedback_pipeline_write: true,
      secret_manager_feedback_bridge: true,
      tainted_feedback_payload: false,
      feedback_auto_promotion: true,
      tainted_feedback_routing: true,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_feedback_pipeline_write: true,
      handler_secret_manager_feedback_bridge: true,
      handler_tainted_feedback_payload: false,
      handler_feedback_auto_promotion: true,
      handler_tainted_feedback_routing: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(langchainSecretManagerFeedbackBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "feedback_auto_promotion",
      "feedback_pipeline_write",
      "filesystem_access",
      "handler_feedback_auto_promotion",
      "handler_feedback_pipeline_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_feedback_bridge",
      "handler_tainted_feedback_routing",
      "handler_tainted_secret_manager_path",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_feedback_bridge",
      "tainted_feedback_routing",
      "tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerFeedbackBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_feedback_auto_promotion",
      "handler_feedback_pipeline_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_feedback_bridge",
      "handler_tainted_feedback_routing",
      "handler_tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerFeedbackBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_SECRET_FEEDBACK_BRIDGE_TOKEN"
    ]);
    expect(langchainSecretManagerFeedbackBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "eval_set_id",
      "feedback_dataset_id",
      "promotion_target",
      "reviewer_ticket",
      "secret_path"
    ]);
    expect(langchainSecretManagerFeedbackBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "eval_set_id",
      "feedback_dataset_id",
      "promotion_target",
      "reviewer_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(langchainSecretManagerFeedbackBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerFeedbackBridgeTool)).not.toContain("feedback_pipeline.promote_to_training");
    expect(JSON.stringify(langchainSecretManagerFeedbackBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerFeedbackBridgeTool)).not.toContain("secret_feedback_value");
    expect(JSON.stringify(langchainSecretManagerFeedbackBridgeTool)).not.toContain("framework vault secret promoted to feedback");
    expect(JSON.stringify(langchainSecretManagerFeedbackBridgeTool)).not.toContain("Record a customer support secret");
    expect(langchainSecretManagerArtifactBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerArtifactBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 6,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      artifact_export: true,
      secret_manager_artifact_bridge: true,
      tainted_artifact_export_payload: false,
      public_artifact_destination: true,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_artifact_export: true,
      handler_secret_manager_artifact_bridge: true,
      handler_tainted_artifact_export_payload: false,
      handler_public_artifact_destination: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainSecretManagerArtifactBridgeTool?.metadata.authority_classes).toEqual([
      "artifact_export",
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "filesystem_access",
      "handler_artifact_export",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_artifact_bridge",
      "handler_tainted_secret_manager_path",
      "pii_input",
      "public_artifact_destination",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_artifact_bridge",
      "tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerArtifactBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_artifact_export",
      "handler_public_artifact_destination",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_artifact_bridge",
      "handler_tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerArtifactBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_SECRET_ARTIFACT_BRIDGE_TOKEN"
    ]);
    expect(langchainSecretManagerArtifactBridgeTool?.metadata.schema_properties).toEqual([
      "artifact_bucket",
      "customer_id",
      "object_key",
      "public_access",
      "requester_ticket",
      "secret_path"
    ]);
    expect(langchainSecretManagerArtifactBridgeTool?.metadata.required_properties).toEqual([
      "artifact_bucket",
      "customer_id",
      "object_key",
      "public_access",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(langchainSecretManagerArtifactBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerArtifactBridgeTool)).not.toContain("artifact_export_client.upload");
    expect(JSON.stringify(langchainSecretManagerArtifactBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerArtifactBridgeTool)).not.toContain("secret_artifact_value");
    expect(JSON.stringify(langchainSecretManagerArtifactBridgeTool)).not.toContain("framework vault secret exported to artifact");
    expect(JSON.stringify(langchainSecretManagerArtifactBridgeTool)).not.toContain("Export a customer support secret");
    expect(langchainSecretManagerTelemetryBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerTelemetryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      telemetry_export: true,
      secret_manager_telemetry_bridge: true,
      tainted_telemetry_payload: true,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_telemetry_export: true,
      handler_secret_manager_telemetry_bridge: true,
      handler_tainted_telemetry_payload: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainSecretManagerTelemetryBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "filesystem_access",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_telemetry_bridge",
      "handler_tainted_secret_manager_path",
      "handler_tainted_telemetry_payload",
      "handler_telemetry_export",
      "pii_input",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_telemetry_bridge",
      "tainted_secret_manager_path",
      "tainted_telemetry_payload",
      "telemetry_export"
    ]);
    expect(langchainSecretManagerTelemetryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_telemetry_bridge",
      "handler_tainted_secret_manager_path",
      "handler_tainted_telemetry_payload",
      "handler_telemetry_export"
    ]);
    expect(langchainSecretManagerTelemetryBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_SECRET_TELEMETRY_BRIDGE_TOKEN"
    ]);
    expect(langchainSecretManagerTelemetryBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path",
      "trace_session_id"
    ]);
    expect(langchainSecretManagerTelemetryBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "requester_ticket",
      "secret_path",
      "trace_session_id"
    ]);
    expect(JSON.stringify(langchainSecretManagerTelemetryBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerTelemetryBridgeTool)).not.toContain("telemetry_client.record_trace");
    expect(JSON.stringify(langchainSecretManagerTelemetryBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerTelemetryBridgeTool)).not.toContain("secret_trace_value");
    expect(JSON.stringify(langchainSecretManagerTelemetryBridgeTool)).not.toContain("framework vault secret exported to telemetry");
    expect(JSON.stringify(langchainSecretManagerTelemetryBridgeTool)).not.toContain("Export a customer support secret");
    expect(langchainSecretManagerPromptCacheBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerPromptCacheBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      prompt_cache_write: true,
      secret_manager_prompt_cache_bridge: true,
      tainted_prompt_cache_key: true,
      tainted_prompt_cache_value: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_prompt_cache_write: true,
      handler_secret_manager_prompt_cache_bridge: true,
      handler_tainted_prompt_cache_key: true,
      handler_tainted_prompt_cache_value: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(langchainSecretManagerPromptCacheBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "filesystem_access",
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_prompt_cache_bridge",
      "handler_tainted_prompt_cache_key",
      "handler_tainted_prompt_cache_value",
      "handler_tainted_secret_manager_path",
      "pii_input",
      "prompt_cache_write",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_prompt_cache_bridge",
      "tainted_prompt_cache_key",
      "tainted_prompt_cache_value",
      "tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerPromptCacheBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_prompt_cache_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_prompt_cache_bridge",
      "handler_tainted_prompt_cache_key",
      "handler_tainted_prompt_cache_value",
      "handler_tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerPromptCacheBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_SECRET_PROMPT_CACHE_BRIDGE_TOKEN"
    ]);
    expect(langchainSecretManagerPromptCacheBridgeTool?.metadata.schema_properties).toEqual([
      "cache_key",
      "customer_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(langchainSecretManagerPromptCacheBridgeTool?.metadata.required_properties).toEqual([
      "cache_key",
      "customer_id",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(langchainSecretManagerPromptCacheBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerPromptCacheBridgeTool)).not.toContain("prompt_cache.set");
    expect(JSON.stringify(langchainSecretManagerPromptCacheBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerPromptCacheBridgeTool)).not.toContain("secret_prompt_cache_value");
    expect(JSON.stringify(langchainSecretManagerPromptCacheBridgeTool)).not.toContain("framework vault secret cached for prompts");
    expect(JSON.stringify(langchainSecretManagerPromptCacheBridgeTool)).not.toContain("Write a customer support secret");
    expect(langchainSecretManagerPromptRegistryBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainSecretManagerPromptRegistryBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 5,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_path_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      secret_manager_access: true,
      tainted_secret_manager_path: true,
      prompt_registry_write: true,
      secret_manager_prompt_registry_bridge: true,
      tainted_prompt_registry_payload: true,
      tainted_prompt_registry_selector: true,
      external_write: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_secret_manager_access: true,
      handler_tainted_secret_manager_path: true,
      handler_prompt_registry_write: true,
      handler_secret_manager_prompt_registry_bridge: true,
      handler_tainted_prompt_registry_payload: true,
      handler_tainted_prompt_registry_selector: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(langchainSecretManagerPromptRegistryBridgeTool?.metadata.authority_classes).toEqual([
      "content_input",
      "credential_input",
      "customer_data_input",
      "external_write",
      "filesystem_access",
      "handler_prompt_registry_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_prompt_registry_bridge",
      "handler_tainted_prompt_registry_payload",
      "handler_tainted_prompt_registry_selector",
      "handler_tainted_secret_manager_path",
      "pii_input",
      "prompt_registry_write",
      "secret_env_access",
      "secret_manager_access",
      "secret_manager_prompt_registry_bridge",
      "tainted_prompt_registry_payload",
      "tainted_prompt_registry_selector",
      "tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerPromptRegistryBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_prompt_registry_write",
      "handler_secret_env_access",
      "handler_secret_manager_access",
      "handler_secret_manager_prompt_registry_bridge",
      "handler_tainted_prompt_registry_payload",
      "handler_tainted_prompt_registry_selector",
      "handler_tainted_secret_manager_path"
    ]);
    expect(langchainSecretManagerPromptRegistryBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_SECRET_PROMPT_REGISTRY_BRIDGE_TOKEN"
    ]);
    expect(langchainSecretManagerPromptRegistryBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "prompt_id",
      "prompt_role",
      "requester_ticket",
      "secret_path"
    ]);
    expect(langchainSecretManagerPromptRegistryBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "prompt_id",
      "prompt_role",
      "requester_ticket",
      "secret_path"
    ]);
    expect(JSON.stringify(langchainSecretManagerPromptRegistryBridgeTool)).not.toContain("vault_client.read_secret");
    expect(JSON.stringify(langchainSecretManagerPromptRegistryBridgeTool)).not.toContain("prompt_registry_client.update_prompt");
    expect(JSON.stringify(langchainSecretManagerPromptRegistryBridgeTool)).not.toContain("secret_record.value");
    expect(JSON.stringify(langchainSecretManagerPromptRegistryBridgeTool)).not.toContain("secret_prompt_registry_value");
    expect(JSON.stringify(langchainSecretManagerPromptRegistryBridgeTool)).not.toContain("framework vault secret published to prompt registry");
    expect(JSON.stringify(langchainSecretManagerPromptRegistryBridgeTool)).not.toContain("Publish a customer support secret");
    expect(langchainExternalServiceWriteTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainExternalServiceWriteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: false,
      agent_config_write: false,
      credential_issuance: false,
      nested_tool_invocation: false,
      browser_automation: false,
      secret_manager_access: false,
      external_service_write: true,
      tainted_external_service_recipient: true,
      network_response_capture: false,
      external_write: true,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_external_service_write: true,
      handler_tainted_external_service_recipient: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_credential_issuance: false,
      handler_tool_invocation: false,
      handler_browser_automation: false,
      handler_secret_manager_access: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 3,
      open_world_schema: false
    });
    expect(langchainExternalServiceWriteTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "external_service_write",
      "external_write",
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient",
      "pii_input",
      "secret_env_access",
      "tainted_external_service_recipient"
    ]);
    expect(langchainExternalServiceWriteTool?.metadata.handler_authority_classes).toEqual([
      "handler_external_service_write",
      "handler_secret_env_access",
      "handler_tainted_external_service_recipient"
    ]);
    expect(langchainExternalServiceWriteTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_SLACK_BOT_TOKEN"]);
    expect(langchainExternalServiceWriteTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_update_text",
      "requester_ticket",
      "slack_channel_id"
    ]);
    expect(langchainExternalServiceWriteTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_update_text",
      "requester_ticket",
      "slack_channel_id"
    ]);
    expect(JSON.stringify(langchainExternalServiceWriteTool)).not.toContain("slack_client.chat_postMessage");
    expect(JSON.stringify(langchainExternalServiceWriteTool)).not.toContain("framework slack update sent");
    expect(JSON.stringify(langchainExternalServiceWriteTool)).not.toContain("Send caller supplied customer update text");
    expect(langchainModelProviderCallTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainModelProviderCallTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_secret_like_input: false,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      memory_write: false,
      agent_config_write: false,
      credential_issuance: false,
      nested_tool_invocation: false,
      browser_automation: false,
      secret_manager_access: false,
      external_service_write: false,
      model_provider_call: true,
      tainted_model_selection: true,
      privileged_prompt_composition: true,
      network_response_capture: false,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_credentialed_network_read: false,
      handler_network_response_to_output: false,
      handler_external_write: false,
      handler_external_service_write: false,
      handler_model_provider_call: true,
      handler_tainted_model_selection: true,
      handler_privileged_prompt_composition: true,
      handler_secret_env_access: true,
      handler_model_visible_output: true,
      handler_secret_to_output: false,
      handler_database_query: false,
      handler_database_write: false,
      handler_memory_write: false,
      handler_agent_config_write: false,
      handler_credential_issuance: false,
      handler_tool_invocation: false,
      handler_browser_automation: false,
      handler_secret_manager_access: false,
      handler_shell_execution: false,
      handler_dynamic_code_execution: false,
      handler_unsafe_deserialization: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4,
      open_world_schema: false
    });
    expect(langchainModelProviderCallTool?.metadata.authority_classes).toEqual([
      "content_input",
      "customer_data_input",
      "handler_model_provider_call",
      "handler_privileged_prompt_composition",
      "handler_secret_env_access",
      "handler_tainted_model_selection",
      "model_provider_call",
      "pii_input",
      "privileged_prompt_composition",
      "secret_env_access",
      "tainted_model_selection"
    ]);
    expect(langchainModelProviderCallTool?.metadata.handler_authority_classes).toEqual([
      "handler_model_provider_call",
      "handler_privileged_prompt_composition",
      "handler_secret_env_access",
      "handler_tainted_model_selection"
    ]);
    expect(langchainModelProviderCallTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_MODEL_PROVIDER_TOKEN"]);
    expect(langchainModelProviderCallTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "model_name"
    ]);
    expect(langchainModelProviderCallTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "model_name"
    ]);
    expect(JSON.stringify(langchainModelProviderCallTool)).not.toContain("openai_client.chat.completions.create");
    expect(JSON.stringify(langchainModelProviderCallTool)).not.toContain("response.choices");
    expect(JSON.stringify(langchainModelProviderCallTool)).not.toContain("Summarize caller supplied customer ticket text");
    expect(JSON.stringify(langchainModelProviderCallTool)).not.toContain("Create an internal support summary");
    expect(langchainModelOutputDynamicCodeBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainModelOutputDynamicCodeBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      model_provider_call: true,
      tainted_model_selection: true,
      dynamic_code_execution: true,
      model_output_dynamic_code_execution_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_model_provider_call: true,
      handler_tainted_model_selection: true,
      handler_dynamic_code_execution: true,
      handler_model_output_dynamic_code_execution_bridge: true,
      handler_privileged_prompt_composition: true,
      handler_secret_env_access: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainModelOutputDynamicCodeBridgeTool?.metadata.authority_classes).toEqual(expect.arrayContaining([
      "dynamic_code_execution",
      "handler_dynamic_code_execution",
      "handler_model_output_dynamic_code_execution_bridge",
      "handler_model_provider_call",
      "handler_privileged_prompt_composition",
      "handler_secret_env_access",
      "handler_tainted_model_selection",
      "model_output_dynamic_code_execution_bridge",
      "model_provider_call",
      "tainted_model_selection"
    ]));
    expect(langchainModelOutputDynamicCodeBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_dynamic_code_execution",
      "handler_model_output_dynamic_code_execution_bridge",
      "handler_model_provider_call",
      "handler_privileged_prompt_composition",
      "handler_secret_env_access",
      "handler_tainted_model_selection"
    ]);
    expect(langchainModelOutputDynamicCodeBridgeTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_MODEL_CODE_EXECUTION_TOKEN"]);
    expect(langchainModelOutputDynamicCodeBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "execution_reason_text",
      "model_name"
    ]);
    expect(langchainModelOutputDynamicCodeBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "execution_reason_text",
      "model_name"
    ]);
    expect(JSON.stringify(langchainModelOutputDynamicCodeBridgeTool)).not.toContain("openai_client.chat.completions.create");
    expect(JSON.stringify(langchainModelOutputDynamicCodeBridgeTool)).not.toContain("model_response");
    expect(JSON.stringify(langchainModelOutputDynamicCodeBridgeTool)).not.toContain("exec(");
    expect(JSON.stringify(langchainModelOutputDynamicCodeBridgeTool)).not.toContain("framework model generated code executed");
    expect(JSON.stringify(langchainModelOutputDynamicCodeBridgeTool)).not.toContain("Ask a model provider to generate code");
    expect(langchainModelOutputNetworkDestinationBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainModelOutputNetworkDestinationBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      model_provider_call: true,
      tainted_model_selection: true,
      model_output_network_destination_bridge: true,
      credentialed_network_read: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: true,
      handler_credentialed_network_read: true,
      handler_model_provider_call: true,
      handler_tainted_model_selection: true,
      handler_model_output_network_destination_bridge: true,
      handler_privileged_prompt_composition: true,
      handler_secret_env_access: true,
      handler_signal_count: 7,
      open_world_schema: false
    });
    expect(langchainModelOutputNetworkDestinationBridgeTool?.metadata.authority_classes).toEqual(expect.arrayContaining([
      "credentialed_network_read",
      "handler_credentialed_network_read",
      "handler_model_output_network_destination_bridge",
      "handler_model_provider_call",
      "handler_network_access",
      "handler_privileged_prompt_composition",
      "handler_secret_env_access",
      "handler_tainted_model_selection",
      "model_output_network_destination_bridge",
      "model_provider_call",
      "network_access",
      "tainted_model_selection"
    ]));
    expect(langchainModelOutputNetworkDestinationBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_credentialed_network_read",
      "handler_model_output_network_destination_bridge",
      "handler_model_provider_call",
      "handler_network_access",
      "handler_privileged_prompt_composition",
      "handler_secret_env_access",
      "handler_tainted_model_selection"
    ]);
    expect(langchainModelOutputNetworkDestinationBridgeTool?.metadata.handler_env_key_names).toEqual([
      "LANGCHAIN_MODEL_URL_SELECTION_TOKEN",
      "LANGCHAIN_PARTNER_STATUS_TOKEN"
    ]);
    expect(langchainModelOutputNetworkDestinationBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "investigation_scope_text",
      "model_name"
    ]);
    expect(langchainModelOutputNetworkDestinationBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "investigation_scope_text",
      "model_name"
    ]);
    expect(JSON.stringify(langchainModelOutputNetworkDestinationBridgeTool)).not.toContain("openai_client.chat.completions.create");
    expect(JSON.stringify(langchainModelOutputNetworkDestinationBridgeTool)).not.toContain("model_response");
    expect(JSON.stringify(langchainModelOutputNetworkDestinationBridgeTool)).not.toContain("selected_endpoint_url");
    expect(JSON.stringify(langchainModelOutputNetworkDestinationBridgeTool)).not.toContain("httpx.get");
    expect(JSON.stringify(langchainModelOutputNetworkDestinationBridgeTool)).not.toContain("framework model selected URL fetched");
    expect(JSON.stringify(langchainModelOutputNetworkDestinationBridgeTool)).not.toContain("Ask a model provider to choose an investigation URL");
    expect(langchainModelOutputShellExecutionBridgeTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false
    });
    expect(langchainModelOutputShellExecutionBridgeTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 4,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      accepts_content_like_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      model_provider_call: true,
      tainted_model_selection: true,
      shell_execution: true,
      model_output_shell_execution_bridge: true,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_model_provider_call: true,
      handler_tainted_model_selection: true,
      handler_shell_execution: true,
      handler_model_output_shell_execution_bridge: true,
      handler_privileged_prompt_composition: true,
      handler_secret_env_access: true,
      handler_signal_count: 6,
      open_world_schema: false
    });
    expect(langchainModelOutputShellExecutionBridgeTool?.metadata.authority_classes).toEqual(expect.arrayContaining([
      "handler_model_output_shell_execution_bridge",
      "handler_model_provider_call",
      "handler_privileged_prompt_composition",
      "handler_secret_env_access",
      "handler_shell_execution",
      "handler_tainted_model_selection",
      "model_output_shell_execution_bridge",
      "model_provider_call",
      "shell_execution",
      "tainted_model_selection"
    ]));
    expect(langchainModelOutputShellExecutionBridgeTool?.metadata.handler_authority_classes).toEqual([
      "handler_model_output_shell_execution_bridge",
      "handler_model_provider_call",
      "handler_privileged_prompt_composition",
      "handler_secret_env_access",
      "handler_shell_execution",
      "handler_tainted_model_selection"
    ]);
    expect(langchainModelOutputShellExecutionBridgeTool?.metadata.handler_env_key_names).toEqual(["LANGCHAIN_MODEL_COMMAND_TOKEN"]);
    expect(langchainModelOutputShellExecutionBridgeTool?.metadata.schema_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "model_name",
      "remediation_goal_text"
    ]);
    expect(langchainModelOutputShellExecutionBridgeTool?.metadata.required_properties).toEqual([
      "customer_id",
      "customer_ticket_text",
      "model_name",
      "remediation_goal_text"
    ]);
    expect(JSON.stringify(langchainModelOutputShellExecutionBridgeTool)).not.toContain("openai_client.chat.completions.create");
    expect(JSON.stringify(langchainModelOutputShellExecutionBridgeTool)).not.toContain("model_response");
    expect(JSON.stringify(langchainModelOutputShellExecutionBridgeTool)).not.toContain("generated_command =");
    expect(JSON.stringify(langchainModelOutputShellExecutionBridgeTool)).not.toContain("subprocess.run");
    expect(JSON.stringify(langchainModelOutputShellExecutionBridgeTool)).not.toContain("framework model generated command queued");
    expect(JSON.stringify(langchainModelOutputShellExecutionBridgeTool)).not.toContain("Ask a model provider to generate a shell command");
    expect(aiSdkExportTool).toMatchObject({
      path: "framework-tools/vercel-ai-tools.ts",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "publish", "send"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true
    });
    expect(aiSdkExportTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "vercel_ai",
      agent_framework_source_tool_registration_kind: "js_tool_factory",
      agent_framework_source_tool_argument_count: 1,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      values_collected: false,
      external_write: true,
      accepts_secret_like_input: true,
      accepts_content_like_input: true,
      accepts_url_input: true,
      accepts_pii_like_input: true,
      accepts_customer_data_input: true,
      open_world_schema: false,
      open_world_authority: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: true,
      handler_tainted_network_destination: true,
      handler_external_write: true,
      handler_secret_env_access: true,
      tainted_network_destination: true,
      handler_shell_execution: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 4
    });
    expect(aiSdkExportTool?.metadata.handler_authority_classes).toEqual([
      "handler_external_write",
      "handler_network_access",
      "handler_secret_env_access",
      "handler_tainted_network_destination"
    ]);
    expect(aiSdkExportTool?.metadata.handler_env_key_names).toEqual(["AI_SDK_EXPORT_TOKEN"]);
    expect(aiSdkExportTool?.metadata.agent_framework_source_tool_schema_styles).toEqual([
      "agent_framework_source_tool",
      "js_tool_factory",
      "vercel_ai",
      "zod_field_map",
      "zod_object",
      "zod_strict"
    ]);
    expect(aiSdkExportTool?.metadata.schema_properties).toEqual([
      "authorization_token",
      "customer_email",
      "customer_reference",
      "destination_webhook_url",
      "source_payload_text"
    ]);
    expect(aiSdkExportTool?.metadata.required_properties).toEqual([
      "authorization_token",
      "customer_email",
      "customer_reference",
      "destination_webhook_url",
      "source_payload_text"
    ]);
    expect(JSON.stringify(aiSdkExportTool)).not.toContain("ai sdk queued");
    expect(JSON.stringify(aiSdkExportTool)).not.toContain("Send AI SDK customer context to a caller supplied webhook");
    expect(JSON.stringify(aiSdkExportTool)).not.toContain("fetch(");
    expect(JSON.stringify(aiSdkExportTool)).not.toContain("Bearer");
    expect(JSON.stringify(aiSdkExportTool)).not.toContain("customerContextExportInput");
    expect(JSON.stringify(aiSdkExportTool)).not.toContain("Sensitive partner webhook schema hint");
    expect(tsLangchainDeleteTool).toMatchObject({
      path: "framework-tools/langchain_tools.ts",
      actions: ["call", "delete", "read"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false
    });
    expect(tsLangchainDeleteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "js_dynamic_structured_tool",
      agent_framework_source_tool_argument_count: 1,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      destructive_action: true,
      accepts_path_input: true,
      open_world_schema: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_shell_execution: false,
      handler_tainted_filesystem_path: true,
      tainted_filesystem_path: true,
      handler_filesystem_write: false,
      handler_filesystem_delete: true,
      handler_signal_count: 2
    });
    expect(tsLangchainDeleteTool?.metadata.authority_classes).toEqual([
      "destructive_action",
      "filesystem_access",
      "handler_filesystem_delete",
      "handler_tainted_filesystem_path",
      "tainted_filesystem_path"
    ]);
    expect(tsLangchainDeleteTool?.metadata.handler_authority_classes).toEqual([
      "handler_filesystem_delete",
      "handler_tainted_filesystem_path"
    ]);
    expect(tsLangchainDeleteTool?.metadata.handler_env_key_names).toEqual([]);
    expect(tsLangchainDeleteTool?.metadata.agent_framework_source_tool_schema_styles).toEqual([
      "agent_framework_source_tool",
      "js_dynamic_structured_tool",
      "langchain",
      "zod_field_map",
      "zod_object",
      "zod_strict"
    ]);
    expect(tsLangchainDeleteTool?.metadata.required_properties).toEqual(["workspace_path"]);
    expect(JSON.stringify(tsLangchainDeleteTool)).not.toContain("ts framework deleted");
    expect(JSON.stringify(tsLangchainDeleteTool)).not.toContain("Delete a workspace path from a TypeScript LangChain tool");
    expect(JSON.stringify(tsLangchainDeleteTool)).not.toContain("rm(");
    expect(JSON.stringify(tsLangchainDeleteTool)).not.toContain("node:fs/promises");
    expect(JSON.stringify(tsLangchainDeleteTool)).not.toContain("deleteWorkspacePathSchema");
    expect(JSON.stringify(tsLangchainDeleteTool)).not.toContain("Sensitive workspace deletion schema hint");
    const openApiTool = surfaces.tools.find((surface) => surface.path === "tools/support-openapi.yaml");
    expect(openApiTool).toMatchObject({
      name: "openapi:post:1",
      trust_level: "third_party",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      untrusted_to_privileged: true
    });
    expect(openApiTool?.metadata).toMatchObject({
      parsed_openapi_tool_spec: true,
      openapi_method: "post",
      openapi_agent_tool_import: true,
      openapi_path_redacted: true,
      openapi_operation_id_redacted: true,
      openapi_summary_redacted: true,
      openapi_server_redacted: true,
      openapi_remote_server: true,
      openapi_server_count: 1,
      openapi_security_required: true,
      openapi_security_scheme_types: ["bearer"],
      openapi_authenticated_operation: true,
      openapi_parameter_count: 1,
      openapi_request_body_present: true,
      openapi_request_schema_redacted: true,
      openapi_request_field_count: 5,
      openapi_user_controlled_input: true,
      openapi_accepts_pii_like_input: true,
      openapi_accepts_customer_data_input: true,
      openapi_prompt_content_input: true,
      openapi_prompt_content_external_write: true,
      openapi_sensitive_input: true,
      openapi_write_operation: true,
      openapi_destructive_operation: false,
      openapi_external_operation: true,
      openapi_broad_or_sensitive_scope: true,
      openapi_approval_required: false
    });
    expect(openApiTool?.metadata.openapi_server_kinds).toEqual(["remote_http_api"]);
    expect(openApiTool?.metadata.openapi_request_data_categories).toEqual([
      "credential_input",
      "customer_data",
      "freeform_content",
      "pii_input"
    ]);
    expect(JSON.stringify(openApiTool)).not.toContain("support-api.agentcsp-demo.example.invalid");
    expect(JSON.stringify(openApiTool)).not.toContain("/customers/{customer_id}/messages");
    expect(JSON.stringify(openApiTool)).not.toContain("postCustomerRemediationMessage");
    expect(JSON.stringify(openApiTool)).not.toContain("openapi_customer_email");
    expect(JSON.stringify(openApiTool)).not.toContain("openapi_authorization_token");
    const runtimeConfig = surfaces.runtime_config.find((surface) => surface.path === ".codex/config.toml");
    expect(runtimeConfig?.metadata).toMatchObject({
      parsed_runtime_config: true,
      sandbox_disabled: true,
      approval_bypass: true,
      network_enabled: true,
      privileged_tools_allowed: true,
      mcp_runtime_bridge: true,
      privileged_mcp_runtime_bridge: true,
      secret_backed_mcp_runtime_bridge: true,
      approvalless_secret_mcp_bridge: true,
      secret_env_exposure: true,
      secret_values_collected: false
    });
    expect(runtimeConfig?.metadata.env_key_names).toEqual(["GITHUB_TOKEN", "SLACK_WEBHOOK_URL"]);
    expect(runtimeConfig?.metadata.referenced_mcp_servers).toEqual(["filesystem-admin"]);
    expect(runtimeConfig?.metadata.referenced_secret_backed_mcp_servers).toEqual(["filesystem-admin"]);
    expect(runtimeConfig?.metadata.referenced_secret_backed_mcp_count).toBe(1);
    expect(runtimeConfig?.actions).toContain("execute");
    expect(runtimeConfig?.actions).toContain("send");
    expect(JSON.stringify(runtimeConfig)).not.toContain("${GITHUB_TOKEN}");
    const claudeRuntimeConfig = surfaces.runtime_config.find((surface) => surface.path === ".claude/settings.json");
    expect(claudeRuntimeConfig).toBeDefined();
    expect(claudeRuntimeConfig?.metadata).toMatchObject({
      parsed_runtime_config: true,
      approval_bypass: true,
      network_enabled: true,
      privileged_tools_allowed: true,
      auto_approved_tools_redacted: true,
      auto_approved_tool_count: 3,
      auto_approved_privileged_tool_count: 3,
      auto_approved_privileged_tool_signal_count: 4,
      auto_approved_privileged_tools: true,
      auto_approved_package_script_names: ["deploy"],
      auto_approved_mcp_servers: ["filesystem_admin"],
      auto_approved_mcp_tool_refs: ["mcp:filesystem_admin/delete_file"],
      auto_approved_mcp_tool_count: 1,
      auto_approved_destructive_mcp_servers: ["filesystem_admin"],
      auto_approved_destructive_mcp_tool_refs: ["mcp:filesystem_admin/delete_file"],
      auto_approved_destructive_mcp_tool_count: 1,
      auto_approved_destructive_mcp_tools: true,
      auto_approved_network_tools: ["WebFetch"],
      auto_approved_network_scope_kinds: ["wildcard_domain"],
      auto_approved_network_scope_count: 1,
      auto_approved_wildcard_network_scope: true,
      auto_approved_unscoped_network_tool: false,
      auto_approved_broad_network_scope: true,
      auto_approved_package_script_bridge: true,
      auto_approved_release_package_script_bridge: true,
      secret_backed_mcp_runtime_bridge: true,
      approvalless_secret_mcp_bridge: true,
      secret_env_exposure: true,
      secret_values_collected: false
    });
    expect(claudeRuntimeConfig?.metadata.permission_allowlist).toEqual(
      expect.arrayContaining(["Bash", "WebFetch", "mcp:filesystem-admin"])
    );
    expect(claudeRuntimeConfig?.metadata.auto_approved_privileged_tool_signals).toEqual(
      expect.arrayContaining(["browser", "filesystem", "mcp", "shell"])
    );
    expect(claudeRuntimeConfig?.metadata.env_key_names).toEqual(["ANTHROPIC_API_KEY", "SLACK_WEBHOOK_URL"]);
    expect(claudeRuntimeConfig?.metadata.referenced_mcp_servers).toEqual(["filesystem-admin"]);
    expect(claudeRuntimeConfig?.metadata.referenced_secret_backed_mcp_servers).toEqual(["filesystem-admin"]);
    expect(claudeRuntimeConfig?.metadata.referenced_auto_approved_package_scripts).toEqual(["package-script:deploy"]);
    expect(claudeRuntimeConfig?.metadata.referenced_release_package_scripts).toEqual(["package-script:deploy"]);
    expect(claudeRuntimeConfig?.actions).toContain("execute");
    expect(claudeRuntimeConfig?.actions).toContain("send");
    expect(JSON.stringify(claudeRuntimeConfig)).not.toContain("npm run deploy");
    expect(JSON.stringify(claudeRuntimeConfig)).not.toContain("domain:*");
    expect(JSON.stringify(claudeRuntimeConfig)).not.toContain("mcp__filesystem-admin__delete_file");
    expect(JSON.stringify(claudeRuntimeConfig)).not.toContain("${ANTHROPIC_API_KEY}");
    const telemetryConfig = surfaces.runtime_config.find((surface) => surface.path === "observability/agent-tracing.yaml");
    expect(telemetryConfig).toBeDefined();
    expect(telemetryConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(telemetryConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_ai_telemetry_config: true,
      ai_telemetry_provider: "langsmith",
      ai_telemetry_export_enabled: true,
      ai_telemetry_remote_export: true,
      ai_telemetry_destination_redacted: true,
      ai_telemetry_captures_prompts: true,
      ai_telemetry_captures_completions: true,
      ai_telemetry_captures_tool_outputs: true,
      ai_telemetry_captures_retrieval: true,
      ai_telemetry_captures_memory: true,
      ai_telemetry_sensitive_capture: true,
      ai_telemetry_pii_capture: true,
      ai_telemetry_secret_capture_signal: true,
      ai_telemetry_redaction_disabled: true,
      ai_telemetry_public_access: true,
      ai_telemetry_shared_workspace: true,
      ai_telemetry_access_control_disabled: true,
      ai_telemetry_retention_enabled: true,
      ai_telemetry_trace_replay_enabled: true,
      ai_telemetry_eval_promotion_enabled: true,
      ai_telemetry_training_promotion_enabled: true
    });
    expect(telemetryConfig?.metadata.ai_telemetry_replay_target_categories).toEqual([
      "agent_context_replay",
      "context_replay",
      "eval_dataset",
      "tool_output_replay",
      "training_dataset"
    ]);
    expect(telemetryConfig?.metadata.ai_telemetry_remote_destination_kinds).toEqual([
      "configured_endpoint",
      "http_endpoint",
      "managed_ai_observability"
    ]);
    expect(telemetryConfig?.metadata.secret_ref_key_names).toEqual(["LANGSMITH_API_KEY"]);
    expect(telemetryConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(telemetryConfig?.actions).toEqual(["call", "read", "remember", "send"]);
    expect(JSON.stringify(telemetryConfig)).not.toContain("${LANGSMITH_API_KEY}");
    expect(JSON.stringify(telemetryConfig)).not.toContain("api.smith.langchain.com");
    expect(JSON.stringify(telemetryConfig)).not.toContain("customer-support-agent");
    expect(JSON.stringify(telemetryConfig)).not.toContain("customer-support-observability");
    expect(JSON.stringify(telemetryConfig)).not.toContain("external_support_vendor");
    expect(JSON.stringify(telemetryConfig)).not.toContain("shared_public_traces");
    expect(JSON.stringify(telemetryConfig)).not.toContain("future_agent_context");
    expect(JSON.stringify(telemetryConfig)).not.toContain("redteam_eval_dataset");
    expect(JSON.stringify(telemetryConfig)).not.toContain("fine_tune_candidate_records");
    expect(JSON.stringify(telemetryConfig)).not.toContain("debugging_prompt_replay");
    const trainingDatasetConfig = surfaces.runtime_config.find(
      (surface) => surface.path === "training/fine-tune-dataset.yaml"
    );
    expect(trainingDatasetConfig).toBeDefined();
    expect(trainingDatasetConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(trainingDatasetConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_ai_training_dataset_config: true,
      ai_training_dataset_provider: "openai",
      ai_training_dataset_enabled: true,
      ai_training_dataset_export_enabled: true,
      ai_training_dataset_model_update_enabled: true,
      ai_training_dataset_remote_upload: true,
      ai_training_dataset_destination_redacted: true,
      ai_training_dataset_prompt_capture: true,
      ai_training_dataset_completion_capture: true,
      ai_training_dataset_tool_output_capture: true,
      ai_training_dataset_retrieval_capture: true,
      ai_training_dataset_memory_capture: true,
      ai_training_dataset_browser_capture: true,
      ai_training_dataset_secret_capture: true,
      ai_training_dataset_sensitive_capture: true,
      ai_training_dataset_pii_capture: true,
      ai_training_dataset_untrusted_input: true,
      ai_training_dataset_redaction_disabled: true,
      ai_training_dataset_retention_enabled: true,
      ai_training_dataset_approval_required: false
    });
    expect(trainingDatasetConfig?.metadata.ai_training_dataset_destination_kinds).toEqual([
      "configured_training_destination",
      "http_training_endpoint",
      "managed_training_provider"
    ]);
    expect(trainingDatasetConfig?.metadata.ai_training_dataset_capture_categories).toEqual([
      "browser_context",
      "completion_context",
      "memory_context",
      "pii_data",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(trainingDatasetConfig?.metadata.env_key_names).toEqual(["FINE_TUNE_TOKEN", "OPENAI_API_KEY"]);
    expect(trainingDatasetConfig?.metadata.secret_ref_key_names).toEqual(["FINE_TUNE_TOKEN", "OPENAI_API_KEY"]);
    expect(trainingDatasetConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(trainingDatasetConfig?.actions).toEqual(["call", "execute", "read", "remember", "send", "write"]);
    expect(JSON.stringify(trainingDatasetConfig)).not.toContain("${FINE_TUNE_TOKEN}");
    expect(JSON.stringify(trainingDatasetConfig)).not.toContain("api.openai.example.invalid");
    expect(JSON.stringify(trainingDatasetConfig)).not.toContain("support-escalation-finetune");
    expect(JSON.stringify(trainingDatasetConfig)).not.toContain("training_customer_email");
    expect(JSON.stringify(trainingDatasetConfig)).not.toContain("training_account_number");
    expect(JSON.stringify(trainingDatasetConfig)).not.toContain("training_confidential_agent_notes");
    expect(JSON.stringify(trainingDatasetConfig)).not.toContain("support_memory_summary");
    const feedbackPipelineConfig = surfaces.runtime_config.find((surface) => surface.path === "feedback/support-feedback-loop.yaml");
    expect(feedbackPipelineConfig).toBeDefined();
    expect(feedbackPipelineConfig).toMatchObject({
      trust_level: "third_party",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "remember", "send", "write"],
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(feedbackPipelineConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_ai_feedback_pipeline_config: true,
      ai_feedback_provider: "humanloop",
      ai_feedback_collection_enabled: true,
      ai_feedback_remote_export: true,
      ai_feedback_destination_redacted: true,
      ai_feedback_destination_count: 3,
      ai_feedback_prompt_capture: true,
      ai_feedback_completion_capture: true,
      ai_feedback_tool_output_capture: true,
      ai_feedback_retrieval_capture: true,
      ai_feedback_memory_capture: true,
      ai_feedback_browser_capture: true,
      ai_feedback_feedback_label_capture: true,
      ai_feedback_secret_capture: true,
      ai_feedback_sensitive_capture: true,
      ai_feedback_pii_capture: true,
      ai_feedback_untrusted_input: true,
      ai_feedback_training_promotion_enabled: true,
      ai_feedback_model_update_enabled: true,
      ai_feedback_eval_set_write: true,
      ai_feedback_redaction_disabled: true,
      ai_feedback_consent_required: false,
      ai_feedback_retention_enabled: true,
      ai_feedback_approval_required: false
    });
    expect(feedbackPipelineConfig?.metadata.ai_feedback_destination_kinds).toEqual([
      "configured_feedback_destination",
      "http_feedback_endpoint",
      "managed_feedback_provider"
    ]);
    expect(feedbackPipelineConfig?.metadata.ai_feedback_capture_categories).toEqual([
      "browser_context",
      "completion_context",
      "feedback_label",
      "memory_context",
      "pii_data",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(feedbackPipelineConfig?.metadata.env_key_names).toEqual(["FEEDBACK_PIPELINE_TOKEN"]);
    expect(feedbackPipelineConfig?.metadata.secret_ref_key_names).toEqual(["FEEDBACK_PIPELINE_TOKEN"]);
    expect(JSON.stringify(feedbackPipelineConfig)).not.toContain("${FEEDBACK_PIPELINE_TOKEN}");
    expect(JSON.stringify(feedbackPipelineConfig)).not.toContain("feedback.agentcsp-demo.example.invalid");
    expect(JSON.stringify(feedbackPipelineConfig)).not.toContain("untrusted_customer_rating");
    expect(JSON.stringify(feedbackPipelineConfig)).not.toContain("support_agent_freeform_feedback");
    expect(JSON.stringify(feedbackPipelineConfig)).not.toContain("feedback_customer_email");
    expect(JSON.stringify(feedbackPipelineConfig)).not.toContain("feedback_account_number");
    expect(JSON.stringify(feedbackPipelineConfig)).not.toContain("feedback_authorization_header");
    expect(JSON.stringify(feedbackPipelineConfig)).not.toContain("support-feedback-rlhf-dataset");
    const taskQueueConfig = surfaces.runtime_config.find((surface) => surface.path === "queues/support-agent-jobs.yaml");
    expect(taskQueueConfig).toBeDefined();
    expect(taskQueueConfig).toMatchObject({
      trust_level: "project",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "publish", "read", "remember", "send", "write"],
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(taskQueueConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_task_queue_config: true,
      agent_task_queue_provider: "bullmq",
      agent_task_queue_detected: true,
      agent_task_queue_remote: true,
      agent_task_queue_destination_redacted: true,
      agent_task_queue_destination_count: 4,
      agent_task_queue_background_consumer: true,
      agent_task_queue_asynchronous_execution: true,
      agent_task_queue_auto_execute: true,
      agent_task_queue_untrusted_payload: true,
      agent_task_queue_prompt_passthrough: true,
      agent_task_queue_tool_output_passthrough: true,
      agent_task_queue_retry_enabled: true,
      agent_task_queue_dead_letter_queue: true,
      agent_task_queue_replay_enabled: true,
      agent_task_queue_privileged_tool_authority: true,
      agent_task_queue_write_authority: true,
      agent_task_queue_external_authority: true,
      agent_task_queue_memory_authority: false,
      agent_task_queue_secret_exposure: true,
      agent_task_queue_sensitive_payload: true,
      agent_task_queue_pii_payload: true,
      agent_task_queue_approval_required: false
    });
    expect(taskQueueConfig?.metadata.agent_task_queue_destination_kinds).toEqual([
      "bullmq",
      "dead_letter_queue",
      "message_queue",
      "redis_queue"
    ]);
    expect(taskQueueConfig?.metadata.agent_task_queue_payload_categories).toEqual([
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(taskQueueConfig?.metadata.agent_task_queue_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(taskQueueConfig?.metadata.env_key_names).toEqual(["AGENT_TASK_QUEUE_URL"]);
    expect(taskQueueConfig?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(taskQueueConfig)).not.toContain("${AGENT_TASK_QUEUE_URL}");
    expect(JSON.stringify(taskQueueConfig)).not.toContain("customer-support-agent-jobs");
    expect(JSON.stringify(taskQueueConfig)).not.toContain("support-agent-dlq");
    expect(JSON.stringify(taskQueueConfig)).not.toContain("support_ticket_event");
    expect(JSON.stringify(taskQueueConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(taskQueueConfig)).not.toContain("queued_customer_email");
    expect(JSON.stringify(taskQueueConfig)).not.toContain("queued_customer_account_id");
    expect(JSON.stringify(taskQueueConfig)).not.toContain("queued_confidential_case_notes");
    expect(JSON.stringify(taskQueueConfig)).not.toContain("queued_support_api_token");
    const promptCacheConfig = surfaces.runtime_config.find(
      (surface) => surface.path === "prompt-cache/llm-response-cache.yaml"
    );
    expect(promptCacheConfig).toBeDefined();
    expect(promptCacheConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(promptCacheConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_llm_prompt_cache_config: true,
      llm_prompt_cache_provider: "redis",
      llm_prompt_cache_enabled: true,
      llm_prompt_cache_remote: true,
      llm_prompt_cache_shared: true,
      llm_prompt_cache_persistent: true,
      llm_prompt_cache_write_enabled: true,
      llm_prompt_cache_destination_redacted: true,
      llm_prompt_cache_prompt_capture: true,
      llm_prompt_cache_completion_capture: true,
      llm_prompt_cache_tool_output_capture: true,
      llm_prompt_cache_retrieval_capture: true,
      llm_prompt_cache_memory_capture: true,
      llm_prompt_cache_browser_capture: true,
      llm_prompt_cache_secret_capture: true,
      llm_prompt_cache_sensitive_capture: true,
      llm_prompt_cache_pii_capture: true,
      llm_prompt_cache_untrusted_input: true,
      llm_prompt_cache_semantic_reuse_enabled: true,
      llm_prompt_cache_user_controlled_key: true,
      llm_prompt_cache_broad_match_threshold: true,
      llm_prompt_cache_cross_tenant_replay: true,
      llm_prompt_cache_tenant_isolation_disabled: true,
      llm_prompt_cache_redaction_disabled: true,
      llm_prompt_cache_replay_enabled: true,
      llm_prompt_cache_retention_enabled: true,
      llm_prompt_cache_approval_required: false
    });
    expect(promptCacheConfig?.metadata.llm_prompt_cache_destination_kinds).toEqual([
      "configured_cache_destination",
      "managed_cache_store",
      "rediss_cache_endpoint"
    ]);
    expect(promptCacheConfig?.metadata.llm_prompt_cache_capture_categories).toEqual([
      "browser_context",
      "completion_context",
      "memory_context",
      "pii_data",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(promptCacheConfig?.metadata.env_key_names).toEqual(["LLM_CACHE_TOKEN", "LLM_CACHE_URL"]);
    expect(promptCacheConfig?.metadata.secret_ref_key_names).toEqual(["LLM_CACHE_TOKEN"]);
    expect(promptCacheConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(promptCacheConfig?.actions).toEqual(["call", "read", "remember", "send", "write"]);
    expect(JSON.stringify(promptCacheConfig)).not.toContain("${LLM_CACHE_TOKEN}");
    expect(JSON.stringify(promptCacheConfig)).not.toContain("${LLM_CACHE_URL}");
    expect(JSON.stringify(promptCacheConfig)).not.toContain("llm-cache.example.invalid");
    expect(JSON.stringify(promptCacheConfig)).not.toContain("support-agent-shared-cache");
    expect(JSON.stringify(promptCacheConfig)).not.toContain("cache_customer_email");
    expect(JSON.stringify(promptCacheConfig)).not.toContain("cache_account_number");
    expect(JSON.stringify(promptCacheConfig)).not.toContain("cache_confidential_agent_notes");
    expect(JSON.stringify(promptCacheConfig)).not.toContain("untrusted_customer_prompt");
    expect(JSON.stringify(promptCacheConfig)).not.toContain("global_support_semantic_cache");
    const artifactExportConfig = surfaces.runtime_config.find(
      (surface) => surface.path === "artifacts/run-export.yaml"
    );
    expect(artifactExportConfig).toBeDefined();
    expect(artifactExportConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(artifactExportConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_artifact_export_config: true,
      agent_artifact_export_provider: "s3",
      agent_artifact_export_remote: true,
      agent_artifact_export_public_access: true,
      agent_artifact_export_destination_redacted: true,
      agent_artifact_export_destination_count: 3,
      agent_artifact_export_path_redacted: true,
      agent_artifact_export_sensitive_capture: true,
      agent_artifact_export_pii_capture: true,
      agent_artifact_export_secret_capture: true,
      agent_artifact_export_browser_capture: true,
      agent_artifact_export_tool_output_capture: true,
      agent_artifact_export_memory_capture: true,
      agent_artifact_export_retrieval_capture: true,
      agent_artifact_export_prompt_capture: true,
      agent_artifact_export_write_enabled: true,
      agent_artifact_export_retention_enabled: true,
      agent_artifact_export_redaction_disabled: true,
      agent_artifact_export_approval_required: false
    });
    expect(artifactExportConfig?.metadata.agent_artifact_export_destination_kinds).toEqual([
      "configured_artifact_destination",
      "http_artifact_endpoint",
      "managed_artifact_store"
    ]);
    expect(artifactExportConfig?.metadata.agent_artifact_export_capture_categories).toEqual([
      "browser_artifact",
      "memory_context",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(artifactExportConfig?.metadata.env_key_names).toEqual(["ARTIFACT_EXPORT_TOKEN"]);
    expect(artifactExportConfig?.metadata.secret_ref_key_names).toEqual(["ARTIFACT_EXPORT_TOKEN"]);
    expect(artifactExportConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(artifactExportConfig?.actions).toEqual(["call", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(artifactExportConfig)).not.toContain("${ARTIFACT_EXPORT_TOKEN}");
    expect(JSON.stringify(artifactExportConfig)).not.toContain("agentcsp-demo-public-artifacts");
    expect(JSON.stringify(artifactExportConfig)).not.toContain("artifacts.agentcsp-demo.example.invalid");
    expect(JSON.stringify(artifactExportConfig)).not.toContain("artifact_customer_email");
    expect(JSON.stringify(artifactExportConfig)).not.toContain("artifact_account_number");
    expect(JSON.stringify(artifactExportConfig)).not.toContain("confidential_ticket_context");
    const webhookEgressConfig = surfaces.runtime_config.find(
      (surface) => surface.path === "webhooks/model-callbacks.yaml"
    );
    expect(webhookEgressConfig).toBeDefined();
    expect(webhookEgressConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(webhookEgressConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_webhook_egress_config: true,
      agent_webhook_egress_provider: "generic_webhook",
      agent_webhook_egress_remote: true,
      agent_webhook_egress_destination_redacted: true,
      agent_webhook_egress_destination_count: 3,
      agent_webhook_egress_plaintext_endpoint: false,
      agent_webhook_egress_auth_header_redacted: true,
      agent_webhook_egress_model_output_payload: true,
      agent_webhook_egress_prompt_payload: true,
      agent_webhook_egress_tool_output_payload: true,
      agent_webhook_egress_retrieval_payload: true,
      agent_webhook_egress_memory_payload: true,
      agent_webhook_egress_browser_payload: true,
      agent_webhook_egress_secret_payload: true,
      agent_webhook_egress_sensitive_payload: true,
      agent_webhook_egress_pii_payload: true,
      agent_webhook_egress_external_write_enabled: true,
      agent_webhook_egress_untrusted_input: true,
      agent_webhook_egress_redaction_disabled: true,
      agent_webhook_egress_retry_enabled: true,
      agent_webhook_egress_approval_required: false
    });
    expect(webhookEgressConfig?.metadata.agent_webhook_egress_destination_kinds).toEqual([
      "configured_webhook_destination",
      "webhook_endpoint",
      "webhook_provider"
    ]);
    expect(webhookEgressConfig?.metadata.agent_webhook_egress_payload_categories).toEqual([
      "browser_context",
      "memory_context",
      "model_output",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(webhookEgressConfig?.metadata.env_key_names).toEqual(["AGENT_WEBHOOK_TOKEN"]);
    expect(webhookEgressConfig?.metadata.secret_ref_key_names).toEqual(["AGENT_WEBHOOK_TOKEN"]);
    expect(webhookEgressConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(webhookEgressConfig?.actions).toEqual(["call", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(webhookEgressConfig)).not.toContain("${AGENT_WEBHOOK_TOKEN}");
    expect(JSON.stringify(webhookEgressConfig)).not.toContain("callback.agentcsp-demo.example.invalid");
    expect(JSON.stringify(webhookEgressConfig)).not.toContain("webhook_customer_email");
    expect(JSON.stringify(webhookEgressConfig)).not.toContain("webhook_account_number");
    expect(JSON.stringify(webhookEgressConfig)).not.toContain("confidential_callback_summary");
    const containerRuntimeConfig = surfaces.runtime_config.find(
      (surface) => surface.path === "runtime/agent-container.yaml"
    );
    expect(containerRuntimeConfig).toBeDefined();
    expect(containerRuntimeConfig).toMatchObject({
      trust_level: "workspace",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(containerRuntimeConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_container_runtime_config: true,
      agent_container_provider: "docker",
      agent_container_runtime_enabled: true,
      agent_container_privileged: true,
      agent_container_root_user: true,
      agent_container_docker_socket_mount: true,
      agent_container_host_path_mount: true,
      agent_container_host_root_mount: true,
      agent_container_writable_host_mount: true,
      agent_container_workspace_mount: false,
      agent_container_credential_mount: true,
      agent_container_sensitive_mount: true,
      agent_container_mounts_redacted: true,
      agent_container_host_network: true,
      agent_container_host_pid: true,
      agent_container_host_ipc: true,
      agent_container_network_enabled: true,
      agent_container_dangerous_capability: true,
      agent_container_shell_authority: true,
      agent_container_filesystem_authority: true,
      agent_container_browser_authority: true,
      agent_container_docker_authority: true,
      agent_container_untrusted_input: true,
      agent_container_pii_input: false,
      agent_container_secret_env_exposure: true,
      agent_container_approval_required: false
    });
    expect(containerRuntimeConfig?.metadata.agent_container_mount_kinds).toEqual([
      "credential_path",
      "docker_socket",
      "host_path",
      "host_root",
      "sensitive_host_path",
      "writable_host_path"
    ]);
    expect(containerRuntimeConfig?.metadata.agent_container_capability_categories).toEqual([
      "net_admin",
      "privileged_mode",
      "sys_admin"
    ]);
    expect(containerRuntimeConfig?.metadata.agent_container_tool_authority_categories).toEqual([
      "browser",
      "docker",
      "filesystem",
      "mcp",
      "shell"
    ]);
    expect(containerRuntimeConfig?.metadata.env_key_names).toEqual(["AGENT_CONTAINER_TOKEN", "OPENAI_API_KEY"]);
    expect(containerRuntimeConfig?.metadata.secret_ref_key_names).toEqual(["AGENT_CONTAINER_TOKEN", "OPENAI_API_KEY"]);
    expect(containerRuntimeConfig?.data_classes).toEqual(["confidential", "credential"]);
    expect(containerRuntimeConfig?.actions).toEqual(["call", "execute", "read", "send", "write"]);
    expect(JSON.stringify(containerRuntimeConfig)).not.toContain("${AGENT_CONTAINER_TOKEN}");
    expect(JSON.stringify(containerRuntimeConfig)).not.toContain("agentcsp-demo/support-agent");
    expect(JSON.stringify(containerRuntimeConfig)).not.toContain("/var/run/docker.sock");
    expect(JSON.stringify(containerRuntimeConfig)).not.toContain("~/.ssh");
    expect(JSON.stringify(containerRuntimeConfig)).not.toContain("untrusted_customer_ticket");
    const deploymentConfig = surfaces.runtime_config.find(
      (surface) => surface.path === "deployments/agent-deployment.yaml"
    );
    expect(deploymentConfig).toBeDefined();
    expect(deploymentConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(deploymentConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_deployment_config: true,
      agent_deployment_platform: "kubernetes",
      agent_deployment_agent_workload: true,
      agent_deployment_image_references_redacted: true,
      agent_deployment_image_count: 1,
      agent_deployment_remote_image: true,
      agent_deployment_unpinned_image: true,
      agent_deployment_digest_pinned: false,
      agent_deployment_pull_policy_always: true,
      agent_deployment_privileged_container: true,
      agent_deployment_root_user: true,
      agent_deployment_host_network: true,
      agent_deployment_host_mount: true,
      agent_deployment_credential_mount: true,
      agent_deployment_mounts_redacted: true,
      agent_deployment_secret_env_exposure: true,
      agent_deployment_service_account_redacted: true,
      agent_deployment_approval_required: false
    });
    expect(deploymentConfig?.metadata.agent_deployment_image_reference_kinds).toEqual([
      "latest_tag",
      "missing_digest",
      "mutable_tag",
      "remote_registry_image"
    ]);
    expect(deploymentConfig?.metadata.agent_deployment_mount_kinds).toEqual([
      "credential_path",
      "docker_socket",
      "host_path"
    ]);
    expect(deploymentConfig?.metadata.env_key_names).toEqual(["AGENT_DEPLOY_TOKEN", "OPENAI_API_KEY"]);
    expect(deploymentConfig?.metadata.secret_ref_key_names).toEqual(["AGENT_DEPLOY_TOKEN", "OPENAI_API_KEY"]);
    expect(deploymentConfig?.data_classes).toEqual(["credential", "internal"]);
    expect(deploymentConfig?.actions).toEqual(["execute", "read", "send", "write"]);
    expect(JSON.stringify(deploymentConfig)).not.toContain("${AGENT_DEPLOY_TOKEN}");
    expect(JSON.stringify(deploymentConfig)).not.toContain("ghcr.io/agentcsp-demo/support-agent");
    expect(JSON.stringify(deploymentConfig)).not.toContain("support-agent:latest");
    expect(JSON.stringify(deploymentConfig)).not.toContain("agent-admin");
    expect(JSON.stringify(deploymentConfig)).not.toContain("agent-deploy-token");
    expect(JSON.stringify(deploymentConfig)).not.toContain("model-api-token");
    expect(JSON.stringify(deploymentConfig)).not.toContain("/var/run/docker.sock");
    expect(JSON.stringify(deploymentConfig)).not.toContain("/root/.ssh");
    const codeInterpreterConfig = surfaces.runtime_config.find(
      (surface) => surface.path === "code-interpreter/python-runtime.yaml"
    );
    expect(codeInterpreterConfig).toBeDefined();
    expect(codeInterpreterConfig).toMatchObject({
      trust_level: "workspace",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(codeInterpreterConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_code_interpreter_config: true,
      agent_code_interpreter_provider: "jupyter",
      agent_code_interpreter_enabled: true,
      agent_code_interpreter_executes_model_code: true,
      agent_code_interpreter_untrusted_input: true,
      agent_code_interpreter_network_enabled: true,
      agent_code_interpreter_package_install: true,
      agent_code_interpreter_shell_access: true,
      agent_code_interpreter_filesystem_access: true,
      agent_code_interpreter_workspace_write: true,
      agent_code_interpreter_output_capture: true,
      agent_code_interpreter_output_persistence: true,
      agent_code_interpreter_mounts_redacted: true,
      agent_code_interpreter_credential_mount: true,
      agent_code_interpreter_sensitive_input: true,
      agent_code_interpreter_pii_input: false,
      agent_code_interpreter_secret_env_exposure: true,
      agent_code_interpreter_approval_required: false
    });
    expect(codeInterpreterConfig?.metadata.agent_code_interpreter_mount_kinds).toEqual([
      "credential_path",
      "host_path",
      "workspace_mount"
    ]);
    expect(codeInterpreterConfig?.metadata.env_key_names).toEqual(["CODE_INTERPRETER_TOKEN", "OPENAI_API_KEY"]);
    expect(codeInterpreterConfig?.metadata.secret_ref_key_names).toEqual([
      "CODE_INTERPRETER_TOKEN",
      "OPENAI_API_KEY"
    ]);
    expect(codeInterpreterConfig?.data_classes).toEqual(["confidential", "credential"]);
    expect(codeInterpreterConfig?.actions).toEqual(["call", "execute", "read", "remember", "send", "write"]);
    expect(JSON.stringify(codeInterpreterConfig)).not.toContain("${CODE_INTERPRETER_TOKEN}");
    expect(JSON.stringify(codeInterpreterConfig)).not.toContain("python3");
    expect(JSON.stringify(codeInterpreterConfig)).not.toContain("~/.aws");
    expect(JSON.stringify(codeInterpreterConfig)).not.toContain("~/.ssh");
    expect(JSON.stringify(codeInterpreterConfig)).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(codeInterpreterConfig)).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(codeInterpreterConfig)).not.toContain("browser_tool_output");
    const modelRouterConfig = surfaces.runtime_config.find((surface) => surface.path === "models/model-router.yaml");
    expect(modelRouterConfig).toBeDefined();
    expect(modelRouterConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(modelRouterConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_ai_model_router_config: true,
      ai_model_router_provider: "litellm",
      ai_model_router_enabled: true,
      ai_model_router_remote_providers: true,
      ai_model_router_destination_redacted: true,
      ai_model_router_fallback_enabled: true,
      ai_model_router_auto_fallback: true,
      ai_model_router_cost_or_latency_routing: true,
      ai_model_router_sends_prompts: true,
      ai_model_router_sends_tool_outputs: true,
      ai_model_router_sends_retrieval_context: true,
      ai_model_router_sends_memory: true,
      ai_model_router_sensitive_context: true,
      ai_model_router_pii_context: true,
      ai_model_router_secret_context: true,
      ai_model_router_untrusted_input: true,
      ai_model_router_redaction_disabled: true,
      ai_model_router_records_outputs: true,
      ai_model_router_approval_required: false
    });
    expect(modelRouterConfig?.metadata.ai_model_router_destination_kinds).toEqual([
      "configured_model_router_destination",
      "custom_model_gateway",
      "fallback_route",
      "http_model_endpoint",
      "managed_model_provider",
      "third_party_model_route"
    ]);
    expect(modelRouterConfig?.metadata.ai_model_router_provider_categories).toEqual([
      "custom_model_gateway",
      "fallback_provider",
      "managed_model_provider",
      "model_router",
      "third_party_model_route"
    ]);
    expect(modelRouterConfig?.metadata.env_key_names).toEqual(["FALLBACK_MODEL_TOKEN", "MODEL_ROUTER_TOKEN"]);
    expect(modelRouterConfig?.metadata.secret_ref_key_names).toEqual(["FALLBACK_MODEL_TOKEN", "MODEL_ROUTER_TOKEN"]);
    expect(modelRouterConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(modelRouterConfig?.actions).toEqual(["call", "execute", "read", "remember", "send"]);
    expect(JSON.stringify(modelRouterConfig)).not.toContain("${MODEL_ROUTER_TOKEN}");
    expect(JSON.stringify(modelRouterConfig)).not.toContain("${FALLBACK_MODEL_TOKEN}");
    expect(JSON.stringify(modelRouterConfig)).not.toContain("api.openai.example.invalid");
    expect(JSON.stringify(modelRouterConfig)).not.toContain("api.anthropic.example.invalid");
    expect(JSON.stringify(modelRouterConfig)).not.toContain("openrouter.example.invalid");
    expect(JSON.stringify(modelRouterConfig)).not.toContain("unapproved-community-model");
    expect(JSON.stringify(modelRouterConfig)).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(modelRouterConfig)).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(modelRouterConfig)).not.toContain("browser_tool_output");
    expect(JSON.stringify(modelRouterConfig)).not.toContain("support_memory_summary");
    const embeddingPipelineConfig = surfaces.runtime_config.find(
      (surface) => surface.path === "embeddings/rag-indexer.yaml"
    );
    expect(embeddingPipelineConfig).toBeDefined();
    expect(embeddingPipelineConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(embeddingPipelineConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_ai_embedding_pipeline_config: true,
      ai_embedding_provider: "openai",
      ai_embedding_enabled: true,
      ai_embedding_remote_provider: true,
      ai_embedding_destination_redacted: true,
      ai_embedding_vector_write_enabled: true,
      ai_embedding_batch_indexing: true,
      ai_embedding_auto_sync: true,
      ai_embedding_document_capture: true,
      ai_embedding_prompt_capture: true,
      ai_embedding_tool_output_capture: true,
      ai_embedding_retrieval_capture: true,
      ai_embedding_memory_capture: true,
      ai_embedding_browser_capture: true,
      ai_embedding_secret_capture: true,
      ai_embedding_sensitive_capture: true,
      ai_embedding_pii_capture: true,
      ai_embedding_untrusted_input: true,
      ai_embedding_redaction_disabled: true,
      ai_embedding_retention_enabled: true,
      ai_embedding_approval_required: false
    });
    expect(embeddingPipelineConfig?.metadata.ai_embedding_destination_kinds).toEqual([
      "configured_embedding_destination",
      "http_embedding_endpoint",
      "http_vector_store_destination",
      "managed_embedding_provider"
    ]);
    expect(embeddingPipelineConfig?.metadata.ai_embedding_capture_categories).toEqual([
      "browser_context",
      "document_context",
      "memory_context",
      "pii_data",
      "prompt_context",
      "retrieval_context",
      "secret_material",
      "tool_output"
    ]);
    expect(embeddingPipelineConfig?.metadata.env_key_names).toEqual(["EMBEDDING_API_KEY"]);
    expect(embeddingPipelineConfig?.metadata.secret_ref_key_names).toEqual(["EMBEDDING_API_KEY"]);
    expect(embeddingPipelineConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(embeddingPipelineConfig?.actions).toEqual(["call", "read", "remember", "send", "write"]);
    expect(JSON.stringify(embeddingPipelineConfig)).not.toContain("${EMBEDDING_API_KEY}");
    expect(JSON.stringify(embeddingPipelineConfig)).not.toContain("api.openai.example.invalid");
    expect(JSON.stringify(embeddingPipelineConfig)).not.toContain("text-embedding-3-large");
    expect(JSON.stringify(embeddingPipelineConfig)).not.toContain("vector-index.example.invalid");
    expect(JSON.stringify(embeddingPipelineConfig)).not.toContain("customer-support-embeddings");
    expect(JSON.stringify(embeddingPipelineConfig)).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(embeddingPipelineConfig)).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(embeddingPipelineConfig)).not.toContain("browser_tool_output");
    expect(JSON.stringify(embeddingPipelineConfig)).not.toContain("support_memory_summary");
    const modelConfig = surfaces.runtime_config.find((surface) => surface.path === "models/model-gateway.yaml");
    expect(modelConfig).toBeDefined();
    expect(modelConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(modelConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_ai_model_config: true,
      ai_model_provider: "openai_compatible",
      ai_model_remote_endpoint: true,
      ai_model_custom_endpoint: true,
      ai_model_public_endpoint: false,
      ai_model_auth_required: false,
      ai_model_auth_disabled: false,
      ai_model_destination_redacted: true,
      ai_model_plaintext_endpoint: true,
      ai_model_encrypted_endpoint: false,
      ai_model_sends_prompts: true,
      ai_model_sends_tool_outputs: true,
      ai_model_sends_retrieval_context: true,
      ai_model_sends_memory: true,
      ai_model_sensitive_context: true,
      ai_model_pii_context: true,
      ai_model_untrusted_input: true,
      ai_model_request_logging_enabled: true,
      ai_model_redaction_disabled: true,
      ai_model_tool_calling_enabled: false,
      ai_model_approval_required: false
    });
    expect(modelConfig?.metadata.ai_model_remote_destination_kinds).toEqual([
      "configured_model_endpoint",
      "http_endpoint"
    ]);
    expect(modelConfig?.metadata.secret_ref_key_names).toEqual(["OPENAI_API_KEY"]);
    expect(modelConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(modelConfig?.actions).toEqual(["call", "read", "remember", "send"]);
    expect(JSON.stringify(modelConfig)).not.toContain("${OPENAI_API_KEY}");
    expect(JSON.stringify(modelConfig)).not.toContain("llm-gateway.example.invalid");
    expect(JSON.stringify(modelConfig)).not.toContain("agentcsp-support-ops");
    const publicModelGateway = surfaces.runtime_config.find((surface) => surface.path === "models/public-gateway.yaml");
    expect(publicModelGateway).toBeDefined();
    expect(publicModelGateway).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(publicModelGateway?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_ai_model_config: true,
      ai_model_provider: "openai_compatible",
      ai_model_remote_endpoint: true,
      ai_model_custom_endpoint: true,
      ai_model_public_endpoint: true,
      ai_model_anonymous_clients: true,
      ai_model_cors_broad: true,
      ai_model_rate_limit_missing: true,
      ai_model_auth_required: false,
      ai_model_auth_disabled: true,
      ai_model_destination_redacted: true,
      ai_model_plaintext_endpoint: false,
      ai_model_encrypted_endpoint: true,
      ai_model_sends_prompts: true,
      ai_model_sends_tool_outputs: true,
      ai_model_sends_retrieval_context: true,
      ai_model_sends_memory: true,
      ai_model_sensitive_context: true,
      ai_model_pii_context: true,
      ai_model_secret_context: true,
      ai_model_untrusted_input: true,
      ai_model_request_logging_enabled: true,
      ai_model_redaction_disabled: true,
      ai_model_tool_calling_enabled: true,
      ai_model_tool_auto_execute: true,
      ai_model_tool_write_authority: true,
      ai_model_tool_external_authority: true,
      ai_model_approval_required: false
    });
    expect(publicModelGateway?.metadata.ai_model_tool_authority_categories).toEqual([
      "database_write",
      "external_response"
    ]);
    expect(publicModelGateway?.metadata.ai_model_remote_destination_kinds).toEqual([
      "configured_model_endpoint",
      "http_endpoint"
    ]);
    expect(publicModelGateway?.metadata.env_key_names).toEqual(["PUBLIC_MODEL_GATEWAY_TOKEN"]);
    expect(publicModelGateway?.metadata.secret_ref_key_names).toEqual(["PUBLIC_MODEL_GATEWAY_TOKEN"]);
    expect(publicModelGateway?.data_classes).toEqual(["confidential", "credential", "pii", "secret"]);
    expect(publicModelGateway?.actions).toEqual(["call", "execute", "read", "remember", "send", "write"]);
    expect(JSON.stringify(publicModelGateway)).not.toContain("${PUBLIC_MODEL_GATEWAY_TOKEN}");
    expect(JSON.stringify(publicModelGateway)).not.toContain("model-gateway.agentcsp-demo.example.invalid");
    expect(JSON.stringify(publicModelGateway)).not.toContain("public-support-model-gateway");
    expect(JSON.stringify(publicModelGateway)).not.toContain("support_db.write");
    expect(JSON.stringify(publicModelGateway)).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(publicModelGateway)).not.toContain("untrusted_customer_prompt");
    expect(JSON.stringify(publicModelGateway)).not.toContain("public_gateway_customer_email");
    const databaseConfig = surfaces.runtime_config.find((surface) => surface.path === "database/support-db.yaml");
    expect(databaseConfig).toBeDefined();
    expect(databaseConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(databaseConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_database_connector_config: true,
      database_provider: "postgres",
      database_remote: true,
      database_destination_redacted: true,
      database_read_enabled: true,
      database_write_enabled: true,
      database_delete_enabled: true,
      database_query_execution_enabled: true,
      database_untrusted_query_input: true,
      database_sensitive_data: true,
      database_pii_data: true,
      database_table_names_redacted: true
    });
    expect(databaseConfig?.metadata.database_remote_destination_kinds).toEqual(["database_host"]);
    expect(databaseConfig?.metadata.env_key_names).toEqual(
      expect.arrayContaining(["SUPPORT_DB_PASSWORD", "SUPPORT_DB_URL"])
    );
    expect(databaseConfig?.metadata.secret_ref_key_names).toEqual(["SUPPORT_DB_PASSWORD", "SUPPORT_DB_URL"]);
    expect(databaseConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(databaseConfig?.actions).toEqual(["call", "delete", "execute", "read", "send", "write"]);
    expect(JSON.stringify(databaseConfig)).not.toContain("${SUPPORT_DB_URL}");
    expect(JSON.stringify(databaseConfig)).not.toContain("${SUPPORT_DB_PASSWORD}");
    expect(JSON.stringify(databaseConfig)).not.toContain("support-db.example.invalid");
    expect(JSON.stringify(databaseConfig)).not.toContain("customer_profiles");
    expect(JSON.stringify(databaseConfig)).not.toContain("agent_writer");
    const agentCspPolicyConfig = surfaces.runtime_config.find((surface) => surface.path === "agentcsp.yaml");
    expect(agentCspPolicyConfig).toBeDefined();
    expect(agentCspPolicyConfig).toMatchObject({
      trust_level: "project",
      external_reach: false,
      secret_exposure: false,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(agentCspPolicyConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agentcsp_policy_config: true,
      agentcsp_policy_trust_override_count: 1,
      agentcsp_policy_trust_overrides_redacted: true,
      agentcsp_policy_marks_untrusted_context_trusted: true,
      agentcsp_policy_suppression_count: 1,
      agentcsp_policy_suppressions_redacted: true,
      agentcsp_policy_broad_suppression: true,
      agentcsp_policy_high_severity_suppression: true,
      agentcsp_policy_long_lived_suppression: true,
      agentcsp_policy_active_suppression: true,
      agentcsp_policy_recommended_control_count: 1,
      agentcsp_policy_recommended_controls_redacted: true,
      agentcsp_policy_recommended_control_downgrade: true,
      agentcsp_policy_weakens_security_controls: true
    });
    expect(agentCspPolicyConfig?.metadata.agentcsp_policy_trust_override_kinds).toEqual([
      "broad_trust_override",
      "trust_elevation",
      "untrusted_context_trusted"
    ]);
    expect(agentCspPolicyConfig?.metadata.agentcsp_policy_suppression_match_kinds).toEqual([
      "broad_match",
      "severity",
      "wildcard_path"
    ]);
    expect(agentCspPolicyConfig?.metadata.agentcsp_policy_recommended_control_downgrade_kinds).toEqual([
      "allow_broad_match",
      "allow_critical",
      "allow_sensitive_scope"
    ]);
    expect(agentCspPolicyConfig?.metadata.agentcsp_policy_weakening_controls).toEqual(["allow"]);
    expect(agentCspPolicyConfig?.actions).toEqual(["approve", "read", "write"]);
    expect(JSON.stringify(agentCspPolicyConfig)).not.toContain("rag/**");
    expect(JSON.stringify(agentCspPolicyConfig)).not.toContain("allow-critical-legacy-agent");
    expect(JSON.stringify(agentCspPolicyConfig)).not.toContain("suppress-critical-legacy-agent");
    expect(JSON.stringify(agentCspPolicyConfig)).not.toContain("security@example.com");
    expect(JSON.stringify(agentCspPolicyConfig)).not.toContain("legacy_agent_security");
    expect(JSON.stringify(agentCspPolicyConfig)).not.toContain("Fixture demonstrates risky");
    const promptRegistryConfig = surfaces.runtime_config.find(
      (surface) => surface.path === "prompt-registry/remote-prompts.yaml"
    );
    expect(promptRegistryConfig).toBeDefined();
    expect(promptRegistryConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(promptRegistryConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_prompt_registry_config: true,
      agent_prompt_registry_provider: "agent_prompt_registry",
      agent_prompt_registry_remote: true,
      agent_prompt_registry_destination_redacted: true,
      agent_prompt_registry_prompt_refs_redacted: true,
      agent_prompt_registry_prompt_ref_count: 10,
      agent_prompt_registry_auto_sync_enabled: true,
      agent_prompt_registry_unpinned_reference: true,
      agent_prompt_registry_signature_verification_disabled: true,
      agent_prompt_registry_provenance_verification_missing: true,
      agent_prompt_registry_untrusted_selector: true,
      agent_prompt_registry_privileged_role_injection: true,
      agent_prompt_registry_tool_directive: true,
      agent_prompt_registry_memory_directive: true,
      agent_prompt_registry_external_directive: true,
      agent_prompt_registry_sensitive_context: true,
      agent_prompt_registry_pii_context: true,
      agent_prompt_registry_approval_required: false
    });
    expect(promptRegistryConfig?.metadata.agent_prompt_registry_destination_kinds).toEqual(["prompt_registry_endpoint"]);
    expect(promptRegistryConfig?.metadata.agent_prompt_registry_prompt_kinds).toEqual([
      "developer_prompt",
      "prompt_template",
      "runbook",
      "system_prompt",
      "tool_instruction"
    ]);
    expect(promptRegistryConfig?.metadata.env_key_names).toEqual(["PROMPT_REGISTRY_TOKEN"]);
    expect(promptRegistryConfig?.metadata.secret_ref_key_names).toEqual(["PROMPT_REGISTRY_TOKEN"]);
    expect(promptRegistryConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(promptRegistryConfig?.actions).toEqual(["call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(promptRegistryConfig)).not.toContain("${PROMPT_REGISTRY_TOKEN}");
    expect(JSON.stringify(promptRegistryConfig)).not.toContain("prompts.agentcsp-demo.example.invalid");
    expect(JSON.stringify(promptRegistryConfig)).not.toContain("customer-escalation-system-vLatest");
    expect(JSON.stringify(promptRegistryConfig)).not.toContain("support-agent-developer-policy");
    expect(JSON.stringify(promptRegistryConfig)).not.toContain("customer_requested_prompt");
    expect(JSON.stringify(promptRegistryConfig)).not.toContain("prompt_registry_customer_email");
    expect(JSON.stringify(promptRegistryConfig)).not.toContain("confidential_prompt_context");
    expect(JSON.stringify(promptRegistryConfig)).not.toContain("support_db.update_customer_record");
    const remoteInstructionLoaderConfig = surfaces.runtime_config.find(
      (surface) => surface.path === "instruction-loader/remote-instructions.yaml"
    );
    expect(remoteInstructionLoaderConfig).toBeDefined();
    expect(remoteInstructionLoaderConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(remoteInstructionLoaderConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_remote_instruction_loader_config: true,
      agent_remote_instruction_provider: "remote_instruction_loader",
      agent_remote_instruction_remote: true,
      agent_remote_instruction_destination_redacted: true,
      agent_remote_instruction_refs_redacted: true,
      agent_remote_instruction_ref_count: 10,
      agent_remote_instruction_system_role: true,
      agent_remote_instruction_developer_role: true,
      agent_remote_instruction_auto_refresh_enabled: true,
      agent_remote_instruction_unpinned_reference: true,
      agent_remote_instruction_signature_verification_disabled: true,
      agent_remote_instruction_provenance_verification_missing: true,
      agent_remote_instruction_untrusted_selector: true,
      agent_remote_instruction_privileged_role_injection: true,
      agent_remote_instruction_privileged_tool_authority: true,
      agent_remote_instruction_write_authority: true,
      agent_remote_instruction_external_authority: true,
      agent_remote_instruction_memory_write: true,
      agent_remote_instruction_secret_access: true,
      agent_remote_instruction_sensitive_context: true,
      agent_remote_instruction_pii_context: true,
      agent_remote_instruction_approval_required: false
    });
    expect(remoteInstructionLoaderConfig?.metadata.agent_remote_instruction_destination_kinds).toEqual([
      "remote_instruction_endpoint"
    ]);
    expect(remoteInstructionLoaderConfig?.metadata.agent_remote_instruction_role_categories).toEqual([
      "developer_instruction",
      "system_instruction",
      "tool_instruction"
    ]);
    expect(remoteInstructionLoaderConfig?.metadata.agent_remote_instruction_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access"
    ]);
    expect(remoteInstructionLoaderConfig?.metadata.env_key_names).toEqual(["REMOTE_INSTRUCTION_TOKEN"]);
    expect(remoteInstructionLoaderConfig?.metadata.secret_ref_key_names).toEqual(["REMOTE_INSTRUCTION_TOKEN"]);
    expect(remoteInstructionLoaderConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(remoteInstructionLoaderConfig?.actions).toEqual(["call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(remoteInstructionLoaderConfig)).not.toContain("${REMOTE_INSTRUCTION_TOKEN}");
    expect(JSON.stringify(remoteInstructionLoaderConfig)).not.toContain("instructions.agentcsp-demo.example.invalid");
    expect(JSON.stringify(remoteInstructionLoaderConfig)).not.toContain("customer-escalation-system-latest");
    expect(JSON.stringify(remoteInstructionLoaderConfig)).not.toContain("support-agent-developer-runtime");
    expect(JSON.stringify(remoteInstructionLoaderConfig)).not.toContain("customer_requested_instruction");
    expect(JSON.stringify(remoteInstructionLoaderConfig)).not.toContain("remote_instruction_customer_email");
    expect(JSON.stringify(remoteInstructionLoaderConfig)).not.toContain("confidential_remote_instruction_notes");
    expect(JSON.stringify(remoteInstructionLoaderConfig)).not.toContain("support_db.update_customer_record");
    const agentExposureConfig = surfaces.runtime_config.find((surface) => surface.path === ".well-known/agent-card.json");
    expect(agentExposureConfig).toBeDefined();
    expect(agentExposureConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(agentExposureConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_exposure_config: true,
      agent_exposure_provider: "a2a_agent_card",
      agent_exposure_public_discovery: true,
      agent_exposure_endpoint_redacted: true,
      agent_exposure_endpoint_count: 1,
      agent_exposure_capabilities_redacted: true,
      agent_exposure_capability_count: 7,
      agent_exposure_auth_required: false,
      agent_exposure_auth_disabled: true,
      agent_exposure_anonymous_access: true,
      agent_exposure_external_callers: true,
      agent_exposure_tool_invocation_enabled: true,
      agent_exposure_privileged_authority: true,
      agent_exposure_write_authority: true,
      agent_exposure_memory_access: true,
      agent_exposure_secret_access: true,
      agent_exposure_callback_credential_reference: true,
      agent_exposure_sensitive_data: true,
      agent_exposure_pii_data: true,
      agent_exposure_rate_limit_missing: true,
      agent_exposure_approval_required: false
    });
    expect(agentExposureConfig?.metadata.agent_exposure_endpoint_kinds).toEqual(["agent_endpoint"]);
    expect(agentExposureConfig?.metadata.agent_exposure_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_access",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(agentExposureConfig?.metadata.env_key_names).toEqual(["A2A_AGENT_TOKEN"]);
    expect(agentExposureConfig?.metadata.secret_ref_key_names).toEqual(["A2A_AGENT_TOKEN"]);
    expect(agentExposureConfig?.data_classes).toEqual(["confidential", "credential", "pii", "secret"]);
    expect(agentExposureConfig?.actions).toEqual(["call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(agentExposureConfig)).not.toContain("${A2A_AGENT_TOKEN}");
    expect(JSON.stringify(agentExposureConfig)).not.toContain("support-agent.agentcsp-demo.example.invalid");
    expect(JSON.stringify(agentExposureConfig)).not.toContain("support-case-remediation-agent");
    expect(JSON.stringify(agentExposureConfig)).not.toContain("customer-record-update");
    expect(JSON.stringify(agentExposureConfig)).not.toContain("credential-assisted-remediation");
    expect(JSON.stringify(agentExposureConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(agentExposureConfig)).not.toContain("browser.submit_customer_form");
    expect(JSON.stringify(agentExposureConfig)).not.toContain("slack.post_escalation_reply");
    expect(JSON.stringify(agentExposureConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(agentExposureConfig)).not.toContain("support_memory_summary");
    expect(JSON.stringify(agentExposureConfig)).not.toContain("public_agent_registry");
    expect(JSON.stringify(agentExposureConfig)).not.toContain("partner_agents");
    expect(JSON.stringify(agentExposureConfig)).not.toContain("a2a_customer_email");
    expect(JSON.stringify(agentExposureConfig)).not.toContain("a2a_account_number");
    expect(JSON.stringify(agentExposureConfig)).not.toContain("confidential_a2a_case_notes");
    const publicChatConfig = surfaces.runtime_config.find((surface) => surface.path === "public-chat/support-widget.yaml");
    expect(publicChatConfig).toBeDefined();
    expect(publicChatConfig).toMatchObject({
      trust_level: "third_party",
      data_classes: ["confidential", "credential", "pii", "secret"],
      actions: ["call", "execute", "publish", "read", "remember", "send", "write"],
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(publicChatConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_public_agent_chat_config: true,
      public_agent_chat_enabled: true,
      public_agent_chat_endpoint_redacted: true,
      public_agent_chat_endpoint_count: 1,
      public_agent_chat_public_endpoint: true,
      public_agent_chat_anonymous_access: true,
      public_agent_chat_auth_disabled: true,
      public_agent_chat_cors_broad: true,
      public_agent_chat_csrf_disabled: true,
      public_agent_chat_rate_limit_missing: true,
      public_agent_chat_abuse_protection_disabled: true,
      public_agent_chat_file_upload_enabled: true,
      public_agent_chat_upload_raw_text: true,
      public_agent_chat_upload_sandbox_disabled: true,
      public_agent_chat_upload_scan_disabled: true,
      public_agent_chat_upload_instruction_stripping_disabled: true,
      public_agent_chat_untrusted_input: true,
      public_agent_chat_auto_tool_invocation: true,
      public_agent_chat_privileged_tool_authority: true,
      public_agent_chat_write_authority: true,
      public_agent_chat_external_response: true,
      public_agent_chat_memory_write: true,
      public_agent_chat_secret_access: true,
      public_agent_chat_sensitive_context: true,
      public_agent_chat_pii_context: true,
      public_agent_chat_redaction_disabled: true,
      public_agent_chat_approval_required: false
    });
    expect(publicChatConfig?.metadata.public_agent_chat_endpoint_kinds).toEqual(["public_chat_endpoint"]);
    expect(publicChatConfig?.metadata.public_agent_chat_tool_authority_categories).toEqual([
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(publicChatConfig?.metadata.env_key_names).toEqual(["PUBLIC_CHAT_AGENT_TOKEN"]);
    expect(publicChatConfig?.metadata.secret_ref_key_names).toEqual(["PUBLIC_CHAT_AGENT_TOKEN"]);
    expect(JSON.stringify(publicChatConfig)).not.toContain("${PUBLIC_CHAT_AGENT_TOKEN}");
    expect(JSON.stringify(publicChatConfig)).not.toContain("support.example.invalid");
    expect(JSON.stringify(publicChatConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(publicChatConfig)).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(publicChatConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(publicChatConfig)).not.toContain("memory.write_customer_summary");
    expect(JSON.stringify(publicChatConfig)).not.toContain("anonymous_website_visitor");
    expect(JSON.stringify(publicChatConfig)).not.toContain("customer_uploaded_attachment");
    expect(JSON.stringify(publicChatConfig)).not.toContain("public_chat_customer_email");
    expect(JSON.stringify(publicChatConfig)).not.toContain("public_chat_account_number");
    expect(JSON.stringify(publicChatConfig)).not.toContain("confidential_public_chat_notes");
    expect(JSON.stringify(publicChatConfig)).not.toContain("public_chat_invoice.pdf");
    expect(JSON.stringify(publicChatConfig)).not.toContain("public_chat_export.html");
    expect(JSON.stringify(publicChatConfig)).not.toContain("public_chat_support_bundle.zip");
    expect(JSON.stringify(publicChatConfig)).not.toContain("public_chat_screenshot_ocr.png");
    const debugConsoleConfig = surfaces.runtime_config.find((surface) => surface.path === "debug/agent-playground.yaml");
    expect(debugConsoleConfig).toBeDefined();
    expect(debugConsoleConfig).toMatchObject({
      trust_level: "third_party",
      data_classes: ["confidential", "credential", "pii", "secret"],
      actions: ["call", "execute", "publish", "read", "remember", "send", "write"],
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(debugConsoleConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_debug_console_config: true,
      agent_debug_console_enabled: true,
      agent_debug_console_endpoint_redacted: true,
      agent_debug_console_endpoint_count: 1,
      agent_debug_console_public_endpoint: true,
      agent_debug_console_anonymous_access: true,
      agent_debug_console_auth_disabled: true,
      agent_debug_console_cors_broad: true,
      agent_debug_console_prompt_view_enabled: true,
      agent_debug_console_system_prompt_visible: true,
      agent_debug_console_developer_prompt_visible: true,
      agent_debug_console_raw_context_visible: true,
      agent_debug_console_trace_view_enabled: true,
      agent_debug_console_memory_view_enabled: true,
      agent_debug_console_tool_schema_visible: true,
      agent_debug_console_prompt_edit_enabled: true,
      agent_debug_console_tool_invocation_enabled: true,
      agent_debug_console_impersonation_enabled: true,
      agent_debug_console_privileged_tool_authority: true,
      agent_debug_console_write_authority: true,
      agent_debug_console_external_authority: true,
      agent_debug_console_memory_write_authority: true,
      agent_debug_console_secret_context_visible: true,
      agent_debug_console_sensitive_context: true,
      agent_debug_console_pii_context: true,
      agent_debug_console_redaction_disabled: true,
      agent_debug_console_audit_logging_disabled: true,
      agent_debug_console_approval_required: false
    });
    expect(debugConsoleConfig?.metadata.agent_debug_console_endpoint_kinds).toEqual(["debug_console_endpoint"]);
    expect(debugConsoleConfig?.metadata.agent_debug_console_tool_authority_categories).toEqual([
      "database_write",
      "external_response",
      "memory_write",
      "prompt_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(debugConsoleConfig?.metadata.env_key_names).toEqual(["DEBUG_CONSOLE_TOKEN"]);
    expect(debugConsoleConfig?.metadata.secret_ref_key_names).toEqual(["DEBUG_CONSOLE_TOKEN"]);
    expect(JSON.stringify(debugConsoleConfig)).not.toContain("${DEBUG_CONSOLE_TOKEN}");
    expect(JSON.stringify(debugConsoleConfig)).not.toContain("debug.agentcsp-demo.example.invalid");
    expect(JSON.stringify(debugConsoleConfig)).not.toContain("support_agent_system_prompt");
    expect(JSON.stringify(debugConsoleConfig)).not.toContain("developer_override_prompt");
    expect(JSON.stringify(debugConsoleConfig)).not.toContain("debug_customer_email");
    expect(JSON.stringify(debugConsoleConfig)).not.toContain("debug_account_number");
    expect(JSON.stringify(debugConsoleConfig)).not.toContain("confidential_debug_trace");
    expect(JSON.stringify(debugConsoleConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(debugConsoleConfig)).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(debugConsoleConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(debugConsoleConfig)).not.toContain("memory.write_debug_summary");
    const responseStreamConfig = surfaces.runtime_config.find((surface) => surface.path === "responses/public-stream.yaml");
    expect(responseStreamConfig).toBeDefined();
    expect(responseStreamConfig).toMatchObject({
      trust_level: "third_party",
      data_classes: ["confidential", "credential", "pii", "secret"],
      actions: ["publish", "read", "send"],
      external_reach: true,
      secret_exposure: true,
      side_effect: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(responseStreamConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_response_exposure_config: true,
      agent_response_exposure_enabled: true,
      agent_response_exposure_endpoint_redacted: true,
      agent_response_exposure_endpoint_count: 1,
      agent_response_exposure_public_endpoint: true,
      agent_response_exposure_anonymous_access: true,
      agent_response_exposure_auth_disabled: true,
      agent_response_exposure_cors_broad: true,
      agent_response_exposure_streaming_enabled: true,
      agent_response_exposure_reasoning_visible: true,
      agent_response_exposure_system_prompt_visible: true,
      agent_response_exposure_developer_prompt_visible: true,
      agent_response_exposure_tool_output_visible: true,
      agent_response_exposure_tool_argument_visible: true,
      agent_response_exposure_retrieval_visible: true,
      agent_response_exposure_memory_visible: true,
      agent_response_exposure_secret_context_visible: true,
      agent_response_exposure_sensitive_context: true,
      agent_response_exposure_pii_context: true,
      agent_response_exposure_redaction_disabled: true,
      agent_response_exposure_external_response: false,
      agent_response_exposure_approval_required: false
    });
    expect(responseStreamConfig?.metadata.agent_response_exposure_endpoint_kinds).toEqual(["response_stream_endpoint"]);
    expect(responseStreamConfig?.metadata.env_key_names).toEqual(["RESPONSE_STREAM_TOKEN"]);
    expect(responseStreamConfig?.metadata.secret_ref_key_names).toEqual(["RESPONSE_STREAM_TOKEN"]);
    expect(JSON.stringify(responseStreamConfig)).not.toContain("${RESPONSE_STREAM_TOKEN}");
    expect(JSON.stringify(responseStreamConfig)).not.toContain("stream.agentcsp-demo.example.invalid");
    expect(JSON.stringify(responseStreamConfig)).not.toContain("response_stream_customer_email");
    expect(JSON.stringify(responseStreamConfig)).not.toContain("response_stream_account_number");
    expect(JSON.stringify(responseStreamConfig)).not.toContain("confidential_response_stream_notes");
    expect(JSON.stringify(responseStreamConfig)).not.toContain("response_stream_api_token");
    const actionRouterConfig = surfaces.runtime_config.find((surface) => surface.path === "action-router/model-actions.yaml");
    expect(actionRouterConfig).toBeDefined();
    expect(actionRouterConfig).toMatchObject({
      trust_level: "third_party",
      data_classes: ["confidential", "credential", "pii", "secret"],
      actions: ["call", "execute", "publish", "read", "remember", "send", "write"],
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(actionRouterConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_action_router_config: true,
      agent_action_router_enabled: true,
      agent_action_router_model_output_input: true,
      agent_action_router_untrusted_input: true,
      agent_action_router_schema_validation_disabled: true,
      agent_action_router_strict_schema: false,
      agent_action_router_open_action_schema: true,
      agent_action_router_unknown_actions_allowed: true,
      agent_action_router_json_repair_enabled: true,
      agent_action_router_batch_execution_enabled: true,
      agent_action_router_auto_execute: true,
      agent_action_router_privileged_tool_authority: true,
      agent_action_router_write_authority: true,
      agent_action_router_external_authority: true,
      agent_action_router_memory_authority: true,
      agent_action_router_secret_access: true,
      agent_action_router_shell_authority: true,
      agent_action_router_sensitive_context: true,
      agent_action_router_pii_context: true,
      agent_action_router_redaction_disabled: true,
      agent_action_router_dry_run_disabled: true,
      agent_action_router_approval_required: false
    });
    expect(actionRouterConfig?.metadata.agent_action_router_action_format_categories).toEqual([
      "action_dsl",
      "json",
      "markdown_fenced",
      "yaml"
    ]);
    expect(actionRouterConfig?.metadata.agent_action_router_tool_authority_categories).toEqual([
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ]);
    expect(actionRouterConfig?.metadata.env_key_names).toEqual(["ACTION_ROUTER_TOKEN"]);
    expect(actionRouterConfig?.metadata.secret_ref_key_names).toEqual(["ACTION_ROUTER_TOKEN"]);
    expect(JSON.stringify(actionRouterConfig)).not.toContain("${ACTION_ROUTER_TOKEN}");
    expect(JSON.stringify(actionRouterConfig)).not.toContain("untrusted_customer_message");
    expect(JSON.stringify(actionRouterConfig)).not.toContain("retrieved_runbook_instruction");
    expect(JSON.stringify(actionRouterConfig)).not.toContain("browser_tool_output");
    expect(JSON.stringify(actionRouterConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(actionRouterConfig)).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(actionRouterConfig)).not.toContain("shell.run_remediation");
    expect(JSON.stringify(actionRouterConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(actionRouterConfig)).not.toContain("memory.write_action_summary");
    expect(JSON.stringify(actionRouterConfig)).not.toContain("action_router_customer_email");
    expect(JSON.stringify(actionRouterConfig)).not.toContain("action_router_account_number");
    expect(JSON.stringify(actionRouterConfig)).not.toContain("confidential_action_router_notes");
    const agentFederationConfig = surfaces.runtime_config.find((surface) => surface.path === "agent-federation/remote-agents.yaml");
    expect(agentFederationConfig).toBeDefined();
    expect(agentFederationConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(agentFederationConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_federation_config: true,
      agent_federation_provider: "a2a",
      agent_federation_remote: true,
      agent_federation_destination_redacted: true,
      agent_federation_destination_count: 3,
      agent_federation_agent_refs_redacted: true,
      agent_federation_agent_ref_count: 2,
      agent_federation_dynamic_discovery: true,
      agent_federation_untrusted_selector: true,
      agent_federation_auto_delegation_enabled: true,
      agent_federation_context_forwarding_enabled: true,
      agent_federation_sensitive_context_forwarding: true,
      agent_federation_pii_context_forwarding: true,
      agent_federation_secret_forwarding: true,
      agent_federation_tool_result_forwarding: true,
      agent_federation_memory_forwarding: true,
      agent_federation_credential_forwarding: true,
      agent_federation_signature_verification_disabled: true,
      agent_federation_identity_verification_missing: true,
      agent_federation_allowlist_missing: true,
      agent_federation_approval_required: false
    });
    expect(agentFederationConfig?.metadata.agent_federation_destination_kinds).toEqual([
      "agent_registry",
      "remote_agent_card"
    ]);
    expect(agentFederationConfig?.metadata.env_key_names).toEqual(["A2A_FEDERATION_TOKEN"]);
    expect(agentFederationConfig?.metadata.secret_ref_key_names).toEqual(["A2A_FEDERATION_TOKEN"]);
    expect(agentFederationConfig?.data_classes).toEqual(["confidential", "credential", "pii", "secret"]);
    expect(agentFederationConfig?.actions).toEqual(["call", "execute", "publish", "read", "remember", "send"]);
    expect(JSON.stringify(agentFederationConfig)).not.toContain("${A2A_FEDERATION_TOKEN}");
    expect(JSON.stringify(agentFederationConfig)).not.toContain("agents.agentcsp-demo.example.invalid");
    expect(JSON.stringify(agentFederationConfig)).not.toContain("refunds.agentcsp-demo.example.invalid");
    expect(JSON.stringify(agentFederationConfig)).not.toContain("partner-agent.agentcsp-demo.example.invalid");
    expect(JSON.stringify(agentFederationConfig)).not.toContain("refund-case-agent");
    expect(JSON.stringify(agentFederationConfig)).not.toContain("partner-remediation-agent");
    expect(JSON.stringify(agentFederationConfig)).not.toContain("customer_requested_agent");
    expect(JSON.stringify(agentFederationConfig)).not.toContain("a2a_federation_customer_email");
    expect(JSON.stringify(agentFederationConfig)).not.toContain("confidential_federated_case_notes");
    expect(JSON.stringify(agentFederationConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(agentFederationConfig)).not.toContain("support_memory_summary");
    const mcpAuthorizationConfig = surfaces.runtime_config.find((surface) => surface.path === "mcp-auth/oauth-client.yaml");
    expect(mcpAuthorizationConfig).toBeDefined();
    expect(mcpAuthorizationConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(mcpAuthorizationConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_mcp_authorization_config: true,
      mcp_authorization_provider: "mcp_oauth",
      mcp_authorization_remote: true,
      mcp_authorization_destination_redacted: true,
      mcp_authorization_destination_count: 5,
      mcp_authorization_plaintext_endpoint: true,
      mcp_authorization_plaintext_oauth_endpoint: true,
      mcp_authorization_plaintext_mcp_resource_endpoint: true,
      mcp_authorization_dynamic_client_registration: true,
      mcp_authorization_client_secret_exposure: true,
      mcp_authorization_public_client: true,
      mcp_authorization_device_flow_enabled: true,
      mcp_authorization_device_endpoint_redacted: true,
      mcp_authorization_device_code_context_exposure: true,
      mcp_authorization_device_verification_uri_untrusted: true,
      mcp_authorization_device_polling_without_approval: true,
      mcp_authorization_redirect_uri_redacted: true,
      mcp_authorization_redirect_uri_count: 7,
      mcp_authorization_wildcard_redirect_uri: true,
      mcp_authorization_user_or_model_selected_redirect_uri: true,
      mcp_authorization_redirect_validation_disabled: true,
      mcp_authorization_pkce_disabled: true,
      mcp_authorization_state_validation_disabled: true,
      mcp_authorization_resource_indicator_missing: true,
      mcp_authorization_scope_redacted: true,
      mcp_authorization_broad_scope: true,
      mcp_authorization_sensitive_scope: true,
      mcp_authorization_pii_scope: true,
      mcp_authorization_refresh_token_storage: true,
      mcp_authorization_token_forwarding: true,
      mcp_authorization_untrusted_server: true,
      mcp_authorization_approval_required: false
    });
    expect(mcpAuthorizationConfig?.metadata.mcp_authorization_destination_kinds).toEqual([
      "authorization_server_metadata",
      "device_authorization_endpoint",
      "dynamic_client_registration_endpoint",
      "mcp_authorization_config",
      "plaintext_mcp_resource_endpoint",
      "plaintext_protected_resource_metadata"
    ]);
    expect(mcpAuthorizationConfig?.metadata.mcp_authorization_redirect_uri_kinds).toEqual([
      "unvalidated_redirect_uri",
      "user_or_model_selected_redirect_uri",
      "wildcard_redirect_uri"
    ]);
    expect(mcpAuthorizationConfig?.metadata.mcp_authorization_scope_kinds).toEqual([
      "agent_resource_scope",
      "broad_scope",
      "identity_or_pii_scope",
      "write_scope"
    ]);
    expect(mcpAuthorizationConfig?.metadata.env_key_names).toEqual(["MCP_OAUTH_CLIENT_SECRET"]);
    expect(mcpAuthorizationConfig?.metadata.secret_ref_key_names).toEqual(["MCP_OAUTH_CLIENT_SECRET"]);
    expect(mcpAuthorizationConfig?.data_classes).toEqual(["confidential", "credential", "pii", "secret"]);
    expect(mcpAuthorizationConfig?.actions).toEqual(["call", "read", "remember", "send", "write"]);
    expect(JSON.stringify(mcpAuthorizationConfig)).not.toContain("${MCP_OAUTH_CLIENT_SECRET}");
    expect(JSON.stringify(mcpAuthorizationConfig)).not.toContain("oauth-mcp.agentcsp-demo.example.invalid");
    expect(JSON.stringify(mcpAuthorizationConfig)).not.toContain("authz.agentcsp-demo.example.invalid");
    expect(JSON.stringify(mcpAuthorizationConfig)).not.toContain("mcp:tools:*");
    expect(JSON.stringify(mcpAuthorizationConfig)).not.toContain("support_db.write");
    expect(JSON.stringify(mcpAuthorizationConfig)).not.toContain("wildcard_customer_callback");
    expect(JSON.stringify(mcpAuthorizationConfig)).not.toContain("customer_provided_redirect_uri");
    expect(JSON.stringify(mcpAuthorizationConfig)).not.toContain("customer_device_user_code");
    expect(JSON.stringify(mcpAuthorizationConfig)).not.toContain("untrusted_mcp_metadata");
    expect(JSON.stringify(mcpAuthorizationConfig)).not.toContain("customer_requested_mcp_server");
    expect(JSON.stringify(mcpAuthorizationConfig)).not.toContain("mcp_oauth_customer_email");
    expect(JSON.stringify(mcpAuthorizationConfig)).not.toContain(".auth/mcp-oauth-tokens.json");
    const browserSessionConfig = surfaces.runtime_config.find((surface) => surface.path === "browser/session.yaml");
    expect(browserSessionConfig).toBeDefined();
    expect(browserSessionConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(browserSessionConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_browser_session_config: true,
      browser_provider: "playwright",
      browser_persistent_profile: true,
      browser_cookie_storage: true,
      browser_session_storage: true,
      browser_authenticated_session: true,
      browser_remote_debugging: true,
      browser_untrusted_navigation: true,
      browser_click_or_form_authority: true,
      browser_download_upload_enabled: true,
      browser_download_auto_accept: true,
      browser_download_raw_content: true,
      browser_download_passes_to_agent_context: true,
      browser_download_sandbox_disabled: true,
      browser_download_scan_disabled: true,
      browser_download_instruction_stripping_disabled: true,
      browser_file_chooser_enabled: true,
      browser_extensions_redacted: true,
      browser_extension_count: 2,
      browser_extension_privileged_permissions: true,
      browser_extension_automation: true,
      browser_password_manager_enabled: true,
      browser_autofill_sensitive_data: true,
      browser_download_path_redacted: true,
      browser_upload_path_redacted: true,
      browser_network_remote: true,
      browser_broad_origin_access: true,
      browser_destination_redacted: true,
      browser_path_references_redacted: true,
      browser_sensitive_data: true,
      browser_pii_data: true,
      browser_approval_required: false
    });
    expect(browserSessionConfig?.metadata.browser_destination_kinds).toEqual([
      "browser_endpoint",
      "wildcard_origin"
    ]);
    expect(browserSessionConfig?.metadata.browser_extension_kinds).toEqual([
      "local_extension",
      "password_manager",
      "payment_wallet",
      "privileged_browser_extension"
    ]);
    expect(browserSessionConfig?.metadata.env_key_names).toEqual(["BROWSER_SESSION_TOKEN"]);
    expect(browserSessionConfig?.metadata.secret_ref_key_names).toEqual(["BROWSER_SESSION_TOKEN"]);
    expect(browserSessionConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(browserSessionConfig?.actions).toEqual(["call", "read", "send", "write"]);
    expect(JSON.stringify(browserSessionConfig)).not.toContain("${BROWSER_SESSION_TOKEN}");
    expect(JSON.stringify(browserSessionConfig)).not.toContain(".browser/support-profile");
    expect(JSON.stringify(browserSessionConfig)).not.toContain(".auth/support-browser-state.json");
    expect(JSON.stringify(browserSessionConfig)).not.toContain(".auth/customer-support-cookies.json");
    expect(JSON.stringify(browserSessionConfig)).not.toContain("support.example.invalid");
    expect(JSON.stringify(browserSessionConfig)).not.toContain("browser_customer_email");
    expect(JSON.stringify(browserSessionConfig)).not.toContain(".browser/extensions/password-manager");
    expect(JSON.stringify(browserSessionConfig)).not.toContain("Support Password Manager");
    expect(JSON.stringify(browserSessionConfig)).not.toContain("wallet-extension-prod");
    expect(JSON.stringify(browserSessionConfig)).not.toContain("Customer Payment Wallet");
    expect(JSON.stringify(browserSessionConfig)).not.toContain(".browser/downloads/customer-exports");
    expect(JSON.stringify(browserSessionConfig)).not.toContain("export.csv");
    expect(JSON.stringify(browserSessionConfig)).not.toContain("browser_customer_invoice.pdf");
    expect(JSON.stringify(browserSessionConfig)).not.toContain("browser_support_export.html");
    expect(JSON.stringify(browserSessionConfig)).not.toContain("browser_case_bundle.zip");
    expect(JSON.stringify(browserSessionConfig)).not.toContain("browser_statement_ocr.png");
    const computerUseConfig = surfaces.runtime_config.find((surface) => surface.path === "computer/desktop-agent.yaml");
    expect(computerUseConfig).toBeDefined();
    expect(computerUseConfig).toMatchObject({
      trust_level: "third_party",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "execute", "read", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(computerUseConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_computer_use_config: true,
      agent_computer_use_provider: "openai_computer_use",
      agent_computer_use_enabled: true,
      agent_computer_use_remote_session: true,
      agent_computer_use_destination_redacted: true,
      agent_computer_use_destination_count: 1,
      agent_computer_use_authenticated_session: true,
      agent_computer_use_credential_store_access: true,
      agent_computer_use_screen_capture: true,
      agent_computer_use_ocr_capture: true,
      agent_computer_use_clipboard_access: true,
      agent_computer_use_clipboard_write: true,
      agent_computer_use_keyboard_input: true,
      agent_computer_use_mouse_control: true,
      agent_computer_use_file_transfer: true,
      agent_computer_use_download_auto_accept: true,
      agent_computer_use_local_path_redacted: true,
      agent_computer_use_app_control: true,
      agent_computer_use_terminal_control: false,
      agent_computer_use_sensitive_context: true,
      agent_computer_use_pii_context: true,
      agent_computer_use_redaction_disabled: true,
      agent_computer_use_untrusted_input: true,
      agent_computer_use_approval_required: false
    });
    expect(computerUseConfig?.metadata.agent_computer_use_destination_kinds).toEqual([
      "computer_use_config",
      "remote_desktop_endpoint",
      "vnc_endpoint"
    ]);
    expect(computerUseConfig?.metadata.env_key_names).toEqual(["DESKTOP_AGENT_TOKEN"]);
    expect(computerUseConfig?.metadata.secret_ref_key_names).toEqual(["DESKTOP_AGENT_TOKEN"]);
    expect(JSON.stringify(computerUseConfig)).not.toContain("${DESKTOP_AGENT_TOKEN}");
    expect(JSON.stringify(computerUseConfig)).not.toContain("desktop.agentcsp-demo.example.invalid");
    expect(JSON.stringify(computerUseConfig)).not.toContain("support-crm-admin");
    expect(JSON.stringify(computerUseConfig)).not.toContain("billing-console-prod");
    expect(JSON.stringify(computerUseConfig)).not.toContain("password-manager-desktop");
    expect(JSON.stringify(computerUseConfig)).not.toContain("customer-crm-window");
    expect(JSON.stringify(computerUseConfig)).not.toContain("billing-admin-window");
    expect(JSON.stringify(computerUseConfig)).not.toContain("/Users/support/customer_exports/export.csv");
    expect(JSON.stringify(computerUseConfig)).not.toContain("/tmp/agent-desktop-downloads");
    expect(JSON.stringify(computerUseConfig)).not.toContain("desktop_customer_email");
    const cloudControlPlaneConfig = surfaces.runtime_config.find(
      (surface) => surface.path === "cloud/aws-admin-agent.yaml"
    );
    expect(cloudControlPlaneConfig).toBeDefined();
    expect(cloudControlPlaneConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(cloudControlPlaneConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_cloud_control_plane_config: true,
      cloud_provider: "aws",
      cloud_control_plane_remote: true,
      cloud_control_plane_account_redacted: true,
      cloud_control_plane_role_redacted: true,
      cloud_control_plane_resource_references_redacted: true,
      cloud_control_plane_scope_redacted: true,
      cloud_control_plane_broad_scope: true,
      cloud_control_plane_admin_scope: true,
      cloud_control_plane_iam_write: true,
      cloud_control_plane_secret_access: true,
      cloud_control_plane_secret_write: true,
      cloud_control_plane_storage_write: true,
      cloud_control_plane_compute_write: true,
      cloud_control_plane_delete_authority: true,
      cloud_control_plane_audit_log_access: true,
      cloud_control_plane_auto_remediation: true,
      cloud_control_plane_untrusted_input: true,
      cloud_control_plane_approval_required: false
    });
    expect(cloudControlPlaneConfig?.metadata.cloud_control_plane_scope_categories).toEqual([
      "admin_scope",
      "audit_log_read",
      "compute_write",
      "iam_write",
      "secret_read",
      "secret_write",
      "storage_write",
      "write_scope"
    ]);
    expect(cloudControlPlaneConfig?.metadata.cloud_control_plane_tool_authority_categories).toEqual([
      "aws_cli",
      "iac_apply"
    ]);
    expect(cloudControlPlaneConfig?.metadata.env_key_names).toEqual([
      "AWS_ACCESS_KEY_ID",
      "AWS_SECRET_ACCESS_KEY",
      "AWS_SESSION_TOKEN"
    ]);
    expect(cloudControlPlaneConfig?.metadata.secret_ref_key_names).toEqual([
      "AWS_ACCESS_KEY_ID",
      "AWS_SECRET_ACCESS_KEY",
      "AWS_SESSION_TOKEN"
    ]);
    expect(cloudControlPlaneConfig?.data_classes).toEqual(["confidential", "credential", "internal", "secret"]);
    expect(cloudControlPlaneConfig?.actions).toEqual(["call", "delete", "execute", "read", "send", "write"]);
    expect(JSON.stringify(cloudControlPlaneConfig)).not.toContain("${AWS_ACCESS_KEY_ID}");
    expect(JSON.stringify(cloudControlPlaneConfig)).not.toContain("${AWS_SECRET_ACCESS_KEY}");
    expect(JSON.stringify(cloudControlPlaneConfig)).not.toContain("${AWS_SESSION_TOKEN}");
    expect(JSON.stringify(cloudControlPlaneConfig)).not.toContain("123456789012");
    expect(JSON.stringify(cloudControlPlaneConfig)).not.toContain("arn:aws:iam");
    expect(JSON.stringify(cloudControlPlaneConfig)).not.toContain("support-agent-admin");
    expect(JSON.stringify(cloudControlPlaneConfig)).not.toContain("AdministratorAccess");
    expect(JSON.stringify(cloudControlPlaneConfig)).not.toContain("iam:PassRole");
    expect(JSON.stringify(cloudControlPlaneConfig)).not.toContain("s3:PutObject");
    expect(JSON.stringify(cloudControlPlaneConfig)).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(cloudControlPlaneConfig)).not.toContain("retrieved_cloud_runbook");
    expect(JSON.stringify(cloudControlPlaneConfig)).not.toContain("aws-cli");
    expect(JSON.stringify(cloudControlPlaneConfig)).not.toContain("terraform-apply");
    const saasConnectorConfig = surfaces.runtime_config.find(
      (surface) => surface.path === "connectors/slack-customer-success.yaml"
    );
    expect(saasConnectorConfig).toBeDefined();
    expect(saasConnectorConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(saasConnectorConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_saas_connector_config: true,
      saas_connector_provider: "slack",
      saas_connector_external_reach: true,
      saas_connector_destination_redacted: true,
      saas_connector_scope_redacted: true,
      saas_connector_broad_scope: true,
      saas_connector_admin_scope: false,
      saas_connector_read_enabled: true,
      saas_connector_external_write_enabled: true,
      saas_connector_recipient_redacted: true,
      saas_connector_user_or_model_selected_recipient: true,
      saas_connector_external_or_shared_destination: true,
      saas_connector_public_channel_destination: true,
      saas_connector_direct_message_destination: true,
      saas_connector_broadcast_destination: true,
      saas_connector_attachment_upload_enabled: true,
      saas_connector_recipient_allowlist_missing: true,
      saas_connector_untrusted_input: true,
      saas_connector_sensitive_data: true,
      saas_connector_pii_data: true,
      saas_connector_approval_required: false
    });
    expect(saasConnectorConfig?.metadata.saas_connector_destination_kinds).toEqual([
      "api_endpoint",
      "managed_saas_provider"
    ]);
    expect(saasConnectorConfig?.metadata.saas_connector_scope_categories).toEqual([
      "messaging_read",
      "messaging_write",
      "read_scope"
    ]);
    expect(saasConnectorConfig?.metadata.saas_connector_recipient_kinds).toEqual([
      "broadcast",
      "channel",
      "direct_message",
      "external_or_shared",
      "public_channel",
      "workspace"
    ]);
    expect(saasConnectorConfig?.metadata.env_key_names).toEqual(
      expect.arrayContaining(["CUSTOMER_SUCCESS_SLACK_BOT_TOKEN"])
    );
    expect(saasConnectorConfig?.metadata.secret_ref_key_names).toEqual(["CUSTOMER_SUCCESS_SLACK_BOT_TOKEN"]);
    expect(saasConnectorConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(saasConnectorConfig?.actions).toEqual(["call", "publish", "read", "send", "write"]);
    expect(JSON.stringify(saasConnectorConfig)).not.toContain("${CUSTOMER_SUCCESS_SLACK_BOT_TOKEN}");
    expect(JSON.stringify(saasConnectorConfig)).not.toContain("hooks.slack.example.invalid");
    expect(JSON.stringify(saasConnectorConfig)).not.toContain("chat:write");
    expect(JSON.stringify(saasConnectorConfig)).not.toContain("channels:history");
    expect(JSON.stringify(saasConnectorConfig)).not.toContain("users:read.email");
    expect(JSON.stringify(saasConnectorConfig)).not.toContain("#customer-escalations");
    expect(JSON.stringify(saasConnectorConfig)).not.toContain("model_selected_customer_channel");
    expect(JSON.stringify(saasConnectorConfig)).not.toContain("agentcsp-demo-workspace");
    expect(JSON.stringify(saasConnectorConfig)).not.toContain("saas_customer_email");
    expect(JSON.stringify(saasConnectorConfig)).not.toContain("saas_ticket_summary");
    expect(JSON.stringify(saasConnectorConfig)).not.toContain("saas_internal_note");
    const secretManagerConfig = surfaces.runtime_config.find((surface) => surface.path === "secrets/vault-agent.yaml");
    expect(secretManagerConfig).toBeDefined();
    expect(secretManagerConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(secretManagerConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_secret_manager_config: true,
      secret_manager_provider: "hashicorp_vault",
      secret_manager_remote: true,
      secret_manager_destination_redacted: true,
      secret_manager_scope_redacted: true,
      secret_manager_path_references_redacted: true,
      secret_manager_read_enabled: true,
      secret_manager_list_enabled: true,
      secret_manager_write_enabled: false,
      secret_manager_broad_scope: true,
      secret_manager_injects_into_tools: true,
      secret_manager_injects_into_prompt_context: true,
      secret_manager_redaction_disabled: true,
      secret_manager_untrusted_input: true,
      secret_manager_sensitive_scope: true,
      secret_manager_pii_scope: false,
      secret_manager_approval_required: false
    });
    expect(secretManagerConfig?.metadata.secret_manager_destination_kinds).toEqual([
      "managed_secret_store",
      "secret_store_endpoint"
    ]);
    expect(secretManagerConfig?.metadata.secret_manager_scope_categories).toEqual([
      "secret_list",
      "secret_read",
      "sensitive_secret_scope"
    ]);
    expect(secretManagerConfig?.metadata.secret_manager_prompt_context_categories).toEqual([
      "model_prompt_context",
      "system_prompt_context"
    ]);
    expect(secretManagerConfig?.metadata.env_key_names).toEqual(["VAULT_AGENT_TOKEN"]);
    expect(secretManagerConfig?.metadata.secret_ref_key_names).toEqual(["VAULT_AGENT_TOKEN"]);
    expect(secretManagerConfig?.data_classes).toEqual(["confidential", "credential", "secret"]);
    expect(secretManagerConfig?.actions).toEqual(["call", "execute", "read", "send"]);
    expect(JSON.stringify(secretManagerConfig)).not.toContain("${VAULT_AGENT_TOKEN}");
    expect(JSON.stringify(secretManagerConfig)).not.toContain("vault.example.invalid");
    expect(JSON.stringify(secretManagerConfig)).not.toContain("secret/data/prod/customer-support");
    expect(JSON.stringify(secretManagerConfig)).not.toContain("kv/agent/service-tokens");
    expect(JSON.stringify(secretManagerConfig)).not.toContain("prod-support-read");
    expect(JSON.stringify(secretManagerConfig)).not.toContain("agent-secret-broker");
    expect(JSON.stringify(secretManagerConfig)).not.toContain("vault_customer_credentials");
    expect(JSON.stringify(secretManagerConfig)).not.toContain("support-agent-system-prompt");
    expect(JSON.stringify(secretManagerConfig)).not.toContain("customer-support-secret-context");
    expect(JSON.stringify(secretManagerConfig)).not.toContain("vault://prod/customer-support/*");
    expect(JSON.stringify(secretManagerConfig)).not.toContain("env://SUPPORT_DB_PASSWORD");
    const agentIdentityConfig = surfaces.runtime_config.find((surface) => surface.path === "identity/agent-oauth.yaml");
    expect(agentIdentityConfig).toBeDefined();
    expect(agentIdentityConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(agentIdentityConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_identity_config: true,
      agent_identity_provider: "google_workload_identity",
      agent_identity_remote: true,
      agent_identity_destination_redacted: true,
      agent_identity_issuer_redacted: true,
      agent_identity_subject_redacted: true,
      agent_identity_scope_redacted: true,
      agent_identity_broad_scope: true,
      agent_identity_admin_scope: true,
      agent_identity_write_scope: true,
      agent_identity_credential_issuance_enabled: true,
      agent_identity_impersonation_enabled: true,
      agent_identity_token_refresh_enabled: true,
      agent_identity_tool_injection: true,
      agent_identity_external_authority: true,
      agent_identity_untrusted_input: true,
      agent_identity_sensitive_data: true,
      agent_identity_pii_data: true,
      agent_identity_approval_required: false
    });
    expect(agentIdentityConfig?.metadata.agent_identity_destination_kinds).toEqual([
      "identity_provider_endpoint",
      "managed_identity_provider"
    ]);
    expect(agentIdentityConfig?.metadata.agent_identity_scope_categories).toEqual([
      "admin_scope",
      "email_modify",
      "iam_admin",
      "storage_write",
      "wildcard_scope"
    ]);
    expect(agentIdentityConfig?.metadata.env_key_names).toEqual(["AGENT_IDENTITY_TOKEN"]);
    expect(agentIdentityConfig?.metadata.secret_ref_key_names).toEqual(["AGENT_IDENTITY_TOKEN"]);
    expect(agentIdentityConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(agentIdentityConfig?.actions).toEqual(["approve", "call", "read", "send", "write"]);
    expect(JSON.stringify(agentIdentityConfig)).not.toContain("${AGENT_IDENTITY_TOKEN}");
    expect(JSON.stringify(agentIdentityConfig)).not.toContain("auth.agentcsp-demo.example.invalid");
    expect(JSON.stringify(agentIdentityConfig)).not.toContain("sts.googleapis.com");
    expect(JSON.stringify(agentIdentityConfig)).not.toContain("support-agent-prod");
    expect(JSON.stringify(agentIdentityConfig)).not.toContain("agentcsp-demo.iam.gserviceaccount.com");
    expect(JSON.stringify(agentIdentityConfig)).not.toContain("customer-support-prod-agent");
    expect(JSON.stringify(agentIdentityConfig)).not.toContain("cloud-platform");
    expect(JSON.stringify(agentIdentityConfig)).not.toContain("gmail.modify");
    expect(JSON.stringify(agentIdentityConfig)).not.toContain("roles/owner");
    expect(JSON.stringify(agentIdentityConfig)).not.toContain("roles/iam.serviceAccountTokenCreator");
    expect(JSON.stringify(agentIdentityConfig)).not.toContain("send_customer_reply");
    expect(JSON.stringify(agentIdentityConfig)).not.toContain("customer_oauth_email");
    const agentExtensionLoaderConfig = surfaces.runtime_config.find((surface) => surface.path === "extensions/remote-skills.yaml");
    expect(agentExtensionLoaderConfig).toBeDefined();
    expect(agentExtensionLoaderConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(agentExtensionLoaderConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_extension_loader_config: true,
      agent_extension_loader_provider: "agent_extension_marketplace",
      agent_extension_loader_remote: true,
      agent_extension_loader_destination_redacted: true,
      agent_extension_loader_extension_refs_redacted: true,
      agent_extension_loader_unpinned_reference: true,
      agent_extension_loader_auto_install_enabled: true,
      agent_extension_loader_auto_update_enabled: true,
      agent_extension_loader_signature_verification_disabled: true,
      agent_extension_loader_provenance_verification_missing: true,
      agent_extension_loader_untrusted_input: true,
      agent_extension_loader_privileged_authority: true,
      agent_extension_loader_external_authority: true,
      agent_extension_loader_sensitive_data: true,
      agent_extension_loader_pii_data: true,
      agent_extension_loader_approval_required: false
    });
    expect(agentExtensionLoaderConfig?.metadata.agent_extension_loader_destination_kinds).toEqual([
      "extension_registry_endpoint",
      "git_repository"
    ]);
    expect(agentExtensionLoaderConfig?.metadata.agent_extension_loader_extension_kinds).toEqual(
      expect.arrayContaining(["plugin", "skill"])
    );
    expect(agentExtensionLoaderConfig?.metadata.agent_extension_loader_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "repo_or_filesystem_write",
      "secret_manager_access"
    ]);
    expect(agentExtensionLoaderConfig?.metadata.env_key_names).toEqual(["AGENT_EXTENSION_TOKEN"]);
    expect(agentExtensionLoaderConfig?.metadata.secret_ref_key_names).toEqual(["AGENT_EXTENSION_TOKEN"]);
    expect(agentExtensionLoaderConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(agentExtensionLoaderConfig?.actions).toEqual(["call", "execute", "publish", "read", "send", "write"]);
    expect(JSON.stringify(agentExtensionLoaderConfig)).not.toContain("${AGENT_EXTENSION_TOKEN}");
    expect(JSON.stringify(agentExtensionLoaderConfig)).not.toContain("skills.agentcsp-demo.example.invalid");
    expect(JSON.stringify(agentExtensionLoaderConfig)).not.toContain("@agentcsp-demo/browser-account-actions");
    expect(JSON.stringify(agentExtensionLoaderConfig)).not.toContain("customer-data-plugin");
    expect(JSON.stringify(agentExtensionLoaderConfig)).not.toContain("github.com/agentcsp-demo/customer-data-plugin");
    expect(JSON.stringify(agentExtensionLoaderConfig)).not.toContain("browser-account-actions");
    expect(JSON.stringify(agentExtensionLoaderConfig)).not.toContain("customer_requested_skill");
    expect(JSON.stringify(agentExtensionLoaderConfig)).not.toContain("customer_extension_email");
    expect(JSON.stringify(agentExtensionLoaderConfig)).not.toContain("confidential_extension_payload");
    const selfModificationConfig = surfaces.runtime_config.find((surface) => surface.path === "self-modification/policy-writer.yaml");
    expect(selfModificationConfig).toBeDefined();
    expect(selfModificationConfig).toMatchObject({
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(selfModificationConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_self_modification_config: true,
      agent_self_modification_target_redacted: true,
      agent_self_modification_instruction_target: true,
      agent_self_modification_prompt_target: true,
      agent_self_modification_policy_target: true,
      agent_self_modification_tool_target: true,
      agent_self_modification_runtime_target: true,
      agent_self_modification_memory_target: true,
      agent_self_modification_write_enabled: true,
      agent_self_modification_auto_apply: true,
      agent_self_modification_persistent_change: true,
      agent_self_modification_executes_after_update: true,
      agent_self_modification_rollback_enabled: false,
      agent_self_modification_untrusted_input: true,
      agent_self_modification_external_authority: true,
      agent_self_modification_sensitive_data: true,
      agent_self_modification_pii_data: true,
      agent_self_modification_approval_required: false
    });
    expect(selfModificationConfig?.metadata.agent_self_modification_target_categories).toEqual([
      "instruction_file",
      "memory_store",
      "policy_file",
      "prompt_template",
      "runtime_config",
      "tool_definition"
    ]);
    expect(selfModificationConfig?.metadata.agent_self_modification_authority_categories).toEqual([
      "control_plane_write",
      "external_response",
      "memory_write",
      "repo_or_filesystem_write",
      "shell_execution",
      "tool_definition_write"
    ]);
    expect(selfModificationConfig?.metadata.env_key_names).toEqual(["AGENT_SELF_MOD_TOKEN"]);
    expect(selfModificationConfig?.metadata.secret_ref_key_names).toEqual(["AGENT_SELF_MOD_TOKEN"]);
    expect(selfModificationConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(selfModificationConfig?.actions).toEqual(["call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(selfModificationConfig)).not.toContain("${AGENT_SELF_MOD_TOKEN}");
    expect(JSON.stringify(selfModificationConfig)).not.toContain("AGENTS.md");
    expect(JSON.stringify(selfModificationConfig)).not.toContain("support-ticket.prompt.md");
    expect(JSON.stringify(selfModificationConfig)).not.toContain("agentcsp.yaml");
    expect(JSON.stringify(selfModificationConfig)).not.toContain(".codex/config.toml");
    expect(JSON.stringify(selfModificationConfig)).not.toContain("tools/agent-tools.json");
    expect(JSON.stringify(selfModificationConfig)).not.toContain("system_prompt");
    expect(JSON.stringify(selfModificationConfig)).not.toContain("developer_prompt");
    expect(JSON.stringify(selfModificationConfig)).not.toContain("tool_allowlist");
    expect(JSON.stringify(selfModificationConfig)).not.toContain("npm run agent:run");
    expect(JSON.stringify(selfModificationConfig)).not.toContain("customer_self_mod_email");
    const approvalGateConfig = surfaces.runtime_config.find((surface) => surface.path === "approvals/model-reviewer.yaml");
    expect(approvalGateConfig).toBeDefined();
    expect(approvalGateConfig).toMatchObject({
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(approvalGateConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_approval_config: true,
      agent_approval_prompt_redacted: true,
      agent_approval_external_channel: false,
      agent_approval_channel_auth_disabled: false,
      agent_approval_approver_identity_unverified: false,
      agent_approval_replay_protection_disabled: false,
      agent_approval_broad_approver_scope: false,
      agent_approval_context_untrusted: true,
      agent_approval_raw_context_included: true,
      agent_approval_decision_model_driven: true,
      agent_approval_uses_untrusted_summary: true,
      agent_approval_human_required: false,
      agent_approval_default_allow: true,
      agent_approval_auto_execute_after_approval: true,
      agent_approval_privileged_actions: true,
      agent_approval_write_actions: true,
      agent_approval_destructive_actions: false,
      agent_approval_external_actions: true,
      agent_approval_memory_write: true,
      agent_approval_secret_access: true,
      agent_approval_sensitive_data: true,
      agent_approval_pii_data: true
    });
    expect(approvalGateConfig?.metadata.agent_approval_prompt_source_categories).toEqual([
      "memory_context",
      "retrieval_context",
      "tool_output",
      "untrusted_user_input"
    ]);
    expect(approvalGateConfig?.metadata.agent_approval_channel_categories).toEqual([]);
    expect(approvalGateConfig?.metadata.agent_approval_action_categories).toEqual([
      "browser_action",
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(approvalGateConfig?.metadata.env_key_names).toEqual(["APPROVAL_GATE_TOKEN"]);
    expect(approvalGateConfig?.metadata.secret_ref_key_names).toEqual(["APPROVAL_GATE_TOKEN"]);
    expect(approvalGateConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(approvalGateConfig?.actions).toEqual(["approve", "call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(approvalGateConfig)).not.toContain("${APPROVAL_GATE_TOKEN}");
    expect(JSON.stringify(approvalGateConfig)).not.toContain("support-approval-classifier");
    expect(JSON.stringify(approvalGateConfig)).not.toContain("Summarize the customer request");
    expect(JSON.stringify(approvalGateConfig)).not.toContain("approve_and_execute");
    expect(JSON.stringify(approvalGateConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(approvalGateConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(approvalGateConfig)).not.toContain("customer_email_address");
    const chatopsApprovalConfig = surfaces.runtime_config.find((surface) => surface.path === "approvals/chatops-approval.yaml");
    expect(chatopsApprovalConfig).toBeDefined();
    expect(chatopsApprovalConfig).toMatchObject({
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(chatopsApprovalConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_approval_config: true,
      agent_approval_prompt_redacted: true,
      agent_approval_external_channel: true,
      agent_approval_channel_auth_disabled: true,
      agent_approval_approver_identity_unverified: true,
      agent_approval_replay_protection_disabled: true,
      agent_approval_broad_approver_scope: true,
      agent_approval_context_untrusted: true,
      agent_approval_raw_context_included: true,
      agent_approval_decision_model_driven: false,
      agent_approval_uses_untrusted_summary: false,
      agent_approval_human_required: true,
      agent_approval_default_allow: false,
      agent_approval_auto_execute_after_approval: true,
      agent_approval_privileged_actions: true,
      agent_approval_write_actions: true,
      agent_approval_external_actions: true,
      agent_approval_memory_write: false,
      agent_approval_secret_access: true,
      agent_approval_sensitive_data: true,
      agent_approval_pii_data: true
    });
    expect(chatopsApprovalConfig?.metadata.agent_approval_channel_categories).toEqual(["chatops", "webhook"]);
    expect(chatopsApprovalConfig?.metadata.agent_approval_prompt_source_categories).toEqual([
      "retrieval_context",
      "tool_output",
      "untrusted_user_input"
    ]);
    expect(chatopsApprovalConfig?.metadata.agent_approval_action_categories).toEqual([
      "browser_action",
      "database_write",
      "external_response",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(chatopsApprovalConfig?.metadata.env_key_names).toEqual(["CHATOPS_APPROVAL_TOKEN"]);
    expect(chatopsApprovalConfig?.metadata.secret_ref_key_names).toEqual(["CHATOPS_APPROVAL_TOKEN"]);
    expect(chatopsApprovalConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(chatopsApprovalConfig?.actions).toEqual(["approve", "call", "execute", "publish", "read", "send", "write"]);
    expect(JSON.stringify(chatopsApprovalConfig)).not.toContain("${CHATOPS_APPROVAL_TOKEN}");
    expect(JSON.stringify(chatopsApprovalConfig)).not.toContain("hooks.slack.example.invalid");
    expect(JSON.stringify(chatopsApprovalConfig)).not.toContain("#customer-support");
    expect(JSON.stringify(chatopsApprovalConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(chatopsApprovalConfig)).not.toContain("chatops_approval_customer_email");
    const sharedSessionConfig = surfaces.runtime_config.find((surface) => surface.path === "sessions/shared-copilot.yaml");
    expect(sharedSessionConfig).toBeDefined();
    expect(sharedSessionConfig).toMatchObject({
      trust_level: "project",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["approve", "call", "publish", "read", "remember", "send", "write"],
      side_effect: true,
      external_reach: true,
      secret_exposure: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(sharedSessionConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_session_sharing_config: true,
      agent_session_sharing_enabled: true,
      agent_session_sharing_external: true,
      agent_session_sharing_public_access: true,
      agent_session_sharing_anonymous_access: true,
      agent_session_sharing_auth_disabled: true,
      agent_session_sharing_destination_redacted: true,
      agent_session_sharing_destination_count: 3,
      agent_session_sharing_collaborator_count: 1,
      agent_session_sharing_external_collaborators: true,
      agent_session_sharing_broad_collaborator_scope: true,
      agent_session_sharing_live_control_enabled: true,
      agent_session_sharing_prompt_injection_enabled: true,
      agent_session_sharing_tool_control_enabled: true,
      agent_session_sharing_tool_write_authority: true,
      agent_session_sharing_tool_execution_authority: false,
      agent_session_sharing_approval_control_enabled: true,
      agent_session_sharing_resume_replay_enabled: true,
      agent_session_sharing_transcript_capture: true,
      agent_session_sharing_sensitive_context: true,
      agent_session_sharing_pii_context: true,
      agent_session_sharing_secret_capture: true,
      agent_session_sharing_redaction_disabled: true,
      agent_session_sharing_untrusted_input: true,
      agent_session_sharing_approval_required: false
    });
    expect(sharedSessionConfig?.metadata.agent_session_sharing_destination_kinds).toEqual([
      "external_share_link",
      "public_share_link",
      "session_config",
      "third_party_collaborator"
    ]);
    expect(sharedSessionConfig?.metadata.agent_session_sharing_control_categories).toEqual([
      "approval_control",
      "database_write",
      "live_control",
      "prompt_injection",
      "resume_replay",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(sharedSessionConfig?.metadata.agent_session_sharing_capture_categories).toEqual([
      "browser_context",
      "completion_context",
      "memory_context",
      "prompt_context",
      "retrieval_context",
      "secret_context",
      "tool_output",
      "transcript"
    ]);
    expect(sharedSessionConfig?.metadata.env_key_names).toEqual(["SESSION_SHARE_TOKEN"]);
    expect(sharedSessionConfig?.metadata.secret_ref_key_names).toEqual(["SESSION_SHARE_TOKEN"]);
    expect(JSON.stringify(sharedSessionConfig)).not.toContain("${SESSION_SHARE_TOKEN}");
    expect(JSON.stringify(sharedSessionConfig)).not.toContain("sessions.agentcsp-demo.example.invalid");
    expect(JSON.stringify(sharedSessionConfig)).not.toContain("customer-support-live-share");
    expect(JSON.stringify(sharedSessionConfig)).not.toContain("external_support_vendor");
    expect(JSON.stringify(sharedSessionConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(sharedSessionConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(sharedSessionConfig)).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(sharedSessionConfig)).not.toContain("browser_tool_output");
    expect(JSON.stringify(sharedSessionConfig)).not.toContain("session_share_customer_email");
    const contextComposerConfig = surfaces.runtime_config.find((surface) => surface.path === "context/system-context.yaml");
    expect(contextComposerConfig).toBeDefined();
    expect(contextComposerConfig).toMatchObject({
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(contextComposerConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_context_composer_config: true,
      agent_context_composer_source_redacted: true,
      agent_context_composer_untrusted_sources: true,
      agent_context_composer_privileged_role_injection: true,
      agent_context_composer_system_role: true,
      agent_context_composer_developer_role: true,
      agent_context_composer_role_boundary_redacted: true,
      agent_context_composer_delimiter_disabled: true,
      agent_context_composer_sanitization_disabled: true,
      agent_context_composer_raw_context_enabled: true,
      agent_context_composer_env_materialization: true,
      agent_context_composer_secret_env_materialization: true,
      agent_context_composer_env_materialization_privileged_context: true,
      agent_context_composer_env_materialization_redaction_disabled: true,
      agent_context_composer_untrusted_env_selector: true,
      agent_context_composer_privileged_tool_authority: true,
      agent_context_composer_write_authority: true,
      agent_context_composer_external_authority: true,
      agent_context_composer_memory_write: true,
      agent_context_composer_shell_authority: false,
      agent_context_composer_destructive_authority: false,
      agent_context_composer_secret_access: true,
      agent_context_composer_sensitive_data: true,
      agent_context_composer_pii_data: true,
      agent_context_composer_approval_required: false
    });
    expect(contextComposerConfig?.metadata.agent_context_composer_source_categories).toEqual([
      "memory_context",
      "retrieval_context",
      "tool_output",
      "untrusted_user_input",
      "web_content"
    ]);
    expect(contextComposerConfig?.metadata.agent_context_composer_env_materialization_target_categories).toEqual([
      "developer_prompt",
      "model_context",
      "system_prompt"
    ]);
    expect(contextComposerConfig?.metadata.agent_context_composer_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(contextComposerConfig?.metadata.env_key_names).toEqual([
      "CONTEXT_COMPOSER_TOKEN",
      "CUSTOMER_SUCCESS_SLACK_BOT_TOKEN",
      "OPENAI_API_KEY",
      "SUPPORT_DB_PASSWORD"
    ]);
    expect(contextComposerConfig?.metadata.secret_ref_key_names).toEqual([
      "CONTEXT_COMPOSER_TOKEN",
      "CUSTOMER_SUCCESS_SLACK_BOT_TOKEN",
      "OPENAI_API_KEY",
      "SUPPORT_DB_PASSWORD"
    ]);
    expect(contextComposerConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(contextComposerConfig?.actions).toEqual(["call", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(contextComposerConfig)).not.toContain("${CONTEXT_COMPOSER_TOKEN}");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("${CUSTOMER_SUCCESS_SLACK_BOT_TOKEN}");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("${OPENAI_API_KEY}");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("${SUPPORT_DB_PASSWORD}");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("customer_requested_env_key");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("customer_ticket_message");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("retrieved_account_context");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("browser_tool_output");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("command_tool_result");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("customer_context_email");
    const contextWindowConfig = surfaces.runtime_config.find((surface) => surface.path === "context-window/truncation-policy.yaml");
    expect(contextWindowConfig).toBeDefined();
    expect(contextWindowConfig).toMatchObject({
      trust_level: "project",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(contextWindowConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_context_window_config: true,
      agent_context_window_enabled: true,
      agent_context_window_truncation_enabled: true,
      agent_context_window_compaction_enabled: false,
      agent_context_window_summarization_enabled: true,
      agent_context_window_overflow_policy_redacted: true,
      agent_context_window_token_budget_low: false,
      agent_context_window_untrusted_priority: true,
      agent_context_window_tool_output_priority: true,
      agent_context_window_memory_priority: true,
      agent_context_window_privileged_instruction_retention: false,
      agent_context_window_privileged_instruction_eviction: true,
      agent_context_window_safety_instruction_retention: false,
      agent_context_window_safety_instruction_eviction: true,
      agent_context_window_memory_replay: true,
      agent_context_window_summary_untrusted: true,
      agent_context_window_summary_verification_disabled: true,
      agent_context_window_delimiter_disabled: true,
      agent_context_window_redaction_disabled: true,
      agent_context_window_privileged_tool_authority: true,
      agent_context_window_write_authority: true,
      agent_context_window_external_authority: true,
      agent_context_window_shell_authority: false,
      agent_context_window_destructive_authority: false,
      agent_context_window_secret_context: true,
      agent_context_window_sensitive_context: true,
      agent_context_window_pii_context: true,
      agent_context_window_approval_required: false
    });
    expect(contextWindowConfig?.metadata.agent_context_window_strategy_categories).toEqual([
      "drop_low_priority",
      "overflow_drop",
      "sliding_window",
      "summarize_then_drop",
      "truncate_oldest"
    ]);
    expect(contextWindowConfig?.metadata.agent_context_window_priority_categories).toEqual([
      "developer_instruction",
      "memory_context",
      "retrieval_context",
      "safety_policy",
      "summary_context",
      "system_instruction",
      "tool_output",
      "untrusted_user_input"
    ]);
    expect(contextWindowConfig?.metadata.agent_context_window_tool_authority_categories).toEqual([
      "database_write",
      "external_response",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(contextWindowConfig?.metadata.env_key_names).toEqual(["CONTEXT_WINDOW_TOKEN"]);
    expect(contextWindowConfig?.metadata.secret_ref_key_names).toEqual(["CONTEXT_WINDOW_TOKEN"]);
    expect(contextWindowConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(contextWindowConfig?.actions).toEqual(["call", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(contextWindowConfig)).not.toContain("${CONTEXT_WINDOW_TOKEN}");
    expect(JSON.stringify(contextWindowConfig)).not.toContain("sliding_window_with_summary");
    expect(JSON.stringify(contextWindowConfig)).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(contextWindowConfig)).not.toContain("browser_tool_output");
    expect(JSON.stringify(contextWindowConfig)).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(contextWindowConfig)).not.toContain("long_term_memory");
    expect(JSON.stringify(contextWindowConfig)).not.toContain("system_prompt");
    expect(JSON.stringify(contextWindowConfig)).not.toContain("developer_instructions");
    expect(JSON.stringify(contextWindowConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(contextWindowConfig)).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(contextWindowConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(contextWindowConfig)).not.toContain("context_window_customer_email");
    const tinyContextWindowConfig = surfaces.runtime_config.find(
      (surface) => surface.path === "context-window/tiny-window-policy.yaml"
    );
    expect(tinyContextWindowConfig).toBeDefined();
    expect(tinyContextWindowConfig).toMatchObject({
      trust_level: "project",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(tinyContextWindowConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_context_window_config: true,
      agent_context_window_enabled: true,
      agent_context_window_truncation_enabled: true,
      agent_context_window_compaction_enabled: false,
      agent_context_window_summarization_enabled: true,
      agent_context_window_overflow_policy_redacted: true,
      agent_context_window_token_budget_low: true,
      agent_context_window_untrusted_priority: true,
      agent_context_window_tool_output_priority: true,
      agent_context_window_memory_priority: true,
      agent_context_window_privileged_instruction_retention: false,
      agent_context_window_privileged_instruction_eviction: true,
      agent_context_window_safety_instruction_retention: false,
      agent_context_window_safety_instruction_eviction: true,
      agent_context_window_memory_replay: true,
      agent_context_window_summary_untrusted: true,
      agent_context_window_summary_verification_disabled: true,
      agent_context_window_delimiter_disabled: true,
      agent_context_window_redaction_disabled: true,
      agent_context_window_privileged_tool_authority: true,
      agent_context_window_write_authority: true,
      agent_context_window_external_authority: true,
      agent_context_window_shell_authority: false,
      agent_context_window_destructive_authority: false,
      agent_context_window_secret_context: true,
      agent_context_window_sensitive_context: true,
      agent_context_window_pii_context: true,
      agent_context_window_approval_required: false
    });
    expect(tinyContextWindowConfig?.metadata.agent_context_window_strategy_categories).toEqual([
      "drop_low_priority",
      "overflow_drop",
      "sliding_window",
      "summarize_then_drop",
      "truncate_oldest"
    ]);
    expect(tinyContextWindowConfig?.metadata.agent_context_window_priority_categories).toEqual([
      "developer_instruction",
      "memory_context",
      "retrieval_context",
      "safety_policy",
      "summary_context",
      "system_instruction",
      "tool_output",
      "untrusted_user_input"
    ]);
    expect(tinyContextWindowConfig?.metadata.agent_context_window_tool_authority_categories).toEqual([
      "database_write",
      "external_response",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(tinyContextWindowConfig?.metadata.env_key_names).toEqual(["TINY_CONTEXT_WINDOW_TOKEN"]);
    expect(tinyContextWindowConfig?.metadata.secret_ref_key_names).toEqual(["TINY_CONTEXT_WINDOW_TOKEN"]);
    expect(tinyContextWindowConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(tinyContextWindowConfig?.actions).toEqual(["call", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(tinyContextWindowConfig)).not.toContain("${TINY_CONTEXT_WINDOW_TOKEN}");
    expect(JSON.stringify(tinyContextWindowConfig)).not.toContain("tiny_sliding_window_with_untrusted_summary");
    expect(JSON.stringify(tinyContextWindowConfig)).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(tinyContextWindowConfig)).not.toContain("browser_tool_output");
    expect(JSON.stringify(tinyContextWindowConfig)).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(tinyContextWindowConfig)).not.toContain("long_term_memory");
    expect(JSON.stringify(tinyContextWindowConfig)).not.toContain("system_prompt");
    expect(JSON.stringify(tinyContextWindowConfig)).not.toContain("developer_instructions");
    expect(JSON.stringify(tinyContextWindowConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(tinyContextWindowConfig)).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(tinyContextWindowConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(tinyContextWindowConfig)).not.toContain("tiny_window_customer_email");
    expect(JSON.stringify(tinyContextWindowConfig)).not.toContain("tiny_window_account_number");
    expect(JSON.stringify(tinyContextWindowConfig)).not.toContain("confidential_tiny_window_notes");
    const toolRetryPolicyConfig = surfaces.runtime_config.find((surface) => surface.path === "tool-retry/retry-policy.yaml");
    expect(toolRetryPolicyConfig).toBeDefined();
    expect(toolRetryPolicyConfig).toMatchObject({
      trust_level: "project",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(toolRetryPolicyConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_tool_retry_policy_config: true,
      agent_tool_retry_enabled: true,
      agent_tool_retry_automatic_retry: true,
      agent_tool_retry_replay_enabled: true,
      agent_tool_retry_retry_on_failure: true,
      agent_tool_retry_retry_on_timeout: true,
      agent_tool_retry_retry_on_rate_limit: true,
      agent_tool_retry_retry_on_validation_error: true,
      agent_tool_retry_max_attempts_redacted: true,
      agent_tool_retry_max_attempts_gt_one: true,
      agent_tool_retry_unbounded_attempts: false,
      agent_tool_retry_budget_missing: false,
      agent_tool_retry_backoff_disabled: true,
      agent_tool_retry_idempotency_required: false,
      agent_tool_retry_idempotency_disabled: true,
      agent_tool_retry_deduplication_disabled: true,
      agent_tool_retry_exactly_once_disabled: true,
      agent_tool_retry_non_idempotent_actions: true,
      agent_tool_retry_untrusted_input: true,
      agent_tool_retry_tool_output_replay: true,
      agent_tool_retry_model_selected_retry: true,
      agent_tool_retry_privileged_tool_authority: true,
      agent_tool_retry_write_authority: true,
      agent_tool_retry_external_authority: true,
      agent_tool_retry_memory_authority: false,
      agent_tool_retry_shell_authority: false,
      agent_tool_retry_destructive_authority: false,
      agent_tool_retry_secret_context: true,
      agent_tool_retry_sensitive_context: true,
      agent_tool_retry_pii_context: true,
      agent_tool_retry_approval_required: false
    });
    expect(toolRetryPolicyConfig?.metadata.agent_tool_retry_action_categories).toEqual([
      "database_write",
      "external_response",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(toolRetryPolicyConfig?.metadata.env_key_names).toEqual(["TOOL_RETRY_POLICY_TOKEN"]);
    expect(toolRetryPolicyConfig?.metadata.secret_ref_key_names).toEqual(["TOOL_RETRY_POLICY_TOKEN"]);
    expect(toolRetryPolicyConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(toolRetryPolicyConfig?.actions).toEqual(["call", "publish", "read", "send", "write"]);
    expect(JSON.stringify(toolRetryPolicyConfig)).not.toContain("${TOOL_RETRY_POLICY_TOKEN}");
    expect(JSON.stringify(toolRetryPolicyConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(toolRetryPolicyConfig)).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(toolRetryPolicyConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(toolRetryPolicyConfig)).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(toolRetryPolicyConfig)).not.toContain("browser_tool_output");
    expect(JSON.stringify(toolRetryPolicyConfig)).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(toolRetryPolicyConfig)).not.toContain("retry_customer_email");
    expect(JSON.stringify(toolRetryPolicyConfig)).not.toContain("retry_account_number");
    expect(JSON.stringify(toolRetryPolicyConfig)).not.toContain("confidential_retry_notes");
    const reasoningStateConfig = surfaces.runtime_config.find((surface) => surface.path === "reasoning/scratchpad-policy.yaml");
    expect(reasoningStateConfig).toBeDefined();
    expect(reasoningStateConfig).toMatchObject({
      trust_level: "project",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(reasoningStateConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_reasoning_state_config: true,
      agent_reasoning_state_enabled: true,
      agent_reasoning_state_capture_enabled: true,
      agent_reasoning_state_chain_of_thought_capture: true,
      agent_reasoning_state_plan_capture: true,
      agent_reasoning_state_tool_observation_capture: true,
      agent_reasoning_state_prompt_context_capture: true,
      agent_reasoning_state_retrieval_context_capture: true,
      agent_reasoning_state_memory_context_capture: true,
      agent_reasoning_state_secret_capture: true,
      agent_reasoning_state_sensitive_capture: true,
      agent_reasoning_state_pii_capture: true,
      agent_reasoning_state_untrusted_input: true,
      agent_reasoning_state_persistent: true,
      agent_reasoning_state_shared: true,
      agent_reasoning_state_remote: true,
      agent_reasoning_state_public_access: true,
      agent_reasoning_state_destination_redacted: true,
      agent_reasoning_state_destination_count: 3,
      agent_reasoning_state_replay_enabled: true,
      agent_reasoning_state_planner_uses_state: true,
      agent_reasoning_state_system_prompt_injection: true,
      agent_reasoning_state_redaction_disabled: true,
      agent_reasoning_state_access_control_disabled: true,
      agent_reasoning_state_retention_enabled: true,
      agent_reasoning_state_approval_required: false
    });
    expect(reasoningStateConfig?.metadata.agent_reasoning_state_capture_categories).toEqual([
      "memory_context",
      "plan_context",
      "prompt_context",
      "reasoning_trace",
      "retrieval_context",
      "secret_material",
      "tool_observation"
    ]);
    expect(reasoningStateConfig?.metadata.agent_reasoning_state_destination_kinds).toEqual([
      "configured_state_store",
      "http_reasoning_store"
    ]);
    expect(reasoningStateConfig?.metadata.env_key_names).toEqual(["REASONING_STATE_TOKEN"]);
    expect(reasoningStateConfig?.metadata.secret_ref_key_names).toEqual(["REASONING_STATE_TOKEN"]);
    expect(reasoningStateConfig?.data_classes).toEqual(["confidential", "credential", "pii", "secret"]);
    expect(reasoningStateConfig?.actions).toEqual(["call", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(reasoningStateConfig)).not.toContain("${REASONING_STATE_TOKEN}");
    expect(JSON.stringify(reasoningStateConfig)).not.toContain("scratchpad.agentcsp-demo.example.invalid");
    expect(JSON.stringify(reasoningStateConfig)).not.toContain("customer-support-reasoning");
    expect(JSON.stringify(reasoningStateConfig)).not.toContain("scratchpad_customer_email");
    expect(JSON.stringify(reasoningStateConfig)).not.toContain("scratchpad_account_number");
    expect(JSON.stringify(reasoningStateConfig)).not.toContain("confidential_reasoning_notes");
    expect(JSON.stringify(reasoningStateConfig)).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(reasoningStateConfig)).not.toContain("browser_tool_output");
    expect(JSON.stringify(reasoningStateConfig)).not.toContain("retrieved_customer_context");
    const networkEgressConfig = surfaces.runtime_config.find((surface) => surface.path === "network/egress-policy.yaml");
    expect(networkEgressConfig).toBeDefined();
    expect(networkEgressConfig).toMatchObject({
      trust_level: "project",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(networkEgressConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_network_egress_config: true,
      agent_network_egress_enabled: true,
      agent_network_egress_web_tool_authority: true,
      agent_network_egress_destination_redacted: true,
      agent_network_egress_destination_count: 11,
      agent_network_egress_private_network_access: true,
      agent_network_egress_metadata_service_access: true,
      agent_network_egress_localhost_access: true,
      agent_network_egress_private_cidr_access: true,
      agent_network_egress_wildcard_destination: true,
      agent_network_egress_untrusted_input: true,
      agent_network_egress_user_controlled_url: true,
      agent_network_egress_redirects_allowed: true,
      agent_network_egress_dns_rebinding_protection_disabled: true,
      agent_network_egress_request_headers_forwarded: true,
      agent_network_egress_credential_forwarding: true,
      agent_network_egress_response_capture: true,
      agent_network_egress_sensitive_response_capture: true,
      agent_network_egress_pii_response_capture: true,
      agent_network_egress_approval_required: false
    });
    expect(networkEgressConfig?.metadata.agent_network_egress_destination_kinds).toEqual([
      "cloud_metadata_service",
      "http_destination",
      "localhost_or_cluster_service",
      "private_network_range",
      "wildcard_destination"
    ]);
    expect(networkEgressConfig?.metadata.env_key_names).toEqual(["NETWORK_EGRESS_TOKEN"]);
    expect(networkEgressConfig?.metadata.secret_ref_key_names).toEqual(["NETWORK_EGRESS_TOKEN"]);
    expect(networkEgressConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(networkEgressConfig?.actions).toEqual(["call", "read", "remember", "send"]);
    expect(JSON.stringify(networkEgressConfig)).not.toContain("${NETWORK_EGRESS_TOKEN}");
    expect(JSON.stringify(networkEgressConfig)).not.toContain("169.254.169.254");
    expect(JSON.stringify(networkEgressConfig)).not.toContain("metadata.google.internal");
    expect(JSON.stringify(networkEgressConfig)).not.toContain("127.0.0.1");
    expect(JSON.stringify(networkEgressConfig)).not.toContain("admin.internal.local");
    expect(JSON.stringify(networkEgressConfig)).not.toContain("egress_metadata_token");
    expect(JSON.stringify(networkEgressConfig)).not.toContain("egress_customer_email");
    expect(JSON.stringify(networkEgressConfig)).not.toContain("confidential_internal_response");
    expect(JSON.stringify(networkEgressConfig)).not.toContain("untrusted_customer_ticket_url");
    expect(JSON.stringify(networkEgressConfig)).not.toContain("browser_tool_url");
    expect(JSON.stringify(networkEgressConfig)).not.toContain("retrieved_support_link");
    const workspaceContextConfig = surfaces.runtime_config.find(
      (surface) => surface.path === "workspace-context/context-sync.yaml"
    );
    expect(workspaceContextConfig).toBeDefined();
    expect(workspaceContextConfig).toMatchObject({
      trust_level: "project",
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "remember", "send", "write"],
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(workspaceContextConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_workspace_context_config: true,
      agent_workspace_context_enabled: true,
      agent_workspace_context_auto_sync_enabled: true,
      agent_workspace_context_source_redacted: true,
      agent_workspace_context_sensitive_paths: true,
      agent_workspace_context_secret_path_exposure: true,
      agent_workspace_context_env_file_access: true,
      agent_workspace_context_ssh_key_access: true,
      agent_workspace_context_cloud_credential_access: true,
      agent_workspace_context_kubeconfig_access: true,
      agent_workspace_context_home_directory_access: true,
      agent_workspace_context_git_history_access: true,
      agent_workspace_context_destination_redacted: true,
      agent_workspace_context_remote_sync: true,
      agent_workspace_context_prompt_context: true,
      agent_workspace_context_rag_indexing: true,
      agent_workspace_context_memory_persistence: true,
      agent_workspace_context_untrusted_input: true,
      agent_workspace_context_pii_context: true,
      agent_workspace_context_redaction_disabled: true,
      agent_workspace_context_agentcspignore_bypassed: true,
      agent_workspace_context_approval_required: false
    });
    expect(workspaceContextConfig?.metadata.agent_workspace_context_source_categories).toEqual([
      "cloud_credential",
      "env_file",
      "git_history",
      "home_directory",
      "kubeconfig",
      "private_repo",
      "ssh_key",
      "untrusted_selector",
      "workspace_file"
    ]);
    expect(workspaceContextConfig?.metadata.agent_workspace_context_destination_kinds).toEqual([
      "http_destination",
      "memory_store",
      "prompt_context",
      "rag_index",
      "remote_context_index",
      "shared_workspace"
    ]);
    expect(workspaceContextConfig?.metadata.env_key_names).toEqual(["WORKSPACE_CONTEXT_TOKEN"]);
    expect(workspaceContextConfig?.metadata.secret_ref_key_names).toEqual(["WORKSPACE_CONTEXT_TOKEN"]);
    expect(JSON.stringify(workspaceContextConfig)).not.toContain("${WORKSPACE_CONTEXT_TOKEN}");
    expect(JSON.stringify(workspaceContextConfig)).not.toContain("context-sync.agentcsp-demo.example.invalid");
    expect(JSON.stringify(workspaceContextConfig)).not.toContain("/workspace/customer_private_repo");
    expect(JSON.stringify(workspaceContextConfig)).not.toContain("/Users/support/.ssh/id_rsa");
    expect(JSON.stringify(workspaceContextConfig)).not.toContain("/Users/support/.aws/credentials");
    expect(JSON.stringify(workspaceContextConfig)).not.toContain("/Users/support/.kube/config");
    expect(JSON.stringify(workspaceContextConfig)).not.toContain("workspace_customer_email");
    expect(JSON.stringify(workspaceContextConfig)).not.toContain("workspace_account_number");
    expect(JSON.stringify(workspaceContextConfig)).not.toContain("confidential_repo_notes");
    const toolOutputPolicyConfig = surfaces.runtime_config.find((surface) => surface.path === "tool-results/result-policy.yaml");
    expect(toolOutputPolicyConfig).toBeDefined();
    expect(toolOutputPolicyConfig).toMatchObject({
      trust_level: "project",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(toolOutputPolicyConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_tool_output_policy_config: true,
      tool_output_source_redacted: true,
      tool_output_untrusted_sources: true,
      tool_output_raw_output_enabled: true,
      tool_output_prompt_context: true,
      tool_output_system_or_developer_context: true,
      tool_output_delimiter_disabled: true,
      tool_output_sanitization_disabled: true,
      tool_output_prompt_injection_filter_disabled: true,
      tool_output_followup_tool_calls: true,
      tool_output_write_authority: true,
      tool_output_external_reach: true,
      tool_output_memory_write: true,
      tool_output_shell_authority: true,
      tool_output_destructive_authority: true,
      tool_output_approval_input: true,
      tool_output_secret_capture: true,
      tool_output_secret_access: true,
      tool_output_sensitive_data: true,
      tool_output_pii_data: true,
      tool_output_approval_required: false
    });
    expect(toolOutputPolicyConfig?.metadata.tool_output_source_categories).toEqual([
      "api_response",
      "browser_output",
      "database_result",
      "mcp_result",
      "shell_output"
    ]);
    expect(toolOutputPolicyConfig?.metadata.tool_output_tool_authority_categories).toEqual([
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ]);
    expect(toolOutputPolicyConfig?.metadata.env_key_names).toEqual(["TOOL_OUTPUT_POLICY_TOKEN"]);
    expect(toolOutputPolicyConfig?.metadata.secret_ref_key_names).toEqual(["TOOL_OUTPUT_POLICY_TOKEN"]);
    expect(toolOutputPolicyConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(toolOutputPolicyConfig?.actions).toEqual(["approve", "call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(toolOutputPolicyConfig)).not.toContain("${TOOL_OUTPUT_POLICY_TOKEN}");
    expect(JSON.stringify(toolOutputPolicyConfig)).not.toContain("browser_tool_output");
    expect(JSON.stringify(toolOutputPolicyConfig)).not.toContain("shell_command_output");
    expect(JSON.stringify(toolOutputPolicyConfig)).not.toContain("mcp_filesystem_result");
    expect(JSON.stringify(toolOutputPolicyConfig)).not.toContain("api_connector_response");
    expect(JSON.stringify(toolOutputPolicyConfig)).not.toContain("customer_uploaded_html");
    expect(JSON.stringify(toolOutputPolicyConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(toolOutputPolicyConfig)).not.toContain("slack.post_escalation_reply");
    expect(JSON.stringify(toolOutputPolicyConfig)).not.toContain("memory.write_long_term_summary");
    expect(JSON.stringify(toolOutputPolicyConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(toolOutputPolicyConfig)).not.toContain("tool_output_customer_email");
    expect(JSON.stringify(toolOutputPolicyConfig)).not.toContain("tool_output_account_number");
    expect(JSON.stringify(toolOutputPolicyConfig)).not.toContain("confidential_tool_trace");
    const visualContextPolicyConfig = surfaces.runtime_config.find((surface) => surface.path === "vision/screenshot-policy.yaml");
    expect(visualContextPolicyConfig).toBeDefined();
    expect(visualContextPolicyConfig).toMatchObject({
      trust_level: "project",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(visualContextPolicyConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_visual_context_policy_config: true,
      visual_context_source_redacted: true,
      visual_context_untrusted_sources: true,
      visual_context_raw_image_enabled: true,
      visual_context_ocr_enabled: true,
      visual_context_prompt_context: true,
      visual_context_system_or_developer_context: true,
      visual_context_boundary_disabled: true,
      visual_context_sanitization_disabled: true,
      visual_context_prompt_injection_filter_disabled: true,
      visual_context_followup_tool_calls: true,
      visual_context_write_authority: true,
      visual_context_external_reach: true,
      visual_context_memory_write: true,
      visual_context_shell_authority: true,
      visual_context_destructive_authority: true,
      visual_context_approval_input: true,
      visual_context_secret_capture: true,
      visual_context_secret_access: true,
      visual_context_sensitive_data: true,
      visual_context_pii_data: true,
      visual_context_approval_required: false
    });
    expect(visualContextPolicyConfig?.metadata.visual_context_source_categories).toEqual([
      "browser_screenshot",
      "document_image",
      "ocr_text",
      "screen_capture",
      "uploaded_image"
    ]);
    expect(visualContextPolicyConfig?.metadata.visual_context_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ]);
    expect(visualContextPolicyConfig?.metadata.env_key_names).toEqual(["VISION_CONTEXT_TOKEN"]);
    expect(visualContextPolicyConfig?.metadata.secret_ref_key_names).toEqual(["VISION_CONTEXT_TOKEN"]);
    expect(visualContextPolicyConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(visualContextPolicyConfig?.actions).toEqual(["approve", "call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(visualContextPolicyConfig)).not.toContain("${VISION_CONTEXT_TOKEN}");
    expect(JSON.stringify(visualContextPolicyConfig)).not.toContain("browser_screenshot_observation");
    expect(JSON.stringify(visualContextPolicyConfig)).not.toContain("screen_capture_after_navigation");
    expect(JSON.stringify(visualContextPolicyConfig)).not.toContain("customer_uploaded_invoice_image");
    expect(JSON.stringify(visualContextPolicyConfig)).not.toContain("ocr_text_from_support_attachment");
    expect(JSON.stringify(visualContextPolicyConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(visualContextPolicyConfig)).not.toContain("slack.post_escalation_reply");
    expect(JSON.stringify(visualContextPolicyConfig)).not.toContain("browser.submit_customer_form");
    expect(JSON.stringify(visualContextPolicyConfig)).not.toContain("memory.write_long_term_summary");
    expect(JSON.stringify(visualContextPolicyConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(visualContextPolicyConfig)).not.toContain("visual_customer_email");
    expect(JSON.stringify(visualContextPolicyConfig)).not.toContain("visual_account_number");
    expect(JSON.stringify(visualContextPolicyConfig)).not.toContain("confidential_invoice_image");
    const inboundTriggerConfig = surfaces.runtime_config.find((surface) => surface.path === "inbox/support-triage.yaml");
    expect(inboundTriggerConfig).toBeDefined();
    expect(inboundTriggerConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(inboundTriggerConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_inbound_trigger_config: true,
      inbound_trigger_provider: "gmail",
      inbound_trigger_external_source: true,
      inbound_trigger_source_redacted: true,
      inbound_trigger_payload_redacted: true,
      inbound_trigger_invokes_agent: true,
      inbound_trigger_invokes_tools: true,
      inbound_trigger_write_authority: true,
      inbound_trigger_external_response: true,
      inbound_trigger_memory_write: true,
      inbound_trigger_sensitive_context: true,
      inbound_trigger_pii_context: true,
      inbound_trigger_webhook_integrity_disabled: true,
      inbound_trigger_webhook_timestamp_validation_disabled: true,
      inbound_trigger_webhook_replay_protection_disabled: true,
      inbound_trigger_attachment_context: true,
      inbound_trigger_approval_required: false
    });
    expect(inboundTriggerConfig?.metadata.inbound_trigger_source_categories).toEqual([
      "chat_message",
      "email_message",
      "ticket_comment",
      "webhook_payload"
    ]);
    expect(inboundTriggerConfig?.metadata.inbound_trigger_payload_categories).toEqual([
      "attachment",
      "message_body",
      "message_title",
      "sender_identity"
    ]);
    expect(inboundTriggerConfig?.metadata.inbound_trigger_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "state_write",
      "tool_call"
    ]);
    expect(inboundTriggerConfig?.metadata.env_key_names).toEqual(["SUPPORT_INBOX_TOKEN"]);
    expect(inboundTriggerConfig?.metadata.secret_ref_key_names).toEqual(["SUPPORT_INBOX_TOKEN"]);
    expect(inboundTriggerConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(inboundTriggerConfig?.actions).toEqual(["call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(inboundTriggerConfig)).not.toContain("${SUPPORT_INBOX_TOKEN}");
    expect(JSON.stringify(inboundTriggerConfig)).not.toContain("mail-router.example.invalid");
    expect(JSON.stringify(inboundTriggerConfig)).not.toContain("secops-support@example.invalid");
    expect(JSON.stringify(inboundTriggerConfig)).not.toContain("support-triage-agent");
    expect(JSON.stringify(inboundTriggerConfig)).not.toContain("inbound_customer_email");
    expect(JSON.stringify(inboundTriggerConfig)).not.toContain("message.body");
    expect(JSON.stringify(inboundTriggerConfig)).not.toContain("unsigned_partner_webhook");
    expect(JSON.stringify(inboundTriggerConfig)).not.toContain("X-Support-Signature");
    expect(JSON.stringify(inboundTriggerConfig)).not.toContain("X-Support-Timestamp");
    expect(JSON.stringify(inboundTriggerConfig)).not.toContain("support_webhook_delivery_id");
    const hostedAssistantConfig = surfaces.runtime_config.find((surface) => surface.path === "assistants/support-assistant.yaml");
    expect(hostedAssistantConfig).toBeDefined();
    expect(hostedAssistantConfig).toMatchObject({
      trust_level: "project",
      data_classes: ["confidential", "credential", "pii", "secret"],
      actions: ["call", "execute", "publish", "read", "remember", "send", "write"],
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(hostedAssistantConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_hosted_assistant_config: true,
      hosted_assistant_provider: "openai_assistants",
      hosted_assistant_definition_detected: true,
      hosted_assistant_model_redacted: true,
      hosted_assistant_instructions_redacted: true,
      hosted_assistant_tool_names_redacted: true,
      hosted_assistant_tool_count: 4,
      hosted_assistant_privileged_tools: true,
      hosted_assistant_privileged_tool_category_count: 4,
      hosted_assistant_code_interpreter_enabled: true,
      hosted_assistant_file_search_enabled: true,
      hosted_assistant_function_tools_enabled: true,
      hosted_assistant_external_tool_authority: true,
      hosted_assistant_write_tool_authority: true,
      hosted_assistant_memory_write: true,
      hosted_assistant_tool_choice_auto: true,
      hosted_assistant_parallel_tool_calls: true,
      hosted_assistant_parallel_privileged_tool_fanout: true,
      hosted_assistant_tool_resources_redacted: true,
      hosted_assistant_vector_store_redacted: true,
      hosted_assistant_vector_store_count: 1,
      hosted_assistant_file_ids_redacted: true,
      hosted_assistant_file_count: 1,
      hosted_assistant_sensitive_context: true,
      hosted_assistant_pii_context: true,
      hosted_assistant_secret_context: true,
      hosted_assistant_untrusted_input: true,
      hosted_assistant_guardrails_disabled: true,
      hosted_assistant_approval_required: false
    });
    expect(hostedAssistantConfig?.metadata.hosted_assistant_tool_categories).toEqual([
      "code_interpreter",
      "external_response",
      "file_search",
      "function_tool",
      "memory_write",
      "state_write"
    ]);
    expect(hostedAssistantConfig?.metadata.env_key_names).toEqual(["OPENAI_ASSISTANT_TOKEN"]);
    expect(hostedAssistantConfig?.metadata.secret_ref_key_names).toEqual(["OPENAI_ASSISTANT_TOKEN"]);
    expect(JSON.stringify(hostedAssistantConfig)).not.toContain("${OPENAI_ASSISTANT_TOKEN}");
    expect(JSON.stringify(hostedAssistantConfig)).not.toContain("asst_support_ops_redacted_by_scanner");
    expect(JSON.stringify(hostedAssistantConfig)).not.toContain("customer-remediation-assistant");
    expect(JSON.stringify(hostedAssistantConfig)).not.toContain("gpt-4.1");
    expect(JSON.stringify(hostedAssistantConfig)).not.toContain("update_customer_record");
    expect(JSON.stringify(hostedAssistantConfig)).not.toContain("post_support_slack_reply");
    expect(JSON.stringify(hostedAssistantConfig)).not.toContain("file_support_private_case_notes");
    expect(JSON.stringify(hostedAssistantConfig)).not.toContain("vs_customer_support_private");
    expect(JSON.stringify(hostedAssistantConfig)).not.toContain("customer_email_address");
    const realtimeAgentConfig = surfaces.runtime_config.find((surface) => surface.path === "realtime/support-voice-agent.yaml");
    expect(realtimeAgentConfig).toBeDefined();
    expect(realtimeAgentConfig).toMatchObject({
      trust_level: "third_party",
      data_classes: ["confidential", "credential", "pii", "secret"],
      actions: ["call", "execute", "publish", "read", "remember", "send", "write"],
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(realtimeAgentConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_realtime_agent_session_config: true,
      realtime_agent_provider: "openai_realtime",
      realtime_agent_session_detected: true,
      realtime_agent_destination_redacted: true,
      realtime_agent_destination_count: 2,
      realtime_agent_external_caller: true,
      realtime_agent_voice_or_audio_input: true,
      realtime_agent_transcript_capture: true,
      realtime_agent_recording_enabled: true,
      realtime_agent_recording_redaction_disabled: true,
      realtime_agent_transcript_sanitization_disabled: true,
      realtime_agent_prompt_injection_filter_disabled: true,
      realtime_agent_tool_calls_enabled: true,
      realtime_agent_privileged_tool_authority: true,
      realtime_agent_write_authority: true,
      realtime_agent_external_response: true,
      realtime_agent_memory_write: true,
      realtime_agent_sensitive_context: true,
      realtime_agent_pii_context: true,
      realtime_agent_secret_exposure: true,
      realtime_agent_approval_required: false
    });
    expect(realtimeAgentConfig?.metadata.realtime_agent_destination_kinds).toEqual([
      "realtime_provider",
      "telephony_provider",
      "websocket_endpoint"
    ]);
    expect(realtimeAgentConfig?.metadata.realtime_agent_tool_authority_categories).toEqual([
      "external_response",
      "memory_write",
      "secret_manager_access",
      "state_write",
      "tool_call"
    ]);
    expect(realtimeAgentConfig?.metadata.env_key_names).toEqual(["REALTIME_AGENT_TOKEN", "TWILIO_AUTH_TOKEN"]);
    expect(realtimeAgentConfig?.metadata.secret_ref_key_names).toEqual(["REALTIME_AGENT_TOKEN", "TWILIO_AUTH_TOKEN"]);
    expect(JSON.stringify(realtimeAgentConfig)).not.toContain("${REALTIME_AGENT_TOKEN}");
    expect(JSON.stringify(realtimeAgentConfig)).not.toContain("${TWILIO_AUTH_TOKEN}");
    expect(JSON.stringify(realtimeAgentConfig)).not.toContain("realtime.agentcsp-demo.example.invalid");
    expect(JSON.stringify(realtimeAgentConfig)).not.toContain("gpt-4o-realtime-preview");
    expect(JSON.stringify(realtimeAgentConfig)).not.toContain("realtime_update_customer_record");
    expect(JSON.stringify(realtimeAgentConfig)).not.toContain("realtime_send_sms_reply");
    expect(JSON.stringify(realtimeAgentConfig)).not.toContain("realtime_secret_lookup");
    expect(JSON.stringify(realtimeAgentConfig)).not.toContain("pstn_customer_phone");
    expect(JSON.stringify(realtimeAgentConfig)).not.toContain("anonymous_support_caller");
    expect(JSON.stringify(realtimeAgentConfig)).not.toContain("support_voice_recordings_private");
    expect(JSON.stringify(realtimeAgentConfig)).not.toContain("realtime_caller_phone_number");
    expect(JSON.stringify(realtimeAgentConfig)).not.toContain("realtime_customer_account_id");
    expect(JSON.stringify(realtimeAgentConfig)).not.toContain("confidential_live_support_notes");
    const agentOrchestrationConfig = surfaces.runtime_config.find((surface) => surface.path === "agents/support-crew.yaml");
    expect(agentOrchestrationConfig).toBeDefined();
    expect(agentOrchestrationConfig).toMatchObject({
      trust_level: "project",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(agentOrchestrationConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_orchestration_config: true,
      agent_orchestration_framework: "crewai",
      agent_orchestration_multi_agent: true,
      agent_orchestration_agent_count: 2,
      agent_orchestration_agent_names_redacted: true,
      agent_orchestration_delegation_enabled: true,
      agent_orchestration_untrusted_input: true,
      agent_orchestration_shared_memory: true,
      agent_orchestration_memory_redacted: true,
      agent_orchestration_invokes_tools: true,
      agent_orchestration_privileged_agent: true,
      agent_orchestration_write_authority: true,
      agent_orchestration_external_authority: true,
      agent_orchestration_secret_authority: true,
      agent_orchestration_sensitive_data: true,
      agent_orchestration_pii_data: true,
      agent_orchestration_approval_required: false
    });
    expect(agentOrchestrationConfig?.metadata.agent_orchestration_delegation_categories).toEqual(
      expect.arrayContaining(["agent_delegation", "automatic_delegation", "peer_handoff"])
    );
    expect(agentOrchestrationConfig?.metadata.agent_orchestration_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "repo_or_filesystem_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(agentOrchestrationConfig?.metadata.env_key_names).toEqual(["CREW_AGENT_TOKEN"]);
    expect(agentOrchestrationConfig?.metadata.secret_ref_key_names).toEqual(["CREW_AGENT_TOKEN"]);
    expect(agentOrchestrationConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(agentOrchestrationConfig?.actions).toEqual(["call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(agentOrchestrationConfig)).not.toContain("${CREW_AGENT_TOKEN}");
    expect(JSON.stringify(agentOrchestrationConfig)).not.toContain("support-escalation-crew");
    expect(JSON.stringify(agentOrchestrationConfig)).not.toContain("production-support-memory");
    expect(JSON.stringify(agentOrchestrationConfig)).not.toContain("intake-router");
    expect(JSON.stringify(agentOrchestrationConfig)).not.toContain("operations-executor");
    expect(JSON.stringify(agentOrchestrationConfig)).not.toContain("customer_account_id");
    const autonomousLoopConfig = surfaces.runtime_config.find((surface) => surface.path === "autonomy/agent-loop.yaml");
    expect(autonomousLoopConfig).toBeDefined();
    expect(autonomousLoopConfig).toMatchObject({
      trust_level: "project",
      data_classes: ["confidential", "credential", "pii", "secret"],
      actions: ["call", "execute", "publish", "read", "remember", "send", "write"],
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(autonomousLoopConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_autonomous_loop_config: true,
      agent_autonomous_loop_enabled: true,
      agent_autonomous_loop_autonomous_mode: true,
      agent_autonomous_loop_loop_enabled: true,
      agent_autonomous_loop_auto_execute: true,
      agent_autonomous_loop_goal_source_redacted: true,
      agent_autonomous_loop_untrusted_goal: true,
      agent_autonomous_loop_privileged_tool_authority: true,
      agent_autonomous_loop_write_authority: true,
      agent_autonomous_loop_external_authority: true,
      agent_autonomous_loop_secret_authority: true,
      agent_autonomous_loop_shell_authority: true,
      agent_autonomous_loop_memory_feedback: true,
      agent_autonomous_loop_tool_output_feedback: true,
      agent_autonomous_loop_unbounded_iterations: true,
      agent_autonomous_loop_iteration_limit_redacted: true,
      agent_autonomous_loop_iteration_limit_high: false,
      agent_autonomous_loop_runtime_budget_missing: true,
      agent_autonomous_loop_stop_condition_missing: true,
      agent_autonomous_loop_kill_switch_disabled: true,
      agent_autonomous_loop_dry_run_disabled: true,
      agent_autonomous_loop_sensitive_context: true,
      agent_autonomous_loop_pii_context: true,
      agent_autonomous_loop_approval_required: false
    });
    expect(autonomousLoopConfig?.metadata.agent_autonomous_loop_goal_source_categories).toEqual([
      "customer_goal",
      "untrusted_prompt"
    ]);
    expect(autonomousLoopConfig?.metadata.agent_autonomous_loop_tool_authority_categories).toEqual([
      "browser_action",
      "database_write",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "shell_execution",
      "tool_call"
    ]);
    expect(autonomousLoopConfig?.metadata.env_key_names).toEqual(["AGENT_LOOP_TOKEN"]);
    expect(autonomousLoopConfig?.metadata.secret_ref_key_names).toEqual(["AGENT_LOOP_TOKEN"]);
    expect(JSON.stringify(autonomousLoopConfig)).not.toContain("${AGENT_LOOP_TOKEN}");
    expect(JSON.stringify(autonomousLoopConfig)).not.toContain("customer_ticket_prompt");
    expect(JSON.stringify(autonomousLoopConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(autonomousLoopConfig)).not.toContain("slack.post_customer_reply");
    expect(JSON.stringify(autonomousLoopConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(autonomousLoopConfig)).not.toContain("browser.submit_refund_form");
    expect(JSON.stringify(autonomousLoopConfig)).not.toContain("shell.run_remediation");
    expect(JSON.stringify(autonomousLoopConfig)).not.toContain("loop_customer_email");
    expect(JSON.stringify(autonomousLoopConfig)).not.toContain("loop_account_number");
    expect(JSON.stringify(autonomousLoopConfig)).not.toContain("confidential_loop_notes");
    const agentSafetyConfig = surfaces.runtime_config.find((surface) => surface.path === "guardrails/agent-safety.yaml");
    expect(agentSafetyConfig).toBeDefined();
    expect(agentSafetyConfig).toMatchObject({
      trust_level: "project",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(agentSafetyConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_safety_config: true,
      agent_safety_framework: "langchain",
      agent_safety_controls_declared: true,
      agent_safety_controls_disabled: true,
      agent_safety_prompt_injection_filter_disabled: true,
      agent_safety_output_validation_disabled: true,
      agent_safety_tool_result_sanitization_disabled: true,
      agent_safety_content_moderation_disabled: true,
      agent_safety_pii_redaction_disabled: true,
      agent_safety_secret_redaction_disabled: true,
      agent_safety_fail_open: true,
      agent_safety_default_allow: false,
      agent_safety_timeout_allows: false,
      agent_safety_error_allows: false,
      agent_safety_monitor_only: true,
      agent_safety_untrusted_input: true,
      agent_safety_privileged_tool_authority: true,
      agent_safety_write_authority: true,
      agent_safety_external_authority: true,
      agent_safety_memory_write_authority: true,
      agent_safety_secret_exposure: true,
      agent_safety_sensitive_data: true,
      agent_safety_pii_data: true,
      agent_safety_approval_required: false
    });
    expect(agentSafetyConfig?.metadata.agent_safety_disabled_controls).toEqual([
      "all_controls",
      "content_moderation",
      "output_validation",
      "pii_redaction",
      "prompt_injection_filter",
      "secret_redaction",
      "tool_result_sanitization"
    ]);
    expect(agentSafetyConfig?.metadata.agent_safety_fail_open_categories).toEqual(["monitor_only"]);
    expect(agentSafetyConfig?.metadata.agent_safety_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(agentSafetyConfig?.metadata.env_key_names).toEqual(["SAFETY_RUNTIME_TOKEN"]);
    expect(agentSafetyConfig?.metadata.secret_ref_key_names).toEqual(["SAFETY_RUNTIME_TOKEN"]);
    expect(agentSafetyConfig?.data_classes).toEqual(["confidential", "credential", "pii", "secret"]);
    expect(agentSafetyConfig?.actions).toEqual(["call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("${SAFETY_RUNTIME_TOKEN}");
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("customer-support-disabled-safety");
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("customer_ticket_message");
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("browser_tool_output");
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("customer_email_address");
    const failOpenSafetyConfig = surfaces.runtime_config.find((surface) => surface.path === "guardrails/fail-open-safety.yaml");
    expect(failOpenSafetyConfig).toBeDefined();
    expect(failOpenSafetyConfig).toMatchObject({
      trust_level: "project",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(failOpenSafetyConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_safety_config: true,
      agent_safety_framework: "openai",
      agent_safety_controls_declared: true,
      agent_safety_controls_disabled: false,
      agent_safety_fail_open: true,
      agent_safety_default_allow: true,
      agent_safety_timeout_allows: true,
      agent_safety_error_allows: true,
      agent_safety_monitor_only: true,
      agent_safety_untrusted_input: true,
      agent_safety_privileged_tool_authority: true,
      agent_safety_write_authority: true,
      agent_safety_external_authority: true,
      agent_safety_memory_write_authority: false,
      agent_safety_secret_exposure: true,
      agent_safety_sensitive_data: true,
      agent_safety_pii_data: true,
      agent_safety_approval_required: false
    });
    expect(failOpenSafetyConfig?.metadata.agent_safety_disabled_controls).toEqual([]);
    expect(failOpenSafetyConfig?.metadata.agent_safety_fail_open_categories).toEqual([
      "default_allow",
      "error_allow",
      "monitor_only",
      "timeout_allow"
    ]);
    expect(failOpenSafetyConfig?.metadata.agent_safety_tool_authority_categories).toEqual([
      "database_access",
      "external_response",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(failOpenSafetyConfig?.metadata.env_key_names).toEqual(["SAFETY_FALLBACK_TOKEN"]);
    expect(failOpenSafetyConfig?.metadata.secret_ref_key_names).toEqual(["SAFETY_FALLBACK_TOKEN"]);
    expect(failOpenSafetyConfig?.data_classes).toEqual(["confidential", "credential", "pii", "secret"]);
    expect(failOpenSafetyConfig?.actions).toEqual(["call", "execute", "publish", "read", "send", "write"]);
    expect(JSON.stringify(failOpenSafetyConfig)).not.toContain("${SAFETY_FALLBACK_TOKEN}");
    expect(JSON.stringify(failOpenSafetyConfig)).not.toContain("customer-support-fail-open-guardrail");
    expect(JSON.stringify(failOpenSafetyConfig)).not.toContain("customer_ticket_message");
    expect(JSON.stringify(failOpenSafetyConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(failOpenSafetyConfig)).not.toContain("failopen_customer_email");
    expect(JSON.stringify(failOpenSafetyConfig)).not.toContain("failopen_account_number");
    expect(JSON.stringify(failOpenSafetyConfig)).not.toContain("failopen_confidential_case_notes");
    const modelOnlySafetyConfig = surfaces.runtime_config.find((surface) => surface.path === "guardrails/model-only-safety.yaml");
    expect(modelOnlySafetyConfig).toBeDefined();
    expect(modelOnlySafetyConfig).toMatchObject({
      trust_level: "project",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(modelOnlySafetyConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_safety_config: true,
      agent_safety_framework: "openai",
      agent_safety_controls_declared: true,
      agent_safety_controls_disabled: false,
      agent_safety_fail_open: false,
      agent_safety_model_only_enforcement: true,
      agent_safety_pre_tool_enforcement_missing: true,
      agent_safety_deterministic_policy_missing: true,
      agent_safety_post_hoc_only: true,
      agent_safety_untrusted_input: true,
      agent_safety_privileged_tool_authority: true,
      agent_safety_write_authority: true,
      agent_safety_external_authority: true,
      agent_safety_secret_exposure: true,
      agent_safety_sensitive_data: true,
      agent_safety_pii_data: true,
      agent_safety_approval_required: false
    });
    expect(modelOnlySafetyConfig?.metadata.agent_safety_model_only_categories).toEqual([
      "deterministic_policy_missing",
      "llm_judge",
      "post_hoc_review",
      "pre_tool_enforcement_missing",
      "prompt_only_policy",
      "self_review"
    ]);
    expect(modelOnlySafetyConfig?.metadata.agent_safety_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(modelOnlySafetyConfig?.metadata.env_key_names).toEqual(["MODEL_GUARDRAIL_TOKEN"]);
    expect(modelOnlySafetyConfig?.metadata.secret_ref_key_names).toEqual(["MODEL_GUARDRAIL_TOKEN"]);
    expect(modelOnlySafetyConfig?.data_classes).toEqual(["confidential", "credential", "pii", "secret"]);
    expect(modelOnlySafetyConfig?.actions).toEqual(["call", "execute", "publish", "read", "send", "write"]);
    expect(JSON.stringify(modelOnlySafetyConfig)).not.toContain("${MODEL_GUARDRAIL_TOKEN}");
    expect(JSON.stringify(modelOnlySafetyConfig)).not.toContain("support-agent-model-only-guardrail");
    expect(JSON.stringify(modelOnlySafetyConfig)).not.toContain("support-agent-self-review-policy");
    expect(JSON.stringify(modelOnlySafetyConfig)).not.toContain("support-approval-model");
    expect(JSON.stringify(modelOnlySafetyConfig)).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(modelOnlySafetyConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(modelOnlySafetyConfig)).not.toContain("model_guardrail_customer_email");
    expect(JSON.stringify(modelOnlySafetyConfig)).not.toContain("confidential_model_guardrail_notes");
    const aiEvalHarnessConfig = surfaces.runtime_config.find((surface) => surface.path === "evals/live-redteam.yaml");
    expect(aiEvalHarnessConfig).toBeDefined();
    expect(aiEvalHarnessConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(aiEvalHarnessConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_ai_eval_harness_config: true,
      ai_eval_framework: "promptfoo",
      ai_eval_live_execution: true,
      ai_eval_adversarial_cases: true,
      ai_eval_untrusted_prompts: true,
      ai_eval_dataset_redacted: true,
      ai_eval_dataset_count: 2,
      ai_eval_invokes_agent: true,
      ai_eval_invokes_tools: true,
      ai_eval_write_authority: true,
      ai_eval_external_write_authority: true,
      ai_eval_remote_target: true,
      ai_eval_production_target: true,
      ai_eval_records_outputs: true,
      ai_eval_sensitive_data: true,
      ai_eval_pii_data: true,
      ai_eval_secret_exposure: true,
      ai_eval_approval_required: false
    });
    expect(aiEvalHarnessConfig?.metadata.ai_eval_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(aiEvalHarnessConfig?.metadata.env_key_names).toEqual(["EVAL_AGENT_TOKEN"]);
    expect(aiEvalHarnessConfig?.metadata.secret_ref_key_names).toEqual(["EVAL_AGENT_TOKEN"]);
    expect(aiEvalHarnessConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(aiEvalHarnessConfig?.actions).toEqual(["call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(aiEvalHarnessConfig)).not.toContain("${EVAL_AGENT_TOKEN}");
    expect(JSON.stringify(aiEvalHarnessConfig)).not.toContain("production-support-redteam");
    expect(JSON.stringify(aiEvalHarnessConfig)).not.toContain("agent-prod.example.invalid");
    expect(JSON.stringify(aiEvalHarnessConfig)).not.toContain("customer-support-prod-agent");
    expect(JSON.stringify(aiEvalHarnessConfig)).not.toContain("Ignore previous instructions");
    expect(JSON.stringify(aiEvalHarnessConfig)).not.toContain("prompt-injection-customer-record");
    expect(JSON.stringify(aiEvalHarnessConfig)).not.toContain("untrusted_customer_ticket");
    expect(JSON.stringify(aiEvalHarnessConfig)).not.toContain("support_api_token");
    expect(JSON.stringify(aiEvalHarnessConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(aiEvalHarnessConfig)).not.toContain(".evals/prod-redteam-results.json");
    expect(surfaces.ci_cd.length).toBe(1);
    expect(surfaces.ci_cd[0]?.metadata).toMatchObject({
      pull_request_trigger: true,
      write_permissions: true,
      mentions_secrets_context: true,
      run_commands_redacted: true,
      run_command_count: 1,
      package_manager_run: true,
      agent_run_command: true,
      agent_package_script_names: ["agent:run"],
      agent_package_script_bridge: true,
      untrusted_event_trigger: true,
      untrusted_event_payload_used: true,
      untrusted_event_payload_redacted: true,
      untrusted_event_agent_input: true
    });
    expect(surfaces.ci_cd[0]?.metadata.referenced_package_scripts).toEqual(["package-script:agent:run"]);
    expect(surfaces.ci_cd[0]?.metadata.untrusted_event_triggers).toEqual([
      "issue_comment",
      "pull_request",
      "repository_dispatch"
    ]);
    expect(surfaces.ci_cd[0]?.metadata.untrusted_event_payload_sources).toEqual([
      "issue_comment_body",
      "pull_request_text",
      "repository_dispatch_payload"
    ]);
    expect(surfaces.ci_cd[0]?.metadata.untrusted_event_context_env_keys).toEqual(["AGENTCSP_TICKET_CONTEXT"]);
    expect(surfaces.ci_cd[0]?.untrusted_to_privileged).toBe(true);
    expect(JSON.stringify(surfaces.ci_cd[0])).not.toContain("github.event.comment.body");
    expect(JSON.stringify(surfaces.ci_cd[0])).not.toContain("github.event.client_payload.prompt");
    expect(JSON.stringify(surfaces.ci_cd[0])).not.toContain("github.event.pull_request.body");
    const automation = surfaces.automations.find((surface) => surface.name === "workflow:agent-maintenance.yml");
    expect(automation).toMatchObject({
      type: "automation",
      path: ".github/workflows/agent-maintenance.yml",
      secret_exposure: true,
      side_effect: true,
      external_reach: true,
      untrusted_to_privileged: true
    });
    expect(automation?.metadata).toMatchObject({
      scheduled: true,
      manual_dispatch: true,
      external_dispatch: true,
      untrusted_event_trigger: true,
      untrusted_event_payload_used: true,
      untrusted_event_payload_redacted: true,
      untrusted_event_agent_input: true,
      write_permissions: true,
      mentions_secrets_context: true,
      run_commands_redacted: true,
      run_command_count: 1,
      package_manager_run: true,
      agent_run_command: true,
      agent_package_script_bridge: true,
      automation_triggers: ["issue_comment", "repository_dispatch", "schedule", "workflow_dispatch"]
    });
    expect(automation?.metadata.agent_package_script_names).toEqual(["agent:run"]);
    expect(automation?.metadata.referenced_agent_package_scripts).toEqual(["package-script:agent:run"]);
    expect(automation?.metadata.untrusted_event_triggers).toEqual(["issue_comment", "pull_request", "repository_dispatch"]);
    expect(automation?.metadata.untrusted_event_payload_sources).toEqual([
      "issue_comment_body",
      "pull_request_text",
      "repository_dispatch_payload"
    ]);
    expect(automation?.metadata.untrusted_event_context_env_keys).toEqual(["AGENTCSP_TICKET_CONTEXT"]);
    expect(automation?.actions).toContain("write");
    expect(automation?.actions).toContain("execute");
    expect(JSON.stringify(automation)).not.toContain("github.event.comment.body");
    expect(JSON.stringify(automation)).not.toContain("github.event.client_payload.prompt");
    expect(JSON.stringify(automation)).not.toContain("github.event.pull_request.body");
    expect(surfaces.rag_sources.length).toBeGreaterThanOrEqual(1);
    expect(surfaces.memory.length).toBeGreaterThanOrEqual(1);
    const ragFile = surfaces.rag_sources.find((surface) => surface.path === "rag/customer-note.md");
    expect(ragFile?.metadata).toMatchObject({
      content_analyzed: true,
      content_redacted: true,
      instruction_like_content: true,
      instruction_override: true,
      tool_directive: true,
      external_directive: true,
      sensitive_context_reference: true,
      data_egress_directive: true,
      context_bridge_data_egress: true
    });
    expect(ragFile?.data_classes).toContain("confidential");
    expect(ragFile?.actions).toContain("call");
    expect(ragFile?.actions).toContain("send");
    expect(JSON.stringify(ragFile)).not.toContain("Ignore previous repository instructions");
    const vectorStore = surfaces.rag_sources.find((surface) => surface.path === "rag/vector-store.yaml");
    expect(vectorStore).toBeDefined();
    expect(vectorStore).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(vectorStore?.metadata).toMatchObject({
      content_redacted: true,
      content_analyzed: false,
      values_collected: false,
      parsed_rag_connector_config: true,
      vector_store: true,
      vector_store_provider: "pinecone",
      vector_store_remote: true,
      vector_store_destination_redacted: true,
      vector_store_write_enabled: true,
      vector_store_sync_enabled: true,
      vector_store_ingests_untrusted_sources: true,
      vector_store_ingestion_enabled: true,
      vector_store_ingestion_source_redacted: true,
      vector_store_auto_ingest_enabled: true,
      vector_store_ingestion_writes_trusted_namespace: true,
      vector_store_ingestion_quarantine_disabled: true,
      vector_store_ingestion_moderation_disabled: true,
      vector_store_ingestion_instruction_stripping_disabled: true,
      vector_store_ingestion_sanitization_disabled: true,
      vector_store_ingestion_provenance_required: false,
      vector_store_ingestion_approval_required: false,
      vector_store_remote_fetch_enabled: true,
      vector_store_fetch_url_source_redacted: true,
      vector_store_fetch_user_or_model_selected_url: true,
      vector_store_fetch_follows_redirects: true,
      vector_store_fetch_private_network_allowed: true,
      vector_store_fetch_metadata_service_allowed: true,
      vector_store_fetch_network_allowlist_missing: true,
      vector_store_fetch_credential_forwarding: true,
      vector_store_sensitive_collection: true,
      vector_store_pii_collection: true,
      vector_store_namespace_redacted: true
    });
    expect(vectorStore?.metadata.vector_store_remote_destination_kinds).toEqual(["http_endpoint", "managed_vector_db"]);
    expect(vectorStore?.metadata.vector_store_ingestion_source_categories).toEqual([
      "message_source",
      "public_web",
      "support_ticket",
      "ticket_attachment",
      "user_upload"
    ]);
    expect(vectorStore?.metadata).toMatchObject({
      vector_store_retrieval_enabled: true,
      vector_store_user_query_input: true,
      vector_store_filter_redacted: true,
      vector_store_filter_count: 5,
      vector_store_broad_retrieval_scope: true,
      vector_store_acl_disabled: true,
      vector_store_provenance_filter_disabled: true,
      vector_store_trust_filter_disabled: true,
      vector_store_prompt_injection_passthrough: true,
      vector_store_raw_chunk_passthrough: true,
      vector_store_tool_context_injection: true,
      vector_store_approval_required: false
    });
    expect(vectorStore?.metadata.vector_store_filter_kinds).toEqual([
      "metadata_filter",
      "namespace_filter",
      "source_filter",
      "user_controlled_filter"
    ]);
    expect(vectorStore?.metadata.secret_ref_key_names).toEqual(["PINECONE_API_KEY"]);
    expect(vectorStore?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(vectorStore?.actions).toEqual(["call", "read", "remember", "send", "write"]);
    expect(JSON.stringify(vectorStore)).not.toContain("${PINECONE_API_KEY}");
    expect(JSON.stringify(vectorStore)).not.toContain("agentcsp-demo-vector.example.invalid");
    expect(JSON.stringify(vectorStore)).not.toContain("customer-support-escalations");
    expect(JSON.stringify(vectorStore)).not.toContain("internal-ticket-memory");
    expect(JSON.stringify(vectorStore)).not.toContain("customer_uploaded_docs");
    expect(JSON.stringify(vectorStore)).not.toContain("support_ticket_attachments");
    expect(JSON.stringify(vectorStore)).not.toContain("shared_inbox_messages");
    expect(JSON.stringify(vectorStore)).not.toContain("trusted_internal_runbooks");
    expect(JSON.stringify(vectorStore)).not.toContain("user_uploaded_url");
    expect(JSON.stringify(vectorStore)).not.toContain("customer_ticket_message");
    expect(JSON.stringify(vectorStore)).not.toContain("customer_account_id");
    expect(JSON.stringify(vectorStore)).not.toContain("internal_runbooks");
    const memoryStore = surfaces.memory.find((surface) => surface.path === "memory/long-term-store.yaml");
    expect(memoryStore).toBeDefined();
    expect(memoryStore).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: false,
      untrusted_to_privileged: true
    });
    expect(memoryStore?.metadata).toMatchObject({
      content_redacted: true,
      content_analyzed: false,
      values_collected: false,
      parsed_agent_memory_store_config: true,
      agent_memory_store_provider: "redis",
      agent_memory_store_remote: true,
      agent_memory_store_destination_redacted: true,
      agent_memory_store_persistent: true,
      agent_memory_store_shared: true,
      agent_memory_store_write_enabled: true,
      agent_memory_store_sync_enabled: true,
      agent_memory_store_untrusted_write: true,
      agent_memory_store_tool_output_capture: true,
      agent_memory_store_prompt_capture: true,
      agent_memory_store_retrieval_capture: true,
      agent_memory_store_secret_capture: true,
      agent_memory_store_output_replay_enabled: true,
      agent_memory_store_retention_days: 90,
      agent_memory_store_long_retention: true,
      agent_memory_store_unbounded_retention: false,
      agent_memory_store_redaction_disabled: true,
      agent_memory_store_sensitive_data: true,
      agent_memory_store_pii_data: true,
      agent_memory_store_namespace_redacted: true,
      agent_memory_store_public_access: true,
      agent_memory_store_cross_tenant_access: true,
      agent_memory_store_access_control_disabled: true,
      agent_memory_store_tenant_isolation_disabled: true,
      agent_memory_store_approval_required: false
    });
    expect(memoryStore?.metadata.agent_memory_store_destination_kinds).toEqual(["memory_store_endpoint"]);
    expect(memoryStore?.metadata.env_key_names).toEqual(["MEMORY_STORE_TOKEN"]);
    expect(memoryStore?.metadata.secret_ref_key_names).toEqual(["MEMORY_STORE_TOKEN"]);
    expect(memoryStore?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(memoryStore?.actions).toEqual(["call", "read", "remember", "send", "write"]);
    expect(JSON.stringify(memoryStore)).not.toContain("${MEMORY_STORE_TOKEN}");
    expect(JSON.stringify(memoryStore)).not.toContain("redis-prod-memory.example.invalid");
    expect(JSON.stringify(memoryStore)).not.toContain("support-long-term-memory");
    expect(JSON.stringify(memoryStore)).not.toContain("customer_memory_namespace");
    expect(JSON.stringify(memoryStore)).not.toContain("partner_support_vendor");
    expect(JSON.stringify(memoryStore)).not.toContain("global_customer_memory");
    expect(JSON.stringify(memoryStore)).not.toContain("untrusted_customer_message");
    expect(JSON.stringify(memoryStore)).not.toContain("browser_tool_output");
    expect(JSON.stringify(memoryStore)).not.toContain("future_agent_context");
    expect(JSON.stringify(memoryStore)).not.toContain("customer_email_address");
    const memoryFile = surfaces.memory.find((surface) => surface.path === "memory/release-notes.md");
    expect(memoryFile?.metadata).toMatchObject({
      content_analyzed: true,
      content_redacted: true,
      instruction_like_content: true,
      memory_write_directive: true,
      tool_directive: true,
      explicit_tool_reference: true,
      explicit_callable_reference: true,
      privileged_callable_reference: true,
      referenced_tool_count: 1,
      referenced_privileged_tool_count: 1
    });
    expect(memoryFile?.metadata.referenced_tools).toEqual(["publish_summary"]);
    expect(memoryFile?.metadata.referenced_privileged_tools).toEqual(["publish_summary"]);
    expect(memoryFile?.actions).toContain("remember");
    expect(memoryFile?.actions).toContain("call");
    expect(JSON.stringify(memoryFile)).not.toContain("maintenance shortcut");
    const promptTemplate = surfaces.prompts.find((surface) => surface.path === "prompts/support-ticket.prompt.md");
    const memoryPromptTemplate = surfaces.prompts.find((surface) => surface.path === "prompts/memory-ingest.prompt.md");
    expect(promptTemplate).toBeDefined();
    expect(promptTemplate?.metadata).toMatchObject({
      content_analyzed: true,
      content_redacted: true,
      prompt_template: true,
      template_variable_count: 2,
      untrusted_template_input: true,
      privileged_prompt_role: true,
      privileged_role_untrusted_template_input: true,
      privileged_role_untrusted_variable_count: 2,
      tool_directive: true,
      external_directive: true,
      template_bridge_tool: true,
      template_bridge_external: true,
      template_bridge_privileged: true,
      explicit_tool_reference: true,
      explicit_callable_reference: true,
      privileged_callable_reference: true,
      referenced_tool_count: 1,
      referenced_privileged_tool_count: 1
    });
    expect(promptTemplate?.metadata.template_variable_names).toEqual(["customer_note", "ticket_id"]);
    expect(promptTemplate?.metadata.untrusted_template_variables).toEqual(["customer_note", "ticket_id"]);
    expect(promptTemplate?.metadata.privileged_template_roles).toEqual(["developer", "system"]);
    expect(promptTemplate?.metadata.privileged_role_untrusted_variables).toEqual(["customer_note", "ticket_id"]);
    expect(promptTemplate?.metadata.referenced_tools).toEqual(["publish_summary"]);
    expect(promptTemplate?.metadata.referenced_privileged_tools).toEqual(["publish_summary"]);
    expect(promptTemplate?.actions).toContain("call");
    expect(promptTemplate?.actions).toContain("send");
    expect(promptTemplate?.untrusted_to_privileged).toBe(true);
    expect(JSON.stringify(promptTemplate)).not.toContain("Review ticket");
    expect(JSON.stringify(promptTemplate)).not.toContain("customer note");
    expect(memoryPromptTemplate?.metadata).toMatchObject({
      content_analyzed: true,
      content_redacted: true,
      prompt_template: true,
      template_variable_count: 1,
      untrusted_template_input: true,
      memory_write_directive: true,
      template_bridge_memory: true,
      template_bridge_privileged: true
    });
    expect(memoryPromptTemplate?.metadata.template_variable_names).toEqual(["customer_note"]);
    expect(memoryPromptTemplate?.metadata.untrusted_template_variables).toEqual(["customer_note"]);
    expect(memoryPromptTemplate?.actions).toContain("remember");
    expect(memoryPromptTemplate?.untrusted_to_privileged).toBe(true);
    expect(JSON.stringify(memoryPromptTemplate)).not.toContain("Summarize");
  });

  it("detects generated transcript state only when logs are included", async () => {
    const defaultFiles = await walkProject({
      root_path: fixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const defaultSurfaces = await detectSurfaces(defaultFiles);
    expect(defaultSurfaces.memory.some((surface) => surface.path === "logs/session-transcript.txt")).toBe(false);

    const logFiles = await walkProject({
      root_path: fixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: true,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const logSurfaces = await detectSurfaces(logFiles);
    const transcript = logSurfaces.memory.find((surface) => surface.path === "logs/session-transcript.txt");

    expect(transcript?.metadata).toMatchObject({
      content_analyzed: true,
      generated_state: true,
      transcript_like: true,
      tool_output_like: true,
      cached_output_like: true,
      instruction_like_content: true,
      tool_directive: true,
      external_directive: true
    });
    expect(transcript?.metadata.generated_state_kinds).toContain("tool_output");
    expect(transcript?.actions).toContain("call");
    expect(transcript?.actions).toContain("send");
    expect(JSON.stringify(transcript)).not.toContain("Ignore previous repository instructions");
  });

  it("keeps pinned context-window policies scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const contextWindowConfig = surfaces.runtime_config.find((surface) => surface.path === "context-window/pinned-policy.yaml");

    expect(contextWindowConfig).toMatchObject({
      trust_level: "project",
      actions: ["call", "read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      untrusted_to_privileged: false
    });
    expect(contextWindowConfig?.metadata).toMatchObject({
      parsed_agent_context_window_config: true,
      agent_context_window_enabled: true,
      agent_context_window_truncation_enabled: true,
      agent_context_window_compaction_enabled: false,
      agent_context_window_summarization_enabled: true,
      agent_context_window_overflow_policy_redacted: true,
      agent_context_window_untrusted_priority: false,
      agent_context_window_tool_output_priority: false,
      agent_context_window_memory_priority: false,
      agent_context_window_privileged_instruction_retention: true,
      agent_context_window_privileged_instruction_eviction: false,
      agent_context_window_safety_instruction_retention: true,
      agent_context_window_safety_instruction_eviction: false,
      agent_context_window_summary_untrusted: false,
      agent_context_window_summary_verification_disabled: false,
      agent_context_window_delimiter_disabled: false,
      agent_context_window_redaction_disabled: false,
      agent_context_window_privileged_tool_authority: false,
      agent_context_window_write_authority: false,
      agent_context_window_external_authority: false,
      agent_context_window_approval_required: true
    });
    expect(contextWindowConfig?.metadata.agent_context_window_tool_authority_categories).toEqual([]);
    expect(contextWindowConfig?.metadata.env_key_names).toEqual([]);
    expect(contextWindowConfig?.metadata.secret_ref_key_names).toEqual([]);
  });

  it("keeps pinned reviewed MCP tool catalogs scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const catalogMcp = surfaces.mcp_servers.find((surface) => surface.name === "internal-docs-catalog");

    expect(catalogMcp).toMatchObject({
      trust_level: "project",
      data_classes: ["confidential"],
      actions: ["call", "read"],
      side_effect: true,
      reversible: true,
      external_reach: false,
      secret_exposure: false,
      untrusted_to_privileged: false
    });
    expect(catalogMcp?.metadata).toMatchObject({
      remote: true,
      remote_host: "localhost",
      remote_scheme: "http",
      plaintext_remote_transport: false,
      encrypted_remote_transport: false,
      mcp_tool_catalog_detected: true,
      mcp_tool_catalog_enabled: true,
      mcp_tool_catalog_source_redacted: true,
      mcp_tool_catalog_source_count: 1,
      mcp_tool_catalog_dynamic: false,
      mcp_tool_catalog_auto_refresh: false,
      mcp_tool_catalog_model_visible_descriptions: true,
      mcp_tool_catalog_remote_schema_trust: false,
      mcp_tool_catalog_unpinned_tools: false,
      mcp_tool_catalog_signature_verification_disabled: false,
      mcp_tool_catalog_provenance_verification_disabled: false,
      mcp_tool_catalog_unreviewed_tools_allowed: false,
      mcp_tool_catalog_privileged_tool_authority: false,
      mcp_tool_catalog_write_authority: false,
      mcp_tool_catalog_external_authority: false,
      mcp_tool_catalog_memory_authority: false,
      mcp_tool_catalog_secret_context: false,
      mcp_tool_catalog_shell_authority: false,
      mcp_tool_catalog_sensitive_context: true,
      mcp_tool_catalog_pii_context: false,
      mcp_tool_catalog_approval_required: true,
      mcp_roots_redacted: false,
      mcp_root_count: 0,
      mcp_root_broad_scope: false,
      mcp_root_credential_scope: false,
      mcp_root_host_scope: false,
      mcp_root_sensitive_scope: false,
      mcp_root_approval_required: false,
      mcp_sampling_enabled: false,
      mcp_sampling_includes_context: false,
      mcp_sampling_sensitive_context: false,
      mcp_sampling_redaction_disabled: false,
      mcp_sampling_prompt_injection_filter_disabled: false,
      mcp_sampling_approval_required: false,
      mcp_elicitation_enabled: false,
      mcp_elicitation_sensitive_fields: false,
      mcp_elicitation_sensitive_field_count: 0,
      mcp_elicitation_redaction_disabled: false,
      mcp_elicitation_sanitization_disabled: false,
      mcp_elicitation_approval_required: false,
      mcp_resource_subscription_detected: true,
      mcp_resource_subscription_enabled: true,
      mcp_resource_subscription_source_redacted: true,
      mcp_resource_subscription_source_count: 1,
      mcp_resource_subscription_dynamic_updates: false,
      mcp_resource_subscription_auto_refresh: false,
      mcp_resource_subscription_auto_include_context: false,
      mcp_resource_subscription_model_visible_context: false,
      mcp_resource_subscription_raw_content_passthrough: false,
      mcp_resource_subscription_untrusted_source: false,
      mcp_resource_subscription_sanitization_disabled: false,
      mcp_resource_subscription_redaction_disabled: false,
      mcp_resource_subscription_prompt_injection_filter_disabled: false,
      mcp_resource_subscription_provenance_verification_disabled: false,
      mcp_resource_subscription_privileged_bridge: false,
      mcp_resource_subscription_write_authority: false,
      mcp_resource_subscription_external_authority: false,
      mcp_resource_subscription_memory_authority: false,
      mcp_resource_subscription_secret_context: false,
      mcp_resource_subscription_shell_authority: false,
      mcp_resource_subscription_sensitive_context: true,
      mcp_resource_subscription_pii_context: false,
      mcp_resource_subscription_approval_required: true,
      values_collected: false,
      content_redacted: true
    });
    expect(catalogMcp?.metadata.mcp_tool_catalog_source_kinds).toEqual(["static_manifest", "tool_catalog"]);
    expect(catalogMcp?.metadata.mcp_tool_catalog_tool_authority_categories).toEqual(["tool_call"]);
    expect(catalogMcp?.metadata.mcp_root_scope_kinds).toEqual([]);
    expect(catalogMcp?.metadata.mcp_resource_subscription_source_kinds).toEqual(["filesystem_resource"]);
    expect(catalogMcp?.metadata.mcp_resource_subscription_authority_categories).toEqual(["tool_call"]);
    expect(catalogMcp?.metadata.mcp_sampling_context_kinds).toEqual([]);
    expect(catalogMcp?.metadata.mcp_elicitation_sensitive_field_kinds).toEqual([]);
    expect(catalogMcp?.metadata.env_key_names).toEqual([]);
    expect(catalogMcp?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(catalogMcp)).not.toContain("static_local_manifest");
    expect(JSON.stringify(catalogMcp)).not.toContain("readonly_docs.search");
    expect(JSON.stringify(catalogMcp)).not.toContain("approved_internal_summary");
    expect(JSON.stringify(catalogMcp)).not.toContain("file:///workspace/docs/approved-internal-digest.json");
    expect(JSON.stringify(catalogMcp)).not.toContain("trusted_internal");
    expect(JSON.stringify(catalogMcp)).not.toContain("approved_internal_docs");
  });

  it("keeps PKCE-bound MCP OAuth clients scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const mcpAuthorization = surfaces.runtime_config.find((surface) => surface.path === "mcp-auth/scoped-oauth.yaml");

    expect(mcpAuthorization).toMatchObject({
      trust_level: "third_party",
      data_classes: ["unknown"],
      actions: ["call", "read", "send"],
      side_effect: false,
      reversible: true,
      external_reach: true,
      secret_exposure: false,
      untrusted_to_privileged: false
    });
    expect(mcpAuthorization?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_mcp_authorization_config: true,
      mcp_authorization_provider: "mcp_oauth",
      mcp_authorization_remote: true,
      mcp_authorization_destination_redacted: true,
      mcp_authorization_destination_count: 3,
      mcp_authorization_plaintext_endpoint: false,
      mcp_authorization_plaintext_oauth_endpoint: false,
      mcp_authorization_plaintext_mcp_resource_endpoint: false,
      mcp_authorization_dynamic_client_registration: false,
      mcp_authorization_client_secret_exposure: false,
      mcp_authorization_public_client: false,
      mcp_authorization_device_flow_enabled: false,
      mcp_authorization_device_endpoint_redacted: false,
      mcp_authorization_device_code_context_exposure: false,
      mcp_authorization_device_verification_uri_untrusted: false,
      mcp_authorization_device_polling_without_approval: false,
      mcp_authorization_redirect_uri_redacted: true,
      mcp_authorization_redirect_uri_count: 1,
      mcp_authorization_wildcard_redirect_uri: false,
      mcp_authorization_user_or_model_selected_redirect_uri: false,
      mcp_authorization_redirect_validation_disabled: false,
      mcp_authorization_pkce_disabled: false,
      mcp_authorization_state_validation_disabled: false,
      mcp_authorization_resource_indicator_missing: false,
      mcp_authorization_scope_redacted: true,
      mcp_authorization_broad_scope: false,
      mcp_authorization_sensitive_scope: false,
      mcp_authorization_pii_scope: false,
      mcp_authorization_refresh_token_storage: false,
      mcp_authorization_token_forwarding: false,
      mcp_authorization_untrusted_server: false,
      mcp_authorization_approval_required: true
    });
    expect(mcpAuthorization?.metadata.mcp_authorization_destination_kinds).toEqual([
      "authorization_server_metadata",
      "mcp_authorization_config",
      "mcp_resource_endpoint",
      "protected_resource_metadata"
    ]);
    expect(mcpAuthorization?.metadata.mcp_authorization_redirect_uri_kinds).toEqual(["remote_redirect_uri"]);
    expect(mcpAuthorization?.metadata.mcp_authorization_scope_kinds).toEqual(["read_scope"]);
    expect(mcpAuthorization?.metadata.env_key_names).toEqual([]);
    expect(mcpAuthorization?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(mcpAuthorization)).not.toContain("safe-mcp.example.invalid");
    expect(JSON.stringify(mcpAuthorization)).not.toContain("auth-safe.example.invalid");
  });

  it("keeps scoped context composers from materializing env secrets", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const composer = surfaces.runtime_config.find((surface) => surface.path === "context/scoped-composer.yaml");

    expect(composer).toMatchObject({
      trust_level: "project",
      secret_exposure: false,
      external_reach: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(composer?.metadata).toMatchObject({
      parsed_agent_context_composer_config: true,
      agent_context_composer_env_materialization: false,
      agent_context_composer_secret_env_materialization: false,
      agent_context_composer_env_materialization_privileged_context: false,
      agent_context_composer_env_materialization_redaction_disabled: false,
      agent_context_composer_untrusted_env_selector: false,
      agent_context_composer_approval_required: true
    });
    expect(composer?.metadata.agent_context_composer_env_materialization_target_categories).toEqual([]);
    expect(composer?.metadata.env_key_names).toEqual([]);
    expect(composer?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(composer)).not.toContain("approved_internal_summary");
    expect(JSON.stringify(composer)).not.toContain("readonly_docs.search");
  });

  it("keeps pinned remote instruction loaders scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const loader = surfaces.runtime_config.find((surface) => surface.path === "instruction-loader/pinned-instructions.yaml");

    expect(loader).toMatchObject({
      trust_level: "project",
      secret_exposure: false,
      external_reach: false,
      untrusted_to_privileged: false
    });
    expect(loader?.metadata).toMatchObject({
      parsed_agent_remote_instruction_loader_config: true,
      agent_remote_instruction_remote: false,
      agent_remote_instruction_auto_refresh_enabled: false,
      agent_remote_instruction_unpinned_reference: false,
      agent_remote_instruction_signature_verification_disabled: false,
      agent_remote_instruction_provenance_verification_missing: false,
      agent_remote_instruction_untrusted_selector: false,
      agent_remote_instruction_privileged_tool_authority: false,
      agent_remote_instruction_approval_required: true
    });
    expect(loader?.metadata.agent_remote_instruction_destination_kinds).toEqual([]);
    expect(loader?.metadata.agent_remote_instruction_role_categories).toEqual(["system_instruction"]);
    expect(loader?.metadata.agent_remote_instruction_tool_authority_categories).toEqual([]);
    expect(loader?.metadata.env_key_names).toEqual([]);
    expect(loader?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(loader)).not.toContain("approved-internal-system-summary");
    expect(JSON.stringify(loader)).not.toContain("readonly_docs.search");
    expect(JSON.stringify(loader)).not.toContain("approved_internal_instruction");
  });

  it("keeps idempotent approval-gated tool retry policies scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const retryPolicy = surfaces.runtime_config.find((surface) => surface.path === "tool-retry/scoped-retry.yaml");

    expect(retryPolicy).toMatchObject({
      trust_level: "project",
      actions: ["call", "read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(retryPolicy?.metadata).toMatchObject({
      parsed_agent_tool_retry_policy_config: true,
      agent_tool_retry_enabled: true,
      agent_tool_retry_automatic_retry: false,
      agent_tool_retry_replay_enabled: false,
      agent_tool_retry_retry_on_failure: false,
      agent_tool_retry_retry_on_timeout: false,
      agent_tool_retry_retry_on_rate_limit: false,
      agent_tool_retry_retry_on_validation_error: false,
      agent_tool_retry_max_attempts_redacted: true,
      agent_tool_retry_max_attempts_gt_one: false,
      agent_tool_retry_unbounded_attempts: false,
      agent_tool_retry_budget_missing: false,
      agent_tool_retry_backoff_disabled: false,
      agent_tool_retry_idempotency_required: true,
      agent_tool_retry_idempotency_disabled: false,
      agent_tool_retry_deduplication_disabled: false,
      agent_tool_retry_exactly_once_disabled: false,
      agent_tool_retry_non_idempotent_actions: false,
      agent_tool_retry_untrusted_input: false,
      agent_tool_retry_tool_output_replay: false,
      agent_tool_retry_model_selected_retry: false,
      agent_tool_retry_privileged_tool_authority: false,
      agent_tool_retry_write_authority: false,
      agent_tool_retry_external_authority: false,
      agent_tool_retry_memory_authority: false,
      agent_tool_retry_shell_authority: false,
      agent_tool_retry_destructive_authority: false,
      agent_tool_retry_secret_context: false,
      agent_tool_retry_sensitive_context: false,
      agent_tool_retry_pii_context: false,
      agent_tool_retry_approval_required: true
    });
    expect(retryPolicy?.metadata.agent_tool_retry_action_categories).toEqual(["tool_call"]);
    expect(retryPolicy?.metadata.env_key_names).toEqual([]);
    expect(retryPolicy?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(retryPolicy)).not.toContain("readonly_docs.search");
  });

  it("keeps local ephemeral reasoning scratchpads scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const scratchpad = surfaces.runtime_config.find((surface) => surface.path === "reasoning/local-scratchpad.yaml");

    expect(scratchpad).toMatchObject({
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["call", "read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(scratchpad?.metadata).toMatchObject({
      parsed_agent_reasoning_state_config: true,
      agent_reasoning_state_enabled: true,
      agent_reasoning_state_capture_enabled: false,
      agent_reasoning_state_chain_of_thought_capture: false,
      agent_reasoning_state_plan_capture: false,
      agent_reasoning_state_tool_observation_capture: false,
      agent_reasoning_state_prompt_context_capture: false,
      agent_reasoning_state_retrieval_context_capture: false,
      agent_reasoning_state_memory_context_capture: false,
      agent_reasoning_state_secret_capture: false,
      agent_reasoning_state_sensitive_capture: false,
      agent_reasoning_state_pii_capture: false,
      agent_reasoning_state_untrusted_input: false,
      agent_reasoning_state_persistent: false,
      agent_reasoning_state_shared: false,
      agent_reasoning_state_remote: false,
      agent_reasoning_state_public_access: false,
      agent_reasoning_state_destination_redacted: false,
      agent_reasoning_state_destination_count: 0,
      agent_reasoning_state_replay_enabled: false,
      agent_reasoning_state_planner_uses_state: false,
      agent_reasoning_state_system_prompt_injection: false,
      agent_reasoning_state_redaction_disabled: false,
      agent_reasoning_state_access_control_disabled: false,
      agent_reasoning_state_retention_enabled: false,
      agent_reasoning_state_approval_required: true
    });
    expect(scratchpad?.metadata.agent_reasoning_state_capture_categories).toEqual([]);
    expect(scratchpad?.metadata.agent_reasoning_state_destination_kinds).toEqual([]);
    expect(scratchpad?.metadata.env_key_names).toEqual([]);
    expect(scratchpad?.metadata.secret_ref_key_names).toEqual([]);
  });

  it("keeps approved web egress policies away from private metadata access", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const egress = surfaces.runtime_config.find((surface) => surface.path === "network/scoped-egress.yaml");

    expect(egress).toMatchObject({
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["call", "read", "send"],
      side_effect: false,
      external_reach: true,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(egress?.metadata).toMatchObject({
      parsed_agent_network_egress_config: true,
      agent_network_egress_enabled: true,
      agent_network_egress_web_tool_authority: true,
      agent_network_egress_destination_redacted: true,
      agent_network_egress_destination_count: 1,
      agent_network_egress_private_network_access: false,
      agent_network_egress_metadata_service_access: false,
      agent_network_egress_localhost_access: false,
      agent_network_egress_private_cidr_access: false,
      agent_network_egress_wildcard_destination: false,
      agent_network_egress_untrusted_input: false,
      agent_network_egress_user_controlled_url: false,
      agent_network_egress_redirects_allowed: false,
      agent_network_egress_dns_rebinding_protection_disabled: false,
      agent_network_egress_request_headers_forwarded: false,
      agent_network_egress_credential_forwarding: false,
      agent_network_egress_response_capture: false,
      agent_network_egress_sensitive_response_capture: false,
      agent_network_egress_pii_response_capture: false,
      agent_network_egress_approval_required: true
    });
    expect(egress?.metadata.agent_network_egress_destination_kinds).toEqual(["http_destination"]);
    expect(egress?.metadata.env_key_names).toEqual([]);
    expect(egress?.metadata.secret_ref_key_names).toEqual([]);
  });

  it("keeps scoped local workspace context loading away from sensitive sync", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const contextLoader = surfaces.runtime_config.find((surface) => surface.path === "workspace-context/scoped-context.yaml");

    expect(contextLoader).toMatchObject({
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["call", "read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(contextLoader?.metadata).toMatchObject({
      parsed_agent_workspace_context_config: true,
      agent_workspace_context_enabled: true,
      agent_workspace_context_auto_sync_enabled: false,
      agent_workspace_context_source_redacted: true,
      agent_workspace_context_source_count: 2,
      agent_workspace_context_sensitive_paths: false,
      agent_workspace_context_secret_path_exposure: false,
      agent_workspace_context_env_file_access: false,
      agent_workspace_context_ssh_key_access: false,
      agent_workspace_context_cloud_credential_access: false,
      agent_workspace_context_kubeconfig_access: false,
      agent_workspace_context_home_directory_access: false,
      agent_workspace_context_git_history_access: false,
      agent_workspace_context_repo_wide_access: false,
      agent_workspace_context_destination_redacted: false,
      agent_workspace_context_destination_count: 0,
      agent_workspace_context_remote_sync: false,
      agent_workspace_context_prompt_context: false,
      agent_workspace_context_rag_indexing: false,
      agent_workspace_context_memory_persistence: false,
      agent_workspace_context_untrusted_input: false,
      agent_workspace_context_pii_context: false,
      agent_workspace_context_redaction_disabled: false,
      agent_workspace_context_agentcspignore_bypassed: false,
      agent_workspace_context_approval_required: true
    });
    expect(contextLoader?.metadata.agent_workspace_context_source_categories).toEqual(["workspace_file"]);
    expect(contextLoader?.metadata.agent_workspace_context_destination_kinds).toEqual([]);
    expect(contextLoader?.metadata.env_key_names).toEqual([]);
    expect(contextLoader?.metadata.secret_ref_key_names).toEqual([]);
  });

  it("keeps approval-gated read-only OpenAPI imports scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const openApiTool = surfaces.tools.find((surface) => surface.path === "tools/read-openapi.yaml");

    expect(openApiTool).toMatchObject({
      name: "openapi:get:1",
      trust_level: "project",
      data_classes: ["confidential"],
      actions: ["call", "read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      untrusted_to_privileged: false
    });
    expect(openApiTool?.metadata).toMatchObject({
      parsed_openapi_tool_spec: true,
      openapi_agent_tool_import: true,
      openapi_method: "get",
      openapi_remote_server: false,
      openapi_server_kinds: ["relative_server"],
      openapi_authenticated_operation: false,
      openapi_write_operation: false,
      openapi_destructive_operation: false,
      openapi_external_operation: false,
      openapi_prompt_content_input: false,
      openapi_prompt_content_external_write: false,
      openapi_broad_or_sensitive_scope: true,
      openapi_approval_required: true
    });
    expect(openApiTool?.metadata.openapi_request_data_categories).toEqual(["customer_data"]);
  });

  it("keeps source-defined read-only MCP tools scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const sourceTool = surfaces.tools.find((surface) => surface.name === "source_read_internal_doc");

    expect(sourceTool).toMatchObject({
      path: "mcp-source/read-only-tools.ts",
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["call"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      untrusted_to_privileged: false
    });
    expect(sourceTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "registerTool",
      mcp_source_tool_argument_count: 3,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      values_collected: false,
      read_only_hint: true,
      idempotent_hint: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      open_world_schema: false,
      open_world_authority: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_shell_execution: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 0
    });
    expect(sourceTool?.metadata.handler_authority_classes).toEqual([]);
    expect(sourceTool?.metadata.handler_env_key_names).toEqual([]);
    expect(sourceTool?.metadata.mcp_source_tool_schema_styles).toEqual([
      "zod_field_map",
      "zod_object",
      "zod_strict"
    ]);
    expect(sourceTool?.metadata.schema_properties).toEqual(["document_id"]);
    expect(JSON.stringify(sourceTool)).not.toContain("approved internal summary");
    expect(JSON.stringify(sourceTool)).not.toContain("Read an approved internal documentation record");

    const pythonSourceTool = surfaces.tools.find((surface) => surface.name === "python_read_internal_doc");
    expect(pythonSourceTool).toMatchObject({
      path: "mcp-source/read_only_tools.py",
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["call"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      untrusted_to_privileged: false
    });
    expect(pythonSourceTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_mcp_source_tool: true,
      mcp_source_tool_registration: true,
      mcp_source_tool_registration_kind: "python_tool_decorator",
      mcp_source_tool_argument_count: 1,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      values_collected: false,
      read_only_hint: true,
      idempotent_hint: true,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      open_world_schema: false,
      open_world_authority: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_shell_execution: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 0
    });
    expect(pythonSourceTool?.metadata.handler_authority_classes).toEqual([]);
    expect(pythonSourceTool?.metadata.handler_env_key_names).toEqual([]);
    expect(pythonSourceTool?.metadata.mcp_source_tool_schema_styles).toEqual([
      "mcp_annotations",
      "pydantic_model",
      "python_signature"
    ]);
    expect(pythonSourceTool?.metadata.schema_properties).toEqual(["document_id"]);
    expect(pythonSourceTool?.metadata.required_properties).toEqual(["document_id"]);
    expect(JSON.stringify(pythonSourceTool)).not.toContain("approved internal summary");
    expect(JSON.stringify(pythonSourceTool)).not.toContain("Read an approved internal documentation record");
    expect(JSON.stringify(pythonSourceTool)).not.toContain("InternalDocRequest");
    expect(JSON.stringify(pythonSourceTool)).not.toContain("Approved internal document request");

    const langchainSourceTool = surfaces.tools.find((surface) => surface.name === "langchain_read_internal_doc");
    expect(langchainSourceTool).toMatchObject({
      path: "framework-tools/langchain_tools.py",
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["call"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      untrusted_to_privileged: false
    });
    expect(langchainSourceTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "langchain",
      agent_framework_source_tool_registration_kind: "python_tool_decorator",
      agent_framework_source_tool_argument_count: 1,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      values_collected: false,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      open_world_schema: false,
      open_world_authority: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_shell_execution: false,
      handler_filesystem_read: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 0
    });
    expect(langchainSourceTool?.metadata.handler_authority_classes).toEqual([]);
    expect(langchainSourceTool?.metadata.handler_env_key_names).toEqual([]);
    expect(langchainSourceTool?.metadata.agent_framework_source_tool_schema_styles).toEqual([
      "agent_framework_source_tool",
      "langchain",
      "pydantic_model",
      "python_signature",
      "python_tool_decorator"
    ]);
    expect(langchainSourceTool?.metadata.schema_properties).toEqual(["document_id"]);
    expect(langchainSourceTool?.metadata.required_properties).toEqual(["document_id"]);
    expect(JSON.stringify(langchainSourceTool)).not.toContain("framework approved internal summary");
    expect(JSON.stringify(langchainSourceTool)).not.toContain("Read approved internal documentation from LangChain");
    expect(JSON.stringify(langchainSourceTool)).not.toContain("LangChainInternalDocRequest");
    expect(JSON.stringify(langchainSourceTool)).not.toContain("Approved documentation identifier");

    const aiSdkSourceTool = surfaces.tools.find((surface) => surface.name === "aiSdkReadInternalDoc");
    expect(aiSdkSourceTool).toMatchObject({
      path: "framework-tools/vercel-ai-tools.ts",
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["call"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      untrusted_to_privileged: false
    });
    expect(aiSdkSourceTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      parsed_agent_framework_source_tool: true,
      agent_framework_source_tool: true,
      agent_framework_source_tool_framework: "vercel_ai",
      agent_framework_source_tool_registration_kind: "js_tool_factory",
      agent_framework_source_tool_argument_count: 1,
      source_tool_schema_redacted: true,
      source_tool_handler_redacted: true,
      values_collected: false,
      external_write: false,
      destructive_action: false,
      read_only_hint_conflict: false,
      open_world_schema: false,
      open_world_authority: false,
      handler_body_analyzed: true,
      handler_body_redacted: true,
      handler_external_network_call: false,
      handler_external_write: false,
      handler_secret_env_access: false,
      handler_shell_execution: false,
      handler_filesystem_write: false,
      handler_filesystem_delete: false,
      handler_signal_count: 0
    });
    expect(aiSdkSourceTool?.metadata.handler_authority_classes).toEqual([]);
    expect(aiSdkSourceTool?.metadata.handler_env_key_names).toEqual([]);
    expect(aiSdkSourceTool?.metadata.agent_framework_source_tool_schema_styles).toEqual([
      "agent_framework_source_tool",
      "js_tool_factory",
      "vercel_ai",
      "zod_field_map",
      "zod_object",
      "zod_strict"
    ]);
    expect(aiSdkSourceTool?.metadata.schema_properties).toEqual(["document_id"]);
    expect(aiSdkSourceTool?.metadata.required_properties).toEqual(["document_id"]);
    expect(JSON.stringify(aiSdkSourceTool)).not.toContain("ai sdk approved internal summary");
    expect(JSON.stringify(aiSdkSourceTool)).not.toContain("Read approved AI SDK internal documentation");
    expect(JSON.stringify(aiSdkSourceTool)).not.toContain("internalDocReadInput");
    expect(JSON.stringify(aiSdkSourceTool)).not.toContain("Approved internal document schema hint");
  });

  it("keeps approval-gated read-only hosted assistants scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const hostedAssistant = surfaces.runtime_config.find((surface) => surface.path === "assistants/read-assistant.yaml");

    expect(hostedAssistant).toMatchObject({
      trust_level: "project",
      actions: ["call", "read", "remember"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      untrusted_to_privileged: false
    });
    expect(hostedAssistant?.metadata).toMatchObject({
      parsed_hosted_assistant_config: true,
      hosted_assistant_provider: "openai_assistants",
      hosted_assistant_definition_detected: true,
      hosted_assistant_file_search_enabled: true,
      hosted_assistant_privileged_tools: false,
      hosted_assistant_privileged_tool_category_count: 0,
      hosted_assistant_tool_choice_auto: false,
      hosted_assistant_parallel_tool_calls: false,
      hosted_assistant_parallel_privileged_tool_fanout: false,
      hosted_assistant_vector_store_redacted: true,
      hosted_assistant_vector_store_count: 1,
      hosted_assistant_untrusted_input: false,
      hosted_assistant_guardrails_disabled: false,
      hosted_assistant_approval_required: true
    });
  });

  it("keeps approval-gated read-only realtime agents scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const realtimeAgent = surfaces.runtime_config.find((surface) => surface.path === "realtime/read-voice-agent.yaml");

    expect(realtimeAgent).toMatchObject({
      trust_level: "project",
      actions: ["call", "read", "remember"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(realtimeAgent?.metadata).toMatchObject({
      parsed_realtime_agent_session_config: true,
      realtime_agent_provider: "openai_realtime",
      realtime_agent_session_detected: true,
      realtime_agent_destination_redacted: false,
      realtime_agent_destination_count: 0,
      realtime_agent_external_caller: false,
      realtime_agent_voice_or_audio_input: true,
      realtime_agent_transcript_capture: true,
      realtime_agent_recording_enabled: false,
      realtime_agent_prompt_injection_filter_disabled: false,
      realtime_agent_tool_calls_enabled: false,
      realtime_agent_write_authority: false,
      realtime_agent_external_response: false,
      realtime_agent_memory_write: false,
      realtime_agent_secret_exposure: false,
      realtime_agent_approval_required: true
    });
    expect(JSON.stringify(realtimeAgent)).not.toContain("approved-realtime-model");
  });

  it("keeps local browser sessions from looking like authenticated file-transfer authority", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const browserSession = surfaces.runtime_config.find((surface) => surface.path === "browser/read-session.yaml");

    expect(browserSession).toMatchObject({
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["call", "read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(browserSession?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_browser_session_config: true,
      browser_provider: "playwright",
      browser_persistent_profile: false,
      browser_cookie_storage: false,
      browser_session_storage: false,
      browser_authenticated_session: false,
      browser_remote_debugging: false,
      browser_untrusted_navigation: false,
      browser_click_or_form_authority: false,
      browser_download_upload_enabled: false,
      browser_download_auto_accept: false,
      browser_download_raw_content: false,
      browser_download_passes_to_agent_context: false,
      browser_download_sandbox_disabled: false,
      browser_download_scan_disabled: false,
      browser_download_instruction_stripping_disabled: false,
      browser_file_chooser_enabled: false,
      browser_extensions_redacted: false,
      browser_extension_count: 0,
      browser_extension_privileged_permissions: false,
      browser_extension_automation: false,
      browser_password_manager_enabled: false,
      browser_autofill_sensitive_data: false,
      browser_download_path_redacted: false,
      browser_upload_path_redacted: false,
      browser_network_remote: false,
      browser_broad_origin_access: false,
      browser_destination_redacted: false,
      browser_path_references_redacted: false,
      browser_sensitive_data: false,
      browser_pii_data: false,
      browser_approval_required: true
    });
    expect(browserSession?.metadata.browser_destination_kinds).toEqual([]);
    expect(browserSession?.metadata.browser_extension_kinds).toEqual([]);
    expect(browserSession?.metadata.env_key_names).toEqual([]);
    expect(browserSession?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(browserSession)).not.toContain("approved_internal_docs");
  });

  it("keeps local read-only computer-use reviews scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const computerUse = surfaces.runtime_config.find((surface) => surface.path === "computer/read-desktop.yaml");

    expect(computerUse).toMatchObject({
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(computerUse?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_computer_use_config: true,
      agent_computer_use_provider: undefined,
      agent_computer_use_enabled: true,
      agent_computer_use_remote_session: false,
      agent_computer_use_destination_redacted: false,
      agent_computer_use_destination_count: 0,
      agent_computer_use_authenticated_session: false,
      agent_computer_use_credential_store_access: false,
      agent_computer_use_screen_capture: false,
      agent_computer_use_ocr_capture: false,
      agent_computer_use_clipboard_access: false,
      agent_computer_use_clipboard_write: false,
      agent_computer_use_keyboard_input: false,
      agent_computer_use_mouse_control: false,
      agent_computer_use_file_transfer: false,
      agent_computer_use_download_auto_accept: false,
      agent_computer_use_local_path_redacted: false,
      agent_computer_use_app_control: false,
      agent_computer_use_terminal_control: false,
      agent_computer_use_sensitive_context: false,
      agent_computer_use_pii_context: false,
      agent_computer_use_redaction_disabled: false,
      agent_computer_use_untrusted_input: false,
      agent_computer_use_approval_required: true
    });
    expect(computerUse?.metadata.agent_computer_use_destination_kinds).toEqual(["computer_use_config"]);
    expect(computerUse?.metadata.env_key_names).toEqual([]);
    expect(computerUse?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(computerUse)).not.toContain("local-desktop-review");
  });

  it("keeps local approved feedback loops scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const feedbackPipeline = surfaces.runtime_config.find((surface) => surface.path === "feedback/read-feedback-loop.yaml");

    expect(feedbackPipeline).toMatchObject({
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["call", "read", "remember"],
      external_reach: false,
      secret_exposure: false,
      untrusted_to_privileged: false
    });
    expect(feedbackPipeline?.metadata).toMatchObject({
      parsed_ai_feedback_pipeline_config: true,
      ai_feedback_provider: "generic_feedback",
      ai_feedback_collection_enabled: true,
      ai_feedback_remote_export: false,
      ai_feedback_destination_redacted: false,
      ai_feedback_destination_count: 0,
      ai_feedback_prompt_capture: false,
      ai_feedback_completion_capture: false,
      ai_feedback_tool_output_capture: false,
      ai_feedback_retrieval_capture: false,
      ai_feedback_memory_capture: false,
      ai_feedback_feedback_label_capture: true,
      ai_feedback_secret_capture: false,
      ai_feedback_sensitive_capture: false,
      ai_feedback_pii_capture: false,
      ai_feedback_untrusted_input: false,
      ai_feedback_training_promotion_enabled: false,
      ai_feedback_model_update_enabled: false,
      ai_feedback_eval_set_write: false,
      ai_feedback_redaction_disabled: false,
      ai_feedback_consent_required: true,
      ai_feedback_approval_required: true
    });
    expect(feedbackPipeline?.metadata.ai_feedback_capture_categories).toEqual(["feedback_label"]);
    expect(JSON.stringify(feedbackPipeline)).not.toContain("local_feedback");
  });

  it("keeps approval-gated read-only SaaS connectors out of publication risk", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const saasConnector = surfaces.runtime_config.find(
      (surface) => surface.path === "connectors/internal-slack-digest.yaml"
    );

    expect(saasConnector).toMatchObject({
      trust_level: "third_party",
      data_classes: ["unknown"],
      actions: ["call", "read", "send"],
      side_effect: false,
      external_reach: true,
      secret_exposure: false,
      reversible: true
    });
    expect(saasConnector?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_saas_connector_config: true,
      saas_connector_provider: "slack",
      saas_connector_external_reach: true,
      saas_connector_destination_redacted: true,
      saas_connector_scope_redacted: true,
      saas_connector_broad_scope: false,
      saas_connector_admin_scope: false,
      saas_connector_read_enabled: true,
      saas_connector_external_write_enabled: false,
      saas_connector_untrusted_input: false,
      saas_connector_sensitive_data: false,
      saas_connector_pii_data: false,
      saas_connector_approval_required: true
    });
    expect(saasConnector?.metadata.saas_connector_destination_kinds).toEqual([
      "api_endpoint",
      "managed_saas_provider"
    ]);
    expect(saasConnector?.metadata.saas_connector_scope_categories).toEqual(["messaging_read", "read_scope"]);
    expect(saasConnector?.metadata.env_key_names).toEqual([]);
    expect(saasConnector?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(saasConnector)).not.toContain("channels:history");
    expect(JSON.stringify(saasConnector)).not.toContain("users:read");
    expect(JSON.stringify(saasConnector)).not.toContain("approved-security-workspace");
    expect(JSON.stringify(saasConnector)).not.toContain("approved_digest");
  });

  it("keeps default-deny approval-gated safety policies scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const safetyPolicy = surfaces.runtime_config.find((surface) => surface.path === "guardrails/default-deny-safety.yaml");

    expect(safetyPolicy).toMatchObject({
      trust_level: "project",
      data_classes: ["confidential"],
      actions: ["call", "execute", "read"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(safetyPolicy?.metadata).toMatchObject({
      parsed_agent_safety_config: true,
      agent_safety_framework: "openai",
      agent_safety_controls_declared: true,
      agent_safety_controls_disabled: false,
      agent_safety_fail_open: false,
      agent_safety_default_allow: false,
      agent_safety_timeout_allows: false,
      agent_safety_error_allows: false,
      agent_safety_monitor_only: false,
      agent_safety_model_only_enforcement: false,
      agent_safety_pre_tool_enforcement_missing: false,
      agent_safety_deterministic_policy_missing: false,
      agent_safety_post_hoc_only: false,
      agent_safety_untrusted_input: false,
      agent_safety_privileged_tool_authority: true,
      agent_safety_write_authority: false,
      agent_safety_external_authority: false,
      agent_safety_memory_write_authority: false,
      agent_safety_secret_exposure: false,
      agent_safety_sensitive_data: true,
      agent_safety_pii_data: false,
      agent_safety_approval_required: true
    });
    expect(safetyPolicy?.metadata.agent_safety_disabled_controls).toEqual([]);
    expect(safetyPolicy?.metadata.agent_safety_fail_open_categories).toEqual([]);
    expect(safetyPolicy?.metadata.agent_safety_model_only_categories).toEqual([]);
    expect(safetyPolicy?.metadata.agent_safety_tool_authority_categories).toEqual(["tool_call"]);
    expect(JSON.stringify(safetyPolicy)).not.toContain("internal-readonly-default-deny");
    expect(JSON.stringify(safetyPolicy)).not.toContain("readonly_docs.search");
    expect(JSON.stringify(safetyPolicy)).not.toContain("approved_internal_docs");
  });

  it("keeps local approval-gated background queues scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const taskQueue = surfaces.runtime_config.find((surface) => surface.path === "queues/internal-review-jobs.yaml");

    expect(taskQueue).toMatchObject({
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["call", "read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(taskQueue?.metadata).toMatchObject({
      parsed_agent_task_queue_config: true,
      agent_task_queue_detected: true,
      agent_task_queue_remote: false,
      agent_task_queue_destination_redacted: true,
      agent_task_queue_destination_count: 1,
      agent_task_queue_background_consumer: false,
      agent_task_queue_asynchronous_execution: true,
      agent_task_queue_auto_execute: false,
      agent_task_queue_untrusted_payload: false,
      agent_task_queue_prompt_passthrough: false,
      agent_task_queue_tool_output_passthrough: false,
      agent_task_queue_retry_enabled: true,
      agent_task_queue_dead_letter_queue: true,
      agent_task_queue_replay_enabled: false,
      agent_task_queue_privileged_tool_authority: false,
      agent_task_queue_write_authority: false,
      agent_task_queue_external_authority: false,
      agent_task_queue_memory_authority: false,
      agent_task_queue_secret_exposure: false,
      agent_task_queue_sensitive_payload: false,
      agent_task_queue_pii_payload: false,
      agent_task_queue_approval_required: true
    });
    expect(taskQueue?.metadata.agent_task_queue_destination_kinds).toEqual(["local_in_memory_queue"]);
    expect(taskQueue?.metadata.agent_task_queue_payload_categories).toEqual([]);
    expect(taskQueue?.metadata.agent_task_queue_tool_authority_categories).toEqual(["tool_call"]);
    expect(JSON.stringify(taskQueue)).not.toContain("internal_review_ticket");
    expect(JSON.stringify(taskQueue)).not.toContain("approved_internal_summary");
    expect(JSON.stringify(taskQueue)).not.toContain("readonly_docs.search");
  });

  it("keeps bounded approval-gated agent loops scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const loop = surfaces.runtime_config.find((surface) => surface.path === "autonomy/bounded-loop.yaml");

    expect(loop).toMatchObject({
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["call", "read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(loop?.metadata).toMatchObject({
      parsed_agent_autonomous_loop_config: true,
      agent_autonomous_loop_enabled: true,
      agent_autonomous_loop_autonomous_mode: false,
      agent_autonomous_loop_loop_enabled: true,
      agent_autonomous_loop_auto_execute: false,
      agent_autonomous_loop_goal_source_redacted: false,
      agent_autonomous_loop_untrusted_goal: false,
      agent_autonomous_loop_privileged_tool_authority: false,
      agent_autonomous_loop_write_authority: false,
      agent_autonomous_loop_external_authority: false,
      agent_autonomous_loop_secret_authority: false,
      agent_autonomous_loop_shell_authority: false,
      agent_autonomous_loop_memory_feedback: false,
      agent_autonomous_loop_tool_output_feedback: false,
      agent_autonomous_loop_unbounded_iterations: false,
      agent_autonomous_loop_iteration_limit_redacted: true,
      agent_autonomous_loop_iteration_limit_high: false,
      agent_autonomous_loop_runtime_budget_missing: false,
      agent_autonomous_loop_stop_condition_missing: false,
      agent_autonomous_loop_kill_switch_disabled: false,
      agent_autonomous_loop_dry_run_disabled: false,
      agent_autonomous_loop_sensitive_context: false,
      agent_autonomous_loop_pii_context: false,
      agent_autonomous_loop_approval_required: true
    });
    expect(loop?.metadata.agent_autonomous_loop_goal_source_categories).toEqual([]);
    expect(loop?.metadata.agent_autonomous_loop_tool_authority_categories).toEqual(["tool_call"]);
    expect(loop?.metadata.env_key_names).toEqual([]);
    expect(loop?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(loop)).not.toContain("approved_review");
    expect(JSON.stringify(loop)).not.toContain("readonly_docs.search");
  });

  it("keeps authenticated internal agent chats scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const chat = surfaces.runtime_config.find((surface) => surface.path === "public-chat/internal-chat.yaml");

    expect(chat).toMatchObject({
      trust_level: "project",
      data_classes: ["confidential"],
      actions: ["call", "read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(chat?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_public_agent_chat_config: true,
      public_agent_chat_enabled: true,
      public_agent_chat_endpoint_redacted: false,
      public_agent_chat_endpoint_count: 0,
      public_agent_chat_public_endpoint: false,
      public_agent_chat_anonymous_access: false,
      public_agent_chat_auth_disabled: false,
      public_agent_chat_cors_broad: false,
      public_agent_chat_csrf_disabled: false,
      public_agent_chat_rate_limit_missing: false,
      public_agent_chat_abuse_protection_disabled: false,
      public_agent_chat_file_upload_enabled: false,
      public_agent_chat_upload_raw_text: false,
      public_agent_chat_upload_sandbox_disabled: false,
      public_agent_chat_upload_scan_disabled: false,
      public_agent_chat_upload_instruction_stripping_disabled: false,
      public_agent_chat_untrusted_input: false,
      public_agent_chat_auto_tool_invocation: false,
      public_agent_chat_privileged_tool_authority: false,
      public_agent_chat_write_authority: false,
      public_agent_chat_external_response: false,
      public_agent_chat_memory_write: false,
      public_agent_chat_secret_access: false,
      public_agent_chat_sensitive_context: true,
      public_agent_chat_pii_context: false,
      public_agent_chat_redaction_disabled: false,
      public_agent_chat_approval_required: true
    });
    expect(chat?.metadata.public_agent_chat_endpoint_kinds).toEqual([]);
    expect(chat?.metadata.public_agent_chat_tool_authority_categories).toEqual(["tool_call"]);
    expect(chat?.metadata.env_key_names).toEqual([]);
    expect(chat?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(chat)).not.toContain("support.internal.example");
    expect(JSON.stringify(chat)).not.toContain("approved_internal_question");
    expect(JSON.stringify(chat)).not.toContain("readonly_docs.search");
    expect(JSON.stringify(chat)).not.toContain("approved_internal_docs");
  });

  it("keeps internal prompt inspectors scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const inspector = surfaces.runtime_config.find((surface) => surface.path === "debug/internal-inspector.yaml");

    expect(inspector).toMatchObject({
      trust_level: "project",
      data_classes: ["confidential"],
      actions: ["call", "read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(inspector?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_debug_console_config: true,
      agent_debug_console_enabled: true,
      agent_debug_console_endpoint_redacted: false,
      agent_debug_console_endpoint_count: 0,
      agent_debug_console_public_endpoint: false,
      agent_debug_console_anonymous_access: false,
      agent_debug_console_auth_disabled: false,
      agent_debug_console_cors_broad: false,
      agent_debug_console_prompt_view_enabled: true,
      agent_debug_console_system_prompt_visible: false,
      agent_debug_console_developer_prompt_visible: false,
      agent_debug_console_raw_context_visible: false,
      agent_debug_console_trace_view_enabled: false,
      agent_debug_console_memory_view_enabled: false,
      agent_debug_console_tool_schema_visible: true,
      agent_debug_console_prompt_edit_enabled: false,
      agent_debug_console_tool_invocation_enabled: false,
      agent_debug_console_impersonation_enabled: false,
      agent_debug_console_privileged_tool_authority: false,
      agent_debug_console_write_authority: false,
      agent_debug_console_external_authority: false,
      agent_debug_console_memory_write_authority: false,
      agent_debug_console_secret_context_visible: false,
      agent_debug_console_sensitive_context: true,
      agent_debug_console_pii_context: false,
      agent_debug_console_redaction_disabled: false,
      agent_debug_console_audit_logging_disabled: false,
      agent_debug_console_approval_required: true
    });
    expect(inspector?.metadata.agent_debug_console_endpoint_kinds).toEqual([]);
    expect(inspector?.metadata.agent_debug_console_tool_authority_categories).toEqual(["tool_call"]);
    expect(inspector?.metadata.env_key_names).toEqual([]);
    expect(inspector?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(inspector)).not.toContain("approved_internal_prompt_summary");
    expect(JSON.stringify(inspector)).not.toContain("readonly_docs.search");
  });

  it("keeps internal redacted response streams scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const stream = surfaces.runtime_config.find((surface) => surface.path === "responses/internal-stream.yaml");

    expect(stream).toMatchObject({
      trust_level: "project",
      data_classes: ["confidential"],
      actions: ["read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(stream?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_response_exposure_config: true,
      agent_response_exposure_enabled: true,
      agent_response_exposure_endpoint_redacted: false,
      agent_response_exposure_endpoint_count: 0,
      agent_response_exposure_public_endpoint: false,
      agent_response_exposure_anonymous_access: false,
      agent_response_exposure_auth_disabled: false,
      agent_response_exposure_cors_broad: false,
      agent_response_exposure_streaming_enabled: true,
      agent_response_exposure_reasoning_visible: false,
      agent_response_exposure_system_prompt_visible: false,
      agent_response_exposure_developer_prompt_visible: false,
      agent_response_exposure_tool_output_visible: false,
      agent_response_exposure_tool_argument_visible: false,
      agent_response_exposure_retrieval_visible: false,
      agent_response_exposure_memory_visible: false,
      agent_response_exposure_secret_context_visible: false,
      agent_response_exposure_sensitive_context: true,
      agent_response_exposure_pii_context: false,
      agent_response_exposure_redaction_disabled: false,
      agent_response_exposure_external_response: false,
      agent_response_exposure_approval_required: true
    });
    expect(stream?.metadata.agent_response_exposure_endpoint_kinds).toEqual([]);
    expect(stream?.metadata.env_key_names).toEqual([]);
    expect(stream?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(stream)).not.toContain("approved_internal_status");
  });

  it("keeps scoped approval-gated action routers quiet", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const router = surfaces.runtime_config.find((surface) => surface.path === "action-router/scoped-actions.yaml");

    expect(router).toMatchObject({
      trust_level: "project",
      data_classes: ["confidential"],
      actions: ["call", "read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(router?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_agent_action_router_config: true,
      agent_action_router_enabled: true,
      agent_action_router_model_output_input: true,
      agent_action_router_untrusted_input: false,
      agent_action_router_schema_validation_disabled: false,
      agent_action_router_strict_schema: true,
      agent_action_router_open_action_schema: false,
      agent_action_router_unknown_actions_allowed: false,
      agent_action_router_json_repair_enabled: false,
      agent_action_router_batch_execution_enabled: false,
      agent_action_router_auto_execute: false,
      agent_action_router_privileged_tool_authority: false,
      agent_action_router_write_authority: false,
      agent_action_router_external_authority: false,
      agent_action_router_memory_authority: false,
      agent_action_router_secret_access: false,
      agent_action_router_shell_authority: false,
      agent_action_router_sensitive_context: true,
      agent_action_router_pii_context: false,
      agent_action_router_redaction_disabled: false,
      agent_action_router_dry_run_disabled: false,
      agent_action_router_approval_required: true
    });
    expect(router?.metadata.agent_action_router_action_format_categories).toEqual(["json"]);
    expect(router?.metadata.agent_action_router_tool_authority_categories).toEqual([]);
    expect(router?.metadata.env_key_names).toEqual([]);
    expect(router?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(router)).not.toContain("approved_internal_task");
    expect(JSON.stringify(router)).not.toContain("approved_internal_summary");
    expect(JSON.stringify(router)).not.toContain("readonly_docs.search");
  });

  it("keeps local tenant-scoped prompt caches quiet", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const promptCache = surfaces.runtime_config.find((surface) => surface.path === "prompt-cache/local-response-cache.yaml");

    expect(promptCache).toMatchObject({
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["call", "read", "write"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(promptCache?.metadata).toMatchObject({
      parsed_llm_prompt_cache_config: true,
      llm_prompt_cache_enabled: true,
      llm_prompt_cache_remote: false,
      llm_prompt_cache_shared: false,
      llm_prompt_cache_persistent: false,
      llm_prompt_cache_write_enabled: true,
      llm_prompt_cache_prompt_capture: false,
      llm_prompt_cache_completion_capture: false,
      llm_prompt_cache_secret_capture: false,
      llm_prompt_cache_sensitive_capture: false,
      llm_prompt_cache_pii_capture: false,
      llm_prompt_cache_untrusted_input: false,
      llm_prompt_cache_semantic_reuse_enabled: false,
      llm_prompt_cache_user_controlled_key: false,
      llm_prompt_cache_broad_match_threshold: false,
      llm_prompt_cache_cross_tenant_replay: false,
      llm_prompt_cache_tenant_isolation_disabled: false,
      llm_prompt_cache_redaction_disabled: false,
      llm_prompt_cache_replay_enabled: false,
      llm_prompt_cache_retention_enabled: false,
      llm_prompt_cache_approval_required: true
    });
    expect(promptCache?.metadata.llm_prompt_cache_capture_categories).toEqual([]);
    expect(promptCache?.metadata.env_key_names).toEqual([]);
    expect(promptCache?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(promptCache)).not.toContain("approved_internal_digest");
    expect(JSON.stringify(promptCache)).not.toContain("tenant_scoped_internal_cache");
  });

  it("keeps authenticated internal model gateways quiet", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const modelGateway = surfaces.runtime_config.find((surface) => surface.path === "models/internal-gateway.yaml");

    expect(modelGateway).toMatchObject({
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["call", "read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(modelGateway?.metadata).toMatchObject({
      parsed_ai_model_config: true,
      ai_model_provider: "openai_compatible",
      ai_model_remote_endpoint: false,
      ai_model_custom_endpoint: true,
      ai_model_public_endpoint: false,
      ai_model_anonymous_clients: false,
      ai_model_cors_broad: false,
      ai_model_rate_limit_missing: false,
      ai_model_auth_required: true,
      ai_model_auth_disabled: false,
      ai_model_destination_redacted: false,
      ai_model_plaintext_endpoint: false,
      ai_model_encrypted_endpoint: false,
      ai_model_sends_prompts: false,
      ai_model_sends_tool_outputs: false,
      ai_model_sends_retrieval_context: false,
      ai_model_sends_memory: false,
      ai_model_sensitive_context: false,
      ai_model_pii_context: false,
      ai_model_secret_context: false,
      ai_model_untrusted_input: false,
      ai_model_request_logging_enabled: false,
      ai_model_redaction_disabled: false,
      ai_model_tool_calling_enabled: false,
      ai_model_tool_auto_execute: false,
      ai_model_tool_write_authority: false,
      ai_model_tool_external_authority: false,
      ai_model_approval_required: true
    });
    expect(modelGateway?.metadata.ai_model_tool_authority_categories).toEqual([]);
    expect(modelGateway?.metadata.ai_model_remote_destination_kinds).toEqual([]);
    expect(JSON.stringify(modelGateway)).not.toContain("internal-read-model-gateway");
    expect(JSON.stringify(modelGateway)).not.toContain("localhost:11434");
  });

  it("keeps scoped approval-gated secret brokers out of prompt materialization risk", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const secretBroker = surfaces.runtime_config.find((surface) => surface.path === "secrets/scoped-broker.yaml");

    expect(secretBroker).toMatchObject({
      trust_level: "project",
      data_classes: ["confidential", "credential", "secret"],
      actions: ["call", "read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: true,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(secretBroker?.metadata).toMatchObject({
      parsed_secret_manager_config: true,
      secret_manager_remote: false,
      secret_manager_destination_redacted: false,
      secret_manager_scope_redacted: true,
      secret_manager_path_references_redacted: true,
      secret_manager_read_enabled: true,
      secret_manager_list_enabled: false,
      secret_manager_write_enabled: false,
      secret_manager_broad_scope: false,
      secret_manager_injects_into_tools: false,
      secret_manager_injects_into_prompt_context: false,
      secret_manager_redaction_disabled: false,
      secret_manager_untrusted_input: false,
      secret_manager_approval_required: true
    });
    expect(secretBroker?.metadata.secret_manager_scope_categories).toEqual(["secret_read"]);
    expect(secretBroker?.metadata.secret_manager_prompt_context_categories).toEqual([]);
    expect(secretBroker?.metadata.env_key_names).toEqual([]);
    expect(secretBroker?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(secretBroker)).not.toContain("aliases/support-readonly-token");
    expect(JSON.stringify(secretBroker)).not.toContain("readonly-secret-aliases");
    expect(JSON.stringify(secretBroker)).not.toContain("approved_internal_task");
    expect(JSON.stringify(secretBroker)).not.toContain("internal_alias_only");
  });

  it("keeps signed internal approval channels quiet", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const approvalChannel = surfaces.runtime_config.find((surface) => surface.path === "approvals/internal-review.yaml");

    expect(approvalChannel).toMatchObject({
      trust_level: "project",
      data_classes: ["confidential"],
      actions: ["approve", "call", "read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(approvalChannel?.metadata).toMatchObject({
      parsed_agent_approval_config: true,
      agent_approval_prompt_redacted: true,
      agent_approval_external_channel: false,
      agent_approval_channel_auth_disabled: false,
      agent_approval_approver_identity_unverified: false,
      agent_approval_replay_protection_disabled: false,
      agent_approval_broad_approver_scope: false,
      agent_approval_context_untrusted: false,
      agent_approval_raw_context_included: false,
      agent_approval_decision_model_driven: false,
      agent_approval_uses_untrusted_summary: false,
      agent_approval_human_required: true,
      agent_approval_default_allow: false,
      agent_approval_auto_execute_after_approval: false,
      agent_approval_privileged_actions: false,
      agent_approval_write_actions: false,
      agent_approval_destructive_actions: false,
      agent_approval_external_actions: false,
      agent_approval_memory_write: false,
      agent_approval_secret_access: false,
      agent_approval_sensitive_data: true,
      agent_approval_pii_data: false
    });
    expect(approvalChannel?.metadata.agent_approval_channel_categories).toEqual(["internal_console"]);
    expect(approvalChannel?.metadata.agent_approval_prompt_source_categories).toEqual([]);
    expect(approvalChannel?.metadata.agent_approval_action_categories).toEqual([]);
    expect(JSON.stringify(approvalChannel)).not.toContain("security_reviewers");
    expect(JSON.stringify(approvalChannel)).not.toContain("approved_internal_summary");
    expect(JSON.stringify(approvalChannel)).not.toContain("readonly_docs.search");
  });

  it("keeps authenticated read-only shared sessions quiet", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const sharedSession = surfaces.runtime_config.find((surface) => surface.path === "sessions/internal-review-session.yaml");

    expect(sharedSession).toMatchObject({
      trust_level: "project",
      data_classes: ["confidential"],
      actions: ["read"],
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(sharedSession?.metadata).toMatchObject({
      parsed_agent_session_sharing_config: true,
      agent_session_sharing_enabled: true,
      agent_session_sharing_external: false,
      agent_session_sharing_public_access: false,
      agent_session_sharing_anonymous_access: false,
      agent_session_sharing_auth_disabled: false,
      agent_session_sharing_destination_redacted: false,
      agent_session_sharing_destination_count: 0,
      agent_session_sharing_collaborator_count: 0,
      agent_session_sharing_external_collaborators: false,
      agent_session_sharing_broad_collaborator_scope: false,
      agent_session_sharing_live_control_enabled: false,
      agent_session_sharing_prompt_injection_enabled: false,
      agent_session_sharing_tool_control_enabled: false,
      agent_session_sharing_tool_write_authority: false,
      agent_session_sharing_tool_execution_authority: false,
      agent_session_sharing_approval_control_enabled: false,
      agent_session_sharing_resume_replay_enabled: false,
      agent_session_sharing_transcript_capture: false,
      agent_session_sharing_sensitive_context: true,
      agent_session_sharing_pii_context: false,
      agent_session_sharing_secret_capture: false,
      agent_session_sharing_redaction_disabled: false,
      agent_session_sharing_untrusted_input: false,
      agent_session_sharing_approval_required: true
    });
    expect(sharedSession?.metadata.agent_session_sharing_destination_kinds).toEqual(["session_config"]);
    expect(sharedSession?.metadata.agent_session_sharing_control_categories).toEqual([]);
    expect(sharedSession?.metadata.agent_session_sharing_capture_categories).toEqual([]);
    expect(sharedSession?.metadata.env_key_names).toEqual([]);
    expect(sharedSession?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(sharedSession)).not.toContain("internal-readonly-review");
    expect(JSON.stringify(sharedSession)).not.toContain("security_reviewers");
  });

  it("keeps rootless approval-gated agent containers scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const containerRuntime = surfaces.runtime_config.find((surface) => surface.path === "runtime/rootless-container.yaml");

    expect(containerRuntime).toMatchObject({
      side_effect: false,
      external_reach: false,
      secret_exposure: false,
      reversible: true,
      untrusted_to_privileged: false
    });
    expect(containerRuntime?.metadata).toMatchObject({
      parsed_agent_container_runtime_config: true,
      agent_container_provider: "docker",
      agent_container_runtime_enabled: true,
      agent_container_privileged: false,
      agent_container_root_user: false,
      agent_container_docker_socket_mount: false,
      agent_container_host_path_mount: false,
      agent_container_host_root_mount: false,
      agent_container_writable_host_mount: false,
      agent_container_workspace_mount: false,
      agent_container_credential_mount: false,
      agent_container_sensitive_mount: false,
      agent_container_mounts_redacted: false,
      agent_container_host_network: false,
      agent_container_host_pid: false,
      agent_container_host_ipc: false,
      agent_container_network_enabled: false,
      agent_container_dangerous_capability: false,
      agent_container_shell_authority: false,
      agent_container_filesystem_authority: false,
      agent_container_browser_authority: false,
      agent_container_docker_authority: false,
      agent_container_untrusted_input: true,
      agent_container_pii_input: false,
      agent_container_secret_env_exposure: false,
      agent_container_approval_required: true
    });
    expect(containerRuntime?.metadata.agent_container_mount_kinds).toEqual([]);
    expect(containerRuntime?.metadata.agent_container_capability_categories).toEqual([]);
    expect(containerRuntime?.metadata.agent_container_tool_authority_categories).toEqual([]);
    expect(containerRuntime?.metadata.env_key_names).toEqual([]);
    expect(containerRuntime?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(containerRuntime)).not.toContain("internal/read-agent");
    expect(JSON.stringify(containerRuntime)).not.toContain("readonly_docs.search");
  });

  it("keeps local approval-gated session memory scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const memoryStore = surfaces.memory.find((surface) => surface.path === "memory/private-session-store.yaml");

    expect(memoryStore).toMatchObject({
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["call", "read", "remember", "write"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      untrusted_to_privileged: false
    });
    expect(surfaces.memory.some((surface) => surface.path === "memory" && surface.metadata.heuristic === true)).toBe(false);
    expect(memoryStore?.metadata).toMatchObject({
      content_redacted: true,
      content_analyzed: false,
      values_collected: false,
      parsed_agent_memory_store_config: true,
      agent_memory_store_provider: "sqlite",
      agent_memory_store_remote: false,
      agent_memory_store_destination_redacted: false,
      agent_memory_store_persistent: true,
      agent_memory_store_shared: false,
      agent_memory_store_write_enabled: true,
      agent_memory_store_sync_enabled: false,
      agent_memory_store_untrusted_write: false,
      agent_memory_store_tool_output_capture: false,
      agent_memory_store_prompt_capture: false,
      agent_memory_store_retrieval_capture: false,
      agent_memory_store_secret_capture: false,
      agent_memory_store_output_replay_enabled: false,
      agent_memory_store_retention_days: 1,
      agent_memory_store_long_retention: false,
      agent_memory_store_unbounded_retention: false,
      agent_memory_store_redaction_disabled: false,
      agent_memory_store_sensitive_data: false,
      agent_memory_store_pii_data: false,
      agent_memory_store_public_access: false,
      agent_memory_store_cross_tenant_access: false,
      agent_memory_store_access_control_disabled: false,
      agent_memory_store_tenant_isolation_disabled: false,
      agent_memory_store_approval_required: true
    });
    expect(memoryStore?.metadata.agent_memory_store_destination_kinds).toEqual([]);
    expect(memoryStore?.metadata.env_key_names).toEqual([]);
    expect(memoryStore?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(memoryStore)).not.toContain("internal_private_session_memory");
    expect(JSON.stringify(memoryStore)).not.toContain("approved_internal_summary");
  });

  it("keeps local redacted telemetry sharing scoped", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const telemetryConfig = surfaces.runtime_config.find((surface) => surface.path === "observability/internal-tracing.yaml");

    expect(telemetryConfig).toMatchObject({
      trust_level: "project",
      data_classes: ["unknown"],
      actions: ["call", "read", "remember"],
      side_effect: true,
      external_reach: false,
      secret_exposure: false,
      reversible: false,
      untrusted_to_privileged: false
    });
    expect(telemetryConfig?.metadata).toMatchObject({
      content_redacted: true,
      values_collected: false,
      parsed_ai_telemetry_config: true,
      ai_telemetry_export_enabled: true,
      ai_telemetry_remote_export: false,
      ai_telemetry_destination_redacted: false,
      ai_telemetry_remote_destination_count: 0,
      ai_telemetry_captures_prompts: false,
      ai_telemetry_captures_completions: false,
      ai_telemetry_captures_tool_outputs: false,
      ai_telemetry_captures_retrieval: false,
      ai_telemetry_captures_memory: false,
      ai_telemetry_sensitive_capture: false,
      ai_telemetry_pii_capture: false,
      ai_telemetry_secret_capture_signal: false,
      ai_telemetry_redaction_disabled: false,
      ai_telemetry_public_access: false,
      ai_telemetry_shared_workspace: false,
      ai_telemetry_access_control_disabled: false,
      ai_telemetry_retention_enabled: true,
      ai_telemetry_trace_replay_enabled: false,
      ai_telemetry_eval_promotion_enabled: false,
      ai_telemetry_training_promotion_enabled: false,
      ai_telemetry_approval_required: true
    });
    expect(telemetryConfig?.metadata.ai_telemetry_remote_destination_kinds).toEqual([]);
    expect(telemetryConfig?.metadata.ai_telemetry_replay_target_categories).toEqual([]);
    expect(telemetryConfig?.metadata.env_key_names).toEqual([]);
    expect(telemetryConfig?.metadata.secret_ref_key_names).toEqual([]);
    expect(JSON.stringify(telemetryConfig)).not.toContain("internal_private_agent_traces");
  });

  it("does not treat negated safety instructions as granted authority", async () => {
    const files = await walkProject({
      root_path: safeFixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const instruction = surfaces.instructions.find((surface) => surface.path === "AGENTS.md");

    expect(instruction).toBeDefined();
    expect(instruction?.actions).toEqual(["read"]);
    expect(instruction?.side_effect).toBe(false);
    expect(instruction?.external_reach).toBe(false);
    expect(instruction?.reversible).toBe(true);
    expect(instruction?.untrusted_to_privileged).toBe(false);
    expect(instruction?.metadata).toMatchObject({
      content_analyzed: true,
      content_redacted: true,
      untrusted_context_reference: false,
      tool_directive: false,
      memory_write_directive: false,
      external_directive: false,
      context_bridge_privileged: false
    });
  });
});
