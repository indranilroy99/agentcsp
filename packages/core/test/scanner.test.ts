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
      "AGENT_CONTAINER_TOKEN",
      "AGENT_DEPLOY_TOKEN",
      "AGENT_EXTENSION_TOKEN",
      "AGENT_IDENTITY_TOKEN",
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
      "CREW_AGENT_TOKEN",
      "CUSTOMER_SUCCESS_SLACK_BOT_TOKEN",
      "EMBEDDING_API_KEY",
      "EVAL_AGENT_TOKEN",
      "FALLBACK_MODEL_TOKEN",
      "FINE_TUNE_TOKEN",
      "GITHUB_TOKEN",
      "LLM_CACHE_TOKEN",
      "LLM_CACHE_URL",
      "MCP_OAUTH_CLIENT_SECRET",
      "MEMORY_STORE_TOKEN",
      "MODEL_ROUTER_TOKEN",
      "OPENAI_API_KEY",
      "PROMPT_REGISTRY_TOKEN",
      "SAFETY_RUNTIME_TOKEN",
      "SLACK_WEBHOOK_URL",
      "SUPPORT_DB_PASSWORD",
      "SUPPORT_DB_URL",
      "SUPPORT_INBOX_TOKEN",
      "TICKETING_MCP_TOKEN",
      "TOOL_OUTPUT_POLICY_TOKEN",
      "VAULT_AGENT_TOKEN",
      "VISION_CONTEXT_TOKEN"
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
      data_classes: ["confidential", "credential", "pii"],
      actions: ["call", "read", "send"],
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
      secret_ref_key_names: ["CONTEXT_BROKER_TOKEN"],
      mcp_roots_redacted: true,
      mcp_root_count: 3,
      mcp_root_scope_kinds: ["absolute_path", "credential_path", "file_uri", "home", "host_root", "workspace"],
      mcp_root_broad_scope: true,
      mcp_sampling_enabled: true,
      mcp_sampling_includes_context: true,
      mcp_elicitation_enabled: true,
      mcp_elicitation_sensitive_fields: true,
      mcp_context_request_authority: true,
      mcp_client_context_exposure: true,
      values_collected: false,
      content_redacted: true
    });
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("${CONTEXT_BROKER_TOKEN}");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("context-broker.example.invalid/mcp");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("file:///home/support/.ssh");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("file:///workspace/customer-escalations");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("file:///");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("support-ssh");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("customer-escalations");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("host-root");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("customer_email");
    expect(JSON.stringify(remoteContextBrokerMcp)).not.toContain("api_token");
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
      package_manifest_risky_dependency_count: 4,
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
      "floating_range",
      "git_dependency",
      "http_tarball",
      "latest_tag"
    ]);
    expect(packageManifestConfig?.metadata.env_key_names).toEqual(["AGENT_EXTENSION_TOKEN"]);
    expect(packageManifestConfig?.metadata.secret_ref_key_names).toEqual(["AGENT_EXTENSION_TOKEN"]);
    expect(packageManifestConfig?.data_classes).toEqual(["credential", "internal"]);
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
      ai_telemetry_retention_enabled: true
    });
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
    expect(webhookEgressConfig?.metadata.agent_webhook_egress_auth_header_names).toEqual(["Authorization"]);
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
      ai_model_destination_redacted: true,
      ai_model_plaintext_endpoint: true,
      ai_model_encrypted_endpoint: false,
      ai_model_sends_prompts: true,
      ai_model_sends_tool_outputs: true,
      ai_model_sends_retrieval_context: true,
      ai_model_sends_memory: true,
      ai_model_sensitive_context: true,
      ai_model_pii_context: true
    });
    expect(modelConfig?.metadata.ai_model_remote_destination_kinds).toEqual([
      "configured_model_endpoint",
      "http_endpoint"
    ]);
    expect(modelConfig?.metadata.secret_ref_key_names).toEqual(["OPENAI_API_KEY"]);
    expect(modelConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(modelConfig?.actions).toEqual(["call", "read", "send"]);
    expect(JSON.stringify(modelConfig)).not.toContain("${OPENAI_API_KEY}");
    expect(JSON.stringify(modelConfig)).not.toContain("llm-gateway.example.invalid");
    expect(JSON.stringify(modelConfig)).not.toContain("agentcsp-support-ops");
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
    expect(JSON.stringify(agentExposureConfig)).not.toContain("a2a_customer_email");
    expect(JSON.stringify(agentExposureConfig)).not.toContain("confidential_a2a_case_notes");
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
      mcp_authorization_destination_count: 4,
      mcp_authorization_dynamic_client_registration: true,
      mcp_authorization_client_secret_exposure: true,
      mcp_authorization_public_client: true,
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
      "dynamic_client_registration_endpoint",
      "mcp_authorization_config",
      "mcp_resource_endpoint",
      "protected_resource_metadata"
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
      browser_pii_data: true
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
    expect(JSON.stringify(saasConnectorConfig)).not.toContain("agentcsp-demo-workspace");
    expect(JSON.stringify(saasConnectorConfig)).not.toContain("saas_customer_email");
    const secretManagerConfig = surfaces.runtime_config.find((surface) => surface.path === "secrets/vault-agent.yaml");
    expect(secretManagerConfig).toBeDefined();
    expect(secretManagerConfig).toMatchObject({
      trust_level: "third_party",
      external_reach: true,
      secret_exposure: true,
      side_effect: true,
      reversible: true,
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
      agent_approval_context_untrusted: true,
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
    expect(contextComposerConfig?.metadata.agent_context_composer_tool_authority_categories).toEqual([
      "browser_action",
      "database_access",
      "external_response",
      "memory_write",
      "secret_manager_access",
      "tool_call"
    ]);
    expect(contextComposerConfig?.metadata.env_key_names).toEqual(["CONTEXT_COMPOSER_TOKEN"]);
    expect(contextComposerConfig?.metadata.secret_ref_key_names).toEqual(["CONTEXT_COMPOSER_TOKEN"]);
    expect(contextComposerConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(contextComposerConfig?.actions).toEqual(["call", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(contextComposerConfig)).not.toContain("${CONTEXT_COMPOSER_TOKEN}");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("customer_ticket_message");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("retrieved_account_context");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("browser_tool_output");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("command_tool_result");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(contextComposerConfig)).not.toContain("customer_context_email");
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
    expect(agentSafetyConfig?.data_classes).toEqual(["confidential", "credential", "pii"]);
    expect(agentSafetyConfig?.actions).toEqual(["call", "execute", "publish", "read", "remember", "send", "write"]);
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("${SAFETY_RUNTIME_TOKEN}");
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("customer-support-disabled-safety");
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("customer_ticket_message");
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("retrieved_customer_context");
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("browser_tool_output");
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("support_db.update_customer_record");
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("vault_secret_lookup.read_support_token");
    expect(JSON.stringify(agentSafetyConfig)).not.toContain("customer_email_address");
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
      agent_memory_store_sensitive_data: true,
      agent_memory_store_pii_data: true,
      agent_memory_store_namespace_redacted: true,
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
      openapi_broad_or_sensitive_scope: true,
      openapi_approval_required: true
    });
    expect(openApiTool?.metadata.openapi_request_data_categories).toEqual(["customer_data"]);
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
