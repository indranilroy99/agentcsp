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
      "GITHUB_TOKEN",
      "OPENAI_API_KEY",
      "SLACK_WEBHOOK_URL",
      "TICKETING_MCP_TOKEN"
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
      remote_scheme: "https",
      url_redacted: true,
      header_names: ["Authorization"],
      auth_header_names: ["Authorization"],
      secret_ref_key_names: ["TICKETING_MCP_TOKEN"],
      values_collected: false
    });
    expect(JSON.stringify(remoteMcp)).not.toContain("${TICKETING_MCP_TOKEN}");
    expect(JSON.stringify(remoteMcp)).not.toContain("/sse");
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
    expect(surfaces.tools.some((surface) => surface.name === "package-script:sync:docs")).toBe(true);
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
      read_only_hint_conflict: false
    });
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
      agent_package_script_bridge: true
    });
    expect(surfaces.ci_cd[0]?.metadata.referenced_package_scripts).toEqual(["package-script:agent:run"]);
    const automation = surfaces.automations.find((surface) => surface.name === "workflow:agent-maintenance.yml");
    expect(automation).toMatchObject({
      type: "automation",
      path: ".github/workflows/agent-maintenance.yml",
      secret_exposure: true,
      side_effect: true,
      external_reach: true
    });
    expect(automation?.metadata).toMatchObject({
      scheduled: true,
      manual_dispatch: true,
      external_dispatch: true,
      write_permissions: true,
      mentions_secrets_context: true,
      run_commands_redacted: true,
      run_command_count: 1,
      package_manager_run: true,
      agent_run_command: true,
      agent_package_script_bridge: true,
      automation_triggers: ["repository_dispatch", "schedule", "workflow_dispatch"]
    });
    expect(automation?.metadata.agent_package_script_names).toEqual(["agent:run"]);
    expect(automation?.metadata.referenced_agent_package_scripts).toEqual(["package-script:agent:run"]);
    expect(automation?.actions).toContain("write");
    expect(automation?.actions).toContain("execute");
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
      vector_store_sensitive_collection: true,
      vector_store_namespace_redacted: true
    });
    expect(vectorStore?.metadata.vector_store_remote_destination_kinds).toEqual(["http_endpoint", "managed_vector_db"]);
    expect(vectorStore?.metadata.secret_ref_key_names).toEqual(["PINECONE_API_KEY"]);
    expect(vectorStore?.data_classes).toEqual(["confidential", "credential"]);
    expect(vectorStore?.actions).toEqual(["call", "read", "remember", "send", "write"]);
    expect(JSON.stringify(vectorStore)).not.toContain("${PINECONE_API_KEY}");
    expect(JSON.stringify(vectorStore)).not.toContain("agentcsp-demo-vector.example.invalid");
    expect(JSON.stringify(vectorStore)).not.toContain("customer-support-escalations");
    expect(JSON.stringify(vectorStore)).not.toContain("internal-ticket-memory");
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
    expect(promptTemplate?.metadata.referenced_tools).toEqual(["publish_summary"]);
    expect(promptTemplate?.metadata.referenced_privileged_tools).toEqual(["publish_summary"]);
    expect(promptTemplate?.actions).toContain("call");
    expect(promptTemplate?.actions).toContain("send");
    expect(promptTemplate?.untrusted_to_privileged).toBe(true);
    expect(JSON.stringify(promptTemplate)).not.toContain("Review ticket");
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
