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
    const remoteMcp = surfaces.mcp_servers.find((surface) => surface.name === "remote-ticketing");
    const packageRunnerMcp = surfaces.mcp_servers.find((surface) => surface.name === "ticketing-package-runner");
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
      read_only_hint_conflict: false
    });
    expect(openWorldTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      external_write: true,
      accepts_url_input: true,
      accepts_secret_like_input: true,
      open_world_schema: true,
      open_world_authority: true,
      read_only_hint_conflict: false
    });
    expect(readOnlyConflictTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      read_only_hint: true,
      destructive_action: true,
      accepts_path_input: true,
      read_only_hint_conflict: true,
      open_world_schema: false
    });
    expect(readOnlyConflictTool?.side_effect).toBe(true);
    expect(readTool?.side_effect).toBe(false);
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
    expect(surfaces.ci_cd.length).toBe(1);
    expect(surfaces.ci_cd[0]?.metadata).toMatchObject({
      pull_request_trigger: true,
      write_permissions: true,
      mentions_secrets_context: true
    });
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
      automation_triggers: ["repository_dispatch", "schedule", "workflow_dispatch"]
    });
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
      external_directive: true
    });
    expect(ragFile?.actions).toContain("call");
    expect(ragFile?.actions).toContain("send");
    expect(JSON.stringify(ragFile)).not.toContain("Ignore previous repository instructions");
    const memoryFile = surfaces.memory.find((surface) => surface.path === "memory/release-notes.md");
    expect(memoryFile?.metadata).toMatchObject({
      content_analyzed: true,
      content_redacted: true,
      instruction_like_content: true,
      memory_write_directive: true,
      tool_directive: true
    });
    expect(memoryFile?.actions).toContain("remember");
    expect(memoryFile?.actions).toContain("call");
    expect(JSON.stringify(memoryFile)).not.toContain("maintenance shortcut");
    const promptTemplate = surfaces.prompts.find((surface) => surface.path === "prompts/support-ticket.prompt.md");
    expect(promptTemplate).toBeDefined();
    expect(promptTemplate?.metadata).toMatchObject({
      content_analyzed: true,
      content_redacted: true,
      prompt_template: true,
      template_variable_count: 2,
      untrusted_template_input: true,
      tool_directive: true,
      external_directive: true
    });
    expect(promptTemplate?.metadata.template_variable_names).toEqual(["customer_note", "ticket_id"]);
    expect(promptTemplate?.metadata.untrusted_template_variables).toEqual(["customer_note", "ticket_id"]);
    expect(promptTemplate?.actions).toContain("call");
    expect(promptTemplate?.actions).toContain("send");
    expect(promptTemplate?.untrusted_to_privileged).toBe(true);
    expect(JSON.stringify(promptTemplate)).not.toContain("Review ticket");
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
