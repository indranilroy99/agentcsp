import { describe, expect, it } from "vitest";
import path from "node:path";
import { detectSurfaces } from "../src/scanner/detect.js";
import { walkProject } from "../src/scanner/walk.js";

const fixtureRoot = path.resolve("examples/vulnerable-agent");

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
    expect(surfaces.skills.some((surface) => surface.path === "skills/exfil-skill/SKILL.md")).toBe(true);
    expect(surfaces.mcp_servers.length).toBeGreaterThanOrEqual(3);
    const remoteMcp = surfaces.mcp_servers.find((surface) => surface.name === "remote-ticketing");
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
    expect(surfaces.tools.some((surface) => surface.name === "package-script:sync:docs")).toBe(true);
    const publishTool = surfaces.tools.find((surface) => surface.name === "publish_summary");
    const deleteTool = surfaces.tools.find((surface) => surface.name === "delete_cache");
    const readTool = surfaces.tools.find((surface) => surface.name === "read_customer_record");
    expect(publishTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      external_write: true,
      accepts_secret_like_input: true,
      accepts_url_input: true
    });
    expect(deleteTool?.metadata).toMatchObject({
      parsed_tool_schema: true,
      destructive_action: true,
      accepts_path_input: true
    });
    expect(readTool?.side_effect).toBe(false);
    const runtimeConfig = surfaces.runtime_config.find((surface) => surface.path === ".codex/config.toml");
    expect(runtimeConfig?.metadata).toMatchObject({
      parsed_runtime_config: true,
      sandbox_disabled: true,
      approval_bypass: true,
      network_enabled: true,
      privileged_tools_allowed: true,
      secret_env_exposure: true,
      secret_values_collected: false
    });
    expect(runtimeConfig?.metadata.env_key_names).toEqual(["GITHUB_TOKEN", "SLACK_WEBHOOK_URL"]);
    expect(runtimeConfig?.actions).toContain("execute");
    expect(runtimeConfig?.actions).toContain("send");
    expect(JSON.stringify(runtimeConfig)).not.toContain("${GITHUB_TOKEN}");
    expect(surfaces.ci_cd.length).toBe(1);
    expect(surfaces.ci_cd[0]?.metadata).toMatchObject({
      pull_request_trigger: true,
      write_permissions: true,
      mentions_secrets_context: true
    });
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
  });
});
