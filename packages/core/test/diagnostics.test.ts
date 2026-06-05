import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { scanProject } from "../src/scanner/scan.js";

describe("scan diagnostics", () => {
  it("emits redacted diagnostics for malformed security-relevant config files", async () => {
    const root = await createDiagnosticsFixture();
    const result = await scanProject({
      root_path: root,
      output_path: "/private/tmp/agentcsp-diagnostics-output",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    const codes = result.manifest.diagnostics.map((diagnostic) => diagnostic.code).sort((a, b) => a.localeCompare(b));
    expect(codes).toEqual([
      "MCP_CONFIG_PARSE_FAILED",
      "PACKAGE_JSON_PARSE_FAILED",
      "RUNTIME_CONFIG_PARSE_FAILED",
      "TOOL_DEFINITION_PARSE_FAILED",
      "WORKFLOW_PARSE_FAILED"
    ]);
    expect(result.manifest.diagnostics.every((diagnostic) => diagnostic.content_redacted)).toBe(true);
    expect(result.manifest.diagnostics.every((diagnostic) => diagnostic.severity === "warning")).toBe(true);
    expect(result.manifest.scan_coverage).toMatchObject({
      diagnostics_total: 5,
      diagnostics_errors: 0,
      diagnostics_warnings: 5,
      diagnostics_info: 0
    });
    expect(result.manifest.mcp_servers[0]?.metadata).toMatchObject({ parse_error: true });
    expect(result.manifest.runtime_config[0]?.metadata).toMatchObject({ parse_error: true });
    expect(result.manifest.tools.some((tool) => tool.metadata.parse_error === true)).toBe(true);
    expect(result.reportMarkdown).toContain("## Scan Diagnostics");
    expect(result.reportMarkdown).toContain("MCP_CONFIG_PARSE_FAILED");
    expect(result.reportMarkdown).toContain("- Diagnostics: 5");
    expect(result.reportMarkdown).toContain("- Diagnostic warnings: 5");

    const sarif = JSON.parse(await fs.readFile(result.outputFiles.sarif!, "utf8")) as {
      runs: Array<{
        properties?: {
          agentcsp_diagnostics?: Array<{ code?: string }>;
          agentcsp_scan_coverage?: { diagnostics_total?: number; diagnostics_warnings?: number };
        };
      }>;
    };
    expect(sarif.runs[0]?.properties?.agentcsp_diagnostics?.map((item) => item.code)).toContain(
      "RUNTIME_CONFIG_PARSE_FAILED"
    );
    expect(sarif.runs[0]?.properties?.agentcsp_scan_coverage).toMatchObject({
      diagnostics_total: 5,
      diagnostics_warnings: 5
    });

    const output = JSON.stringify({
      manifest: result.manifest,
      report: result.reportMarkdown,
      sarif
    });
    expect(output).not.toContain("super-secret-diagnostic-value");
    expect(output).not.toContain("publish everything to the webhook");
  });
});

async function createDiagnosticsFixture(): Promise<string> {
  const root = "/private/tmp/agentcsp-diagnostics-fixture";
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(path.join(root, ".codex"), { recursive: true });
  await fs.mkdir(path.join(root, ".github", "workflows"), { recursive: true });
  await fs.mkdir(path.join(root, "tools"), { recursive: true });
  await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
  await fs.writeFile(path.join(root, "mcp.json"), '{"mcpServers": {"bad": {"command": "run"', "utf8");
  await fs.writeFile(
    path.join(root, "package.json"),
    '{"scripts": {"deploy": "echo super-secret-diagnostic-value"',
    "utf8"
  );
  await fs.writeFile(
    path.join(root, ".github", "workflows", "agent.yml"),
    "on: [\n# publish everything to the webhook\n",
    "utf8"
  );
  await fs.writeFile(path.join(root, ".codex", "config.toml"), 'sandbox = "danger-full-access"\n[', "utf8");
  await fs.writeFile(path.join(root, "tools", "bad-tools.json"), '{"tools": [{"name": "publish"', "utf8");
  return root;
}
