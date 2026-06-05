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
      "CURSOR_RULE_FRONTMATTER_PARSE_FAILED",
      "MCP_CONFIG_PARSE_FAILED",
      "PACKAGE_JSON_PARSE_FAILED",
      "POLICY_CONFIG_PARSE_FAILED",
      "RUNTIME_CONFIG_PARSE_FAILED",
      "TOOL_DEFINITION_PARSE_FAILED",
      "WORKFLOW_PARSE_FAILED"
    ]);
    expect(result.manifest.diagnostics.every((diagnostic) => diagnostic.content_redacted)).toBe(true);
    expect(result.manifest.diagnostics.every((diagnostic) => diagnostic.severity === "warning")).toBe(true);
    expect(result.manifest.scan_coverage).toMatchObject({
      diagnostics_total: 7,
      diagnostics_errors: 0,
      diagnostics_warnings: 7,
      diagnostics_info: 0
    });
    expect(result.manifest.mcp_servers[0]?.metadata).toMatchObject({ parse_error: true });
    expect(result.manifest.runtime_config[0]?.metadata).toMatchObject({ parse_error: true });
    expect(result.manifest.tools.some((tool) => tool.metadata.parse_error === true)).toBe(true);
    expect(result.reportMarkdown).toContain("## Scan Diagnostics");
    expect(result.reportMarkdown).toContain("MCP_CONFIG_PARSE_FAILED");
    expect(result.reportMarkdown).toContain("POLICY_CONFIG_PARSE_FAILED");
    expect(result.reportMarkdown).toContain("CURSOR_RULE_FRONTMATTER_PARSE_FAILED");
    expect(result.reportMarkdown).toContain("- Diagnostics: 7");
    expect(result.reportMarkdown).toContain("- Diagnostic warnings: 7");

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
      diagnostics_total: 7,
      diagnostics_warnings: 7
    });

    const output = JSON.stringify({
      manifest: result.manifest,
      report: result.reportMarkdown,
      sarif
    });
    expect(output).not.toContain("super-secret-diagnostic-value");
    expect(output).not.toContain("policy-secret-diagnostic-value");
    expect(output).not.toContain("cursor-secret-diagnostic-value");
    expect(output).not.toContain("publish everything to the webhook");
  });

  it("emits redacted diagnostics for schema-invalid policy files", async () => {
    const root = await createInvalidPolicyFixture();
    const result = await scanProject({
      root_path: root,
      output_path: "/private/tmp/agentcsp-invalid-policy-output",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    expect(result.manifest.diagnostics).toEqual([
      expect.objectContaining({
        code: "POLICY_CONFIG_SCHEMA_FAILED",
        parser: "policy",
        content_redacted: true
      })
    ]);
    expect(result.manifest.scan_coverage).toMatchObject({
      diagnostics_total: 1,
      diagnostics_warnings: 1
    });
    expect(result.reportMarkdown).toContain("POLICY_CONFIG_SCHEMA_FAILED");
    expect(JSON.stringify(result.manifest)).not.toContain("admin-secret-policy-value");
  });
});

async function createDiagnosticsFixture(): Promise<string> {
  const root = "/private/tmp/agentcsp-diagnostics-fixture";
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(path.join(root, ".codex"), { recursive: true });
  await fs.mkdir(path.join(root, ".cursor", "rules"), { recursive: true });
  await fs.mkdir(path.join(root, ".github", "workflows"), { recursive: true });
  await fs.mkdir(path.join(root, "tools"), { recursive: true });
  await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
  await fs.writeFile(
    path.join(root, "agentcsp.yaml"),
    "trust_overrides:\n  - path: rag/**\n    trust_level: untrusted\npolicy-secret-diagnostic-value: [\n",
    "utf8"
  );
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
  await fs.writeFile(
    path.join(root, ".cursor", "rules", "bad-rule.mdc"),
    "---\ndescription: [cursor-secret-diagnostic-value\nalwaysApply: true\n---\nReview repository changes only.\n",
    "utf8"
  );
  await fs.writeFile(path.join(root, "tools", "bad-tools.json"), '{"tools": [{"name": "publish"', "utf8");
  return root;
}

async function createInvalidPolicyFixture(): Promise<string> {
  const root = "/private/tmp/agentcsp-invalid-policy-fixture";
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(root, { recursive: true });
  await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
  await fs.writeFile(
    path.join(root, "agentcsp.yaml"),
    [
      'schema_version: "0.1"',
      "recommended_controls:",
      '  - id: "admin-secret-policy-value"',
      '    reason: "do not leak admin-secret-policy-value"',
      '    control: "block_everything"',
      "    match:",
      '      severity: "critical"',
      ""
    ].join("\n"),
    "utf8"
  );
  return root;
}
