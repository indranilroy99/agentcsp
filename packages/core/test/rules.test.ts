import { describe, expect, it } from "vitest";
import path from "node:path";
import { detectSurfaces } from "../src/scanner/detect.js";
import { walkProject } from "../src/scanner/walk.js";
import { loadRules, runRules } from "../src/rules/engine.js";

describe("rule engine", () => {
  it("runs built-in YAML rules over normalized manifest objects", async () => {
    const fixtureRoot = path.resolve("examples/vulnerable-agent");
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
    const rules = await loadRules(path.resolve("rules"));
    const findings = runRules(surfaces, rules);

    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-001")).toBe(true);
    expect(findings.every((finding) => finding.evidence.every((item) => item.redacted))).toBe(true);
  });
});
