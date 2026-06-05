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
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-003")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-004")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-005")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-006")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-007")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-008")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-003")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MCP-004")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RUNTIME-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-CICD-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-AUTOMATION-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-PROMPT-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RAG-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-RAG-002")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-SKILL-001")).toBe(true);
    expect(findings.some((finding) => finding.rule_id === "AGENTCSP-MEMORY-002")).toBe(true);
    expect(findings.some((finding) => finding.severity === "critical")).toBe(true);
    expect(findings.some((finding) => finding.confidence === "very_high")).toBe(true);
    expect(findings.find((finding) => finding.rule_id === "AGENTCSP-RUNTIME-001")?.confidence).toBe("very_high");
    expect(findings.find((finding) => finding.rule_id === "AGENTCSP-MCP-004")?.matched_object.name).toBe(
      "ticketing-package-runner"
    );
    expect(findings.find((finding) => finding.rule_id === "AGENTCSP-PROMPT-001")?.matched_object.path).toBe(
      "prompts/support-ticket.prompt.md"
    );
    expect(findings.find((finding) => finding.rule_id === "AGENTCSP-SKILL-001")?.matched_object.path).toBe(
      "skills/exfil-skill/SKILL.md"
    );
    expect(findings.find((finding) => finding.rule_id === "AGENTCSP-TOOL-005")?.matched_object.name).toBe(
      "post_customer_update"
    );
    expect(findings.find((finding) => finding.rule_id === "AGENTCSP-TOOL-006")?.matched_object.name).toBe(
      "readonly_cleanup_workspace"
    );
    const toolPathExfilFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-TOOL-008");
    expect(toolPathExfilFindings).toHaveLength(1);
    expect(toolPathExfilFindings[0]?.matched_object.name).toBe("customer_record");
    const toolShadowFindings = findings.filter((finding) => finding.rule_id === "AGENTCSP-TOOL-007");
    expect(toolShadowFindings.map((finding) => finding.matched_object.path).sort()).toEqual([
      "tools/agent-tools.json",
      "tools/shadow-tools.json"
    ]);
    expect(findings.every((finding) => finding.confidence_rationale.length > 0)).toBe(true);
    expect(findings.every((finding) => finding.evidence.every((item) => item.redacted))).toBe(true);
  });

  it("keeps the safe read-only fixture free of high and critical findings", async () => {
    const fixtureRoot = path.resolve("examples/safe-agent");
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

    expect(findings.filter((finding) => finding.severity === "critical" || finding.severity === "high")).toHaveLength(0);
  });

  it("flags generated agent state replay risk when logs are explicitly included", async () => {
    const fixtureRoot = path.resolve("examples/vulnerable-agent");
    const files = await walkProject({
      root_path: fixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: true,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const rules = await loadRules(path.resolve("rules"));
    const findings = runRules(surfaces, rules);
    const generatedStateFinding = findings.find((finding) => finding.rule_id === "AGENTCSP-GENSTATE-001");

    expect(generatedStateFinding).toBeDefined();
    expect(generatedStateFinding?.matched_object.path).toBe("logs/session-transcript.txt");
    expect(generatedStateFinding?.recommended_control).toBe("quarantine");
    expect(JSON.stringify(generatedStateFinding)).not.toContain("Ignore previous repository instructions");
  });
});
