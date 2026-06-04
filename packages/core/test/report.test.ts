import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { scanProject } from "../src/scanner/scan.js";

describe("scanProject", () => {
  it("emits a manifest, findings, and a static blast-radius report", async () => {
    const result = await scanProject({
      root_path: path.resolve("examples/vulnerable-agent"),
      output_path: "/private/tmp/agentcsp-test-output",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    expect(result.manifest.metadata.config.secret_values_collected).toBe(false);
    expect(result.manifest.static_blast_radius?.title).toBe("Static Blast-Radius Summary");
    expect(result.manifest.static_blast_radius?.attack_paths).toBeGreaterThan(0);
    expect(result.manifest.triage_summary?.title).toBe("AgentCSP Triage Summary");
    expect(result.manifest.triage_summary?.total_findings).toBe(result.findings.length);
    expect(result.manifest.triage_summary?.active_findings).toBeGreaterThan(0);
    expect(result.manifest.triage_summary?.highest_active_severity).toBe("critical");
    expect(result.manifest.triage_summary?.active_by_severity.critical).toBeGreaterThan(0);
    expect(result.manifest.triage_summary?.active_by_confidence.very_high).toBeGreaterThan(0);
    expect(result.manifest.triage_summary?.active_by_surface_type.some((item) => item.surface_type === "tool")).toBe(true);
    expect(result.manifest.triage_summary?.active_by_recommended_control.length).toBeGreaterThan(0);
    expect(result.manifest.triage_summary?.top_active_risks[0]?.risk_score).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.outputFiles.sarif).toBeDefined();
    const sarif = JSON.parse(await fs.readFile(result.outputFiles.sarif!, "utf8")) as {
      runs: Array<{ properties?: { agentcsp_triage_summary?: { total_findings?: number } } }>;
    };
    expect(sarif.runs[0]?.properties?.agentcsp_triage_summary?.total_findings).toBe(result.findings.length);
    expect(JSON.stringify(sarif.runs[0]?.properties?.agentcsp_triage_summary)).not.toContain("replace-me");
    expect(result.reportMarkdown).toContain("## Triage Summary");
    expect(result.reportMarkdown).toContain("### Active Findings by Severity");
    expect(result.reportMarkdown).toContain("### Top Active Rules");
    expect(result.reportMarkdown).toContain("### Top Active Risks");
    expect(result.reportMarkdown).toContain("| Severity | Confidence | Risk | Rule | Object | Path | Recommended control |");
    expect(result.reportMarkdown).toContain("Recommended Controls");
    expect(result.reportMarkdown).toContain("Static Attack Paths");
    expect(result.reportMarkdown).toContain("| Severity | Confidence | Rule | Object | Recommended control | Policy | Risk factors |");
    expect(result.reportMarkdown).toContain("Policy actions in this MVP are recommended controls");
  });

  it("emits a quiet triage summary for the safe fixture", async () => {
    const result = await scanProject({
      root_path: path.resolve("examples/safe-agent"),
      output_path: "/private/tmp/agentcsp-safe-report-test-output",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    expect(result.findings).toHaveLength(0);
    expect(result.manifest.triage_summary?.total_findings).toBe(0);
    expect(result.manifest.triage_summary?.active_findings).toBe(0);
    expect(result.manifest.triage_summary?.highest_active_severity).toBe("info");
    expect(result.manifest.triage_summary?.max_active_risk_score).toBe(0);
    expect(result.manifest.triage_summary?.top_active_risks).toHaveLength(0);
    expect(result.reportMarkdown).toContain("No active findings were generated.");
  });
});
