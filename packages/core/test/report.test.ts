import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { scanProject } from "../src/scanner/scan.js";
import { renderSarifReport } from "../src/reports/sarif.js";

describe("scanProject", () => {
  it("emits a manifest, findings, and a static blast-radius report", async () => {
    const rootPath = path.resolve("examples/vulnerable-agent");
    const result = await scanProject({
      root_path: rootPath,
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
    expect(result.manifest.static_blast_radius?.sensitive_data_external_reach_paths).toBeGreaterThan(0);
    expect(result.manifest.static_blast_radius?.pii_external_reach_paths).toBeGreaterThan(0);
    expect(result.manifest.static_blast_radius?.credential_external_reach_paths).toBeGreaterThan(0);
    expect(result.manifest.static_blast_radius?.sensitive_data_attack_paths).toBeGreaterThan(0);
    expect(result.manifest.static_blast_radius?.pii_attack_paths).toBeGreaterThan(0);
    expect(result.manifest.static_blast_radius?.credential_attack_paths).toBeGreaterThan(0);
    expect(result.manifest.scan_coverage?.title).toBe("AgentCSP Scan Coverage");
    expect(result.manifest.scan_coverage?.files_indexed).toBeGreaterThan(0);
    expect(result.manifest.scan_coverage?.max_files_reached).toBe(false);
    expect(result.manifest.triage_summary?.title).toBe("AgentCSP Triage Summary");
    expect(result.manifest.triage_summary?.total_findings).toBe(result.findings.length);
    expect(result.manifest.triage_summary?.active_findings).toBeGreaterThan(0);
    expect(result.manifest.triage_summary?.highest_active_severity).toBe("critical");
    expect(result.manifest.triage_summary?.active_by_severity.critical).toBeGreaterThan(0);
    expect(result.manifest.triage_summary?.active_by_confidence.very_high).toBeGreaterThan(0);
    expect(result.manifest.triage_summary?.active_by_surface_type.some((item) => item.surface_type === "tool")).toBe(true);
    expect(result.manifest.triage_summary?.active_by_recommended_control.length).toBeGreaterThan(0);
    expect(result.manifest.triage_summary?.top_active_risks[0]?.risk_score).toBeGreaterThan(0);
    expect(result.manifest.action_plan?.title).toBe("AgentCSP Action Plan");
    expect(result.manifest.action_plan?.total_actions).toBeGreaterThan(0);
    expect(result.manifest.action_plan?.immediate_actions).toBeGreaterThan(0);
    expect(result.manifest.action_plan?.actions[0]).toMatchObject({
      priority: 1,
      severity: "critical"
    });
    expect(result.manifest.action_plan?.actions[0]?.rationale.length).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.outputFiles.sarif).toBeDefined();
    const sarif = JSON.parse(await fs.readFile(result.outputFiles.sarif!, "utf8")) as {
      runs: Array<{
        automationDetails?: { id?: string };
        tool?: {
          driver?: {
            rules?: Array<{
              id?: string;
              help?: { markdown?: string };
              defaultConfiguration?: { rank?: number };
              properties?: { "security-severity"?: string; securitySeverity?: string; precision?: string; tags?: string[] };
            }>;
          };
        };
        results?: Array<{
          rank?: number;
          properties?: { "security-severity"?: string; precision?: string; rule_tags?: string[] };
        }>;
        properties?: {
          agentcsp_triage_summary?: { total_findings?: number };
          agentcsp_action_plan?: { total_actions?: number; actions?: Array<{ priority?: number; rule_id?: string }> };
          agentcsp_ci_gate_summary?: { status?: string; should_fail?: boolean };
          agentcsp_scan_coverage?: { files_indexed?: number };
          agentcsp_static_blast_radius?: { pii_external_reach_paths?: number };
        };
      }>;
    };
    const firstRule = sarif.runs[0]?.tool?.driver?.rules?.[0];
    const firstResult = sarif.runs[0]?.results?.[0];
    expect(sarif.runs[0]?.automationDetails?.id).toBe("agentcsp-scan");
    expect(firstRule?.properties?.["security-severity"]).toMatch(/^\d+\.\d$/u);
    expect(firstRule?.properties?.securitySeverity).toBe(firstRule?.properties?.["security-severity"]);
    expect(firstRule?.properties?.precision).toBeDefined();
    expect(firstRule?.properties?.tags?.length).toBeGreaterThan(0);
    expect(firstRule?.defaultConfiguration?.rank).toBeGreaterThan(0);
    expect(firstRule?.help?.markdown).toContain("Recommended control:");
    expect(firstResult?.rank).toBeGreaterThan(0);
    expect(firstResult?.properties?.["security-severity"]).toMatch(/^\d+\.\d$/u);
    expect(firstResult?.properties?.precision).toBeDefined();
    expect(firstResult?.properties?.rule_tags?.length).toBeGreaterThan(0);
    expect(sarif.runs[0]?.properties?.agentcsp_triage_summary?.total_findings).toBe(result.findings.length);
    expect(sarif.runs[0]?.properties?.agentcsp_action_plan?.total_actions).toBe(
      result.manifest.action_plan?.total_actions
    );
    expect(sarif.runs[0]?.properties?.agentcsp_action_plan?.actions?.[0]?.priority).toBe(1);
    expect(sarif.runs[0]?.properties?.agentcsp_ci_gate_summary).toMatchObject({
      status: "pass",
      should_fail: false
    });
    expect(sarif.runs[0]?.properties?.agentcsp_scan_coverage?.files_indexed).toBe(
      result.manifest.scan_coverage?.files_indexed
    );
    expect(sarif.runs[0]?.properties?.agentcsp_static_blast_radius?.pii_external_reach_paths).toBe(
      result.manifest.static_blast_radius?.pii_external_reach_paths
    );
    expect(JSON.stringify(sarif.runs[0]?.properties?.agentcsp_triage_summary)).not.toContain("replace-me");
    expect(result.reportMarkdown).toContain("## Triage Summary");
    expect(result.reportMarkdown).toContain("## Action Plan");
    expect(result.reportMarkdown).toContain("| Priority | Severity | Risk | Control | Rule | Surface | Path | Rationale |");
    expect(result.reportMarkdown).toContain("- Root: `<scan-root>`");
    expect(result.reportMarkdown).not.toContain(rootPath);
    expect(result.reportMarkdown).toContain("## CI Gate Summary");
    expect(result.reportMarkdown).toContain("- Status: `pass`");
    expect(result.reportMarkdown).toContain("### Active Findings by Severity");
    expect(result.reportMarkdown).toContain("### Top Active Rules");
    expect(result.reportMarkdown).toContain("### Top Active Risks");
    expect(result.reportMarkdown).toContain("| Severity | Confidence | Risk | Rule | Object | Path | Recommended control |");
    expect(result.reportMarkdown).toContain("## Highest-Risk Blast-Radius Paths");
    expect(result.reportMarkdown).toContain("| Risk | Severity | Rule | Object | Boundary | Data | Actions | Recommended control |");
    expect(result.reportMarkdown).toContain("untrusted -> privileged");
    expect(result.reportMarkdown).toContain("secret exposure");
    expect(result.reportMarkdown).toContain("## Scan Coverage");
    expect(result.reportMarkdown).toContain("### Expired Suppressions");
    expect(result.reportMarkdown).toContain("PII external reach paths");
    expect(result.reportMarkdown).toContain("PII attack paths");
    expect(result.reportMarkdown).toContain("Recommended Controls");
    expect(result.reportMarkdown).toContain("Static Attack Paths");
    expect(result.reportMarkdown).toContain("| Severity | Confidence | Route | Path | Recommended control |");
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
    expect(result.manifest.ci_gate_summary).toMatchObject({
      status: "pass",
      should_fail: false,
      evaluated_findings: 0,
      severity_gate_findings: 0
    });
    expect(result.manifest.triage_summary?.active_findings).toBe(0);
    expect(result.manifest.triage_summary?.highest_active_severity).toBe("info");
    expect(result.manifest.triage_summary?.max_active_risk_score).toBe(0);
    expect(result.manifest.triage_summary?.top_active_risks).toHaveLength(0);
    expect(result.manifest.action_plan).toMatchObject({
      total_actions: 0,
      immediate_actions: 0,
      approval_actions: 0,
      quarantine_actions: 0,
      redaction_actions: 0
    });
    expect(result.manifest.action_plan?.actions).toHaveLength(0);
    expect(result.manifest.static_blast_radius?.sensitive_data_external_reach_paths).toBe(0);
    expect(result.manifest.static_blast_radius?.pii_external_reach_paths).toBe(0);
    expect(result.manifest.static_blast_radius?.credential_external_reach_paths).toBe(0);
    expect(result.manifest.static_blast_radius?.sensitive_data_attack_paths).toBe(0);
    expect(result.manifest.static_blast_radius?.pii_attack_paths).toBe(0);
    expect(result.manifest.static_blast_radius?.credential_attack_paths).toBe(0);
    expect(result.reportMarkdown).toContain("No active findings were generated.");
    expect(result.reportMarkdown).toContain("No active remediation actions were generated.");
    expect(result.reportMarkdown).toContain("No active high-risk blast-radius paths were identified.");
  });

  it("redacts absolute artifact paths in SARIF locations", async () => {
    const result = await scanProject({
      root_path: path.resolve("examples/vulnerable-agent"),
      output_path: "/private/tmp/agentcsp-sarif-redaction-test-output",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const finding = result.findings[0];
    expect(finding).toBeDefined();

    const sarif = renderSarifReport({
      ...result.manifest,
      findings: [
        { ...finding!, file_path: "/Users/security/projects/agentcsp/AGENTS.md" },
        { ...finding!, id: "finding_windows_path", file_path: "C:\\Users\\security\\agentcsp\\AGENTS.md" },
        { ...finding!, id: "finding_file_uri", file_path: "file:///Users/security/projects/agentcsp/AGENTS.md" },
        { ...finding!, id: "finding_relative_windows_path", file_path: "configs\\agent.yaml" }
      ]
    }) as {
      runs: Array<{ results?: Array<{ locations?: Array<{ physicalLocation?: { artifactLocation?: { uri?: string } } }> }> }>;
    };

    const uris =
      sarif.runs[0]?.results?.map(
        (item) => item.locations?.[0]?.physicalLocation?.artifactLocation?.uri
      ) ?? [];
    expect(uris).toEqual(["<redacted-path>", "<redacted-path>", "<redacted-file-uri>", "configs/agent.yaml"]);
    expect(JSON.stringify(sarif)).not.toContain("/Users/security");
    expect(JSON.stringify(sarif)).not.toContain("C:\\Users");
    expect(JSON.stringify(sarif)).not.toContain("file:///Users/security");
  });

  it("reports generated-state replay findings when logs are included", async () => {
    const result = await scanProject({
      root_path: path.resolve("examples/vulnerable-agent"),
      output_path: "/private/tmp/agentcsp-include-logs-report-test-output",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: true,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    const finding = result.findings.find((item) => item.rule_id === "AGENTCSP-GENSTATE-001");
    expect(finding).toBeDefined();
    expect(result.manifest.memory.some((surface) => surface.path === "logs/session-transcript.txt")).toBe(true);
    expect(result.reportMarkdown).toContain("AGENTCSP-GENSTATE-001");
    expect(JSON.stringify(result.manifest)).not.toContain("Ignore previous repository instructions");
  });
});
