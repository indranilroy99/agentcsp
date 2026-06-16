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
    expect(result.manifest.metadata.rule_pack).toMatchObject({
      built_in_rules: 383,
      project_rules: 0,
      total_rules: 383,
      project_rules_loaded: false,
      rule_diagnostics: 0
    });
    expect(result.manifest.metadata.config).toMatchObject({
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      output_path_scope: "outside_scan_root",
      config_path_configured: false,
      baseline_path_configured: false,
      fail_on_new: false,
      fail_on_expired_suppressions: false,
      fail_on_diagnostics: false,
      evidence_redacted: true,
      secret_values_collected: false
    });
    expect(result.manifest.static_blast_radius?.title).toBe("Static Blast-Radius Summary");
    expect(result.manifest.static_blast_radius?.attack_paths).toBeGreaterThan(0);
    expect(result.manifest.static_blast_radius?.sensitive_data_external_reach_paths).toBeGreaterThan(0);
    expect(result.manifest.static_blast_radius?.pii_external_reach_paths).toBeGreaterThan(0);
    expect(result.manifest.static_blast_radius?.credential_external_reach_paths).toBeGreaterThan(0);
    expect(result.manifest.static_blast_radius?.sensitive_data_attack_paths).toBeGreaterThan(0);
    expect(result.manifest.static_blast_radius?.pii_attack_paths).toBeGreaterThan(0);
    expect(result.manifest.static_blast_radius?.credential_attack_paths).toBeGreaterThan(0);
    expect(result.manifest.static_blast_radius?.attack_path_limit).toBe(15);
    expect(result.manifest.static_blast_radius?.attack_paths_total).toBeGreaterThanOrEqual(
      result.manifest.static_blast_radius?.attack_paths ?? 0
    );
    expect(result.manifest.static_blast_radius?.attack_paths_truncated).toBe(
      (result.manifest.static_blast_radius?.attack_paths_total ?? 0) >
        (result.manifest.static_blast_radius?.attack_paths ?? 0)
    );
    expect(result.manifest.static_blast_radius?.preview_limit).toBe(20);
    expect(result.manifest.static_blast_radius?.high_risk_objects_total).toBeGreaterThan(20);
    expect(result.manifest.static_blast_radius?.high_risk_objects_truncated).toBe(true);
    expect(result.manifest.static_blast_radius?.recommended_controls_total).toBeGreaterThan(20);
    expect(result.manifest.static_blast_radius?.recommended_controls_truncated).toBe(true);
    expect(result.manifest.scan_coverage?.title).toBe("AgentCSP Scan Coverage");
    expect(result.manifest.scan_coverage?.scan_health).toBe("complete");
    expect(result.manifest.scan_coverage?.scan_health_reasons).toEqual([]);
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
    expect(
      result.manifest.triage_summary?.active_by_risk_driver.some(
        (item) => item.driver === "untrusted_to_privileged" && item.count > 0 && item.max_risk_score > 0
      )
    ).toBe(true);
    expect(
      result.manifest.triage_summary?.active_by_risk_driver.some(
        (item) => item.driver === "secret_exposure" && item.by_severity.critical > 0
      )
    ).toBe(true);
    expect(result.manifest.triage_summary?.top_active_limit).toBe(10);
    expect(result.manifest.triage_summary?.top_active_rules_total).toBeGreaterThan(10);
    expect(result.manifest.triage_summary?.top_active_rules_truncated).toBe(true);
    expect(result.manifest.triage_summary?.top_active_risks_total).toBe(result.manifest.triage_summary?.active_findings);
    expect(result.manifest.triage_summary?.top_active_risks_truncated).toBe(true);
    expect(result.manifest.triage_summary?.top_active_risks[0]?.risk_score).toBeGreaterThan(0);
    expect(result.manifest.action_plan?.title).toBe("AgentCSP Action Plan");
    expect(result.manifest.action_plan?.total_actions).toBeGreaterThan(0);
    expect(result.manifest.action_plan?.total_active_findings_considered).toBe(result.findings.length);
    expect(result.manifest.action_plan?.max_actions).toBe(12);
    expect(result.manifest.action_plan?.truncated).toBe(true);
    expect(result.manifest.action_plan?.omitted_actions).toBe(result.findings.length - 12);
    expect(result.manifest.action_plan?.omitted_highest_severity).toBe("critical");
    expect(result.manifest.action_plan?.omitted_max_risk_score).toBeGreaterThan(0);
    expect(
      Object.values(result.manifest.action_plan?.omitted_by_severity ?? {}).reduce((sum, count) => sum + count, 0)
    ).toBe(result.manifest.action_plan?.omitted_actions);
    expect(result.manifest.action_plan?.immediate_actions).toBeGreaterThan(0);
    expect(
      (result.manifest.action_plan?.immediate_actions ?? 0) +
        (result.manifest.action_plan?.urgent_actions ?? 0) +
        (result.manifest.action_plan?.scheduled_actions ?? 0) +
        (result.manifest.action_plan?.backlog_actions ?? 0)
    ).toBe(result.manifest.action_plan?.total_actions);
    expect(result.manifest.action_plan?.actions[0]).toMatchObject({
      priority: 1,
      severity: "critical",
      response_tier: "immediate"
    });
    expect(result.manifest.action_plan?.actions[0]?.response_reason).toBeTruthy();
    expect(result.manifest.action_plan?.actions[0]?.owner_hint).toMatch(
      /^(agent-engineering|agent-platform|application-security|data-and-knowledge|identity-and-secrets|platform-ci|runtime-platform)$/u
    );
    expect(result.manifest.action_plan?.actions[0]?.owner_reason).toBeTruthy();
    expect(result.manifest.action_plan?.by_owner.length).toBeGreaterThan(0);
    expect(result.manifest.action_plan?.by_owner[0]).toMatchObject({
      owner_hint: expect.any(String),
      count: expect.any(Number),
      immediate_actions: expect.any(Number),
      urgent_actions: expect.any(Number),
      scheduled_actions: expect.any(Number),
      backlog_actions: expect.any(Number),
      highest_severity: expect.any(String),
      max_risk_score: expect.any(Number),
      by_recommended_control: expect.any(Array),
      by_surface_type: expect.any(Array),
      top_action_id_limit: 5,
      top_action_ids_truncated: expect.any(Boolean),
      top_action_ids: expect.any(Array)
    });
    expect(result.manifest.action_plan?.by_owner[0]?.top_action_ids.length).toBeGreaterThan(0);
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
          partialFingerprints?: {
            agentcspFindingId?: string;
            agentcspObjectId?: string;
            agentcspRuleObject?: string;
            agentcspRulePath?: string;
            agentcspSurfacePath?: string;
          };
          properties?: { "security-severity"?: string; precision?: string; rule_tags?: string[] };
        }>;
        properties?: {
          agentcsp_scan_config?: {
            formats?: string[];
            include_hidden?: boolean;
            include_logs?: boolean;
            max_files?: number;
            output_path_scope?: string;
            fail_on_new?: boolean;
            secret_values_collected?: boolean;
          };
          agentcsp_rule_pack?: {
            built_in_rules?: number;
            project_rules?: number;
            total_rules?: number;
            project_rules_loaded?: boolean;
            rule_diagnostics?: number;
          };
          agentcsp_triage_summary?: {
            total_findings?: number;
            top_active_risks_truncated?: boolean;
            active_by_risk_driver?: Array<{ driver?: string; count?: number; max_risk_score?: number }>;
          };
          agentcsp_action_plan?: { total_actions?: number; actions?: Array<{ priority?: number; rule_id?: string }> };
          agentcsp_ci_gate_summary?: {
            status?: string;
            should_fail?: boolean;
            blocker_id_limit?: number;
            severity_gate_by_severity?: Record<string, number>;
            severity_gate_by_confidence?: Record<string, number>;
            active_suppressions_by_severity?: Record<string, number>;
            expired_suppression_by_severity?: Record<string, number>;
          };
          agentcsp_scan_coverage?: { files_indexed?: number };
          agentcsp_static_blast_radius?: {
            pii_external_reach_paths?: number;
            high_risk_objects_truncated?: boolean;
            attack_path_limit?: number;
          };
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
    expect(firstResult?.partialFingerprints).toMatchObject({
      agentcspFindingId: expect.any(String),
      agentcspObjectId: expect.any(String),
      agentcspRuleObject: expect.any(String),
      agentcspRulePath: expect.any(String),
      agentcspSurfacePath: expect.any(String)
    });
    expect(firstResult?.properties?.["security-severity"]).toMatch(/^\d+\.\d$/u);
    expect(firstResult?.properties?.precision).toBeDefined();
    expect(firstResult?.properties?.rule_tags?.length).toBeGreaterThan(0);
    expect(sarif.runs[0]?.properties?.agentcsp_scan_config).toMatchObject({
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_files: 5000,
      output_path_scope: "outside_scan_root",
      fail_on_new: false,
      secret_values_collected: false
    });
    expect(sarif.runs[0]?.properties?.agentcsp_rule_pack).toMatchObject({
      built_in_rules: 383,
      project_rules: 0,
      total_rules: 383,
      project_rules_loaded: false,
      rule_diagnostics: 0
    });
    expect(sarif.runs[0]?.properties?.agentcsp_triage_summary?.total_findings).toBe(result.findings.length);
    expect(sarif.runs[0]?.properties?.agentcsp_triage_summary?.top_active_risks_truncated).toBe(true);
    expect(
      sarif.runs[0]?.properties?.agentcsp_triage_summary?.active_by_risk_driver?.some(
        (item) => item.driver === "external_reach" && (item.count ?? 0) > 0
      )
    ).toBe(true);
    expect(sarif.runs[0]?.properties?.agentcsp_action_plan?.total_actions).toBe(
      result.manifest.action_plan?.total_actions
    );
    expect(sarif.runs[0]?.properties?.agentcsp_action_plan?.actions?.[0]?.priority).toBe(1);
    expect(sarif.runs[0]?.properties?.agentcsp_ci_gate_summary).toMatchObject({
      status: "pass",
      should_fail: false,
      blocker_id_limit: 50,
      blocker_ids_truncated: false,
      severity_gate_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      severity_gate_by_confidence: { very_high: 0, high: 0, medium: 0, low: 0 },
      active_suppressions_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      expired_suppression_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      severity_gate_finding_ids: [],
      severity_gate_finding_ids_truncated: false,
      expired_suppression_finding_ids: [],
      expired_suppression_finding_ids_truncated: false,
      diagnostic_ids: [],
      diagnostic_ids_truncated: false
    });
    expect(sarif.runs[0]?.properties?.agentcsp_scan_coverage?.files_indexed).toBe(
      result.manifest.scan_coverage?.files_indexed
    );
    expect(sarif.runs[0]?.properties?.agentcsp_static_blast_radius?.pii_external_reach_paths).toBe(
      result.manifest.static_blast_radius?.pii_external_reach_paths
    );
    expect(sarif.runs[0]?.properties?.agentcsp_static_blast_radius?.high_risk_objects_truncated).toBe(true);
    expect(sarif.runs[0]?.properties?.agentcsp_static_blast_radius?.attack_path_limit).toBe(15);
    expect(JSON.stringify(sarif.runs[0]?.properties?.agentcsp_triage_summary)).not.toContain("replace-me");
    expect(result.reportMarkdown).toContain("## Triage Summary");
    expect(result.reportMarkdown).toContain("- Built-in rules loaded: 383");
    expect(result.reportMarkdown).toContain("- Total rules loaded: 383");
    expect(result.reportMarkdown).toContain("- Rule diagnostics: 0");
    expect(result.reportMarkdown).toContain("- Output formats: `json`, `md`, `sarif`");
    expect(result.reportMarkdown).toContain("- Output path scope: `outside_scan_root`");
    expect(result.reportMarkdown).toContain("- Baseline supplied: `false`");
    expect(result.reportMarkdown).toContain("- Scan health gate: `none`");
    expect(result.reportMarkdown).toContain("- Top active limit: 10");
    expect(result.reportMarkdown).toContain("- Top active rules truncated: `true`");
    expect(result.reportMarkdown).toContain("- Top active risks truncated: `true`");
    expect(result.reportMarkdown).toContain("## Action Plan");
    expect(result.reportMarkdown).toContain("- Truncated: `true`");
    expect(result.reportMarkdown).toContain("- Omitted actions:");
    expect(result.reportMarkdown).toContain("- Omitted highest severity:");
    expect(result.reportMarkdown).toContain("- Omitted max risk score:");
    expect(result.reportMarkdown).toContain("### Action Owners");
    expect(result.reportMarkdown).toContain(
      "| Owner hint | Actions | Immediate | Urgent | Scheduled | Backlog | Highest severity | Max risk |"
    );
    expect(result.reportMarkdown).toContain("### Omitted Action Risk");
    expect(result.reportMarkdown).toContain("| Omitted | Highest severity | Max risk | Critical | High | Medium | Low | Info |");
    expect(result.reportMarkdown).toContain(
      "| Priority | Response | Severity | Risk | Baseline | Owner | Control | Rule | Surface | Path | Rationale |"
    );
    expect(result.reportMarkdown).toContain("- Root: `<scan-root>`");
    expect(result.reportMarkdown).not.toContain(rootPath);
    expect(result.reportMarkdown).toContain("- Scan health: `complete`");
    expect(result.reportMarkdown).toContain("- Scan health reasons: none");
    expect(result.reportMarkdown).toContain("## CI Gate Summary");
    expect(result.reportMarkdown).toContain("- Status: `pass`");
    expect(result.reportMarkdown).toContain("- Blocker ID limit: 50");
    expect(result.reportMarkdown).toContain("- Blocker IDs truncated: `false`");
    expect(result.reportMarkdown).toContain("### CI Gate Blockers");
    expect(result.reportMarkdown).toContain("| Blocker list | Total | IDs shown | Truncated |");
    expect(result.reportMarkdown).toContain("### CI Gate Blocker Mix");
    expect(result.reportMarkdown).toContain(
      "| Blocker set | Critical | High | Medium | Low | Info | Very high confidence | High confidence | Medium confidence | Low confidence |"
    );
    expect(result.reportMarkdown).toContain("No CI gate blockers were identified.");
    expect(result.reportMarkdown).toContain("### Active Findings by Severity");
    expect(result.reportMarkdown).toContain("### Top Active Rules");
    expect(result.reportMarkdown).toContain("### Active Risk Drivers");
    expect(result.reportMarkdown).toContain("| Driver | Findings | Max risk | Critical | High | Medium | Low | Info |");
    expect(result.reportMarkdown).toContain("untrusted to privileged");
    expect(result.reportMarkdown).toContain("### Top Active Risks");
    expect(result.reportMarkdown).toContain(
      "| Severity | Confidence | Risk | Trust | Data | Actions | External | Secret | Untrusted->privileged | Boundary | Rule | Object | Path | Recommended control |"
    );
    expect(result.reportMarkdown).toContain("- Attack path limit: 15");
    expect(result.reportMarkdown).toContain("- Attack paths total:");
    expect(result.reportMarkdown).toContain("- Attack paths truncated:");
    expect(result.reportMarkdown).toContain("- Preview limit: 20");
    expect(result.reportMarkdown).toContain("- High-risk objects truncated: `true`");
    expect(result.reportMarkdown).toContain("- Recommended controls truncated: `true`");
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
      severity_gate_findings: 0,
      severity_gate_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      severity_gate_by_confidence: { very_high: 0, high: 0, medium: 0, low: 0 },
      active_suppressions_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      expired_suppression_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      blocker_id_limit: 50,
      blocker_ids_truncated: false
    });
    expect(result.manifest.triage_summary?.active_findings).toBe(0);
    expect(result.manifest.triage_summary?.highest_active_severity).toBe("info");
    expect(result.manifest.triage_summary?.max_active_risk_score).toBe(0);
    expect(result.manifest.triage_summary?.top_active_limit).toBe(10);
    expect(result.manifest.triage_summary?.top_active_rules_total).toBe(0);
    expect(result.manifest.triage_summary?.top_active_rules_truncated).toBe(false);
    expect(result.manifest.triage_summary?.active_by_risk_driver).toEqual([]);
    expect(result.manifest.triage_summary?.top_active_risks_total).toBe(0);
    expect(result.manifest.triage_summary?.top_active_risks_truncated).toBe(false);
    expect(result.manifest.triage_summary?.top_active_risks).toHaveLength(0);
    expect(result.manifest.action_plan).toMatchObject({
      total_actions: 0,
      total_active_findings_considered: 0,
      max_actions: 12,
      omitted_actions: 0,
      omitted_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      omitted_highest_severity: "info",
      omitted_max_risk_score: 0,
      truncated: false,
      immediate_actions: 0,
      urgent_actions: 0,
      scheduled_actions: 0,
      backlog_actions: 0,
      approval_actions: 0,
      quarantine_actions: 0,
      redaction_actions: 0,
      new_actions: 0,
      existing_actions: 0,
      by_owner: []
    });
    expect(result.manifest.action_plan?.actions).toHaveLength(0);
    expect(result.manifest.static_blast_radius?.sensitive_data_external_reach_paths).toBe(0);
    expect(result.manifest.static_blast_radius?.pii_external_reach_paths).toBe(0);
    expect(result.manifest.static_blast_radius?.credential_external_reach_paths).toBe(0);
    expect(result.manifest.static_blast_radius?.sensitive_data_attack_paths).toBe(0);
    expect(result.manifest.static_blast_radius?.pii_attack_paths).toBe(0);
    expect(result.manifest.static_blast_radius?.credential_attack_paths).toBe(0);
    expect(result.manifest.static_blast_radius?.attack_path_limit).toBe(15);
    expect(result.manifest.static_blast_radius?.attack_paths_total).toBe(0);
    expect(result.manifest.static_blast_radius?.attack_paths_truncated).toBe(false);
    expect(result.manifest.static_blast_radius?.preview_limit).toBe(20);
    expect(result.manifest.static_blast_radius?.high_risk_objects_total).toBe(
      result.manifest.static_blast_radius?.high_risk_objects.length
    );
    expect(result.manifest.static_blast_radius?.high_risk_objects_truncated).toBe(false);
    expect(result.manifest.static_blast_radius?.recommended_controls_total).toBe(0);
    expect(result.manifest.static_blast_radius?.recommended_controls_truncated).toBe(false);
    expect(result.reportMarkdown).toContain("No active findings were generated.");
    expect(result.reportMarkdown).toContain("No active risk drivers were generated.");
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
