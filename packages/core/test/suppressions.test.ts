import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { scanProject } from "../src/scanner/scan.js";
import { ciGateBlockerIdLimit } from "../src/reports/gates.js";

const fixtureRoot = path.resolve("examples/vulnerable-agent");

describe("policy suppressions", () => {
  it("applies advisory recommended controls without suppressing evidence", async () => {
    const policyPath = await writeRecommendedControlPolicy();
    const result = await scanProject({
      root_path: fixtureRoot,
      output_path: "/private/tmp/agentcsp-policy-control",
      config_path: policyPath,
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true,
      fail_on: "critical"
    });

    const finding = result.findings.find((item) => item.rule_id === "AGENTCSP-RUNTIME-001");
    expect(finding?.recommended_control).toBe("deny");
    expect(finding?.policy_control).toMatchObject({
      id: "deny-unsandboxed-runtime",
      control: "deny",
      previous_control: "require_approval",
      match_scope: "rule_and_path",
      change_direction: "strengthened",
      reason: "Organization policy forbids unsandboxed runtime without approval."
    });
    expect(finding?.policy_control?.matched_on).toEqual(["rule_id", "path"]);
    expect(finding?.evidence.every((item) => item.redacted)).toBe(true);
    expect(result.shouldFail).toBe(true);
    expect(result.reportMarkdown).toContain("policy override from require approval to deny");
    expect(result.reportMarkdown).toContain("direction: strengthened");
    expect(result.reportMarkdown).toContain("scope: rule and path");
    expect(result.reportMarkdown).toContain("matched on: rule_id, path");
    expect(result.reportMarkdown).toContain("reason redacted");
    expect(result.reportMarkdown).not.toContain("Organization policy forbids unsandboxed runtime without approval.");
    expect(JSON.stringify(result.manifest.findings)).toContain("deny-unsandboxed-runtime");
    expect(JSON.stringify(result.manifest.findings)).toContain("Organization policy forbids unsandboxed runtime without approval.");
    const sarif = JSON.parse(await fs.readFile(result.outputFiles.sarif!, "utf8")) as {
      runs: Array<{
        results?: Array<{
          properties?: {
            policy_control?: Record<string, unknown>;
          };
        }>;
      }>;
    };
    expect(JSON.stringify(sarif)).not.toContain("Organization policy forbids unsandboxed runtime without approval.");
    const sarifPolicyControl = sarif.runs[0]?.results?.find(
      (item) => item.properties?.policy_control
    )?.properties?.policy_control;
    expect(sarifPolicyControl).toMatchObject({
      id_present: true,
      control: "deny",
      previous_control: "require_approval",
      match_scope: "rule_and_path",
      change_direction: "strengthened",
      matched_on: ["rule_id", "path"],
      reason_redacted: true
    });
  });

  it("marks active suppressions and excludes them from fail gates", async () => {
    const policyPath = await writePolicy("active", "2999-12-31T23:59:59.000Z");
    const result = await scanProject({
      root_path: fixtureRoot,
      output_path: "/private/tmp/agentcsp-suppression-active",
      config_path: policyPath,
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true,
      fail_on: "critical"
    });

    const suppressed = result.findings.filter((finding) => finding.suppression?.status === "active");
    expect(suppressed.length).toBeGreaterThan(0);
    expect(suppressed.every((finding) => finding.suppression?.owner === "security@example.com")).toBe(true);
    expect(suppressed.every((finding) => finding.suppression?.match_scope === "severity")).toBe(true);
    expect(result.manifest.static_blast_radius?.active_suppressions).toBe(suppressed.length);
    expect(result.manifest.ci_gate_summary).toMatchObject({
      status: "pass",
      should_fail: false,
      fail_on: "critical",
      severity_gate_findings: 0,
      active_suppressions_excluded: suppressed.length,
      active_suppressions_by_severity: {
        critical: suppressed.length,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      },
      active_suppressions_by_scope: {
        specific_finding: 0,
        specific_object: 0,
        rule_and_path: 0,
        rule: 0,
        path: 0,
        category: 0,
        severity: suppressed.length,
        broad: 0
      },
      broad_active_suppression_findings: suppressed.length,
      broad_active_suppression_by_severity: {
        critical: suppressed.length,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      },
      severity_gate_finding_ids: []
    });
    expect(result.shouldFail).toBe(false);
    expect(result.reportMarkdown).toContain("Suppressed Findings");
    expect(result.reportMarkdown).toContain("Suppression status");
    expect(result.reportMarkdown).toContain("Scope");
    expect(result.reportMarkdown).toContain("severity");
    expect(result.reportMarkdown).toContain("Suppression Review Posture");
    expect(result.reportMarkdown).toContain("Broad active suppressions");
    expect(result.reportMarkdown).toContain("active suppression exclusion");
    expect(result.reportMarkdown).toContain("severity");
    expect(result.reportMarkdown).not.toContain("active-critical-demo-risk");
    expect(result.reportMarkdown).not.toContain("Accepted for fixture regression only.");
    expect(result.reportMarkdown).not.toContain("security@example.com");
    const sarif = JSON.parse(await fs.readFile(result.outputFiles.sarif!, "utf8")) as {
      runs: Array<{
        results?: Array<{
          suppressions?: Array<{ justification?: string }>;
        }>;
      }>;
    };
    const sarifSuppression = sarif.runs[0]?.results?.find((item) => item.suppressions?.length)?.suppressions?.[0];
    expect(sarifSuppression?.justification).toContain("Suppression reason and owner are redacted");
    expect(sarifSuppression?.justification).toContain("Scope: severity");
    expect(sarifSuppression?.justification).toContain("2999-12-31T23:59:59.000Z");
    expect(sarifSuppression?.justification).not.toContain("Accepted for fixture regression only.");
    expect(sarifSuppression?.justification).not.toContain("security@example.com");
    expect(JSON.stringify(sarif)).not.toContain("active-critical-demo-risk");
  });

  it("keeps expired suppressions as active risk", async () => {
    const policyPath = await writePolicy("expired", "2000-01-01T00:00:00.000Z");
    const result = await scanProject({
      root_path: fixtureRoot,
      output_path: "/private/tmp/agentcsp-suppression-expired",
      config_path: policyPath,
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true,
      fail_on: "critical"
    });

    const expired = result.findings.filter((finding) => finding.suppression?.status === "expired");
    expect(expired.length).toBeGreaterThan(0);
    expect(result.manifest.static_blast_radius?.expired_suppressions).toBe(expired.length);
    expect(result.manifest.static_blast_radius?.active_suppressions).toBe(0);
    expect(result.manifest.ci_gate_summary).toMatchObject({
      status: "fail",
      should_fail: true,
      fail_on: "critical",
      severity_gate_findings: expired.length,
      expired_suppression_findings: expired.length,
      failed_gates: ["severity"]
    });
    expect(result.manifest.ci_gate_summary?.severity_gate_finding_ids).toEqual(
      firstGateBlockerIds(expired)
    );
    expect(result.manifest.ci_gate_summary?.expired_suppression_finding_ids).toEqual(
      firstGateBlockerIds(expired)
    );
    expect(result.shouldFail).toBe(true);
    expect(result.reportMarkdown).toContain("### Expired Suppressions");
    expect(result.reportMarkdown).toContain("### CI Gate Blockers");
    expect(result.reportMarkdown).toContain("expired suppression");
    expect(result.reportMarkdown).toContain("2000-01-01T00:00:00.000Z");
    expect(result.reportMarkdown).not.toContain("expired-critical-demo-risk");
    expect(result.reportMarkdown).not.toContain("Accepted for fixture regression only.");
    expect(result.reportMarkdown).not.toContain("security@example.com");
  });

  it("can fail CI on expired suppressions without a severity gate", async () => {
    const policyPath = await writePolicy("expired-waiver", "2000-01-01T00:00:00.000Z");
    const result = await scanProject({
      root_path: fixtureRoot,
      output_path: "/private/tmp/agentcsp-suppression-expired-gate",
      config_path: policyPath,
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true,
      fail_on_expired_suppressions: true
    });

    const expired = result.findings.filter((finding) => finding.suppression?.status === "expired");
    expect(expired.length).toBeGreaterThan(0);
    expect(result.manifest.ci_gate_summary).toMatchObject({
      status: "fail",
      should_fail: true,
      fail_on_expired_suppressions: true,
      severity_gate_findings: 0,
      expired_suppression_findings: expired.length,
      failed_gates: ["expired_suppressions"]
    });
    expect(result.manifest.ci_gate_summary?.expired_suppression_finding_ids).toEqual(
      firstGateBlockerIds(expired)
    );
    expect(result.shouldFail).toBe(true);
  });

  it("keeps expired suppression failures opt-in", async () => {
    const policyPath = await writePolicy("expired-observed", "2000-01-01T00:00:00.000Z");
    const result = await scanProject({
      root_path: fixtureRoot,
      output_path: "/private/tmp/agentcsp-suppression-expired-observed",
      config_path: policyPath,
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    const expired = result.findings.filter((finding) => finding.suppression?.status === "expired");
    expect(expired.length).toBeGreaterThan(0);
    expect(result.manifest.ci_gate_summary).toMatchObject({
      status: "pass",
      should_fail: false,
      fail_on_expired_suppressions: false,
      severity_gate_findings: 0,
      expired_suppression_findings: expired.length,
      failed_gates: [],
      severity_gate_finding_ids: [],
      expired_suppression_finding_ids: firstGateBlockerIds(expired)
    });
    expect(result.shouldFail).toBe(false);
  });

  it("records narrow suppression match scope for rule and path waivers", async () => {
    const policyPath = await writeRulePathSuppressionPolicy();
    const result = await scanProject({
      root_path: fixtureRoot,
      output_path: "/private/tmp/agentcsp-suppression-rule-path",
      config_path: policyPath,
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    const suppressed = result.findings.find((finding) => finding.suppression?.id === "accepted-risk-runtime-config");
    expect(suppressed?.rule_id).toBe("AGENTCSP-RUNTIME-001");
    expect(suppressed?.suppression).toMatchObject({
      status: "active",
      match_scope: "rule_and_path",
      matched_on: ["rule_id", "path"]
    });
    expect(result.manifest.ci_gate_summary).toMatchObject({
      active_suppressions_by_scope: {
        specific_finding: 0,
        specific_object: 0,
        rule_and_path: 1,
        rule: 0,
        path: 0,
        category: 0,
        severity: 0,
        broad: 0
      },
      broad_active_suppression_findings: 0,
      broad_active_suppression_finding_ids: []
    });
    expect(result.reportMarkdown).toContain("rule and path");
  });
});

async function writePolicy(name: string, expiresAt: string): Promise<string> {
  const policyPath = `/private/tmp/agentcsp-${name}-policy.yaml`;
  await fs.writeFile(
    policyPath,
    [
      'schema_version: "0.1"',
      "suppressions:",
      `  - id: "${name}-critical-demo-risk"`,
      '    reason: "Accepted for fixture regression only."',
      '    owner: "security@example.com"',
      `    expires_at: "${expiresAt}"`,
      "    match:",
      '      severity: "critical"',
      ""
    ].join("\n"),
    "utf8"
  );
  return policyPath;
}

function firstGateBlockerIds(findings: Array<{ id: string }>): string[] {
  return findings
    .map((finding) => finding.id)
    .sort((left, right) => left.localeCompare(right))
    .slice(0, ciGateBlockerIdLimit);
}

async function writeRecommendedControlPolicy(): Promise<string> {
  const policyPath = "/private/tmp/agentcsp-recommended-control-policy.yaml";
  await fs.writeFile(
    policyPath,
    [
      'schema_version: "0.1"',
      "recommended_controls:",
      '  - id: "deny-unsandboxed-runtime"',
      '    reason: "Organization policy forbids unsandboxed runtime without approval."',
      '    control: "deny"',
      "    match:",
      '      rule_id: "AGENTCSP-RUNTIME-001"',
      '      path: ".codex/config.toml"',
      ""
    ].join("\n"),
    "utf8"
  );
  return policyPath;
}

async function writeRulePathSuppressionPolicy(): Promise<string> {
  const policyPath = "/private/tmp/agentcsp-rule-path-suppression-policy.yaml";
  await fs.writeFile(
    policyPath,
    [
      'schema_version: "0.1"',
      "suppressions:",
      '  - id: "accepted-risk-runtime-config"',
      '    reason: "Accepted for fixture regression only."',
      '    owner: "security@example.com"',
      '    expires_at: "2999-12-31T23:59:59.000Z"',
      "    match:",
      '      rule_id: "AGENTCSP-RUNTIME-001"',
      '      path: ".codex/config.toml"',
      ""
    ].join("\n"),
    "utf8"
  );
  return policyPath;
}
