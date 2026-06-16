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
      reason: "Organization policy forbids unsandboxed runtime without approval."
    });
    expect(finding?.policy_control?.matched_on).toEqual(["rule_id", "path"]);
    expect(finding?.evidence.every((item) => item.redacted)).toBe(true);
    expect(result.shouldFail).toBe(true);
    expect(result.reportMarkdown).toContain("policy override from require approval");
    expect(JSON.stringify(result.manifest.findings)).toContain("deny-unsandboxed-runtime");
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
      severity_gate_finding_ids: []
    });
    expect(result.shouldFail).toBe(false);
    expect(result.reportMarkdown).toContain("Suppressed Findings");
    expect(result.reportMarkdown).toContain("Suppression status");
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
