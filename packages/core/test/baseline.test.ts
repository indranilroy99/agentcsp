import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import {
  applyBaselineComparison,
  baselineFindingIdLimit,
  createBaselineEnvelope,
  diffBaselineEnvelopes
} from "../src/reports/baseline.js";
import { scanProject } from "../src/scanner/scan.js";
import type { Finding } from "../src/schemas/index.js";
import { tempPath } from "./temp-path.js";

const fixtureRoot = path.resolve("examples/vulnerable-agent");

describe("baseline comparison", () => {
  it("creates deterministic v0.2 envelopes and diffs finding identities", () => {
    const createdAt = new Date("2026-01-02T03:04:05.000Z");
    const baseline = createBaselineEnvelope(
      [
        { id: "finding_b", rule_id: "RULE-B" },
        { id: "finding_a", rule_id: "RULE-A" },
        { id: "finding_a" }
      ],
      createdAt
    );
    const current = createBaselineEnvelope(
      [
        { id: "finding_b", rule_id: "RULE-B" },
        { id: "finding_c", rule_id: "RULE-C" }
      ],
      createdAt
    );

    expect(baseline).toMatchObject({
      schema_version: "0.2.0",
      identity_version: "agentcsp-finding-v1",
      created_at: createdAt.toISOString(),
      findings: [
        { id: "finding_a", rule_id: "RULE-A" },
        { id: "finding_b", rule_id: "RULE-B" }
      ]
    });
    expect(diffBaselineEnvelopes(baseline, current)).toEqual({
      added: ["finding_c"],
      removed: ["finding_a"],
      unchanged: ["finding_b"]
    });
  });

  it("compares against the exact baseline bytes supplied by trusted-input verification", async () => {
    const baselinePath = tempPath("agentcsp-pinned-baseline.json");
    const approved = '[{"id":"finding_approved"}]\n';
    await fs.writeFile(baselinePath, '[{"id":"finding_replaced"}]\n', "utf8");

    const result = await applyBaselineComparison(
      [finding("finding_approved")],
      baselinePath,
      undefined,
      Buffer.from(approved)
    );

    expect(result.findings[0]?.baseline_status).toBe("existing");
    expect(result.comparison.resolved_findings).toBe(0);
  });

  it("marks unchanged findings as existing when scanning against a manifest baseline", async () => {
    const baseline = await scanProject({
      root_path: fixtureRoot,
      output_path: tempPath("agentcsp-baseline-source"),
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    const result = await scanProject({
      root_path: fixtureRoot,
      output_path: tempPath("agentcsp-baseline-existing"),
      baseline_path: baseline.outputFiles.manifest,
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true,
      fail_on: "critical",
      fail_on_confidence: "medium",
      fail_on_new: true
    });

    expect(result.shouldFail).toBe(false);
    expect(result.manifest.baseline_comparison).toMatchObject({
      baseline_format: "manifest",
      baseline_fingerprint: baseline.manifest.metadata.fingerprint,
      baseline_rule_pack_fingerprint: baseline.manifest.metadata.rule_pack.fingerprint,
      current_findings: baseline.findings.length,
      baseline_findings: baseline.findings.length,
      new_findings: 0,
      new_findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      new_findings_by_confidence: { very_high: 0, high: 0, medium: 0, low: 0 },
      existing_findings: baseline.findings.length,
      resolved_findings: 0,
      baseline_id_limit: baselineFindingIdLimit,
      baseline_ids_truncated: false,
      new_finding_ids_truncated: false,
      resolved_finding_ids_truncated: false
    });
    expect(result.findings.every((finding) => finding.baseline_status === "existing")).toBe(true);
    expect(result.manifest.action_plan).toMatchObject({
      new_actions: 0,
      existing_actions: result.manifest.action_plan?.total_actions,
      truncated: true
    });
    expect(result.manifest.action_plan?.actions.every((action) => action.baseline_status === "existing")).toBe(true);
    expect(result.reportMarkdown).toContain("## Baseline Comparison");
    expect(result.reportMarkdown).toContain(`- Baseline fingerprint: \`${baseline.manifest.metadata.fingerprint?.value}\``);
    expect(result.reportMarkdown).toContain(
      `- Baseline rule pack fingerprint: \`${baseline.manifest.metadata.rule_pack.fingerprint.value}\``
    );
    expect(result.reportMarkdown).toContain("### New Finding Drift Mix");
    expect(result.reportMarkdown).toContain("- Existing actions:");
    expect(result.reportMarkdown).toContain("No new findings were introduced.");
    const sarif = JSON.parse(await fs.readFile(result.outputFiles.sarif!, "utf8")) as {
      runs: Array<{
        results: Array<{ baselineState?: string }>;
        properties?: {
          agentcsp_baseline_comparison?: {
            new_findings?: number;
            baseline_fingerprint?: { value?: string; algorithm?: string };
            baseline_rule_pack_fingerprint?: { value?: string; algorithm?: string };
            new_findings_by_severity?: Record<string, number>;
            new_findings_by_confidence?: Record<string, number>;
            new_findings_by_risk_driver?: Array<{ driver?: string; count?: number }>;
          };
        };
      }>;
    };
    expect(sarif.runs[0]?.results.every((item) => item.baselineState === "unchanged")).toBe(true);
    expect(sarif.runs[0]?.properties?.agentcsp_baseline_comparison?.baseline_fingerprint?.value).toBe(
      baseline.manifest.metadata.fingerprint?.value
    );
    expect(sarif.runs[0]?.properties?.agentcsp_baseline_comparison?.baseline_rule_pack_fingerprint?.value).toBe(
      baseline.manifest.metadata.rule_pack.fingerprint.value
    );
    expect(sarif.runs[0]?.properties?.agentcsp_baseline_comparison?.new_findings).toBe(0);
    expect(sarif.runs[0]?.properties?.agentcsp_baseline_comparison?.new_findings_by_severity?.critical).toBe(0);
    expect(sarif.runs[0]?.properties?.agentcsp_baseline_comparison?.new_findings_by_confidence?.very_high).toBe(0);
    expect(sarif.runs[0]?.properties?.agentcsp_baseline_comparison?.new_findings_by_risk_driver).toEqual([]);
  }, 30_000);

  it("tracks new and resolved findings from a findings baseline", async () => {
    const baseline = await scanProject({
      root_path: fixtureRoot,
      output_path: tempPath("agentcsp-baseline-source-findings"),
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const targetNewFinding = baseline.findings.find(
      (finding) => finding.rule_id === "AGENTCSP-TOOL-004"
    );
    expect(targetNewFinding).toBeDefined();

    const baselinePath = tempPath("agentcsp-findings-baseline-with-drift.json");
    await fs.writeFile(
      baselinePath,
      `${JSON.stringify([
        ...baseline.findings
          .filter((finding) => finding.id !== targetNewFinding?.id)
          .map((finding) => ({ id: finding.id })),
        { id: "finding_resolved_demo" }
      ], null, 2)}\n`,
      "utf8"
    );

    const result = await scanProject({
      root_path: fixtureRoot,
      output_path: tempPath("agentcsp-baseline-drift"),
      baseline_path: baselinePath,
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true,
      fail_on: targetNewFinding?.severity ?? "critical",
      fail_on_confidence: targetNewFinding?.confidence ?? "medium",
      fail_on_new: true
    });

    expect(result.shouldFail).toBe(true);
    expect(result.manifest.baseline_comparison).toMatchObject({
      baseline_format: "findings",
      baseline_fingerprint: undefined,
      baseline_rule_pack_fingerprint: undefined,
      new_findings: 1,
      new_findings_by_severity: {
        critical: targetNewFinding?.severity === "critical" ? 1 : 0,
        high: targetNewFinding?.severity === "high" ? 1 : 0,
        medium: targetNewFinding?.severity === "medium" ? 1 : 0,
        low: targetNewFinding?.severity === "low" ? 1 : 0,
        info: targetNewFinding?.severity === "info" ? 1 : 0
      },
      new_findings_by_confidence: {
        very_high: targetNewFinding?.confidence === "very_high" ? 1 : 0,
        high: targetNewFinding?.confidence === "high" ? 1 : 0,
        medium: targetNewFinding?.confidence === "medium" ? 1 : 0,
        low: targetNewFinding?.confidence === "low" ? 1 : 0
      },
      new_findings_by_risk_driver: expect.any(Array),
      resolved_findings: 1,
      baseline_id_limit: baselineFindingIdLimit,
      baseline_ids_truncated: false
    });
    expect(result.manifest.baseline_comparison?.new_finding_ids).toEqual([targetNewFinding?.id]);
    expect(result.manifest.baseline_comparison?.new_findings_by_risk_driver.length).toBeGreaterThan(0);
    expect(result.manifest.baseline_comparison?.resolved_finding_ids).toEqual(["finding_resolved_demo"]);
    expect(result.findings.find((finding) => finding.id === targetNewFinding?.id)?.baseline_status).toBe("new");
    expect(result.manifest.action_plan?.new_actions).toBeGreaterThan(0);
    expect(result.manifest.action_plan?.actions.some((action) => action.baseline_status === "new")).toBe(true);
    expect(result.reportMarkdown).toContain("New findings: 1");
    expect(result.reportMarkdown).toContain("- Baseline fingerprint: `unavailable`");
    expect(result.reportMarkdown).toContain("- Baseline rule pack fingerprint: `unavailable`");
    expect(result.reportMarkdown).toContain("### New Finding Drift Mix");
    expect(result.reportMarkdown).toContain("### New Finding Risk Drivers");
    expect(result.reportMarkdown).toContain(`Baseline ID limit: ${baselineFindingIdLimit}`);
    expect(result.reportMarkdown).toContain("Baseline IDs truncated: `false`");
    const sarif = JSON.parse(await fs.readFile(result.outputFiles.sarif!, "utf8")) as {
      runs: Array<{ results: Array<{ partialFingerprints?: { agentcspFindingId?: string }; baselineState?: string }> }>;
    };
    const sarifFinding = sarif.runs[0]?.results.find(
      (item) => item.partialFingerprints?.agentcspFindingId === targetNewFinding?.id
    );
    expect(sarifFinding?.baselineState).toBe("new");
  });

  it("bounds baseline comparison ID previews while preserving exact counts", async () => {
    const baselinePath = tempPath("agentcsp-large-baseline.json");
    await fs.writeFile(
      baselinePath,
      `${JSON.stringify(
        Array.from({ length: baselineFindingIdLimit + 4 }, (_, index) => ({
          id: `resolved_${index.toString().padStart(3, "0")}`
        })),
        null,
        2
      )}\n`,
      "utf8"
    );
    const findings = Array.from({ length: baselineFindingIdLimit + 3 }, (_, index) =>
      finding(`new_${index.toString().padStart(3, "0")}`)
    );

    const result = await applyBaselineComparison(findings, baselinePath, tempPath());

    expect(result.comparison).toMatchObject({
      current_findings: baselineFindingIdLimit + 3,
      baseline_findings: baselineFindingIdLimit + 4,
      new_findings: baselineFindingIdLimit + 3,
      existing_findings: 0,
      resolved_findings: baselineFindingIdLimit + 4,
      baseline_id_limit: baselineFindingIdLimit,
      baseline_ids_truncated: true,
      new_finding_ids_truncated: true,
      resolved_finding_ids_truncated: true
    });
    expect(result.comparison.new_finding_ids).toHaveLength(baselineFindingIdLimit);
    expect(result.comparison.resolved_finding_ids).toHaveLength(baselineFindingIdLimit);
    expect(result.comparison.new_finding_ids[0]).toBe("new_000");
    expect(result.comparison.resolved_finding_ids[0]).toBe("resolved_000");
  });

  it("summarizes new baseline drift by severity, confidence, and risk driver", async () => {
    const baselinePath = tempPath("agentcsp-baseline-drift-mix.json");
    await fs.writeFile(baselinePath, '[{"id":"existing_high"}]\n', "utf8");

    const result = await applyBaselineComparison(
      [
        finding("existing_high", "high", "high"),
        finding("new_critical_very_high", "critical", "very_high", {
          secretExposure: true,
          externalReach: true,
          dataClasses: ["credential"],
          actions: ["send"],
          riskScore: 95
        }),
        finding("new_critical_high", "critical", "high", {
          untrustedToPrivileged: true,
          externalReach: true,
          actions: ["execute"],
          riskScore: 90
        }),
        finding("new_medium_low", "medium", "low", {
          dataClasses: ["pii"],
          actions: ["write"],
          riskScore: 55
        })
      ],
      baselinePath,
      tempPath()
    );

    expect(result.comparison).toMatchObject({
      new_findings: 3,
      existing_findings: 1,
      resolved_findings: 0,
      new_findings_by_severity: { critical: 2, high: 0, medium: 1, low: 0, info: 0 },
      new_findings_by_confidence: { very_high: 1, high: 1, medium: 0, low: 1 },
      new_findings_by_risk_driver: [
        {
          driver: "external_reach",
          count: 2,
          max_risk_score: 95,
          by_severity: { critical: 2, high: 0, medium: 0, low: 0, info: 0 }
        },
        {
          driver: "sensitive_data",
          count: 2,
          max_risk_score: 95,
          by_severity: { critical: 1, high: 0, medium: 1, low: 0, info: 0 }
        },
        {
          driver: "write_action",
          count: 2,
          max_risk_score: 95,
          by_severity: { critical: 1, high: 0, medium: 1, low: 0, info: 0 }
        },
        {
          driver: "secret_exposure",
          count: 1,
          max_risk_score: 95,
          by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
        },
        {
          driver: "credential_data",
          count: 1,
          max_risk_score: 95,
          by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
        },
        {
          driver: "untrusted_to_privileged",
          count: 1,
          max_risk_score: 90,
          by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
        },
        {
          driver: "execute_action",
          count: 1,
          max_risk_score: 90,
          by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
        },
        {
          driver: "pii_data",
          count: 1,
          max_risk_score: 55,
          by_severity: { critical: 0, high: 0, medium: 1, low: 0, info: 0 }
        }
      ]
    });
  });

  it("resolves relative baseline paths from the scan root", async () => {
    const root = tempPath("agentcsp-relative-baseline-fixture");
    await fs.rm(root, { recursive: true, force: true });
    await fs.mkdir(path.join(root, "baselines"), { recursive: true });
    await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
    await fs.writeFile(path.join(root, "baselines", "agent-manifest.json"), '{"findings": []}\n', "utf8");

    const result = await scanProject({
      root_path: root,
      output_path: "scan-output",
      baseline_path: "baselines/agent-manifest.json",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    expect(result.manifest.baseline_comparison).toMatchObject({
      baseline_path: "baselines/agent-manifest.json",
      baseline_format: "manifest"
    });
    expect(result.reportMarkdown).toContain("- Baseline: `baselines/agent-manifest.json`");
    const sarif = JSON.parse(await fs.readFile(result.outputFiles.sarif!, "utf8")) as {
      runs: Array<{ properties?: { agentcsp_baseline_comparison?: { baseline_path?: string } } }>;
    };
    expect(sarif.runs[0]?.properties?.agentcsp_baseline_comparison?.baseline_path).toBe(
      "baselines/agent-manifest.json"
    );
  });

  it("redacts external baseline paths in emitted artifacts", async () => {
    const root = tempPath("agentcsp-external-baseline-fixture");
    const externalBaselinePath = tempPath("agentcsp-external-baseline-store/team/accepted.json");
    await fs.rm(root, { recursive: true, force: true });
    await fs.rm(tempPath("agentcsp-external-baseline-store"), { recursive: true, force: true });
    await fs.mkdir(root, { recursive: true });
    await fs.mkdir(path.dirname(externalBaselinePath), { recursive: true });
    await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
    await fs.writeFile(externalBaselinePath, "[]\n", "utf8");

    const result = await scanProject({
      root_path: root,
      output_path: "scan-output",
      baseline_path: externalBaselinePath,
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    expect(result.manifest.baseline_comparison).toMatchObject({
      baseline_path: "<external-baseline>",
      baseline_format: "findings"
    });
    expect(JSON.stringify(result.manifest)).not.toContain(tempPath("agentcsp-external-baseline-store"));
    expect(result.reportMarkdown).toContain("`<external-baseline>`");
    expect(result.reportMarkdown).not.toContain(tempPath("agentcsp-external-baseline-store"));
    const sarif = JSON.parse(await fs.readFile(result.outputFiles.sarif!, "utf8")) as {
      runs: Array<{ properties?: { agentcsp_baseline_comparison?: { baseline_path?: string } } }>;
    };
    expect(sarif.runs[0]?.properties?.agentcsp_baseline_comparison?.baseline_path).toBe("<external-baseline>");
  });

  it("redacts external baseline paths in read errors", async () => {
    const root = tempPath("agentcsp-missing-external-baseline-fixture");
    const externalBaselinePath = tempPath("agentcsp-missing-external-baseline-store/team/accepted.json");
    await fs.rm(root, { recursive: true, force: true });
    await fs.rm(tempPath("agentcsp-missing-external-baseline-store"), { recursive: true, force: true });
    await fs.mkdir(root, { recursive: true });
    await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");

    let captured: unknown;
    try {
      await scanProject({
        root_path: root,
        output_path: "scan-output",
        baseline_path: externalBaselinePath,
        formats: ["json", "md"],
        include_hidden: true,
        include_logs: false,
        max_file_size_bytes: 1024 * 1024,
        max_files: 5000,
        quiet: true
      });
    } catch (error) {
      captured = error;
    }

    expect(captured).toMatchObject({
      code: "AGENTCSP-E1001",
      kind: "input",
      message: "Baseline <external-baseline> does not exist."
    });
    expect(String(captured)).not.toContain(tempPath("agentcsp-missing-external-baseline-store"));
  });

  it("classifies malformed baseline JSON as configuration input", async () => {
    const baselinePath = tempPath("agentcsp-malformed-baseline.json");
    await fs.writeFile(baselinePath, "{not-json}\n", "utf8");

    await expect(applyBaselineComparison([], baselinePath, tempPath())).rejects.toMatchObject({
      code: "AGENTCSP-E1002",
      kind: "configuration",
      message: expect.stringContaining("is not valid JSON")
    });
  });
});

function finding(
  id: string,
  severity: Finding["severity"] = "high",
  confidence: Finding["confidence"] = "high",
  options: {
    dataClasses?: Finding["data_classes"];
    actions?: Finding["risk"]["actions"];
    externalReach?: boolean;
    secretExposure?: boolean;
    untrustedToPrivileged?: boolean;
    reversible?: boolean;
    sideEffect?: boolean;
    riskScore?: number;
  } = {}
): Finding {
  const dataClasses = options.dataClasses ?? [];
  const actions = options.actions ?? ["call"];
  const externalReach = options.externalReach ?? false;
  const secretExposure = options.secretExposure ?? false;
  const untrustedToPrivileged = options.untrustedToPrivileged ?? false;
  const sideEffect = options.sideEffect ?? false;
  const reversible = options.reversible ?? true;
  return {
    id,
    rule_id: `RULE-${id}`,
    name: id,
    category: "baseline_test",
    severity,
    confidence,
    confidence_rationale: [],
    matched_object: {
      id: `object_${id}`,
      type: "tool",
      name: id,
      path: `${id}.yaml`,
      trust_level: "project",
      data_classes: dataClasses,
      actions,
      side_effect: sideEffect,
      reversible,
      external_reach: externalReach,
      secret_exposure: secretExposure,
      untrusted_to_privileged: untrustedToPrivileged,
      evidence: [],
      metadata: {}
    },
    file_path: `${id}.yaml`,
    reason: id,
    trust_boundary_crossed: untrustedToPrivileged,
    data_classes: dataClasses,
    recommended_control: "require_approval",
    risk: {
      trust_level: "project",
      data_classes: dataClasses,
      actions,
      side_effect: sideEffect,
      reversible,
      external_reach: externalReach,
      secret_exposure: secretExposure,
      untrusted_to_privileged: untrustedToPrivileged,
      score: options.riskScore ?? 80,
      rationale: []
    },
    maps_to: { owasp: [], mitre_atlas: [], nist_ai_rmf: [] },
    evidence: []
  } as Finding;
}
