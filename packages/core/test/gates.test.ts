import { describe, expect, it } from "vitest";
import { buildCiGateSummary, ciGateBlockerIdLimit } from "../src/reports/gates.js";
import type { Finding, ScanConfig, ScanDiagnostic } from "../src/schemas/index.js";

describe("CI gate summary", () => {
  it("reports blocker ID truncation for bounded CI previews", () => {
    const findings = Array.from({ length: ciGateBlockerIdLimit + 3 }, (_, index) =>
      finding(`finding_${index.toString().padStart(3, "0")}`)
    );
    const diagnostics = Array.from({ length: ciGateBlockerIdLimit + 2 }, (_, index) =>
      diagnostic(`diagnostic_${index.toString().padStart(3, "0")}`)
    );

    const summary = buildCiGateSummary({
      findings,
      diagnostics,
      scanCoverage: scanCoverage("complete"),
      config: {
        root_path: ".",
        output_path: ".agentcsp",
        formats: ["json"],
        include_hidden: true,
        include_logs: false,
        max_file_size_bytes: 1024 * 1024,
        max_files: 5000,
        quiet: true,
        fail_on: "high",
        fail_on_diagnostics: true
      } satisfies ScanConfig
    });

    expect(summary).toMatchObject({
      status: "fail",
      blocker_id_limit: ciGateBlockerIdLimit,
      blocker_ids_truncated: true,
      severity_gate_findings: ciGateBlockerIdLimit + 3,
      severity_gate_by_severity: { critical: 0, high: ciGateBlockerIdLimit + 3, medium: 0, low: 0, info: 0 },
      severity_gate_by_confidence: { very_high: 0, high: ciGateBlockerIdLimit + 3, medium: 0, low: 0 },
      severity_gate_by_risk_driver: [
        {
          driver: "side_effect",
          count: ciGateBlockerIdLimit + 3,
          max_risk_score: 80,
          by_severity: { critical: 0, high: ciGateBlockerIdLimit + 3, medium: 0, low: 0, info: 0 }
        }
      ],
      severity_gate_finding_ids_truncated: true,
      diagnostic_count: ciGateBlockerIdLimit + 2,
      diagnostic_ids_truncated: true,
      expired_suppression_findings: 0,
      active_suppressions_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      active_suppressions_by_scope: {
        specific_finding: 0,
        specific_object: 0,
        rule_and_path: 0,
        rule: 0,
        path: 0,
        category: 0,
        severity: 0,
        broad: 0
      },
      broad_active_suppression_findings: 0,
      broad_active_suppression_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      broad_active_suppression_finding_ids_truncated: false,
      expired_suppression_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      expired_suppression_by_risk_driver: [],
      expired_suppression_finding_ids_truncated: false
    });
    expect(summary.severity_gate_finding_ids).toHaveLength(ciGateBlockerIdLimit);
    expect(summary.diagnostic_ids).toHaveLength(ciGateBlockerIdLimit);
    expect(summary.severity_gate_finding_ids[0]).toBe("finding_000");
    expect(summary.diagnostic_ids[0]).toBe("diagnostic_000");
  });

  it("fails when scan health meets the configured threshold", () => {
    const degraded = buildCiGateSummary({
      findings: [],
      diagnostics: [],
      scanCoverage: scanCoverage("degraded", ["files_skipped_for_size"]),
      config: {
        root_path: ".",
        output_path: ".agentcsp",
        formats: ["json"],
        include_hidden: true,
        include_logs: false,
        max_file_size_bytes: 1024 * 1024,
        max_files: 5000,
        quiet: true,
        fail_on_scan_health: "degraded"
      } satisfies ScanConfig
    });

    expect(degraded).toMatchObject({
      status: "fail",
      should_fail: true,
      fail_on_scan_health: "degraded",
      scan_health: "degraded",
      scan_health_reasons: ["files_skipped_for_size"],
      failed_gates: ["scan_health"]
    });

    const incompleteOnly = buildCiGateSummary({
      findings: [],
      diagnostics: [],
      scanCoverage: scanCoverage("degraded", ["files_skipped_for_size"]),
      config: {
        root_path: ".",
        output_path: ".agentcsp",
        formats: ["json"],
        include_hidden: true,
        include_logs: false,
        max_file_size_bytes: 1024 * 1024,
        max_files: 5000,
        quiet: true,
        fail_on_scan_health: "incomplete"
      } satisfies ScanConfig
    });

    expect(incompleteOnly).toMatchObject({
      status: "pass",
      should_fail: false,
      fail_on_scan_health: "incomplete",
      scan_health: "degraded",
      failed_gates: []
    });
  });

  it("summarizes CI blockers by severity and confidence", () => {
    const summary = buildCiGateSummary({
      findings: [
        finding("critical_high", "critical", "high"),
        finding("critical_very_high", "critical", "very_high", {
          externalReach: true,
          secretExposure: true,
          dataClasses: ["credential"],
          actions: ["send"],
          riskScore: 95
        }),
        finding("high_medium", "high", "medium"),
        finding("medium_high", "medium", "high"),
        {
          ...finding("expired_high", "high", "high", {
            externalReach: true,
            untrustedToPrivileged: true,
            actions: ["execute"],
            riskScore: 90
          }),
          suppression: { status: "expired", match_scope: "severity" }
        } as Finding,
        {
          ...finding("active_critical", "critical", "very_high"),
          suppression: { status: "active", match_scope: "severity" }
        } as Finding
      ],
      diagnostics: [],
      scanCoverage: scanCoverage("complete"),
      config: {
        root_path: ".",
        output_path: ".agentcsp",
        formats: ["json"],
        include_hidden: true,
        include_logs: false,
        max_file_size_bytes: 1024 * 1024,
        max_files: 5000,
        quiet: true,
        fail_on: "high",
        fail_on_confidence: "high",
        fail_on_expired_suppressions: true
      } satisfies ScanConfig
    });

    expect(summary).toMatchObject({
      status: "fail",
      severity_gate_findings: 3,
      severity_gate_by_severity: { critical: 2, high: 1, medium: 0, low: 0, info: 0 },
      severity_gate_by_confidence: { very_high: 1, high: 2, medium: 0, low: 0 },
      severity_gate_by_risk_driver: [
        {
          driver: "side_effect",
          count: 3,
          max_risk_score: 95,
          by_severity: { critical: 2, high: 1, medium: 0, low: 0, info: 0 }
        },
        {
          driver: "external_reach",
          count: 2,
          max_risk_score: 95,
          by_severity: { critical: 1, high: 1, medium: 0, low: 0, info: 0 }
        },
        {
          driver: "secret_exposure",
          count: 1,
          max_risk_score: 95,
          by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
        },
        {
          driver: "sensitive_data",
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
          driver: "write_action",
          count: 1,
          max_risk_score: 95,
          by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
        },
        {
          driver: "untrusted_to_privileged",
          count: 1,
          max_risk_score: 90,
          by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }
        },
        {
          driver: "execute_action",
          count: 1,
          max_risk_score: 90,
          by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }
        }
      ],
      active_suppressions_excluded: 1,
      active_suppressions_by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      active_suppressions_by_scope: {
        specific_finding: 0,
        specific_object: 0,
        rule_and_path: 0,
        rule: 0,
        path: 0,
        category: 0,
        severity: 1,
        broad: 0
      },
      broad_active_suppression_findings: 1,
      broad_active_suppression_by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      broad_active_suppression_finding_ids: ["active_critical"],
      expired_suppression_findings: 1,
      expired_suppression_by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      expired_suppression_by_risk_driver: [
        {
          driver: "untrusted_to_privileged",
          count: 1,
          max_risk_score: 90,
          by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }
        },
        {
          driver: "external_reach",
          count: 1,
          max_risk_score: 90,
          by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }
        },
        {
          driver: "side_effect",
          count: 1,
          max_risk_score: 90,
          by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }
        },
        {
          driver: "execute_action",
          count: 1,
          max_risk_score: 90,
          by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }
        }
      ],
      failed_gates: ["severity", "expired_suppressions"]
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
    riskScore?: number;
  } = {}
): Finding {
  const dataClasses = options.dataClasses ?? [];
  const actions = options.actions ?? ["call"];
  const externalReach = options.externalReach ?? false;
  const secretExposure = options.secretExposure ?? false;
  const untrustedToPrivileged = options.untrustedToPrivileged ?? false;
  return {
    id,
    rule_id: `RULE-${id}`,
    name: id,
    category: "gate_test",
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
      side_effect: true,
      reversible: true,
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
      side_effect: true,
      reversible: true,
      external_reach: externalReach,
      secret_exposure: secretExposure,
      untrusted_to_privileged: untrustedToPrivileged,
      score: options.riskScore ?? 80,
      rationale: []
    },
    maps_to: { owasp: [], mitre_atlas: [], nist_ai_rmf: [] },
    evidence: [],
    suppression: undefined
  } as Finding;
}

function diagnostic(id: string): ScanDiagnostic {
  return {
    id,
    code: "TEST_DIAGNOSTIC",
    severity: "warning",
    message: "Synthetic diagnostic for gate summary regression.",
    path: "<test>",
    content_redacted: true
  };
}

function scanCoverage(scan_health: "complete" | "degraded" | "incomplete", scan_health_reasons: string[] = []) {
  return {
    title: "AgentCSP Scan Coverage",
    scan_health,
    scan_health_reasons,
    directories_visited: 1,
    files_seen: 1,
    files_indexed: 1,
    files_skipped_for_size: 0,
    files_skipped_by_ignore: 0,
    directories_skipped_by_ignore: 0,
    directories_skipped_hidden: 0,
    directories_skipped_logs: 0,
    diagnostics_total: 0,
    diagnostics_errors: 0,
    diagnostics_warnings: 0,
    diagnostics_info: 0,
    max_files_reached: false,
    max_files: 5000,
    max_file_size_bytes: 1024 * 1024
  } as const;
}
