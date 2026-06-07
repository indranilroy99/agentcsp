import type { CiGateName, CiGateSummary, Confidence, Finding, ScanConfig, ScanDiagnostic, Severity } from "../schemas/index.js";

const severityRank: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

const confidenceRank: Record<Confidence, number> = {
  low: 0,
  medium: 1,
  high: 2,
  very_high: 3
};

export function buildCiGateSummary(input: {
  findings: Finding[];
  diagnostics: ScanDiagnostic[];
  config: ScanConfig;
}): CiGateSummary {
  const evaluatedFindings = input.config.fail_on_new
    ? input.findings.filter((finding) => finding.baseline_status === "new")
    : input.findings;
  const failOn = input.config.fail_on;
  const severityGateFindings = failOn
    ? evaluatedFindings.filter((finding) =>
        findingMatchesSeverityGate(finding, failOn, input.config.fail_on_confidence)
      )
    : [];
  const expiredSuppressionFindings = input.findings.filter((finding) => finding.suppression?.status === "expired");
  const activeSuppressionsExcluded = input.findings.filter((finding) => finding.suppression?.status === "active").length;
  const failedGates: CiGateName[] = [];

  if (severityGateFindings.length > 0) {
    failedGates.push(input.config.fail_on_new ? "new_findings" : "severity");
  }
  if (input.config.fail_on_expired_suppressions && expiredSuppressionFindings.length > 0) {
    failedGates.push("expired_suppressions");
  }
  if (input.config.fail_on_diagnostics && input.diagnostics.length > 0) {
    failedGates.push("diagnostics");
  }

  return {
    title: "AgentCSP CI Gate Summary",
    status: failedGates.length > 0 ? "fail" : "pass",
    should_fail: failedGates.length > 0,
    fail_on: input.config.fail_on,
    fail_on_confidence: input.config.fail_on_confidence,
    fail_on_new: input.config.fail_on_new,
    fail_on_expired_suppressions: input.config.fail_on_expired_suppressions,
    fail_on_diagnostics: input.config.fail_on_diagnostics,
    evaluated_findings: evaluatedFindings.length,
    severity_gate_findings: severityGateFindings.length,
    active_suppressions_excluded: activeSuppressionsExcluded,
    expired_suppression_findings: expiredSuppressionFindings.length,
    diagnostic_count: input.diagnostics.length,
    failed_gates: failedGates
  };
}

function findingMatchesSeverityGate(
  finding: Finding,
  failOn: Severity,
  failOnConfidence?: Confidence
): boolean {
  if (finding.suppression?.status === "active") return false;
  if (severityRank[finding.severity] < severityRank[failOn]) return false;
  if (!failOnConfidence) return true;
  return confidenceRank[finding.confidence] >= confidenceRank[failOnConfidence];
}
