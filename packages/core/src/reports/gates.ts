import type {
  CiGateName,
  CiGateSummary,
  Confidence,
  Finding,
  ScanConfig,
  ScanCoverageSummary,
  ScanDiagnostic,
  ScanHealth,
  ScanHealthGate,
  Severity
} from "../schemas/index.js";

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

const scanHealthRank: Record<ScanHealth, number> = {
  complete: 0,
  degraded: 1,
  incomplete: 2
};

export const ciGateBlockerIdLimit = 50;

export function buildCiGateSummary(input: {
  findings: Finding[];
  diagnostics: ScanDiagnostic[];
  scanCoverage: ScanCoverageSummary;
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
  const diagnosticIds = input.diagnostics.map((diagnostic) => diagnostic.id).sort();

  if (severityGateFindings.length > 0) {
    failedGates.push(input.config.fail_on_new ? "new_findings" : "severity");
  }
  if (input.config.fail_on_expired_suppressions && expiredSuppressionFindings.length > 0) {
    failedGates.push("expired_suppressions");
  }
  if (input.config.fail_on_diagnostics && input.diagnostics.length > 0) {
    failedGates.push("diagnostics");
  }
  if (
    input.config.fail_on_scan_health &&
    scanHealthMeetsGate(input.scanCoverage.scan_health, input.config.fail_on_scan_health)
  ) {
    failedGates.push("scan_health");
  }
  const severityGateFindingIds = limitIds(severityGateFindings.map((finding) => finding.id));
  const expiredSuppressionFindingIds = limitIds(expiredSuppressionFindings.map((finding) => finding.id));
  const limitedDiagnosticIds = limitIds(diagnosticIds);

  return {
    title: "AgentCSP CI Gate Summary",
    status: failedGates.length > 0 ? "fail" : "pass",
    should_fail: failedGates.length > 0,
    fail_on: input.config.fail_on,
    fail_on_confidence: input.config.fail_on_confidence,
    fail_on_new: input.config.fail_on_new,
    fail_on_expired_suppressions: input.config.fail_on_expired_suppressions,
    fail_on_diagnostics: input.config.fail_on_diagnostics,
    fail_on_scan_health: input.config.fail_on_scan_health,
    scan_health: input.scanCoverage.scan_health,
    scan_health_reasons: input.scanCoverage.scan_health_reasons,
    evaluated_findings: evaluatedFindings.length,
    severity_gate_findings: severityGateFindings.length,
    active_suppressions_excluded: activeSuppressionsExcluded,
    expired_suppression_findings: expiredSuppressionFindings.length,
    diagnostic_count: input.diagnostics.length,
    failed_gates: failedGates,
    blocker_id_limit: ciGateBlockerIdLimit,
    blocker_ids_truncated:
      severityGateFindings.length > severityGateFindingIds.length ||
      expiredSuppressionFindings.length > expiredSuppressionFindingIds.length ||
      diagnosticIds.length > limitedDiagnosticIds.length,
    severity_gate_finding_ids: severityGateFindingIds,
    severity_gate_finding_ids_truncated: severityGateFindings.length > severityGateFindingIds.length,
    expired_suppression_finding_ids: expiredSuppressionFindingIds,
    expired_suppression_finding_ids_truncated:
      expiredSuppressionFindings.length > expiredSuppressionFindingIds.length,
    diagnostic_ids: limitedDiagnosticIds,
    diagnostic_ids_truncated: diagnosticIds.length > limitedDiagnosticIds.length
  };
}

function scanHealthMeetsGate(actual: ScanHealth, threshold: ScanHealthGate): boolean {
  return scanHealthRank[actual] >= scanHealthRank[threshold];
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

function limitIds(ids: string[], limit = ciGateBlockerIdLimit): string[] {
  return [...ids].sort((a, b) => a.localeCompare(b)).slice(0, limit);
}
