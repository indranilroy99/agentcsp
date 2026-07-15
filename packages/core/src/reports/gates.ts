import type {
  CiGateName,
  CiGateSummary,
  Confidence,
  ConfidenceCounts,
  Finding,
  ScanConfig,
  ScanCoverageSummary,
  ScanDiagnostic,
  ScanHealth,
  ScanHealthGate,
  Severity,
  SeverityCounts,
  SuppressionMatchScope
} from "../schemas/index.js";
import { riskDriverOrder, riskDriversForFinding } from "./risk-drivers.js";

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

const broadSuppressionScopes = new Set<SuppressionMatchScope>(["category", "severity", "broad"]);

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
  const blockingFindings =
    input.config.profile === "ci_strict"
      ? evaluatedFindings.filter(
          (finding) => finding.disposition === "blocking" && finding.suppression?.status !== "active"
        )
      : [];
  const severityGateFindings = failOn
    ? evaluatedFindings.filter((finding) =>
        findingMatchesSeverityGate(finding, failOn, input.config.fail_on_confidence)
      )
    : [];
  const expiredSuppressionFindings = input.findings.filter((finding) => finding.suppression?.status === "expired");
  const activeSuppressionFindings = input.findings.filter((finding) => finding.suppression?.status === "active");
  const broadActiveSuppressionFindings = activeSuppressionFindings.filter((finding) =>
    broadSuppressionScopes.has(finding.suppression?.match_scope ?? "broad")
  );
  const activeSuppressionsExcluded = activeSuppressionFindings.length;
  const failedGates: CiGateName[] = [];
  const diagnosticIds = input.diagnostics.map((diagnostic) => diagnostic.id).sort();
  const gateDiagnostics = input.diagnostics.filter((diagnostic) => diagnostic.severity !== "info");

  if (blockingFindings.length > 0) {
    failedGates.push("blocking_findings");
  }
  if (severityGateFindings.length > 0) {
    failedGates.push(input.config.fail_on_new ? "new_findings" : "severity");
  }
  if (input.config.fail_on_expired_suppressions && expiredSuppressionFindings.length > 0) {
    failedGates.push("expired_suppressions");
  }
  if (input.config.fail_on_diagnostics && gateDiagnostics.length > 0) {
    failedGates.push("diagnostics");
  }
  if (
    input.config.fail_on_scan_health &&
    scanHealthMeetsGate(input.scanCoverage.scan_health, input.config.fail_on_scan_health)
  ) {
    failedGates.push("scan_health");
  }
  const severityGateFindingIds = limitIds(severityGateFindings.map((finding) => finding.id));
  const blockingFindingIds = limitIds(blockingFindings.map((finding) => finding.id));
  const broadActiveSuppressionFindingIds = limitIds(broadActiveSuppressionFindings.map((finding) => finding.id));
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
    blocking_findings: blockingFindings.length,
    blocking_finding_ids: blockingFindingIds,
    blocking_finding_ids_truncated: blockingFindings.length > blockingFindingIds.length,
    severity_gate_findings: severityGateFindings.length,
    severity_gate_by_severity: countBySeverity(severityGateFindings),
    severity_gate_by_confidence: countByConfidence(severityGateFindings),
    severity_gate_by_risk_driver: countByRiskDriver(severityGateFindings),
    active_suppressions_excluded: activeSuppressionsExcluded,
    active_suppressions_by_severity: countBySeverity(activeSuppressionFindings),
    active_suppressions_by_scope: countBySuppressionScope(activeSuppressionFindings),
    broad_active_suppression_findings: broadActiveSuppressionFindings.length,
    broad_active_suppression_by_severity: countBySeverity(broadActiveSuppressionFindings),
    expired_suppression_findings: expiredSuppressionFindings.length,
    expired_suppression_by_severity: countBySeverity(expiredSuppressionFindings),
    expired_suppression_by_risk_driver: countByRiskDriver(expiredSuppressionFindings),
    diagnostic_count: input.diagnostics.length,
    diagnostic_mix: summarizeDiagnosticMix(input.diagnostics),
    failed_gates: failedGates,
    blocker_id_limit: ciGateBlockerIdLimit,
    blocker_ids_truncated:
      severityGateFindings.length > severityGateFindingIds.length ||
      blockingFindings.length > blockingFindingIds.length ||
      broadActiveSuppressionFindings.length > broadActiveSuppressionFindingIds.length ||
      expiredSuppressionFindings.length > expiredSuppressionFindingIds.length ||
      diagnosticIds.length > limitedDiagnosticIds.length,
    severity_gate_finding_ids: severityGateFindingIds,
    severity_gate_finding_ids_truncated: severityGateFindings.length > severityGateFindingIds.length,
    broad_active_suppression_finding_ids: broadActiveSuppressionFindingIds,
    broad_active_suppression_finding_ids_truncated:
      broadActiveSuppressionFindings.length > broadActiveSuppressionFindingIds.length,
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

function countBySeverity(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

function countByConfidence(findings: Finding[]): ConfidenceCounts {
  const counts: ConfidenceCounts = { very_high: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) counts[finding.confidence] += 1;
  return counts;
}

function countByRiskDriver(findings: Finding[]): CiGateSummary["severity_gate_by_risk_driver"] {
  const counts = new Map<
    CiGateSummary["severity_gate_by_risk_driver"][number]["driver"],
    { count: number; max_risk_score: number; by_severity: SeverityCounts }
  >();

  for (const finding of findings) {
    for (const driver of riskDriversForFinding(finding)) {
      const current = counts.get(driver) ?? {
        count: 0,
        max_risk_score: 0,
        by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
      };
      current.count += 1;
      current.max_risk_score = Math.max(current.max_risk_score, finding.risk.score);
      current.by_severity[finding.severity] += 1;
      counts.set(driver, current);
    }
  }

  return [...counts.entries()]
    .map(([driver, summary]) => ({ driver, ...summary }))
    .sort(
      (a, b) =>
        b.count - a.count ||
        b.max_risk_score - a.max_risk_score ||
        riskDriverOrder.indexOf(a.driver) - riskDriverOrder.indexOf(b.driver)
    );
}

function countBySuppressionScope(findings: Finding[]): CiGateSummary["active_suppressions_by_scope"] {
  const counts: CiGateSummary["active_suppressions_by_scope"] = {
    specific_finding: 0,
    specific_object: 0,
    rule_and_path: 0,
    rule: 0,
    path: 0,
    category: 0,
    severity: 0,
    broad: 0
  };
  for (const finding of findings) {
    counts[finding.suppression?.match_scope ?? "broad"] += 1;
  }
  return counts;
}

function summarizeDiagnosticMix(diagnostics: ScanDiagnostic[]): CiGateSummary["diagnostic_mix"] {
  const counts = new Map<string, CiGateSummary["diagnostic_mix"][number]>();
  for (const diagnostic of diagnostics) {
    const key = `${diagnostic.severity}\0${diagnostic.parser}\0${diagnostic.code}`;
    const current = counts.get(key) ?? {
      code: diagnostic.code,
      parser: diagnostic.parser,
      severity: diagnostic.severity,
      count: 0
    };
    current.count += 1;
    counts.set(key, current);
  }
  return [...counts.values()].sort(
    (a, b) =>
      diagnosticSeverityRank(b.severity) - diagnosticSeverityRank(a.severity) ||
      b.count - a.count ||
      a.parser.localeCompare(b.parser) ||
      a.code.localeCompare(b.code)
  );
}

function diagnosticSeverityRank(severity: ScanDiagnostic["severity"]): number {
  if (severity === "error") return 2;
  if (severity === "warning") return 1;
  return 0;
}
