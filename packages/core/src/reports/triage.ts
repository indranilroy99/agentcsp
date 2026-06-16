import type {
  Confidence,
  ConfidenceCounts,
  Control,
  Finding,
  TriageSummary,
  Severity,
  SeverityCounts,
  SurfaceType
} from "../schemas/index.js";
import { highestSeverity } from "../risk/score.js";
import { riskDriverOrder, riskDriversForFinding } from "./risk-drivers.js";

const severityOrder = ["critical", "high", "medium", "low", "info"] as const satisfies readonly Severity[];
const confidenceOrder = ["very_high", "high", "medium", "low"] as const satisfies readonly Confidence[];
const controlOrder = ["deny", "require_approval", "quarantine", "redact", "warn", "allow"] as const satisfies readonly Control[];
export const triageTopListLimit = 10;

const severityRank: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0
};

const confidenceRank: Record<Confidence, number> = {
  very_high: 3,
  high: 2,
  medium: 1,
  low: 0
};

export function buildTriageSummary(findings: Finding[]): TriageSummary {
  const activeFindings = findings.filter((finding) => finding.suppression?.status !== "active");
  const suppressedFindings = findings.filter((finding) => finding.suppression?.status === "active");
  const sortedActiveFindings = sortByTriagePriority(activeFindings);
  const topActiveRules = summarizeTopRules(sortedActiveFindings);
  const totalActiveRules = countUniqueRules(activeFindings);
  const topActiveRisks = sortedActiveFindings.slice(0, triageTopListLimit).map((finding) => ({
    finding_id: finding.id,
    rule_id: finding.rule_id,
    severity: finding.severity,
    confidence: finding.confidence,
    risk_score: finding.risk.score,
    object_id: finding.matched_object.id,
    object_type: finding.matched_object.type,
    object_name: finding.matched_object.name,
    path: finding.file_path,
    recommended_control: finding.recommended_control,
    primary_driver: finding.risk_summary.primary_driver,
    risk_drivers: finding.risk_summary.drivers,
    impact: finding.risk_summary.impact,
    control_objective: finding.risk_summary.control_objective,
    trust_level: finding.risk.trust_level,
    data_classes: finding.data_classes,
    actions: finding.risk.actions,
    external_reach: finding.risk.external_reach,
    secret_exposure: finding.risk.secret_exposure,
    untrusted_to_privileged: finding.risk.untrusted_to_privileged,
    trust_boundary_crossed: finding.trust_boundary_crossed
  }));

  return {
    title: "AgentCSP Triage Summary",
    total_findings: findings.length,
    active_findings: activeFindings.length,
    suppressed_findings: suppressedFindings.length,
    expired_suppressions: findings.filter((finding) => finding.suppression?.status === "expired").length,
    highest_active_severity: highestSeverity(activeFindings),
    max_active_risk_score: sortedActiveFindings[0]?.risk.score ?? 0,
    active_by_severity: countBySeverity(activeFindings),
    active_by_confidence: countByConfidence(activeFindings),
    active_by_surface_type: countBySurfaceType(activeFindings),
    active_by_category: countByCategory(activeFindings),
    active_by_recommended_control: countByRecommendedControl(activeFindings),
    active_by_risk_driver: countByRiskDriver(activeFindings),
    top_active_limit: triageTopListLimit,
    top_active_rules_total: totalActiveRules,
    top_active_rules_truncated: totalActiveRules > topActiveRules.length,
    top_active_rules: topActiveRules,
    top_active_risks_total: activeFindings.length,
    top_active_risks_truncated: activeFindings.length > topActiveRisks.length,
    top_active_risks: topActiveRisks
  };
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

function countBySurfaceType(findings: Finding[]): TriageSummary["active_by_surface_type"] {
  const counts = new Map<SurfaceType, number>();
  for (const finding of findings) {
    const surfaceType = finding.matched_object.type;
    counts.set(surfaceType, (counts.get(surfaceType) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([surface_type, count]) => ({ surface_type, count }))
    .sort((a, b) => b.count - a.count || a.surface_type.localeCompare(b.surface_type));
}

function countByCategory(findings: Finding[]): TriageSummary["active_by_category"] {
  const counts = new Map<string, number>();
  for (const finding of findings) counts.set(finding.category, (counts.get(finding.category) ?? 0) + 1);
  return [...counts.entries()]
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count || a.category.localeCompare(b.category));
}

function countByRecommendedControl(findings: Finding[]): TriageSummary["active_by_recommended_control"] {
  const counts = new Map<Control, number>();
  for (const finding of findings) {
    counts.set(finding.recommended_control, (counts.get(finding.recommended_control) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([control, count]) => ({ control, count }))
    .sort((a, b) => b.count - a.count || controlOrder.indexOf(a.control) - controlOrder.indexOf(b.control));
}

function countByRiskDriver(findings: Finding[]): TriageSummary["active_by_risk_driver"] {
  const counts = new Map<
    TriageSummary["active_by_risk_driver"][number]["driver"],
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

function summarizeTopRules(findings: Finding[]): TriageSummary["top_active_rules"] {
  const rules = new Map<string, { count: number; representative: Finding }>();
  for (const finding of findings) {
    const current = rules.get(finding.rule_id);
    if (current) {
      current.count += 1;
    } else {
      rules.set(finding.rule_id, { count: 1, representative: finding });
    }
  }

  return [...rules.values()]
    .sort((a, b) => compareFindings(a.representative, b.representative) || b.count - a.count)
    .slice(0, triageTopListLimit)
    .map(({ count, representative }) => ({
      rule_id: representative.rule_id,
      name: representative.name,
      category: representative.category,
      severity: representative.severity,
      confidence: representative.confidence,
      count
    }));
}

function countUniqueRules(findings: Finding[]): number {
  return new Set(findings.map((finding) => finding.rule_id)).size;
}

function sortByTriagePriority(findings: Finding[]): Finding[] {
  return [...findings].sort(compareFindings);
}

function compareFindings(a: Finding, b: Finding): number {
  return (
    severityRank[b.severity] - severityRank[a.severity] ||
    b.risk.score - a.risk.score ||
    confidenceRank[b.confidence] - confidenceRank[a.confidence] ||
    severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity) ||
    confidenceOrder.indexOf(a.confidence) - confidenceOrder.indexOf(b.confidence) ||
    a.id.localeCompare(b.id)
  );
}
