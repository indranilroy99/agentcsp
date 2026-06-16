import type { ActionPlanSummary, Control, Finding } from "../schemas/index.js";
import { stableId } from "../utils/ids.js";

const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const confidenceRank = { very_high: 4, high: 3, medium: 2, low: 1 };
const controlRank: Record<Control, number> = {
  deny: 6,
  quarantine: 5,
  require_approval: 4,
  redact: 3,
  warn: 2,
  allow: 1
};

export function buildActionPlan(findings: Finding[], limit = 12): ActionPlanSummary {
  const activeFindings = findings.filter((finding) => finding.suppression?.status !== "active");
  const rankedFindings = [...activeFindings].sort(compareActionPriority).slice(0, limit);
  const actions = rankedFindings.map((finding, index) => ({
    id: stableId("action", [finding.id, finding.recommended_control]),
    priority: index + 1,
    title: actionTitle(finding),
    recommended_control: finding.recommended_control,
    severity: finding.severity,
    confidence: finding.confidence,
    risk_score: finding.risk.score,
    rule_id: finding.rule_id,
    category: finding.category,
    surface_type: finding.matched_object.type,
    path: finding.file_path,
    rationale: actionRationale(finding),
    related_finding_ids: [finding.id],
    data_classes: finding.data_classes,
    actions: finding.risk.actions,
    trust_boundary_crossed: finding.trust_boundary_crossed
  }));

  return {
    title: "AgentCSP Action Plan",
    total_actions: actions.length,
    immediate_actions: actions.filter(isImmediateAction).length,
    approval_actions: actions.filter((action) => action.recommended_control === "require_approval").length,
    quarantine_actions: actions.filter((action) => action.recommended_control === "quarantine").length,
    redaction_actions: actions.filter((action) => action.recommended_control === "redact").length,
    warn_actions: actions.filter((action) => action.recommended_control === "warn").length,
    actions
  };
}

function compareActionPriority(a: Finding, b: Finding): number {
  return (
    severityRank[b.severity] - severityRank[a.severity] ||
    b.risk.score - a.risk.score ||
    controlRank[b.recommended_control] - controlRank[a.recommended_control] ||
    confidenceRank[b.confidence] - confidenceRank[a.confidence] ||
    Number(b.trust_boundary_crossed) - Number(a.trust_boundary_crossed) ||
    Number(b.risk.secret_exposure) - Number(a.risk.secret_exposure) ||
    a.id.localeCompare(b.id)
  );
}

function isImmediateAction(action: ActionPlanSummary["actions"][number]): boolean {
  return (
    action.severity === "critical" ||
    action.severity === "high" ||
    action.recommended_control === "deny" ||
    action.recommended_control === "quarantine"
  );
}

function actionTitle(finding: Finding): string {
  const control = finding.recommended_control.replaceAll("_", " ");
  return `${control}: ${finding.matched_object.type} at ${finding.file_path}`;
}

function actionRationale(finding: Finding): string[] {
  const rationale = [
    `Severity ${finding.severity} with risk score ${finding.risk.score}`,
    `Rule ${finding.rule_id}: ${finding.name}`
  ];
  if (finding.trust_boundary_crossed) rationale.push("Trust boundary crossed");
  if (finding.risk.secret_exposure) rationale.push("Secret or credential exposure signal");
  if (finding.risk.external_reach) rationale.push("External reach present");
  if (finding.risk.actions.length > 0) rationale.push(`Actions: ${finding.risk.actions.join(", ")}`);
  if (finding.data_classes.length > 0) rationale.push(`Data classes: ${finding.data_classes.join(", ")}`);
  return rationale;
}
