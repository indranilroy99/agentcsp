import type { ActionPlanSummary, Control, Finding, Severity, SurfaceType } from "../schemas/index.js";
import { stableId } from "../utils/ids.js";

const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const confidenceRank = { very_high: 4, high: 3, medium: 2, low: 1 };
const baselineRank = { new: 2, existing: 1, unbaselined: 0 };
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
  const actions = rankedFindings.map((finding, index) => {
    const owner = ownerForFinding(finding);
    return {
      id: stableId("action", [finding.id, finding.recommended_control]),
      priority: index + 1,
      title: actionTitle(finding),
      owner_hint: owner.owner_hint,
      owner_reason: owner.owner_reason,
      recommended_control: finding.recommended_control,
      severity: finding.severity,
      confidence: finding.confidence,
      risk_score: finding.risk.score,
      rule_id: finding.rule_id,
      category: finding.category,
      surface_type: finding.matched_object.type,
      path: finding.file_path,
      baseline_status: finding.baseline_status,
      rationale: actionRationale(finding),
      related_finding_ids: [finding.id],
      data_classes: finding.data_classes,
      actions: finding.risk.actions,
      trust_boundary_crossed: finding.trust_boundary_crossed
    };
  });

  return {
    title: "AgentCSP Action Plan",
    total_actions: actions.length,
    immediate_actions: actions.filter(isImmediateAction).length,
    approval_actions: actions.filter((action) => action.recommended_control === "require_approval").length,
    quarantine_actions: actions.filter((action) => action.recommended_control === "quarantine").length,
    redaction_actions: actions.filter((action) => action.recommended_control === "redact").length,
    warn_actions: actions.filter((action) => action.recommended_control === "warn").length,
    new_actions: actions.filter((action) => action.baseline_status === "new").length,
    existing_actions: actions.filter((action) => action.baseline_status === "existing").length,
    by_owner: summarizeOwners(actions),
    actions
  };
}

function compareActionPriority(a: Finding, b: Finding): number {
  return (
    severityRank[b.severity] - severityRank[a.severity] ||
    baselinePriority(b) - baselinePriority(a) ||
    b.risk.score - a.risk.score ||
    controlRank[b.recommended_control] - controlRank[a.recommended_control] ||
    confidenceRank[b.confidence] - confidenceRank[a.confidence] ||
    Number(b.trust_boundary_crossed) - Number(a.trust_boundary_crossed) ||
    Number(b.risk.secret_exposure) - Number(a.risk.secret_exposure) ||
    a.id.localeCompare(b.id)
  );
}

function baselinePriority(finding: Finding): number {
  return baselineRank[finding.baseline_status ?? "unbaselined"];
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

function ownerForFinding(finding: Finding): { owner_hint: string; owner_reason: string } {
  if (
    finding.data_classes.some((dataClass) => dataClass === "credential" || dataClass === "secret") ||
    finding.risk.secret_exposure ||
    finding.category.includes("secret") ||
    finding.category.includes("identity") ||
    finding.category.includes("authorization")
  ) {
    return { owner_hint: "identity-and-secrets", owner_reason: "credential, secret, identity, or authorization risk" };
  }
  if (
    finding.matched_object.type === "ci_cd" ||
    finding.category.includes("ci") ||
    finding.category.includes("automation") ||
    finding.category.includes("supply")
  ) {
    return { owner_hint: "platform-ci", owner_reason: "CI/CD, automation, package, or deployment surface" };
  }
  if (
    finding.matched_object.type === "rag_source" ||
    finding.matched_object.type === "memory" ||
    finding.category.includes("rag") ||
    finding.category.includes("memory") ||
    finding.data_classes.some((dataClass) => dataClass === "pii" || dataClass === "confidential")
  ) {
    return { owner_hint: "data-and-knowledge", owner_reason: "RAG, memory, PII, or confidential-data surface" };
  }
  if (
    finding.matched_object.type === "mcp_server" ||
    finding.matched_object.type === "tool" ||
    finding.category.includes("mcp") ||
    finding.category.includes("tool")
  ) {
    return { owner_hint: "agent-platform", owner_reason: "agent-callable tool or MCP authority" };
  }
  if (
    finding.matched_object.type === "instruction" ||
    finding.matched_object.type === "prompt" ||
    finding.matched_object.type === "skill" ||
    finding.category.includes("instruction") ||
    finding.category.includes("prompt") ||
    finding.category.includes("skill")
  ) {
    return { owner_hint: "agent-engineering", owner_reason: "agent instruction, prompt, or skill context" };
  }
  if (isRuntimeSurface(finding.matched_object.type) || finding.category.includes("runtime")) {
    return { owner_hint: "runtime-platform", owner_reason: "runtime, sandbox, approval, network, or hosted-agent posture" };
  }
  return { owner_hint: "application-security", owner_reason: "general agent security review" };
}

function isRuntimeSurface(surfaceType: SurfaceType): boolean {
  return surfaceType === "runtime_config" || surfaceType === "agent" || surfaceType === "automation";
}

function summarizeOwners(actions: ActionPlanSummary["actions"]): ActionPlanSummary["by_owner"] {
  const owners = new Map<string, { count: number; highest_severity: Severity; max_risk_score: number }>();
  for (const action of actions) {
    const current = owners.get(action.owner_hint) ?? {
      count: 0,
      highest_severity: "info" as Severity,
      max_risk_score: 0
    };
    current.count += 1;
    if (severityRank[action.severity] > severityRank[current.highest_severity]) {
      current.highest_severity = action.severity;
    }
    current.max_risk_score = Math.max(current.max_risk_score, action.risk_score);
    owners.set(action.owner_hint, current);
  }
  return [...owners.entries()]
    .map(([owner_hint, summary]) => ({ owner_hint, ...summary }))
    .sort(
      (a, b) =>
        severityRank[b.highest_severity] - severityRank[a.highest_severity] ||
        b.max_risk_score - a.max_risk_score ||
        b.count - a.count ||
        a.owner_hint.localeCompare(b.owner_hint)
    );
}
