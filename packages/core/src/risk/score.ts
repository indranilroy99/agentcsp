import type { Confidence, Finding, RiskFactors, Rule, Severity, SurfaceObject } from "../schemas/index.js";

const severityRank: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

const severityByRank: Severity[] = ["info", "low", "medium", "high", "critical"];

const confidenceRank: Record<Confidence, number> = {
  low: 0,
  medium: 1,
  high: 2,
  very_high: 3
};

const severityFloor: Record<Severity, number> = {
  info: 0,
  low: 20,
  medium: 40,
  high: 65,
  critical: 85
};

export function scoreObjectRisk(object: SurfaceObject, rule?: Rule): RiskFactors {
  let score = rule ? severityFloor[rule.severity] : 0;
  const rationale: string[] = [];

  const trustScore = {
    trusted: 0,
    project: 5,
    workspace: 10,
    third_party: 20,
    untrusted: 30,
    unknown: 15
  }[object.trust_level];
  if (trustScore > 0) rationale.push(`trust level ${object.trust_level} adds ${trustScore}`);
  score += trustScore;

  if (object.data_classes.includes("credential") || object.data_classes.includes("secret")) {
    score += 30;
    rationale.push("secret or credential data class adds 30");
  } else if (object.data_classes.includes("pii")) {
    score += 20;
    rationale.push("PII data class adds 20");
  } else if (object.data_classes.includes("confidential")) {
    score += 15;
    rationale.push("confidential data class adds 15");
  }

  const privilegedActions = object.actions.filter((action) =>
    ["execute", "publish", "send", "delete"].includes(action)
  );
  if (privilegedActions.length > 0) {
    score += 25;
    rationale.push(`privileged action ${privilegedActions.join(", ")} adds 25`);
  } else if (object.actions.some((action) => ["write", "remember", "call"].includes(action))) {
    score += 15;
    rationale.push("state-changing or callable authority adds 15");
  }

  if (object.side_effect) {
    score += 10;
    rationale.push("side effect adds 10");
  }
  if (!object.reversible) {
    score += 20;
    rationale.push("irreversible action adds 20");
  }
  if (object.external_reach) {
    score += 20;
    rationale.push("external reach adds 20");
  }
  if (object.secret_exposure) {
    score += 30;
    rationale.push("secret exposure signal adds 30");
  }
  if (object.untrusted_to_privileged) {
    score += 25;
    rationale.push("untrusted-to-privileged influence adds 25");
  }

  return {
    trust_level: object.trust_level,
    data_classes: object.data_classes,
    actions: object.actions,
    side_effect: object.side_effect,
    reversible: object.reversible,
    external_reach: object.external_reach,
    secret_exposure: object.secret_exposure,
    untrusted_to_privileged: object.untrusted_to_privileged,
    score: Math.min(100, score),
    rationale
  };
}

export function severityFromScore(score: number, floor?: Severity): Severity {
  const calculated: Severity = score >= 85 ? "critical" : score >= 65 ? "high" : score >= 40 ? "medium" : score >= 20 ? "low" : "info";
  if (!floor) return calculated;
  const floorRank = severityRank[floor];
  const calculatedRank = severityRank[calculated];
  const cappedRank = Math.min(calculatedRank, floorRank + 1);
  return severityByRank[Math.max(floorRank, cappedRank)] ?? floor;
}

export function shouldFail(findings: Finding[], failOn?: Severity, failOnConfidence?: Confidence): boolean {
  if (!failOn) return false;
  const threshold = severityRank[failOn];
  const confidenceThreshold = failOnConfidence ? confidenceRank[failOnConfidence] : undefined;
  return findings.some((finding) => {
    if (finding.suppression?.status === "active") return false;
    if (severityRank[finding.severity] < threshold) return false;
    if (confidenceThreshold === undefined) return true;
    return confidenceRank[finding.confidence] >= confidenceThreshold;
  });
}

export function highestSeverity(findings: Finding[]): Severity {
  let highest: Severity = "info";
  for (const finding of findings) {
    if (finding.suppression?.status === "active") continue;
    if (severityRank[finding.severity] > severityRank[highest]) highest = finding.severity;
  }
  return highest;
}
