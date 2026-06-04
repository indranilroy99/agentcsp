import type {
  AttackPath,
  Confidence,
  Control,
  Finding,
  GraphEdge,
  GraphNodeRef,
  GraphRelation,
  RiskFactors,
  Severity,
  SurfaceObject
} from "../schemas/index.js";
import type { DetectedSurfaces } from "../scanner/detect.js";
import { allManifestObjects } from "../manifest/build.js";
import { scoreObjectRisk, severityFromScore } from "../risk/score.js";
import { stableId } from "../utils/ids.js";

export interface StaticGraph {
  relationships: GraphEdge[];
  attackPaths: AttackPath[];
}

export function buildStaticGraph(surfaces: DetectedSurfaces, findings: Finding[]): StaticGraph {
  const objects = allManifestObjects(surfaces);
  const highRiskCapabilities = objects.filter(isHighRiskCapability);
  const contextSources = objects.filter(isContextSource);
  const relationships = new Map<string, GraphEdge>();

  for (const context of contextSources) {
    for (const capability of highRiskCapabilities.slice(0, 20)) {
      if (context.id === capability.id) continue;
      addEdge(
        relationships,
        context,
        capability,
        "influences",
        "Agent-consumable context may influence a privileged capability during runtime."
      );
    }
  }

  for (const secret of surfaces.secrets) {
    for (const target of highRiskCapabilities.filter((object) => object.secret_exposure)) {
      addEdge(
        relationships,
        secret,
        target,
        "uses_secret",
        "A credential reference is associated with a privileged capability."
      );
    }
  }

  for (const memory of surfaces.memory) {
    for (const context of contextSources.filter((object) => object.id !== memory.id)) {
      addEdge(
        relationships,
        context,
        memory,
        "persists",
        "Agent-consumable context may be written into or retrieved from persistent memory."
      );
    }
  }

  const relationshipList = [...relationships.values()].sort((a, b) => a.id.localeCompare(b.id));
  return {
    relationships: relationshipList,
    attackPaths: buildAttackPaths(relationshipList, findings)
  };
}

function buildAttackPaths(edges: GraphEdge[], findings: Finding[]): AttackPath[] {
  const findingsByObject = new Map<string, Finding[]>();
  for (const finding of findings) {
    const existing = findingsByObject.get(finding.matched_object.id) ?? [];
    existing.push(finding);
    findingsByObject.set(finding.matched_object.id, existing);
  }

  const paths: AttackPath[] = [];
  for (const edge of edges) {
    const targetFindings = findingsByObject.get(edge.target.id) ?? [];
    const strongest = strongestFinding(targetFindings);
    if (!strongest) continue;
    if (!isAttackPathCandidate(edge, strongest)) continue;

    const risk = mergeRisk(edge.target, strongest);
    const severity = pathSeverity(edge, strongest, risk);
    paths.push({
      id: stableId("attack_path", [edge.id, strongest.id]),
      title: attackPathTitle(edge, strongest),
      severity,
      confidence: pathConfidence(edge, strongest),
      source: edge.source,
      target: edge.target,
      edges: [edge],
      reason: `${edge.reason} ${strongest.reason}`,
      recommended_control: strongest.recommended_control,
      risk,
      evidence: [...edge.evidence, ...strongest.evidence]
    });
  }

  const deduped = new Map<string, AttackPath>();
  for (const path of sortAttackPaths(paths)) {
    const key = `${path.target.id}:${path.reason}`;
    if (!deduped.has(key)) deduped.set(key, path);
  }

  return [...deduped.values()].slice(0, 15);
}

function addEdge(
  relationships: Map<string, GraphEdge>,
  source: SurfaceObject,
  target: SurfaceObject,
  relation: GraphRelation,
  reason: string
): void {
  const id = stableId("edge", [source.id, relation, target.id]);
  relationships.set(id, {
    id,
    source: toNodeRef(source),
    target: toNodeRef(target),
    relation,
    reason,
    evidence: [...source.evidence, ...target.evidence].slice(0, 4)
  });
}

function toNodeRef(object: SurfaceObject): GraphNodeRef {
  return {
    id: object.id,
    type: object.type,
    name: object.name,
    path: object.path,
    trust_level: object.trust_level
  };
}

function isContextSource(object: SurfaceObject): boolean {
  return ["instruction", "prompt", "rag_source", "memory", "skill"].includes(object.type);
}

function isHighRiskCapability(object: SurfaceObject): boolean {
  return (
    ["tool", "mcp_server", "ci_cd", "plugin", "automation"].includes(object.type) &&
    (object.side_effect ||
      object.external_reach ||
      object.secret_exposure ||
      object.actions.some((action) => ["execute", "publish", "send", "delete", "write", "call"].includes(action)))
  );
}

function isAttackPathCandidate(edge: GraphEdge, finding: Finding): boolean {
  const untrustedSource = ["unknown", "untrusted", "third_party"].includes(edge.source.trust_level);
  const criticalRule = finding.severity === "critical" || finding.severity === "high";
  const privilegedTarget = finding.risk.side_effect || finding.risk.external_reach || finding.risk.secret_exposure;
  return (untrustedSource && privilegedTarget) || criticalRule;
}

function strongestFinding(findings: Finding[]): Finding | undefined {
  return [...findings].sort((a, b) => {
    const severityCompare = severityWeight(b.severity) - severityWeight(a.severity);
    if (severityCompare !== 0) return severityCompare;
    return b.risk.score - a.risk.score;
  })[0];
}

function mergeRisk(target: GraphNodeRef, finding: Finding): RiskFactors {
  const rationale = [...finding.risk.rationale];
  if (["unknown", "untrusted", "third_party"].includes(target.trust_level)) {
    rationale.push(`target trust level ${target.trust_level} contributes to attack-path risk`);
  }
  return {
    ...finding.risk,
    rationale
  };
}

function pathSeverity(edge: GraphEdge, finding: Finding, risk: RiskFactors): Severity {
  if (
    finding.severity === "critical" &&
    (edge.relation === "uses_secret" || risk.external_reach || risk.secret_exposure)
  ) {
    return "critical";
  }
  const computed = severityFromScore(risk.score, finding.severity);
  if (computed === "critical" && finding.severity !== "critical") return "high";
  return computed;
}

function pathConfidence(edge: GraphEdge, finding: Finding): Confidence {
  if (finding.severity === "critical" && (edge.relation === "uses_secret" || finding.risk.external_reach)) {
    return "very_high";
  }
  if (finding.severity === "critical") return "high";
  if (finding.risk.secret_exposure || finding.risk.untrusted_to_privileged) return "high";
  if (edge.source.trust_level === "unknown") return "medium";
  return "high";
}

function attackPathTitle(edge: GraphEdge, finding: Finding): string {
  if (edge.relation === "uses_secret") {
    return `${edge.target.name} can use credential references`;
  }
  return `${edge.source.name} can influence ${edge.target.name}: ${finding.name}`;
}

function severityWeight(severity: Severity): number {
  return {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
  }[severity];
}

function confidenceWeight(confidence: Confidence): number {
  return {
    low: 0,
    medium: 1,
    high: 2,
    very_high: 3
  }[confidence];
}

function sortAttackPaths(paths: AttackPath[]): AttackPath[] {
  return [...paths].sort((a, b) => {
    const severityCompare = severityWeight(b.severity) - severityWeight(a.severity);
    if (severityCompare !== 0) return severityCompare;
    const sourceTrustCompare = trustWeight(b.source.trust_level) - trustWeight(a.source.trust_level);
    if (sourceTrustCompare !== 0) return sourceTrustCompare;
    const confidenceCompare = confidenceWeight(b.confidence) - confidenceWeight(a.confidence);
    if (confidenceCompare !== 0) return confidenceCompare;
    const relationCompare = relationWeight(b.edges[0]?.relation) - relationWeight(a.edges[0]?.relation);
    if (relationCompare !== 0) return relationCompare;
    return a.id.localeCompare(b.id);
  });
}

function trustWeight(trustLevel: GraphNodeRef["trust_level"]): number {
  return {
    untrusted: 5,
    unknown: 4,
    third_party: 3,
    workspace: 2,
    project: 1,
    trusted: 0
  }[trustLevel];
}

function relationWeight(relation: GraphEdge["relation"] | undefined): number {
  return {
    uses_secret: 4,
    influences: 3,
    calls: 2,
    triggers: 2,
    loads: 1,
    reads: 1,
    writes: 1,
    persists: 1,
    external_reach: 1
  }[relation ?? "reads"];
}
