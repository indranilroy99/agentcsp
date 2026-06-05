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
import { severityFromScore } from "../risk/score.js";
import { stableId } from "../utils/ids.js";

export interface StaticGraph {
  relationships: GraphEdge[];
  attackPaths: AttackPath[];
}

export function buildStaticGraph(surfaces: DetectedSurfaces, findings: Finding[]): StaticGraph {
  const objects = allManifestObjects(surfaces);
  const highRiskCapabilities = sortCapabilities(objects.filter(isHighRiskCapability)).slice(0, 30);
  const contextSources = objects.filter(isContextSource);
  const actionableContextSources = contextSources.filter(isActionableContextSource);
  const relationships = new Map<string, GraphEdge>();

  for (const context of actionableContextSources) {
    for (const capability of highRiskCapabilities.filter((target) => contextCanSteerCapability(context, target)).slice(0, 12)) {
      if (context.id === capability.id) continue;
      addEdge(
        relationships,
        context,
        capability,
        "influences",
        contextInfluenceReason(context, capability)
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

  for (const runtime of surfaces.runtime_config) {
    const referencedMcpNames = stringMetadataArray(runtime.metadata.referenced_mcp_servers);
    if (referencedMcpNames.length === 0) continue;
    const referencedMcpNameSet = new Set(referencedMcpNames);
    for (const mcpServer of surfaces.mcp_servers.filter((server) => referencedMcpNameSet.has(server.name))) {
      addEdge(
        relationships,
        runtime,
        mcpServer,
        "calls",
        "Runtime tool allowlist explicitly references this MCP server. Raw runtime values are redacted; review approval and credential scope before agent use."
      );
    }
  }

  const packageScriptTools = surfaces.tools.filter((tool) => tool.name.startsWith("package-script:"));
  for (const workflow of [...surfaces.ci_cd, ...surfaces.automations]) {
    const referencedPackageScripts = stringMetadataArray(workflow.metadata.referenced_package_scripts);
    if (referencedPackageScripts.length === 0) continue;
    const referencedPackageScriptSet = new Set(referencedPackageScripts);
    for (const tool of packageScriptTools.filter((candidate) => referencedPackageScriptSet.has(candidate.name))) {
      addEdge(
        relationships,
        workflow,
        tool,
        "triggers",
        "Workflow run command references this package script. Raw workflow command text is redacted; review agent script authority before automated execution."
      );
    }
  }

  for (const memory of surfaces.memory) {
    if (isHeuristicSurface(memory)) continue;
    const persistenceSources = actionableContextSources
      .filter((object) => object.id !== memory.id && explicitBoolean(object, "memory_write_directive"))
      .slice(0, 10);
    for (const context of persistenceSources) {
      addEdge(
        relationships,
        context,
        memory,
        "persists",
        "Specific context signal requests persistence into agent memory. Raw context is redacted; review provenance before retrieval or replay."
      );
    }
  }

  const relationshipList = [...relationships.values()].sort((a, b) => a.id.localeCompare(b.id));
  return {
    relationships: relationshipList,
    attackPaths: buildAttackPaths(relationshipList, findings, objects)
  };
}

function buildAttackPaths(edges: GraphEdge[], findings: Finding[], objects: SurfaceObject[]): AttackPath[] {
  const findingsByObject = new Map<string, Finding[]>();
  for (const finding of findings) {
    const existing = findingsByObject.get(finding.matched_object.id) ?? [];
    existing.push(finding);
    findingsByObject.set(finding.matched_object.id, existing);
  }
  const objectsById = new Map(objects.map((object) => [object.id, object]));

  const paths: AttackPath[] = [];
  for (const edge of edges) {
    const targetObject = objectsById.get(edge.target.id);
    const targetFindings = findingsByObject.get(edge.target.id) ?? [];
    const strongest = strongestFinding(targetFindings);
    if (strongest && isAttackPathCandidate(edge, strongest)) {
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

    const sourceFindings = findingsByObject.get(edge.source.id) ?? [];
    const strongestSourceFinding = strongestSourceFindingForEdge(sourceFindings, targetObject);
    if (!strongestSourceFinding || !targetObject) continue;
    if (!isSourceFindingAttackPathCandidate(edge, strongestSourceFinding, targetObject)) continue;

    const sourceAnchoredRisk = mergeSourceToTargetRisk(strongestSourceFinding, targetObject);
    const sourceAnchoredSeverity = pathSeverity(edge, strongestSourceFinding, sourceAnchoredRisk);
    paths.push({
      id: stableId("attack_path", [edge.id, strongestSourceFinding.id, "source"]),
      title: attackPathTitle(edge, strongestSourceFinding),
      severity: sourceAnchoredSeverity,
      confidence: pathConfidence(edge, strongestSourceFinding),
      source: edge.source,
      target: edge.target,
      edges: [edge],
      reason: `${edge.reason} ${strongestSourceFinding.reason}`,
      recommended_control: strongestSourceFinding.recommended_control,
      risk: sourceAnchoredRisk,
      evidence: [...edge.evidence, ...strongestSourceFinding.evidence]
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

function isActionableContextSource(object: SurfaceObject): boolean {
  if (isHeuristicSurface(object)) return false;
  if (contextSignalCount(object) >= 2) return true;
  if (
    ["instruction_like_content", "instruction_override", "tool_directive", "memory_write_directive", "external_directive"].some((signal) =>
      explicitBoolean(object, signal)
    )
  ) {
    return true;
  }
  if (object.type === "instruction" || object.type === "skill") {
    return (
      object.side_effect ||
      object.external_reach ||
      object.secret_exposure ||
      object.actions.some((action) => ["execute", "publish", "send", "delete", "write", "call", "remember"].includes(action))
    );
  }
  return false;
}

function isHighRiskCapability(object: SurfaceObject): boolean {
  return (
    ["tool", "mcp_server", "runtime_config", "ci_cd", "plugin", "automation"].includes(object.type) &&
    (object.side_effect ||
      object.external_reach ||
      object.secret_exposure ||
      object.actions.some((action) => ["execute", "publish", "send", "delete", "write", "call"].includes(action)))
  );
}

function contextCanSteerCapability(context: SurfaceObject, target: SurfaceObject): boolean {
  if (!isActionableContextSource(context)) return false;

  if (explicitBoolean(context, "tool_directive") && isAgentCallableAuthority(target)) return true;
  if (
    explicitBoolean(context, "data_egress_directive") &&
    explicitBoolean(context, "context_bridge_data_egress") &&
    isExternalEgressCapability(target)
  ) {
    return true;
  }
  if (
    explicitBoolean(context, "external_directive") &&
    (target.external_reach || target.actions.some((action) => ["send", "publish"].includes(action)))
  ) {
    return true;
  }
  if (
    (explicitBoolean(context, "instruction_like_content") || explicitBoolean(context, "instruction_override")) &&
    (target.side_effect || target.external_reach || target.secret_exposure)
  ) {
    return true;
  }
  if (explicitBoolean(context, "secret_reference") && target.secret_exposure) return true;

  if (context.type === "instruction" || context.type === "skill") {
    return sharesAuthorityIntent(context, target);
  }

  return false;
}

function contextInfluenceReason(context: SurfaceObject, target: SurfaceObject): string {
  const signals = contextSignalLabels(context);
  const targetAuthority = targetAuthorityLabels(target);
  const signalText = signals.length > 0 ? signals.join(", ") : "agent-authority instruction";
  const targetText = targetAuthority.length > 0 ? targetAuthority.join(", ") : "privileged capability";
  return `Specific context signal (${signalText}) can steer target authority (${targetText}). Raw context is redacted; review provenance before privileged use.`;
}

function isAttackPathCandidate(edge: GraphEdge, finding: Finding): boolean {
  const untrustedSource = ["unknown", "untrusted", "third_party"].includes(edge.source.trust_level);
  const criticalRule = finding.severity === "critical" || finding.severity === "high";
  const privilegedTarget = finding.risk.side_effect || finding.risk.external_reach || finding.risk.secret_exposure;
  return (untrustedSource && privilegedTarget) || criticalRule;
}

function isSourceFindingAttackPathCandidate(edge: GraphEdge, finding: Finding, target: SurfaceObject): boolean {
  if (edge.relation !== "influences") return false;
  if (!isContextRiskFinding(finding)) return false;
  if (!["unknown", "untrusted", "third_party"].includes(edge.source.trust_level)) return false;
  if (finding.severity !== "critical" && finding.severity !== "high") return false;
  if (finding.rule_id === "AGENTCSP-RAG-003") return isDirectDataEgressCapability(target);
  return isAgentCallableAuthority(target) && (target.side_effect || target.external_reach || target.secret_exposure);
}

function isContextRiskFinding(finding: Finding): boolean {
  return /^(AGENTCSP-(RAG|MEMORY|GENSTATE|PROMPT|INSTRUCTION|SKILL)-)/u.test(finding.rule_id);
}

function strongestFinding(findings: Finding[]): Finding | undefined {
  return [...findings].sort((a, b) => {
    const severityCompare = severityWeight(b.severity) - severityWeight(a.severity);
    if (severityCompare !== 0) return severityCompare;
    return b.risk.score - a.risk.score;
  })[0];
}

function strongestSourceFindingForEdge(findings: Finding[], target: SurfaceObject | undefined): Finding | undefined {
  if (target && isExternalEgressCapability(target)) {
    const dataEgressFinding = findings.find((finding) => finding.rule_id === "AGENTCSP-RAG-003");
    if (dataEgressFinding) return dataEgressFinding;
  }
  return strongestFinding(findings);
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

function mergeSourceToTargetRisk(finding: Finding, target: SurfaceObject): RiskFactors {
  const rationale = [...finding.risk.rationale];
  let score = finding.risk.score;
  if (target.external_reach) {
    score += 20;
    rationale.push("target external reach adds 20 to attack-path risk");
  }
  if (target.secret_exposure) {
    score += 20;
    rationale.push("target secret exposure adds 20 to attack-path risk");
  }
  if (target.side_effect) {
    score += 10;
    rationale.push("target side effect adds 10 to attack-path risk");
  }
  const actions = [...new Set([...finding.risk.actions, ...target.actions])].sort((a, b) => a.localeCompare(b));
  const dataClasses = [...new Set([...finding.risk.data_classes, ...target.data_classes])].sort((a, b) => a.localeCompare(b));
  return {
    ...finding.risk,
    actions,
    data_classes: dataClasses,
    side_effect: finding.risk.side_effect || target.side_effect,
    external_reach: finding.risk.external_reach || target.external_reach,
    secret_exposure: finding.risk.secret_exposure || target.secret_exposure,
    score: Math.min(100, score),
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
  if (finding.matched_object.id === edge.source.id && finding.rule_id === "AGENTCSP-RAG-003") {
    return `${edge.source.name} can route sensitive context to ${edge.target.name}`;
  }
  if (finding.matched_object.id === edge.source.id) {
    return `${edge.source.name} can steer ${edge.target.name}: ${finding.name}`;
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
    const attackPathPriorityCompare = attackPathPriority(b) - attackPathPriority(a);
    if (attackPathPriorityCompare !== 0) return attackPathPriorityCompare;
    const sourceTrustCompare = trustWeight(b.source.trust_level) - trustWeight(a.source.trust_level);
    if (sourceTrustCompare !== 0) return sourceTrustCompare;
    const confidenceCompare = confidenceWeight(b.confidence) - confidenceWeight(a.confidence);
    if (confidenceCompare !== 0) return confidenceCompare;
    const relationCompare = relationWeight(b.edges[0]?.relation) - relationWeight(a.edges[0]?.relation);
    if (relationCompare !== 0) return relationCompare;
    return a.id.localeCompare(b.id);
  });
}

function attackPathPriority(path: AttackPath): number {
  let score = 0;
  if (path.title.includes("route sensitive context")) score += 5;
  if (path.reason.includes("data-egress directive")) score += 3;
  if (path.reason.includes("RAG source directs sensitive context")) score += 3;
  if (path.reason.includes("generated-state replay")) score += 5;
  return score;
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

function sortCapabilities(objects: SurfaceObject[]): SurfaceObject[] {
  return [...objects].sort((a, b) => {
    const riskCompare = capabilityWeight(b) - capabilityWeight(a);
    if (riskCompare !== 0) return riskCompare;
    return a.id.localeCompare(b.id);
  });
}

function capabilityWeight(object: SurfaceObject): number {
  let score = 0;
  if (object.secret_exposure || object.data_classes.includes("credential")) score += 50;
  if (object.external_reach) score += 35;
  if (object.actions.includes("execute")) score += 30;
  if (object.actions.some((action) => ["publish", "send", "delete", "write"].includes(action))) score += 25;
  if (object.side_effect) score += 15;
  if (!object.reversible) score += 10;
  if (["third_party", "untrusted", "unknown"].includes(object.trust_level)) score += 10;
  return score;
}

function contextSignalCount(object: SurfaceObject): number {
  const value = object.metadata.content_signal_count;
  return typeof value === "number" ? value : 0;
}

function explicitBoolean(object: SurfaceObject, metadataKey: string): boolean {
  return object.metadata[metadataKey] === true;
}

function isHeuristicSurface(object: SurfaceObject): boolean {
  return object.metadata.heuristic === true;
}

function isAgentCallableAuthority(object: SurfaceObject): boolean {
  return (
    ["tool", "mcp_server", "runtime_config", "plugin", "automation"].includes(object.type) ||
    object.actions.some((action) => ["execute", "publish", "send", "delete", "write", "call"].includes(action))
  );
}

function isExternalEgressCapability(object: SurfaceObject): boolean {
  return (
    object.external_reach ||
    object.actions.some((action) => ["send", "publish"].includes(action)) ||
    object.metadata.external_write === true ||
    object.metadata.accepts_url_input === true
  );
}

function isDirectDataEgressCapability(object: SurfaceObject): boolean {
  if (object.type === "tool") {
    return (
      object.metadata.external_write === true &&
      (object.metadata.accepts_url_input === true || object.metadata.accepts_secret_like_input === true)
    );
  }
  if (object.type === "mcp_server") {
    return object.external_reach && (object.secret_exposure || object.actions.some((action) => ["send", "publish"].includes(action)));
  }
  return false;
}

function sharesAuthorityIntent(context: SurfaceObject, target: SurfaceObject): boolean {
  const privilegedActions = ["execute", "publish", "send", "delete", "write", "call", "remember"];
  if (!context.actions.some((action) => privilegedActions.includes(action))) return false;
  if (context.actions.some((action) => target.actions.includes(action))) return true;
  if (context.actions.includes("call") && ["tool", "mcp_server", "plugin"].includes(target.type)) return true;
  if (context.actions.includes("execute") && ["tool", "runtime_config", "ci_cd", "automation"].includes(target.type)) return true;
  if (context.actions.includes("send") && target.external_reach) return true;
  return false;
}

function contextSignalLabels(object: SurfaceObject): string[] {
  const labels: string[] = [];
  if (explicitBoolean(object, "instruction_override")) labels.push("instruction override");
  if (explicitBoolean(object, "instruction_like_content")) labels.push("instruction-like content");
  if (explicitBoolean(object, "tool_directive")) labels.push("tool directive");
  if (explicitBoolean(object, "external_directive")) labels.push("external directive");
  if (explicitBoolean(object, "sensitive_context_reference")) labels.push("sensitive context reference");
  if (explicitBoolean(object, "data_egress_directive")) labels.push("data-egress directive");
  if (explicitBoolean(object, "context_bridge_data_egress")) labels.push("data-egress bridge");
  if (explicitBoolean(object, "memory_write_directive")) labels.push("memory-write directive");
  if (explicitBoolean(object, "generated_state")) labels.push("generated-state replay");
  if (explicitBoolean(object, "secret_reference")) labels.push("secret reference");
  if (labels.length === 0 && (object.type === "instruction" || object.type === "skill")) {
    labels.push(
      ...object.actions
        .filter((action) => ["execute", "publish", "send", "delete", "write", "call", "remember"].includes(action))
        .map((action) => `${action} authority`)
    );
  }
  return labels;
}

function stringMetadataArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string").sort((a, b) => a.localeCompare(b));
}

function targetAuthorityLabels(object: SurfaceObject): string[] {
  const labels: string[] = [];
  if (object.secret_exposure || object.data_classes.includes("credential")) labels.push("credential-backed access");
  if (object.external_reach) labels.push("external reach");
  if (object.actions.includes("execute")) labels.push("execution");
  if (object.actions.includes("publish")) labels.push("publish");
  if (object.actions.includes("send")) labels.push("send");
  if (object.actions.includes("delete")) labels.push("delete");
  if (object.actions.includes("write")) labels.push("write");
  if (object.actions.includes("call")) labels.push("tool call");
  if (object.side_effect) labels.push("side effect");
  return [...new Set(labels)];
}
