import path from "node:path";
import { createHash } from "node:crypto";
import {
  AgentManifestSchema,
  ManifestSchemaVersion,
  type ActionPlanSummary,
  type AgentManifest,
  type AttackPath,
  type BaselineComparison,
  type CiGateSummary,
  type Finding,
  type GraphEdge,
  type InventorySummary,
  type RulePackSummary,
  type ScanConfig,
  type ScanCoverageSummary,
  type StaticBlastRadiusSummary,
  type SurfaceObject,
  type TriageSummary
} from "../schemas/index.js";
import type { DetectedSurfaces } from "../scanner/detect.js";
import { isPathInsideRoot } from "../utils/paths.js";
import { sortFindings, sortObjects } from "../utils/sort.js";
import { canonicalJson } from "../utils/canonical-json.js";

export function buildManifest(input: {
  rootPath: string;
  scanConfig: ScanConfig;
  surfaces: DetectedSurfaces;
  findings?: Finding[];
  relationships?: GraphEdge[];
  attackPaths?: AttackPath[];
  triageSummary?: TriageSummary;
  actionPlan?: ActionPlanSummary;
  baselineComparison?: BaselineComparison;
  ciGateSummary?: CiGateSummary;
  rulePackSummary: RulePackSummary;
  scanCoverage?: ScanCoverageSummary;
  inventorySummary?: InventorySummary;
  staticBlastRadius?: StaticBlastRadiusSummary;
}): AgentManifest {
  const evidence = collectEvidence(input.surfaces, input.findings ?? []);
  const manifest = AgentManifestSchema.parse({
    metadata: {
      schema_version: ManifestSchemaVersion,
      generated_at: new Date().toISOString(),
      root_path: path.resolve(input.rootPath),
      scanner: {
        name: "agentcsp",
        version: "0.1.0"
      },
      config: {
        formats: [...input.scanConfig.formats].sort(),
        include_hidden: input.scanConfig.include_hidden,
        include_logs: input.scanConfig.include_logs,
        max_file_size_bytes: input.scanConfig.max_file_size_bytes,
        max_files: input.scanConfig.max_files,
        output_path_scope: isPathInsideRoot(input.rootPath, input.scanConfig.output_path)
          ? "inside_scan_root"
          : "outside_scan_root",
        config_path_configured: input.scanConfig.config_path !== undefined,
        baseline_path_configured: input.scanConfig.baseline_path !== undefined,
        fail_on: input.scanConfig.fail_on,
        fail_on_confidence: input.scanConfig.fail_on_confidence,
        fail_on_new: input.scanConfig.fail_on_new,
        fail_on_expired_suppressions: input.scanConfig.fail_on_expired_suppressions,
        fail_on_diagnostics: input.scanConfig.fail_on_diagnostics,
        fail_on_scan_health: input.scanConfig.fail_on_scan_health,
        evidence_redacted: true,
        secret_values_collected: false
      },
      rule_pack: input.rulePackSummary
    },
    agents: sortObjects(input.surfaces.agents),
    instructions: sortObjects(input.surfaces.instructions),
    skills: sortObjects(input.surfaces.skills),
    plugins: sortObjects(input.surfaces.plugins),
    mcp_servers: sortObjects(input.surfaces.mcp_servers),
    tools: sortObjects(input.surfaces.tools),
    prompts: sortObjects(input.surfaces.prompts),
    rag_sources: sortObjects(input.surfaces.rag_sources),
    memory: sortObjects(input.surfaces.memory),
    secrets: sortObjects(input.surfaces.secrets),
    runtime_config: sortObjects(input.surfaces.runtime_config),
    ci_cd: sortObjects(input.surfaces.ci_cd),
    automations: sortObjects(input.surfaces.automations),
    relationships: sortRelationships(input.relationships ?? []),
    attack_paths: sortAttackPaths(input.attackPaths ?? []),
    findings: sortFindings(input.findings ?? []),
    evidence,
    diagnostics: input.surfaces.diagnostics,
    triage_summary: input.triageSummary,
    action_plan: input.actionPlan,
    baseline_comparison: input.baselineComparison,
    ci_gate_summary: input.ciGateSummary,
    scan_coverage: input.scanCoverage,
    inventory_summary: input.inventorySummary,
    static_blast_radius: input.staticBlastRadius
  });
  return AgentManifestSchema.parse({
    ...manifest,
    metadata: {
      ...manifest.metadata,
      fingerprint: fingerprintManifest(manifest)
    }
  });
}

export function allManifestObjects(manifestOrSurfaces: AgentManifest | DetectedSurfaces): SurfaceObject[] {
  return [
    ...manifestOrSurfaces.agents,
    ...manifestOrSurfaces.instructions,
    ...manifestOrSurfaces.skills,
    ...manifestOrSurfaces.plugins,
    ...manifestOrSurfaces.mcp_servers,
    ...manifestOrSurfaces.tools,
    ...manifestOrSurfaces.prompts,
    ...manifestOrSurfaces.rag_sources,
    ...manifestOrSurfaces.memory,
    ...manifestOrSurfaces.secrets,
    ...manifestOrSurfaces.runtime_config,
    ...manifestOrSurfaces.ci_cd,
    ...manifestOrSurfaces.automations
  ];
}

function collectEvidence(surfaces: DetectedSurfaces, findings: Finding[]) {
  const evidence = new Map<string, ReturnType<typeof allManifestObjects>[number]["evidence"][number]>();
  for (const object of allManifestObjects(surfaces)) {
    for (const item of object.evidence) evidence.set(item.id, item);
  }
  for (const finding of findings) {
    for (const item of finding.evidence) evidence.set(item.id, item);
  }
  return [...evidence.values()].sort((a, b) => a.id.localeCompare(b.id));
}

function sortRelationships(relationships: GraphEdge[]): GraphEdge[] {
  return [...relationships].sort((a, b) => a.id.localeCompare(b.id));
}

function sortAttackPaths(attackPaths: AttackPath[]): AttackPath[] {
  const severityWeight = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const confidenceWeight = { very_high: 0, high: 1, medium: 2, low: 3 };
  return [...attackPaths].sort((a, b) => {
    const severityCompare = severityWeight[a.severity] - severityWeight[b.severity];
    if (severityCompare !== 0) return severityCompare;
    const priorityCompare = attackPathPriority(b) - attackPathPriority(a);
    if (priorityCompare !== 0) return priorityCompare;
    const confidenceCompare = confidenceWeight[a.confidence] - confidenceWeight[b.confidence];
    if (confidenceCompare !== 0) return confidenceCompare;
    return a.id.localeCompare(b.id);
  });
}

function attackPathPriority(path: AttackPath): number {
  let score = 0;
  if (path.title.includes("route untrusted input")) score += 12;
  if (path.title.includes("auto-approve package-script")) score += 12;
  if (path.title.includes("auto-approve destructive MCP")) score += 12;
  if (path.title.includes("replay memory")) score += 12;
  if (path.title.includes("replay generated state")) score += 12;
  if (path.title.includes("route sensitive context")) score += 12;
  if (path.reason.includes("data-egress directive")) score += 3;
  if (path.reason.includes("explicit tool reference")) score += 4;
  if (path.reason.includes("specific agent-callable capability")) score += 4;
  if (path.source.path.startsWith("rag/") && path.reason.includes("direct path from untrusted context to mutable records")) {
    score += 6;
  }
  if (path.reason.includes("generated-state replay")) score += 5;
  return score;
}

function fingerprintManifest(manifest: AgentManifest): AgentManifest["metadata"]["fingerprint"] {
  const fingerprintInput = {
    ...manifest,
    metadata: {
      ...manifest.metadata,
      generated_at: "<excluded>",
      root_path: "<excluded>",
      fingerprint: undefined
    }
  };
  return {
    algorithm: "sha256",
    value: createHash("sha256").update(canonicalJson(fingerprintInput)).digest("hex"),
    excludes: ["metadata.generated_at", "metadata.root_path", "metadata.fingerprint"]
  };
}
