import path from "node:path";
import {
  AgentManifestSchema,
  ManifestSchemaVersion,
  type AgentManifest,
  type AttackPath,
  type BaselineComparison,
  type Finding,
  type GraphEdge,
  type ScanConfig,
  type ScanCoverageSummary,
  type StaticBlastRadiusSummary,
  type SurfaceObject,
  type TriageSummary
} from "../schemas/index.js";
import type { DetectedSurfaces } from "../scanner/detect.js";
import { sortFindings, sortObjects } from "../utils/sort.js";

export function buildManifest(input: {
  rootPath: string;
  scanConfig: ScanConfig;
  surfaces: DetectedSurfaces;
  findings?: Finding[];
  relationships?: GraphEdge[];
  attackPaths?: AttackPath[];
  triageSummary?: TriageSummary;
  baselineComparison?: BaselineComparison;
  scanCoverage?: ScanCoverageSummary;
  staticBlastRadius?: StaticBlastRadiusSummary;
}): AgentManifest {
  const evidence = collectEvidence(input.surfaces, input.findings ?? []);
  return AgentManifestSchema.parse({
    metadata: {
      schema_version: ManifestSchemaVersion,
      generated_at: new Date().toISOString(),
      root_path: path.resolve(input.rootPath),
      scanner: {
        name: "agentcsp",
        version: "0.1.0"
      },
      config: {
        include_hidden: input.scanConfig.include_hidden,
        include_logs: input.scanConfig.include_logs,
        max_file_size_bytes: input.scanConfig.max_file_size_bytes,
        evidence_redacted: true,
        secret_values_collected: false
      }
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
    baseline_comparison: input.baselineComparison,
    scan_coverage: input.scanCoverage,
    static_blast_radius: input.staticBlastRadius
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
    const confidenceCompare = confidenceWeight[a.confidence] - confidenceWeight[b.confidence];
    if (confidenceCompare !== 0) return confidenceCompare;
    return a.id.localeCompare(b.id);
  });
}
