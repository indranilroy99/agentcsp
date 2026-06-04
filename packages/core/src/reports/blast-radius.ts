import type { AttackPath, Finding, GraphEdge, StaticBlastRadiusSummary, SurfaceObject } from "../schemas/index.js";
import { allManifestObjects } from "../manifest/build.js";
import type { DetectedSurfaces } from "../scanner/detect.js";
import { highestSeverity } from "../risk/score.js";

export function buildStaticBlastRadiusSummary(
  surfaces: DetectedSurfaces,
  findings: Finding[],
  relationships: GraphEdge[] = [],
  attackPaths: AttackPath[] = []
): StaticBlastRadiusSummary {
  const objects = allManifestObjects(surfaces);
  const highRiskObjects = objects.filter(isHighRiskObject).slice(0, 20);
  return {
    title: "Static Blast-Radius Summary",
    read_paths: countByAction(objects, "read"),
    write_paths: countByAction(objects, "write"),
    execute_paths: countByAction(objects, "execute"),
    external_reach_paths: objects.filter((object) => object.external_reach).length,
    secret_reference_paths: objects.filter((object) => object.secret_exposure || object.data_classes.includes("credential")).length,
    memory_surfaces: surfaces.memory.length,
    rag_surfaces: surfaces.rag_sources.length,
    relationships: relationships.length,
    attack_paths: attackPaths.length,
    critical_attack_paths: attackPaths.filter((attackPath) => attackPath.severity === "critical").length,
    highest_severity: highestSeverity(findings),
    high_risk_objects: highRiskObjects,
    recommended_controls: summarizeControls(findings)
  };
}

function countByAction(objects: SurfaceObject[], action: string): number {
  return objects.filter((object) => object.actions.includes(action as never)).length;
}

function isHighRiskObject(object: SurfaceObject): boolean {
  return (
    object.secret_exposure ||
    object.untrusted_to_privileged ||
    object.external_reach ||
    object.actions.some((action) => ["execute", "publish", "send", "delete"].includes(action))
  );
}

function summarizeControls(findings: Finding[]): string[] {
  const controls = new Set<string>();
  for (const finding of findings) {
    controls.add(`Recommended control: ${finding.recommended_control.replaceAll("_", " ")} for ${finding.file_path}`);
  }
  return [...controls].sort((a, b) => a.localeCompare(b)).slice(0, 20);
}
