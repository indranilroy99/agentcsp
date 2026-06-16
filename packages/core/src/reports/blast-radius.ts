import type { AttackPath, Finding, GraphEdge, StaticBlastRadiusSummary, SurfaceObject } from "../schemas/index.js";
import { allManifestObjects } from "../manifest/build.js";
import type { DetectedSurfaces } from "../scanner/detect.js";
import { highestSeverity } from "../risk/score.js";

export const blastRadiusPreviewLimit = 20;

export function buildStaticBlastRadiusSummary(
  surfaces: DetectedSurfaces,
  findings: Finding[],
  relationships: GraphEdge[] = [],
  attackPaths: AttackPath[] = []
): StaticBlastRadiusSummary {
  const objects = allManifestObjects(surfaces);
  const allHighRiskObjects = objects.filter(isHighRiskObject);
  const highRiskObjects = allHighRiskObjects.slice(0, blastRadiusPreviewLimit);
  const externalReachObjects = objects.filter((object) => object.external_reach);
  const allRecommendedControls = summarizeControls(findings);
  return {
    title: "Static Blast-Radius Summary",
    read_paths: countByAction(objects, "read"),
    write_paths: countByAction(objects, "write"),
    execute_paths: countByAction(objects, "execute"),
    external_reach_paths: externalReachObjects.length,
    secret_reference_paths: objects.filter((object) => object.secret_exposure || object.data_classes.includes("credential")).length,
    sensitive_data_external_reach_paths: externalReachObjects.filter(hasSensitiveDataClass).length,
    pii_external_reach_paths: externalReachObjects.filter((object) => object.data_classes.includes("pii")).length,
    credential_external_reach_paths: externalReachObjects.filter(hasCredentialDataClass).length,
    sensitive_data_attack_paths: attackPaths.filter((attackPath) => hasSensitiveDataClass(attackPath.risk)).length,
    pii_attack_paths: attackPaths.filter((attackPath) => attackPath.risk.data_classes.includes("pii")).length,
    credential_attack_paths: attackPaths.filter((attackPath) => hasCredentialDataClass(attackPath.risk)).length,
    memory_surfaces: surfaces.memory.length,
    rag_surfaces: surfaces.rag_sources.length,
    relationships: relationships.length,
    attack_paths: attackPaths.length,
    critical_attack_paths: attackPaths.filter((attackPath) => attackPath.severity === "critical").length,
    active_suppressions: findings.filter((finding) => finding.suppression?.status === "active").length,
    expired_suppressions: findings.filter((finding) => finding.suppression?.status === "expired").length,
    highest_severity: highestSeverity(findings),
    preview_limit: blastRadiusPreviewLimit,
    high_risk_objects_total: allHighRiskObjects.length,
    high_risk_objects_truncated: allHighRiskObjects.length > highRiskObjects.length,
    high_risk_objects: highRiskObjects,
    recommended_controls_total: allRecommendedControls.length,
    recommended_controls_truncated: allRecommendedControls.length > blastRadiusPreviewLimit,
    recommended_controls: allRecommendedControls.slice(0, blastRadiusPreviewLimit)
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

function hasSensitiveDataClass(object: { data_classes: string[] }): boolean {
  return object.data_classes.some((dataClass) => ["credential", "secret", "pii", "confidential"].includes(dataClass));
}

function hasCredentialDataClass(object: { data_classes: string[] }): boolean {
  return object.data_classes.some((dataClass) => dataClass === "credential" || dataClass === "secret");
}

function summarizeControls(findings: Finding[]): string[] {
  const controls = new Set<string>();
  for (const finding of findings) {
    if (finding.suppression?.status === "active") continue;
    controls.add(`Recommended control: ${finding.recommended_control.replaceAll("_", " ")} for ${finding.file_path}`);
  }
  return [...controls].sort((a, b) => a.localeCompare(b));
}
