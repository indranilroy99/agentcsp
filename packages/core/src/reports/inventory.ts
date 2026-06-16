import type {
  ActionType,
  DataClass,
  InventorySummary,
  SurfaceObject,
  SurfaceType,
  TrustLevel
} from "../schemas/index.js";
import { allManifestObjects } from "../manifest/build.js";
import type { DetectedSurfaces } from "../scanner/detect.js";

export function buildInventorySummary(surfaces: DetectedSurfaces): InventorySummary {
  const objects = allManifestObjects(surfaces);
  return {
    title: "AgentCSP Inventory Summary",
    total_objects: objects.length,
    by_surface_type: countSurfaceTypes(objects),
    by_trust_level: countTrustLevels(objects),
    by_data_class: countDataClasses(objects),
    by_action: countActions(objects),
    side_effect_objects: objects.filter((object) => object.side_effect).length,
    irreversible_objects: objects.filter((object) => object.reversible === false).length,
    external_reach_objects: objects.filter((object) => object.external_reach).length,
    secret_exposure_objects: objects.filter((object) => object.secret_exposure).length,
    untrusted_to_privileged_objects: objects.filter((object) => object.untrusted_to_privileged).length,
    credential_or_secret_objects: objects.filter((object) =>
      object.data_classes.some((dataClass) => dataClass === "credential" || dataClass === "secret")
    ).length,
    pii_objects: objects.filter((object) => object.data_classes.includes("pii")).length,
    high_authority_objects: objects.filter(isHighAuthorityObject).length
  };
}

function isHighAuthorityObject(object: SurfaceObject): boolean {
  return (
    object.untrusted_to_privileged ||
    object.secret_exposure ||
    object.external_reach ||
    object.side_effect ||
    object.reversible === false ||
    object.actions.some((action) => ["approve", "delete", "execute", "publish", "send", "write"].includes(action))
  );
}

function countSurfaceTypes(objects: SurfaceObject[]): InventorySummary["by_surface_type"] {
  const counts = new Map<SurfaceType, number>();
  for (const object of objects) counts.set(object.type, (counts.get(object.type) ?? 0) + 1);
  return [...counts.entries()]
    .map(([surface_type, count]) => ({ surface_type, count }))
    .sort((left, right) => right.count - left.count || left.surface_type.localeCompare(right.surface_type));
}

function countTrustLevels(objects: SurfaceObject[]): InventorySummary["by_trust_level"] {
  const counts = new Map<TrustLevel, number>();
  for (const object of objects) counts.set(object.trust_level, (counts.get(object.trust_level) ?? 0) + 1);
  return [...counts.entries()]
    .map(([trust_level, count]) => ({ trust_level, count }))
    .sort((left, right) => right.count - left.count || left.trust_level.localeCompare(right.trust_level));
}

function countDataClasses(objects: SurfaceObject[]): InventorySummary["by_data_class"] {
  const counts = new Map<DataClass, number>();
  for (const object of objects) {
    for (const dataClass of new Set(object.data_classes)) counts.set(dataClass, (counts.get(dataClass) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([data_class, count]) => ({ data_class, count }))
    .sort((left, right) => right.count - left.count || left.data_class.localeCompare(right.data_class));
}

function countActions(objects: SurfaceObject[]): InventorySummary["by_action"] {
  const counts = new Map<ActionType, number>();
  for (const object of objects) {
    for (const action of new Set(object.actions)) counts.set(action, (counts.get(action) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([action, count]) => ({ action, count }))
    .sort((left, right) => right.count - left.count || left.action.localeCompare(right.action));
}
