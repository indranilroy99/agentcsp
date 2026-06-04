import type { Finding, SurfaceObject } from "../schemas/index.js";

export function sortObjects<T extends SurfaceObject>(objects: T[]): T[] {
  return [...objects].sort((a, b) => {
    const pathCompare = a.path.localeCompare(b.path);
    if (pathCompare !== 0) return pathCompare;
    const typeCompare = a.type.localeCompare(b.type);
    if (typeCompare !== 0) return typeCompare;
    return a.name.localeCompare(b.name);
  });
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const severityCompare = severityOrder[a.severity] - severityOrder[b.severity];
    if (severityCompare !== 0) return severityCompare;
    const confidenceOrder = { very_high: 0, high: 1, medium: 2, low: 3 };
    const confidenceCompare = confidenceOrder[a.confidence] - confidenceOrder[b.confidence];
    if (confidenceCompare !== 0) return confidenceCompare;
    return a.id.localeCompare(b.id);
  });
}
