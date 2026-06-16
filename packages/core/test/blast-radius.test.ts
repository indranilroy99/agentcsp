import { describe, expect, it } from "vitest";
import { buildStaticBlastRadiusSummary, blastRadiusPreviewLimit } from "../src/reports/blast-radius.js";
import { emptyDetectedSurfaces } from "../src/scanner/detect.js";
import type { Finding, SurfaceObject } from "../src/schemas/index.js";

describe("static blast-radius summary", () => {
  it("reports truncation metadata for bounded high-risk object and control previews", () => {
    const surfaces = emptyDetectedSurfaces();
    surfaces.tools = Array.from({ length: blastRadiusPreviewLimit + 4 }, (_, index) =>
      surface(`tool_${index.toString().padStart(3, "0")}`)
    );
    const findings = Array.from({ length: blastRadiusPreviewLimit + 3 }, (_, index) =>
      finding(`finding_${index.toString().padStart(3, "0")}`, `control-${index.toString().padStart(3, "0")}.yaml`)
    );

    const summary = buildStaticBlastRadiusSummary(surfaces, findings);

    expect(summary).toMatchObject({
      preview_limit: blastRadiusPreviewLimit,
      high_risk_objects_total: blastRadiusPreviewLimit + 4,
      high_risk_objects_truncated: true,
      recommended_controls_total: blastRadiusPreviewLimit + 3,
      recommended_controls_truncated: true
    });
    expect(summary.high_risk_objects).toHaveLength(blastRadiusPreviewLimit);
    expect(summary.recommended_controls).toHaveLength(blastRadiusPreviewLimit);
    expect(summary.high_risk_objects[0]?.name).toBe("tool_000");
    expect(summary.recommended_controls[0]).toContain("control-000.yaml");
  });
});

function surface(name: string): SurfaceObject {
  return {
    id: name,
    type: "tool",
    name,
    path: `${name}.yaml`,
    trust_level: "project",
    data_classes: ["credential"],
    actions: ["execute"],
    side_effect: true,
    reversible: false,
    external_reach: true,
    secret_exposure: true,
    untrusted_to_privileged: true,
    evidence: [],
    metadata: {}
  };
}

function finding(id: string, filePath: string): Finding {
  return {
    id,
    rule_id: `RULE-${id}`,
    name: id,
    category: "agent_authority",
    severity: "high",
    confidence: "high",
    file_path: filePath,
    recommended_control: "require_approval"
  } as Finding;
}
