import { describe, expect, it } from "vitest";
import { buildInventorySummary } from "../src/reports/inventory.js";
import { emptyDetectedSurfaces } from "../src/scanner/detect.js";
import type { SurfaceObject } from "../src/schemas/index.js";

describe("inventory summary", () => {
  it("summarizes platform-ready surface, trust, data, action, and authority counts", () => {
    const surfaces = emptyDetectedSurfaces();
    surfaces.tools = [
      surface("deploy-tool", {
        trust_level: "project",
        data_classes: ["credential", "secret"],
        actions: ["execute", "write"],
        side_effect: true,
        reversible: false,
        external_reach: true,
        secret_exposure: true,
        untrusted_to_privileged: true
      }),
      surface("read-tool", {
        trust_level: "trusted",
        data_classes: ["internal"],
        actions: ["read"]
      })
    ];
    surfaces.rag_sources = [
      surface("customer-rag", {
        type: "rag_source",
        trust_level: "third_party",
        data_classes: ["pii", "confidential"],
        actions: ["read"],
        external_reach: true
      })
    ];

    const summary = buildInventorySummary(surfaces);

    expect(summary).toMatchObject({
      total_objects: 3,
      side_effect_objects: 1,
      irreversible_objects: 1,
      external_reach_objects: 2,
      secret_exposure_objects: 1,
      untrusted_to_privileged_objects: 1,
      credential_or_secret_objects: 1,
      pii_objects: 1,
      high_authority_objects: 2
    });
    expect(summary.by_surface_type).toEqual([
      { surface_type: "tool", count: 2 },
      { surface_type: "rag_source", count: 1 }
    ]);
    expect(summary.by_trust_level).toEqual([
      { trust_level: "project", count: 1 },
      { trust_level: "third_party", count: 1 },
      { trust_level: "trusted", count: 1 }
    ]);
    expect(summary.by_data_class).toEqual([
      { data_class: "confidential", count: 1 },
      { data_class: "credential", count: 1 },
      { data_class: "internal", count: 1 },
      { data_class: "pii", count: 1 },
      { data_class: "secret", count: 1 }
    ]);
    expect(summary.by_action).toEqual([
      { action: "read", count: 2 },
      { action: "execute", count: 1 },
      { action: "write", count: 1 }
    ]);
  });
});

function surface(name: string, overrides: Partial<SurfaceObject> = {}): SurfaceObject {
  return {
    id: name,
    type: "tool",
    name,
    path: `${name}.yaml`,
    trust_level: "unknown",
    data_classes: [],
    actions: [],
    side_effect: false,
    reversible: true,
    external_reach: false,
    secret_exposure: false,
    untrusted_to_privileged: false,
    evidence: [],
    metadata: {},
    ...overrides
  };
}
