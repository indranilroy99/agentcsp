import { describe, expect, it } from "vitest";
import { toFindingArtifact } from "../src/manifest/artifact.js";
import type { Finding } from "../src/schemas/index.js";

describe("compact finding artifacts", () => {
  it("references normalized objects and evidence without embedding duplicates", () => {
    const finding = sampleFinding();
    const artifact = toFindingArtifact(finding);

    expect(artifact.matched_object_ref).toEqual({
      id: "tool_1",
      type: "tool",
      name: "deploy",
      path: "tools.json",
      trust_level: "project"
    });
    expect(artifact.evidence_refs).toEqual(["evidence_1"]);
    expect(artifact).not.toHaveProperty("matched_object");
    expect(artifact).not.toHaveProperty("evidence");
    expect(JSON.stringify(artifact)).not.toContain("parsed_tool_schema");
  });
});

function sampleFinding(): Finding {
  return {
    id: "finding_1",
    rule_id: "AGENTCSP-TEST-001",
    name: "Test finding",
    category: "test",
    severity: "high",
    confidence: "high",
    confidence_rationale: ["structured test evidence"],
    origin: "built_in",
    maturity: "stable",
    disposition: "advisory",
    suppressibility: "policy",
    support_tier: "structured",
    matched_object: {
      id: "tool_1",
      type: "tool",
      name: "deploy",
      path: "tools.json",
      trust_level: "project",
      data_classes: ["internal"],
      actions: ["execute"],
      side_effect: true,
      reversible: false,
      external_reach: false,
      secret_exposure: false,
      untrusted_to_privileged: false,
      evidence: [],
      metadata: { parsed_tool_schema: true, repeated_payload: "must not be embedded" }
    },
    file_path: "tools.json",
    reason: "A privileged tool is callable.",
    trust_boundary_crossed: false,
    data_classes: ["internal"],
    recommended_control: "require_approval",
    risk: {
      trust_level: "project",
      data_classes: ["internal"],
      actions: ["execute"],
      side_effect: true,
      reversible: false,
      external_reach: false,
      secret_exposure: false,
      untrusted_to_privileged: false,
      score: 70,
      rationale: []
    },
    risk_summary: {
      drivers: ["execute_action", "irreversible_action"],
      impact: "Privileged execution is possible.",
      control_objective: "Require approval.",
      analyst_summary: []
    },
    maps_to: { owasp: [], mitre_atlas: [], nist_ai_rmf: [] },
    evidence: [
      {
        id: "evidence_1",
        object_id: "tool_1",
        file_path: "tools.json",
        field_paths: [],
        classifications: [],
        snippet: "[redacted by default]",
        redacted: true,
        reason: "Structured tool evidence."
      }
    ]
  };
}
