import { describe, expect, it } from "vitest";
import { buildActionPlan } from "../src/reports/action-plan.js";
import type { Finding, SurfaceType } from "../src/schemas/index.js";

describe("action plan owner routing", () => {
  it("routes remediation actions to deterministic owner hints", () => {
    const plan = buildActionPlan([
      finding({ id: "finding_secret", category: "secret_exposure", type: "tool", dataClasses: ["credential"] }),
      finding({ id: "finding_ci", category: "automation", type: "ci_cd" }),
      finding({ id: "finding_rag", category: "rag_ingestion", type: "rag_source", dataClasses: ["confidential"] }),
      finding({ id: "finding_mcp", category: "mcp_authority", type: "mcp_server" }),
      finding({ id: "finding_prompt", category: "prompt_injection", type: "prompt" }),
      finding({ id: "finding_runtime", category: "runtime_posture", type: "runtime_config" })
    ]);

    expect(plan.actions.map((action) => action.owner_hint).sort()).toEqual([
      "agent-engineering",
      "agent-platform",
      "data-and-knowledge",
      "identity-and-secrets",
      "platform-ci",
      "runtime-platform"
    ]);
    expect(plan.by_owner.map((owner) => owner.owner_hint).sort()).toEqual([
      "agent-engineering",
      "agent-platform",
      "data-and-knowledge",
      "identity-and-secrets",
      "platform-ci",
      "runtime-platform"
    ]);
    expect(plan.actions.every((action) => action.owner_reason.length > 0)).toBe(true);
  });

  it("reports when the bounded action queue omits lower-priority findings", () => {
    const findings = Array.from({ length: 15 }, (_, index) =>
      finding({ id: `finding_${index.toString().padStart(2, "0")}`, category: "mcp_authority", type: "mcp_server" })
    );
    const plan = buildActionPlan(findings, 5);

    expect(plan).toMatchObject({
      total_actions: 5,
      total_active_findings_considered: 15,
      max_actions: 5,
      omitted_actions: 10,
      truncated: true
    });
  });
});

function finding(input: {
  id: string;
  category: string;
  type: SurfaceType;
  dataClasses?: Finding["data_classes"];
}): Finding {
  return {
    id: input.id,
    rule_id: `RULE-${input.id}`,
    name: input.id,
    category: input.category,
    severity: "high",
    confidence: "high",
    confidence_rationale: [],
    matched_object: {
      id: `object_${input.id}`,
      type: input.type,
      name: input.id,
      path: `${input.id}.yaml`,
      trust_level: "project",
      data_classes: input.dataClasses ?? [],
      actions: ["call"],
      side_effect: true,
      reversible: true,
      external_reach: false,
      secret_exposure: input.dataClasses?.includes("credential") ?? false,
      untrusted_to_privileged: false,
      evidence: [],
      metadata: {}
    },
    file_path: `${input.id}.yaml`,
    reason: input.id,
    trust_boundary_crossed: false,
    data_classes: input.dataClasses ?? [],
    recommended_control: "require_approval",
    risk: {
      trust_level: "project",
      data_classes: input.dataClasses ?? [],
      actions: ["call"],
      side_effect: true,
      reversible: true,
      external_reach: false,
      secret_exposure: input.dataClasses?.includes("credential") ?? false,
      untrusted_to_privileged: false,
      score: 80,
      rationale: []
    },
    maps_to: { owasp: [], mitre_atlas: [], nist_ai_rmf: [] },
    evidence: []
  };
}
