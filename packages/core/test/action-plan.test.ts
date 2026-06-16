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
    expect(plan.actions.every((action) => action.validation_steps.length > 0)).toBe(true);
    expect(plan.actions.every((action) => action.remediation_steps.length > 0)).toBe(true);
    expect(
      plan.actions.find((action) => action.related_finding_ids[0] === "finding_secret")?.validation_steps
    ).toContain("Verify that secret or credential material is not exposed to model-visible, external, or persistent channels.");
    expect(plan.actions.every((action) => action.response_tier === "urgent")).toBe(true);
    expect(plan.actions.find((action) => action.related_finding_ids[0] === "finding_secret")?.risk_drivers).toEqual([
      "secret_exposure",
      "side_effect",
      "sensitive_data",
      "credential_data"
    ]);
    expect(plan.urgent_actions).toBe(6);
    expect(plan.immediate_actions).toBe(0);
    expect(plan.by_owner.every((owner) => owner.urgent_actions === 1)).toBe(true);
    expect(plan.by_owner.every((owner) => owner.immediate_actions === 0)).toBe(true);
    expect(plan.by_owner.every((owner) => owner.top_action_id_limit === 5)).toBe(true);
    expect(plan.by_owner.every((owner) => owner.top_action_ids.length === 1)).toBe(true);
    expect(plan.by_owner.every((owner) => owner.top_action_ids_truncated === false)).toBe(true);
    expect(plan.by_owner.every((owner) => owner.by_recommended_control.length > 0)).toBe(true);
    expect(plan.by_owner.every((owner) => owner.by_surface_type.length > 0)).toBe(true);
    expect(plan.by_owner.every((owner) => owner.by_risk_driver.length > 0)).toBe(true);
  });

  it("assigns deterministic response tiers from severity, risk, and controls", () => {
    const plan = buildActionPlan([
      finding({ id: "critical", category: "runtime", type: "runtime_config", severity: "critical" }),
      finding({ id: "quarantine", category: "memory", type: "memory", control: "quarantine", severity: "medium" }),
      finding({ id: "urgent", category: "mcp", type: "mcp_server", severity: "high" }),
      finding({ id: "scheduled", category: "prompt", type: "prompt", severity: "medium", riskScore: 55 }),
      finding({ id: "backlog", category: "instruction", type: "instruction", severity: "low", riskScore: 30 })
    ]);

    const tiersById = Object.fromEntries(plan.actions.map((action) => [action.related_finding_ids[0], action.response_tier]));
    expect(tiersById).toMatchObject({
      critical: "immediate",
      quarantine: "immediate",
      urgent: "urgent",
      scheduled: "scheduled",
      backlog: "backlog"
    });
    expect(plan.immediate_actions).toBe(2);
    expect(plan.urgent_actions).toBe(1);
    expect(plan.scheduled_actions).toBe(1);
    expect(plan.backlog_actions).toBe(1);
    expect(plan.actions.every((action) => action.response_reason.length > 0)).toBe(true);
    expect(plan.actions.find((action) => action.related_finding_ids[0] === "quarantine")?.remediation_steps).toContain(
      "Temporarily isolate the surface from agent execution until ownership and trust boundaries are reviewed."
    );
    expect(
      Object.values(
        plan.by_owner.reduce<Record<string, number>>((counts, owner) => {
          counts.immediate += owner.immediate_actions;
          counts.urgent += owner.urgent_actions;
          counts.scheduled += owner.scheduled_actions;
          counts.backlog += owner.backlog_actions;
          return counts;
        }, { immediate: 0, urgent: 0, scheduled: 0, backlog: 0 })
      )
    ).toEqual([2, 1, 1, 1]);
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
      omitted_by_severity: { critical: 0, high: 10, medium: 0, low: 0, info: 0 },
      omitted_highest_severity: "high",
      omitted_max_risk_score: 80,
      truncated: true
    });
  });

  it("summarizes owner workloads by control, surface, risk driver, and bounded action IDs", () => {
    const findings = Array.from({ length: 7 }, (_, index) =>
      finding({
        id: `mcp_${index}`,
        category: "mcp_authority",
        type: index < 4 ? "mcp_server" : "tool",
        control: index < 3 ? "quarantine" : "require_approval"
      })
    );
    const plan = buildActionPlan(findings);
    const owner = plan.by_owner.find((item) => item.owner_hint === "agent-platform");

    expect(owner).toMatchObject({
      count: 7,
      top_action_id_limit: 5,
      top_action_ids_truncated: true
    });
    expect(owner?.top_action_ids).toHaveLength(5);
    expect(owner?.by_recommended_control).toEqual([
      { control: "require_approval", count: 4 },
      { control: "quarantine", count: 3 }
    ]);
    expect(owner?.by_surface_type).toEqual([
      { surface_type: "mcp_server", count: 4 },
      { surface_type: "tool", count: 3 }
    ]);
    expect(owner?.by_risk_driver).toEqual([{ driver: "side_effect", count: 7 }]);
  });
});

function finding(input: {
  id: string;
  category: string;
  type: SurfaceType;
  dataClasses?: Finding["data_classes"];
  severity?: Finding["severity"];
  control?: Finding["recommended_control"];
  riskScore?: number;
}): Finding {
  return {
    id: input.id,
    rule_id: `RULE-${input.id}`,
    name: input.id,
    category: input.category,
    severity: input.severity ?? "high",
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
    recommended_control: input.control ?? "require_approval",
    risk: {
      trust_level: "project",
      data_classes: input.dataClasses ?? [],
      actions: ["call"],
      side_effect: true,
      reversible: true,
      external_reach: false,
      secret_exposure: input.dataClasses?.includes("credential") ?? false,
      untrusted_to_privileged: false,
      score: input.riskScore ?? 80,
      rationale: []
    },
    risk_summary: {
      primary_driver: input.dataClasses?.includes("credential") ? "secret_exposure" : "side_effect",
      drivers: input.dataClasses?.includes("credential") ? ["secret_exposure", "side_effect"] : ["side_effect"],
      impact: "Rule matched an agent security condition that should be reviewed.",
      control_objective: "require explicit human or policy approval before the action proceeds",
      analyst_summary: ["Synthetic test finding."]
    },
    maps_to: { owasp: [], mitre_atlas: [], nist_ai_rmf: [] },
    evidence: []
  };
}
