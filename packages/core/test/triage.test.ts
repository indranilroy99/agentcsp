import { describe, expect, it } from "vitest";
import { buildTriageSummary, triageTopListLimit } from "../src/reports/triage.js";
import type { Finding } from "../src/schemas/index.js";

describe("triage summary", () => {
  it("reports top-list truncation without losing exact active counts", () => {
    const findings = [
      ...Array.from({ length: triageTopListLimit + 3 }, (_, index) =>
        finding(`finding_${index.toString().padStart(3, "0")}`, `RULE-${index.toString().padStart(3, "0")}`)
      ),
      {
        ...finding("finding_suppressed", "RULE-SUPPRESSED"),
        suppression: { status: "active" }
      } as Finding
    ];

    const summary = buildTriageSummary(findings);

    expect(summary).toMatchObject({
      total_findings: triageTopListLimit + 4,
      active_findings: triageTopListLimit + 3,
      suppressed_findings: 1,
      top_active_limit: triageTopListLimit,
      top_active_rules_total: triageTopListLimit + 3,
      top_active_rules_truncated: true,
      top_active_risks_total: triageTopListLimit + 3,
      top_active_risks_truncated: true
    });
    expect(summary.top_active_rules).toHaveLength(triageTopListLimit);
    expect(summary.top_active_risks).toHaveLength(triageTopListLimit);
    expect(summary.top_active_rules.some((rule) => rule.rule_id === "RULE-SUPPRESSED")).toBe(false);
  });

  it("includes risk factors in top active risk summaries", () => {
    const summary = buildTriageSummary([
      {
        ...finding("finding_critical", "RULE-CRITICAL"),
        severity: "critical",
        data_classes: ["credential", "pii"],
        trust_boundary_crossed: true,
        risk: {
          trust_level: "untrusted",
          data_classes: ["credential", "pii"],
          actions: ["execute", "send"],
          side_effect: true,
          reversible: false,
          external_reach: true,
          secret_exposure: true,
          untrusted_to_privileged: true,
          score: 95,
          rationale: []
        }
      } as Finding
    ]);

    expect(summary.top_active_risks[0]).toMatchObject({
      finding_id: "finding_critical",
      trust_level: "untrusted",
      data_classes: ["credential", "pii"],
      actions: ["execute", "send"],
      external_reach: true,
      secret_exposure: true,
      untrusted_to_privileged: true,
      trust_boundary_crossed: true
    });
  });
});

function finding(id: string, ruleId: string): Finding {
  return {
    id,
    rule_id: ruleId,
    name: ruleId,
    category: "agent_authority",
    severity: "high",
    confidence: "high",
    matched_object: {
      id: `object_${id}`,
      type: "tool",
      name: id,
      trust_level: "project",
      data_classes: [],
      actions: ["call"],
      side_effect: true,
      reversible: true,
      external_reach: false,
      secret_exposure: false,
      untrusted_to_privileged: false,
      evidence: [],
      metadata: {}
    },
    file_path: `${id}.yaml`,
    data_classes: [],
    trust_boundary_crossed: false,
    recommended_control: "require_approval",
    risk: {
      trust_level: "project",
      data_classes: [],
      actions: ["call"],
      side_effect: true,
      reversible: true,
      external_reach: false,
      secret_exposure: false,
      untrusted_to_privileged: false,
      score: 80,
      rationale: []
    }
  } as Finding;
}
