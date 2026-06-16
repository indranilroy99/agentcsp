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
    expect(summary.active_by_risk_driver.find((item) => item.driver === "side_effect")?.count).toBe(
      triageTopListLimit + 3
    );
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

    expect(summary.active_by_risk_driver).toEqual([
      {
        driver: "untrusted_to_privileged",
        count: 1,
        max_risk_score: 95,
        by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
      },
      {
        driver: "secret_exposure",
        count: 1,
        max_risk_score: 95,
        by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
      },
      {
        driver: "external_reach",
        count: 1,
        max_risk_score: 95,
        by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
      },
      {
        driver: "irreversible_action",
        count: 1,
        max_risk_score: 95,
        by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
      },
      {
        driver: "side_effect",
        count: 1,
        max_risk_score: 95,
        by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
      },
      {
        driver: "sensitive_data",
        count: 1,
        max_risk_score: 95,
        by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
      },
      {
        driver: "credential_data",
        count: 1,
        max_risk_score: 95,
        by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
      },
      {
        driver: "pii_data",
        count: 1,
        max_risk_score: 95,
        by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
      },
      {
        driver: "execute_action",
        count: 1,
        max_risk_score: 95,
        by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
      },
      {
        driver: "write_action",
        count: 1,
        max_risk_score: 95,
        by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }
      }
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
