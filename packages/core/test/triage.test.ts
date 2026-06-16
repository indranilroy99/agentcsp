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
      name: id
    },
    file_path: `${id}.yaml`,
    recommended_control: "require_approval",
    risk: {
      score: 80
    }
  } as Finding;
}
