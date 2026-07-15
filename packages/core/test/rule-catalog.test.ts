import { describe, expect, it } from "vitest";
import { loadBuiltInRuleset, loadRecommendedPackManifest } from "../src/rules/catalog.js";

describe("built-in rule catalog", () => {
  it("ships a bounded recommended pack with explicit evidence maturity", async () => {
    const manifest = await loadRecommendedPackManifest();
    const recommended = await loadBuiltInRuleset("recommended");

    expect(manifest.id).toBe("agentcsp-recommended");
    expect(recommended.rules).toHaveLength(17);
    expect(recommended.rules.map((rule) => rule.id)).toEqual([...manifest.rule_ids].sort((a, b) => a.localeCompare(b)));
    expect(recommended.rules.every((rule) => rule.maturity === "stable")).toBe(true);
    expect(recommended.rules.every((rule) => rule.support_tier === "structured")).toBe(true);
    expect(recommended.rules.every((rule) => rule.disposition === "advisory")).toBe(true);
  });

  it("keeps the full research catalog behind the extended ruleset", async () => {
    const extended = await loadBuiltInRuleset("extended");
    expect(extended.rules.length).toBeGreaterThan(300);
    expect(extended.manifest).toBeUndefined();
  });
});
