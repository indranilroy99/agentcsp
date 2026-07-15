import { loadBuiltInRuleset, type Rule, type Ruleset } from "@agentcsp/core";
import { configurationError } from "../errors.js";

export async function runRulesList(options: { ruleset?: string; json?: boolean }): Promise<void> {
  const ruleset = parseRuleset(options.ruleset);
  const result = await loadBuiltInRuleset(ruleset);
  if (options.json) {
    console.log(
      JSON.stringify({
        type: "agentcsp_rule_list",
        ruleset,
        count: result.rules.length,
        pack: result.manifest,
        rules: result.rules.map(ruleSummary)
      })
    );
    return;
  }
  console.log(`AgentCSP ${ruleset} rules (${result.rules.length})`);
  for (const rule of result.rules) {
    console.log(
      `${rule.id}\t${rule.severity}\t${rule.maturity ?? "experimental"}\t${rule.support_tier ?? "heuristic"}\t${rule.name}`
    );
  }
}

export async function runRulesExplain(ruleId: string, options: { json?: boolean }): Promise<void> {
  const result = await loadBuiltInRuleset("extended");
  const rule = result.rules.find((candidate) => candidate.id === ruleId);
  if (!rule) {
    throw configurationError(
      `Rule "${ruleId}" was not found in the built-in catalog.`,
      "Run agentcsp rules list --ruleset extended and use an exact rule ID."
    );
  }
  if (options.json) {
    console.log(JSON.stringify({ type: "agentcsp_rule", rule }));
    return;
  }
  console.log(`${rule.id}: ${rule.name}`);
  console.log(`Severity: ${rule.severity}`);
  console.log(`Maturity: ${rule.maturity ?? "experimental"}`);
  console.log(`Disposition: ${rule.disposition ?? "advisory"}`);
  console.log(`Support: ${rule.support_tier ?? "heuristic"}`);
  console.log(`Category: ${rule.category}`);
  console.log(`Description: ${rule.description}`);
  console.log(`Recommended control: ${rule.recommendation.control}`);
  console.log(`Recommendation: ${rule.recommendation.text}`);
}

function parseRuleset(value: string | undefined): Ruleset {
  if (value === undefined || value === "recommended" || value === "extended") return value ?? "recommended";
  throw configurationError("Unsupported ruleset.", "Use --ruleset recommended or --ruleset extended.");
}

function ruleSummary(rule: Rule): Record<string, unknown> {
  return {
    id: rule.id,
    name: rule.name,
    category: rule.category,
    severity: rule.severity,
    maturity: rule.maturity ?? "experimental",
    disposition: rule.disposition ?? "advisory",
    suppressibility: rule.suppressibility ?? "policy",
    support_tier: rule.support_tier ?? "heuristic"
  };
}
