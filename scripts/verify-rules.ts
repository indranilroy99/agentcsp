import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";
import { RuleSchema, type Rule } from "../packages/core/src/schemas/index.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const rulesRoot = path.join(repoRoot, "rules", "core");
const ruleIdPattern = /^AGENTCSP-[A-Z0-9]+-\d{3}$/u;
const failures: string[] = [];
const seenRuleIds = new Map<string, string>();

const rulePaths = await collectRulePaths(rulesRoot);
if (rulePaths.length === 0) {
  failures.push("rules/core must contain at least one built-in rule");
}

for (const rulePath of rulePaths) {
  const relativeRulePath = path.relative(repoRoot, rulePath);
  let rule: Rule;
  try {
    rule = RuleSchema.parse(YAML.parse(await fs.readFile(rulePath, "utf8")));
  } catch (error) {
    failures.push(`${relativeRulePath}: failed schema validation: ${formatError(error)}`);
    continue;
  }

  verifyRule(relativeRulePath, rule);
}

if (failures.length > 0) {
  throw new Error(`Rule pack verification failed:\n${failures.map((failure) => `- ${failure}`).join("\n")}`);
}

console.log(`Rule pack verified: ${rulePaths.length} built-in rules`);

async function collectRulePaths(directory: string): Promise<string[]> {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const paths: string[] = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      paths.push(...(await collectRulePaths(absolutePath)));
      continue;
    }
    if (entry.isFile() && (entry.name.endsWith(".yaml") || entry.name.endsWith(".yml"))) {
      paths.push(absolutePath);
    }
  }
  return paths.sort((left, right) => left.localeCompare(right));
}

function verifyRule(relativeRulePath: string, rule: Rule): void {
  if (!ruleIdPattern.test(rule.id)) {
    failures.push(`${relativeRulePath}: rule id must match ${ruleIdPattern.source}`);
  }

  const existingPath = seenRuleIds.get(rule.id);
  if (existingPath) {
    failures.push(`${relativeRulePath}: duplicates rule id ${rule.id} already used by ${existingPath}`);
  }
  seenRuleIds.set(rule.id, relativeRulePath);

  if (rule.name.trim().length < 10) {
    failures.push(`${relativeRulePath}: rule name must be descriptive`);
  }
  if (rule.description.trim().length < 50) {
    failures.push(`${relativeRulePath}: rule description must explain the security condition`);
  }
  if (rule.recommendation.text.trim().length < 40) {
    failures.push(`${relativeRulePath}: recommendation text must describe a concrete control`);
  }

  verifyMappings(relativeRulePath, rule);
  verifyMatch(relativeRulePath, rule);
}

function verifyMappings(relativeRulePath: string, rule: Rule): void {
  const mappingSets = [
    ["maps_to.owasp", rule.maps_to.owasp],
    ["maps_to.mitre_atlas", rule.maps_to.mitre_atlas],
    ["maps_to.nist_ai_rmf", rule.maps_to.nist_ai_rmf]
  ] as const;

  for (const [field, values] of mappingSets) {
    if (values.length === 0) {
      failures.push(`${relativeRulePath}: ${field} must include at least one mapping`);
      continue;
    }
    for (const value of values) {
      if (value.trim().length === 0) {
        failures.push(`${relativeRulePath}: ${field} must not include blank mappings`);
      }
    }
  }
}

function verifyMatch(relativeRulePath: string, rule: Rule): void {
  if (rule.match.where.length === 0) {
    failures.push(`${relativeRulePath}: match.where must include at least one condition`);
  }

  rule.match.where.forEach((condition, index) => {
    const conditionPath = `match.where[${index}]`;
    if (condition.field.trim().length === 0 || /\s/u.test(condition.field)) {
      failures.push(`${relativeRulePath}: ${conditionPath}.field must be a non-empty dotted field path`);
    }

    if (condition.op !== "exists" && condition.value === undefined) {
      failures.push(`${relativeRulePath}: ${conditionPath}.value is required for ${condition.op}`);
    }

    if (["contains_any", "in"].includes(condition.op)) {
      if (!Array.isArray(condition.value) || condition.value.length === 0) {
        failures.push(`${relativeRulePath}: ${conditionPath}.value must be a non-empty array for ${condition.op}`);
      }
    }

    if (["gt", "gte", "lt", "lte"].includes(condition.op) && typeof condition.value !== "number") {
      failures.push(`${relativeRulePath}: ${conditionPath}.value must be numeric for ${condition.op}`);
    }
  });
}

function formatError(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}
