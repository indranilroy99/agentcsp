import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AgentCspError } from "../errors.js";
import {
  RulePackManifestSchema,
  type Rule,
  type RulePackManifest,
  type Ruleset
} from "../schemas/index.js";
import { loadRules } from "./engine.js";

const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));

export async function loadBuiltInRuleCatalog(): Promise<Rule[]> {
  return loadRules(await builtInRulesDirectoryPath());
}

export async function loadBuiltInRuleset(ruleset: Ruleset): Promise<{
  rules: Rule[];
  manifest?: RulePackManifest;
}> {
  const rules = await loadBuiltInRuleCatalog();
  if (ruleset === "extended") return { rules };
  const manifest = await loadRecommendedPackManifest();
  const rulesById = new Map(rules.map((rule) => [rule.id, rule]));
  const selected = manifest.rule_ids.map((ruleId) => rulesById.get(ruleId)).filter((rule): rule is Rule => Boolean(rule));
  const missing = manifest.rule_ids.filter((ruleId) => !rulesById.has(ruleId));
  if (missing.length > 0) {
    throw new AgentCspError({
      code: "AGENTCSP-E3003",
      kind: "integrity",
      problem: `Recommended rule pack references ${missing.length} missing built-in rule(s).`,
      fix: "Reinstall the pinned AgentCSP package and verify packaged rule integrity.",
      help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/rules.md#pack-integrity"
    });
  }
  return { rules: selected.sort((a, b) => a.id.localeCompare(b.id)), manifest };
}

export async function loadRecommendedPackManifest(): Promise<RulePackManifest> {
  const rulesDirectory = await builtInRulesDirectoryPath();
  const manifestPath = path.join(rulesDirectory, "packs", "recommended.json");
  try {
    return RulePackManifestSchema.parse(JSON.parse(await fs.readFile(manifestPath, "utf8")));
  } catch (error) {
    throw new AgentCspError({
      code: "AGENTCSP-E3004",
      kind: "integrity",
      problem: "Recommended rule pack manifest is missing or invalid.",
      fix: "Reinstall the pinned AgentCSP package and verify packaged rule integrity.",
      help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/rules.md#pack-integrity",
      cause: error
    });
  }
}

export async function builtInRulesDirectoryPath(): Promise<string> {
  return firstExistingDirectory([
    path.resolve(moduleDirectory, "../builtin-rules"),
    path.resolve(moduleDirectory, "../../rules"),
    path.resolve(moduleDirectory, "../../../../rules")
  ]);
}

async function firstExistingDirectory(candidates: string[]): Promise<string> {
  for (const candidate of candidates) {
    try {
      const stats = await fs.stat(candidate);
      if (stats.isDirectory() && (await hasRuleFiles(candidate))) return candidate;
    } catch {
      continue;
    }
  }
  throw new AgentCspError({
    code: "AGENTCSP-E3005",
    kind: "integrity",
    problem: "No packaged built-in rules directory could be verified.",
    fix: "Reinstall the pinned AgentCSP package and verify the package contents.",
    help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/rules.md#pack-integrity"
  });
}

async function hasRuleFiles(directory: string): Promise<boolean> {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory() && (await hasRuleFiles(absolutePath))) return true;
    if (entry.isFile() && (entry.name.endsWith(".yaml") || entry.name.endsWith(".yml"))) return true;
  }
  return false;
}
