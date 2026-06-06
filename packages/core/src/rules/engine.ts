import fs from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";
import {
  RuleSchema,
  type Confidence,
  type Finding,
  type RiskFactors,
  type Rule,
  type ScanDiagnostic,
  type SurfaceObject
} from "../schemas/index.js";
import { stableId } from "../utils/ids.js";
import { relativePath } from "../utils/paths.js";
import { allManifestObjects } from "../manifest/build.js";
import type { DetectedSurfaces } from "../scanner/detect.js";
import { scoreObjectRisk, severityFromScore } from "../risk/score.js";

export interface LoadedRules {
  rules: Rule[];
  diagnostics: ScanDiagnostic[];
  pathsByRuleId: Map<string, string>;
}

export async function loadRules(rulesDirectory: string): Promise<Rule[]> {
  const rules: Rule[] = [];
  const entries = await fs.readdir(rulesDirectory, { withFileTypes: true });
  const sorted = entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of sorted) {
    const absolute = path.join(rulesDirectory, entry.name);
    if (entry.isDirectory()) {
      rules.push(...(await loadRules(absolute)));
      continue;
    }
    if (!entry.isFile()) continue;
    if (!entry.name.endsWith(".yaml") && !entry.name.endsWith(".yml")) continue;
    const content = await fs.readFile(absolute, "utf8");
    rules.push(RuleSchema.parse(YAML.parse(content)));
  }
  return rules.sort((a, b) => a.id.localeCompare(b.id));
}

export async function loadRulesWithDiagnostics(rulesDirectory: string, rootPath: string): Promise<LoadedRules> {
  const result: LoadedRules = { rules: [], diagnostics: [], pathsByRuleId: new Map() };
  await loadRulesWithDiagnosticsInto(rulesDirectory, rootPath, result);
  result.rules.sort((a, b) => a.id.localeCompare(b.id));
  return result;
}

export function runRules(surfaces: DetectedSurfaces, rules: Rule[]): Finding[] {
  const objects = allManifestObjects(surfaces);
  const findings: Finding[] = [];
  for (const rule of rules) {
    for (const object of objects) {
      if (matchesRule(object, rule)) {
        const risk = scoreObjectRisk(object, rule);
        const severity = severityFromScore(risk.score, rule.severity);
        const confidence = confidenceForMatch(object, rule, risk);
        findings.push({
          id: stableId("finding", [rule.id, object.id]),
          rule_id: rule.id,
          name: rule.name,
          category: rule.category,
          severity,
          confidence: confidence.level,
          confidence_rationale: confidence.rationale,
          matched_object: object,
          file_path: object.path,
          reason: rule.description,
          trust_boundary_crossed: object.untrusted_to_privileged,
          data_classes: object.data_classes,
          recommended_control: rule.recommendation.control,
          risk,
          maps_to: rule.maps_to,
          evidence: object.evidence
        });
      }
    }
  }
  return findings.sort((a, b) => a.id.localeCompare(b.id));
}

async function loadRulesWithDiagnosticsInto(
  rulesDirectory: string,
  rootPath: string,
  result: LoadedRules
): Promise<void> {
  const entries = await fs.readdir(rulesDirectory, { withFileTypes: true });
  const sorted = entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of sorted) {
    const absolute = path.join(rulesDirectory, entry.name);
    if (entry.isDirectory()) {
      await loadRulesWithDiagnosticsInto(absolute, rootPath, result);
      continue;
    }
    if (!entry.isFile()) continue;
    if (!entry.name.endsWith(".yaml") && !entry.name.endsWith(".yml")) continue;

    try {
      const content = await fs.readFile(absolute, "utf8");
      const rule = RuleSchema.parse(YAML.parse(content));
      result.rules.push(rule);
      result.pathsByRuleId.set(rule.id, absolute);
    } catch (error) {
      const code = isValidationError(error) ? "RULE_SCHEMA_FAILED" : "RULE_PARSE_FAILED";
      result.diagnostics.push(
        ruleDiagnostic(rootPath, absolute, {
          code,
          reason:
            code === "RULE_SCHEMA_FAILED"
              ? "Project-local AgentCSP rule failed schema validation and was skipped. Raw content was redacted."
              : "Project-local AgentCSP rule could not be parsed as YAML and was skipped. Raw content was redacted."
        })
      );
    }
  }
}

export function ruleDiagnostic(
  rootPath: string,
  absolutePath: string,
  input: {
    code: string;
    reason: string;
  }
): ScanDiagnostic {
  const filePath = relativePath(rootPath, absolutePath);
  return {
    id: stableId("diagnostic", [input.code, filePath]),
    severity: "warning",
    code: input.code,
    file_path: filePath,
    parser: "rule",
    reason: input.reason,
    content_redacted: true
  };
}

function isValidationError(error: unknown): boolean {
  return Boolean(
    error &&
      typeof error === "object" &&
      "name" in error &&
      (error as { name?: string }).name === "ZodError"
  );
}

function confidenceForMatch(
  object: SurfaceObject,
  rule: Rule,
  risk: RiskFactors
): { level: Confidence; rationale: string[] } {
  let score = 0;
  const rationale: string[] = [];
  const conditionCount = rule.match.where.length;

  if (conditionCount >= 3) {
    score += 35;
    rationale.push(`correlated rule uses ${conditionCount} match conditions`);
  } else if (conditionCount === 2) {
    score += 25;
    rationale.push("rule combines two match conditions");
  } else if (conditionCount === 1) {
    score += 10;
    rationale.push("single-condition rule match");
  }

  if (rule.match.object_type) {
    score += 10;
    rationale.push(`rule is scoped to ${rule.match.object_type}`);
  }
  if (risk.secret_exposure || risk.data_classes.some((dataClass) => dataClass === "credential" || dataClass === "secret")) {
    score += 20;
    rationale.push("credential or secret signal present");
  }
  if (risk.external_reach) {
    score += 15;
    rationale.push("external reach present");
  }
  if (risk.actions.some((action) => ["approve", "delete", "execute", "publish", "send", "write"].includes(action))) {
    score += 15;
    rationale.push("privileged action present");
  }
  if (!risk.reversible || risk.side_effect) {
    score += 10;
    rationale.push("side effect or irreversible action present");
  }
  if (
    object.metadata.parsed_tool_schema === true ||
    Object.entries(object.metadata).some(([key, value]) => key.startsWith("parsed_") && key.endsWith("_config") && value === true)
  ) {
    score += 10;
    rationale.push("structured agent configuration parsed");
  }
  if (object.metadata.content_analyzed === true && object.metadata.content_redacted === true) {
    score += 10;
    rationale.push("redacted content signals analyzed");
  }

  if (score >= 80) return { level: "very_high", rationale };
  if (score >= 55) return { level: "high", rationale };
  if (score >= 25) return { level: "medium", rationale };
  return { level: "low", rationale };
}

function matchesRule(object: SurfaceObject, rule: Rule): boolean {
  if (rule.match.object_type && object.type !== rule.match.object_type) return false;
  return rule.match.where.every((condition) => {
    const actual = getField(object, condition.field);
    switch (condition.op) {
      case "equals":
        return actual === condition.value;
      case "not_equals":
        return actual !== condition.value;
      case "includes":
        return Array.isArray(actual) && actual.includes(condition.value);
      case "contains_any":
        return Array.isArray(actual) && Array.isArray(condition.value) && condition.value.some((value) => actual.includes(value));
      case "exists":
        return actual !== undefined && actual !== null;
      case "in":
        return Array.isArray(condition.value) && condition.value.includes(actual);
      case "gt":
        return typeof actual === "number" && typeof condition.value === "number" && actual > condition.value;
      case "gte":
        return typeof actual === "number" && typeof condition.value === "number" && actual >= condition.value;
      case "lt":
        return typeof actual === "number" && typeof condition.value === "number" && actual < condition.value;
      case "lte":
        return typeof actual === "number" && typeof condition.value === "number" && actual <= condition.value;
      default:
        return false;
    }
  });
}

function getField(object: SurfaceObject, field: string): unknown {
  return field.split(".").reduce<unknown>((value, part) => {
    if (value && typeof value === "object" && part in value) {
      return (value as Record<string, unknown>)[part];
    }
    return undefined;
  }, object);
}
