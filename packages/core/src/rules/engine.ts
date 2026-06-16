import fs from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";
import {
  RuleSchema,
  type ActionType,
  type Confidence,
  type DataClass,
  type Finding,
  type FindingRiskSummary,
  type RiskFactors,
  type Rule,
  type ScanDiagnostic,
  type SurfaceObject,
  type TriageRiskDriver
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
        const riskSummary = summarizeFindingRisk(object, risk, rule.recommendation.control);
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
          risk_summary: riskSummary,
          maps_to: rule.maps_to,
          evidence: object.evidence
        });
      }
    }
  }
  return findings.sort((a, b) => a.id.localeCompare(b.id));
}

const riskDriverOrder: TriageRiskDriver[] = [
  "untrusted_to_privileged",
  "secret_exposure",
  "credential_data",
  "pii_data",
  "sensitive_data",
  "external_reach",
  "execute_action",
  "write_action",
  "irreversible_action",
  "side_effect"
];

function summarizeFindingRisk(
  object: SurfaceObject,
  risk: RiskFactors,
  recommendedControl: Rule["recommendation"]["control"]
): FindingRiskSummary {
  const dataClasses = new Set<DataClass>([...object.data_classes, ...risk.data_classes]);
  const actions = new Set<ActionType>([...object.actions, ...risk.actions]);
  const drivers = riskDriverOrder.filter((driver) => {
    switch (driver) {
      case "untrusted_to_privileged":
        return object.untrusted_to_privileged || risk.untrusted_to_privileged;
      case "secret_exposure":
        return object.secret_exposure || risk.secret_exposure;
      case "credential_data":
        return dataClasses.has("credential");
      case "pii_data":
        return dataClasses.has("pii");
      case "sensitive_data":
        return sensitiveDataClasses.some((dataClass) => dataClasses.has(dataClass));
      case "external_reach":
        return object.external_reach || risk.external_reach;
      case "execute_action":
        return actions.has("execute");
      case "write_action":
        return writeActions.some((action) => actions.has(action));
      case "irreversible_action":
        return object.reversible === false || risk.reversible === false;
      case "side_effect":
        return object.side_effect || risk.side_effect;
      default:
        return false;
    }
  });

  const summary = [
    `Matched ${object.type} surface has ${object.trust_level} trust and risk score ${risk.score}.`,
    summarizeDataAndAuthority(dataClasses, actions),
    summarizeBoundary(object, risk),
    `Control objective: ${controlObjective(recommendedControl)}.`
  ].filter((item) => item.length > 0);

  return {
    primary_driver: drivers[0],
    drivers,
    impact: impactForDrivers(drivers),
    control_objective: controlObjective(recommendedControl),
    analyst_summary: [...new Set(summary)].slice(0, 4)
  };
}

const sensitiveDataClasses: DataClass[] = ["confidential", "secret", "credential", "pii"];
const writeActions: ActionType[] = ["approve", "delete", "publish", "send", "write"];

function summarizeDataAndAuthority(dataClasses: Set<DataClass>, actions: Set<ActionType>): string {
  const data = [...dataClasses].filter((item) => item !== "unknown").sort((a, b) => a.localeCompare(b));
  const authority = [...actions].sort((a, b) => a.localeCompare(b));
  if (data.length > 0 && authority.length > 0) {
    return `Surface combines ${data.join(", ")} data with ${authority.join(", ")} authority.`;
  }
  if (data.length > 0) return `Surface handles ${data.join(", ")} data.`;
  if (authority.length > 0) return `Surface has ${authority.join(", ")} authority.`;
  return "Surface matched rule conditions but exposes no additional normalized data or action class.";
}

function summarizeBoundary(object: SurfaceObject, risk: RiskFactors): string {
  if (object.untrusted_to_privileged || risk.untrusted_to_privileged) {
    return "Untrusted or lower-trust context can influence a more privileged capability.";
  }
  if (object.external_reach || risk.external_reach) {
    return "Capability can reach an external boundary.";
  }
  if (object.secret_exposure || risk.secret_exposure) {
    return "Secret or credential exposure is represented in normalized metadata.";
  }
  return "";
}

function impactForDrivers(drivers: TriageRiskDriver[]): string {
  if (drivers.includes("untrusted_to_privileged")) return "Untrusted context can influence privileged agent authority.";
  if (drivers.includes("secret_exposure") || drivers.includes("credential_data")) {
    return "Secrets or credentials may be exposed, materialized, or used across an unsafe boundary.";
  }
  if (drivers.includes("pii_data") || drivers.includes("sensitive_data")) {
    return "Sensitive data may move through an agent-controlled capability that needs review.";
  }
  if (drivers.includes("external_reach")) return "Agent-controlled behavior can cross an external system boundary.";
  if (drivers.includes("execute_action")) return "Agent-controlled behavior can execute code or commands.";
  if (drivers.includes("write_action")) return "Agent-controlled behavior can mutate state or publish externally.";
  return "Rule matched an agent security condition that should be reviewed.";
}

function controlObjective(control: Rule["recommendation"]["control"]): string {
  const controls: Record<Rule["recommendation"]["control"], string> = {
    allow: "document accepted risk and keep the surface observable",
    deny: "remove or block the unsafe authority path",
    require_approval: "require explicit human or policy approval before the action proceeds",
    redact: "prevent sensitive context from entering the exposed channel",
    quarantine: "isolate the surface until trust, data flow, and authority are reviewed",
    warn: "surface the risk to reviewers without blocking the workflow"
  };
  return controls[control];
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
