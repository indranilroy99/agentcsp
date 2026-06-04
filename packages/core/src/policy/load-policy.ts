import fs from "node:fs/promises";
import path from "node:path";
import { minimatch } from "minimatch";
import YAML from "yaml";
import {
  PolicySchema,
  type Control,
  type Finding,
  type FindingPolicyControl,
  type FindingSuppression,
  type Policy,
  type SurfaceObject,
  type TrustLevel
} from "../schemas/index.js";

export async function loadPolicy(rootPath: string, configPath?: string): Promise<Policy> {
  const candidate = configPath ? path.resolve(rootPath, configPath) : path.join(rootPath, "agentcsp.yaml");
  try {
    const content = await fs.readFile(candidate, "utf8");
    return PolicySchema.parse(YAML.parse(content) ?? {});
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return PolicySchema.parse({});
    throw error;
  }
}

export function applyTrustOverrides<T extends SurfaceObject>(objects: T[], policy: Policy): T[] {
  return objects.map((object) => {
    const override = policy.trust_overrides.find((entry) =>
      minimatch(object.path, entry.path, { dot: true })
    );
    if (!override) return object;
    return { ...object, trust_level: override.trust_level as TrustLevel };
  });
}

export function applyFindingSuppressions(findings: Finding[], policy: Policy, now = new Date()): Finding[] {
  return findings.map((finding) => {
    const suppression = policy.suppressions.find((entry) => suppressionMatches(finding, entry));
    if (!suppression) return finding;
    const status = isSuppressionActive(suppression.expires_at, now) ? "active" : "expired";
    return {
      ...finding,
      suppression: {
        id: suppression.id,
        status,
        reason: suppression.reason,
        owner: suppression.owner,
        expires_at: suppression.expires_at,
        matched_on: matchedFields(finding, suppression),
        applied_at: now.toISOString()
      } satisfies FindingSuppression
    };
  });
}

export function applyRecommendedControls(findings: Finding[], policy: Policy, now = new Date()): Finding[] {
  return findings.map((finding) => {
    const recommendedControl = policy.recommended_controls.find((entry) => recommendedControlMatches(finding, entry));
    if (!recommendedControl) return finding;
    return {
      ...finding,
      recommended_control: recommendedControl.control as Control,
      policy_control: {
        id: recommendedControl.id,
        control: recommendedControl.control as Control,
        previous_control: finding.recommended_control,
        reason: recommendedControl.reason,
        matched_on: recommendedControlMatchedFields(finding, recommendedControl),
        applied_at: now.toISOString()
      } satisfies FindingPolicyControl
    };
  });
}

function suppressionMatches(finding: Finding, suppression: Policy["suppressions"][number]): boolean {
  const match = suppression.match;
  if (match.finding_id && finding.id !== match.finding_id) return false;
  if (match.rule_id && finding.rule_id !== match.rule_id) return false;
  if (match.object_id && finding.matched_object.id !== match.object_id) return false;
  if (match.path && !minimatch(finding.file_path, match.path, { dot: true })) return false;
  if (match.category && finding.category !== match.category) return false;
  if (match.severity && finding.severity !== match.severity) return false;
  return Object.values(match).some((value) => value !== undefined);
}

function isSuppressionActive(expiresAt: string, now: Date): boolean {
  const expires = Date.parse(expiresAt);
  if (!Number.isFinite(expires)) return false;
  return expires > now.getTime();
}

function matchedFields(finding: Finding, suppression: Policy["suppressions"][number]): string[] {
  const fields: string[] = [];
  const match = suppression.match;
  if (match.finding_id && finding.id === match.finding_id) fields.push("finding_id");
  if (match.rule_id && finding.rule_id === match.rule_id) fields.push("rule_id");
  if (match.object_id && finding.matched_object.id === match.object_id) fields.push("object_id");
  if (match.path && minimatch(finding.file_path, match.path, { dot: true })) fields.push("path");
  if (match.category && finding.category === match.category) fields.push("category");
  if (match.severity && finding.severity === match.severity) fields.push("severity");
  return fields;
}

function recommendedControlMatches(finding: Finding, entry: Policy["recommended_controls"][number]): boolean {
  return recommendedControlMatchedFields(finding, entry).length === Object.keys(entry.match).length && Object.keys(entry.match).length > 0;
}

function recommendedControlMatchedFields(finding: Finding, entry: Policy["recommended_controls"][number]): string[] {
  const fields: string[] = [];
  for (const [field, expected] of Object.entries(entry.match)) {
    if (recommendedControlFieldMatches(finding, field, expected)) fields.push(field);
  }
  return fields;
}

function recommendedControlFieldMatches(finding: Finding, field: string, expected: unknown): boolean {
  switch (field) {
    case "finding_id":
      return expected === finding.id;
    case "rule_id":
      return expected === finding.rule_id;
    case "object_id":
      return expected === finding.matched_object.id;
    case "path":
      return typeof expected === "string" && minimatch(finding.file_path, expected, { dot: true });
    case "category":
      return expected === finding.category;
    case "severity":
      return expected === finding.severity;
    case "confidence":
      return expected === finding.confidence;
    case "object_type":
      return expected === finding.matched_object.type;
    case "trust_level":
      return expected === finding.matched_object.trust_level;
    case "data_class":
      return typeof expected === "string" && finding.data_classes.includes(expected as never);
    case "action":
      return typeof expected === "string" && finding.risk.actions.includes(expected as never);
    default:
      return genericFieldMatches(finding, field, expected);
  }
}

function genericFieldMatches(finding: Finding, field: string, expected: unknown): boolean {
  const actual = field.split(".").reduce<unknown>((value, part) => {
    if (value && typeof value === "object" && part in value) return (value as Record<string, unknown>)[part];
    return undefined;
  }, finding);
  if (Array.isArray(actual)) {
    if (Array.isArray(expected)) return expected.every((value) => actual.includes(value));
    return actual.includes(expected);
  }
  return actual === expected;
}
