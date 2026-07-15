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
  type PolicyControlChangeDirection,
  type PolicyControlMatchScope,
  type Policy,
  type ScanDiagnostic,
  type SuppressionMatchScope,
  type SurfaceObject,
  type TrustLevel
} from "../schemas/index.js";
import { stableId } from "../utils/ids.js";
import { isPathInsideRoot, relativePath, resolvePathFromRoot } from "../utils/paths.js";

export interface LoadedPolicy {
  policy: Policy;
  diagnostics: ScanDiagnostic[];
}

export interface PolicyLoadOptions {
  loadProjectDefault?: boolean;
  maxBytes?: number;
  verifiedContent?: Uint8Array;
}

const defaultMaxPolicyBytes = 1024 * 1024;

export async function loadPolicy(rootPath: string, configPath?: string): Promise<Policy> {
  const candidate = policyCandidate(rootPath, configPath);
  try {
    const content = await fs.readFile(candidate, "utf8");
    return PolicySchema.parse(YAML.parse(content) ?? {});
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return PolicySchema.parse({});
    throw error;
  }
}

export async function loadPolicyWithDiagnostics(
  rootPath: string,
  configPath?: string,
  options: PolicyLoadOptions = {}
): Promise<LoadedPolicy> {
  const emptyPolicy = PolicySchema.parse({});
  if (!configPath && options.loadProjectDefault === false) {
    const projectPolicy = path.join(rootPath, "agentcsp.yaml");
    try {
      await fs.access(projectPolicy);
      return {
        policy: emptyPolicy,
        diagnostics: [
          {
            ...policyDiagnostic(rootPath, projectPolicy, {
              code: "PROJECT_POLICY_IGNORED",
              reason: "Repository policy was discovered but not applied by the ci_strict profile."
            }),
            severity: "info"
          }
        ]
      };
    } catch {
      return { policy: emptyPolicy, diagnostics: [] };
    }
  }
  const candidate = policyCandidate(rootPath, configPath);
  try {
    let content: string;
    if (options.verifiedContent) {
      content = Buffer.from(options.verifiedContent).toString("utf8");
    } else {
      const stats = await fs.stat(candidate);
      if (stats.size > (options.maxBytes ?? defaultMaxPolicyBytes)) {
        return {
          policy: emptyPolicy,
          diagnostics: [
            policyDiagnostic(rootPath, candidate, {
              code: "POLICY_CONFIG_TOO_LARGE",
              reason: `AgentCSP policy exceeds the ${options.maxBytes ?? defaultMaxPolicyBytes}-byte safety limit and was not loaded.`
            })
          ]
        };
      }
      content = await fs.readFile(candidate, "utf8");
    }
    return { policy: PolicySchema.parse(YAML.parse(content) ?? {}), diagnostics: [] };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      if (configPath) {
        return {
          policy: emptyPolicy,
          diagnostics: [
            policyDiagnostic(rootPath, candidate, {
              code: "POLICY_CONFIG_NOT_FOUND",
              reason: "Explicit AgentCSP policy config was not found. Scan continued with empty advisory policy."
            })
          ]
        };
      }
      return { policy: emptyPolicy, diagnostics: [] };
    }
    return {
      policy: emptyPolicy,
      diagnostics: [
        policyDiagnostic(rootPath, candidate, {
          code: isValidationError(error) ? "POLICY_CONFIG_SCHEMA_FAILED" : "POLICY_CONFIG_PARSE_FAILED",
          reason: isValidationError(error)
            ? "AgentCSP policy config failed schema validation. Scan continued with empty advisory policy and raw content redacted."
            : "AgentCSP policy config could not be parsed as YAML. Scan continued with empty advisory policy and raw content redacted."
        })
      ]
    };
  }
}

function policyCandidate(rootPath: string, configPath?: string): string {
  return configPath ? resolvePathFromRoot(rootPath, configPath) : path.join(rootPath, "agentcsp.yaml");
}

function policyDiagnostic(
  rootPath: string,
  absolutePath: string,
  input: {
    code: string;
    reason: string;
  }
): ScanDiagnostic {
  const filePath = policyDiagnosticPath(rootPath, absolutePath);
  return {
    id: stableId("diagnostic", [input.code, filePath]),
    severity: "warning",
    code: input.code,
    file_path: filePath,
    parser: "policy",
    reason: input.reason,
    content_redacted: true
  };
}

function policyDiagnosticPath(rootPath: string, absolutePath: string): string {
  return isPathInsideRoot(rootPath, absolutePath) ? relativePath(rootPath, absolutePath) : "<external-policy-config>";
}

function isValidationError(error: unknown): boolean {
  return Boolean(
    error &&
      typeof error === "object" &&
      "name" in error &&
      (error as { name?: string }).name === "ZodError"
  );
}

export function applyTrustOverrides<T extends SurfaceObject>(
  objects: T[],
  policy: Policy,
  authority: "project" | "operator" = "project"
): T[] {
  return objects.map((object) => {
    const override = policy.trust_overrides.find((entry) =>
      minimatch(object.path, entry.path, { dot: true })
    );
    if (!override) return object;
    return {
      ...object,
      trust_level: override.trust_level as TrustLevel,
      metadata: {
        ...object.metadata,
        trust_provenance: {
          source: "policy_override",
          authority,
          previous: object.trust_level,
          applied: override.trust_level
        }
      }
    };
  });
}

export function applyFindingSuppressions(
  findings: Finding[],
  policy: Policy,
  now = new Date(),
  authority: "project" | "operator" = "project"
): Finding[] {
  return findings.map((finding) => {
    if (finding.suppressibility === "never") return finding;
    if (finding.suppressibility === "trusted_policy_only" && authority !== "operator") return finding;
    const suppression = policy.suppressions.find((entry) => suppressionMatches(finding, entry));
    if (!suppression) return finding;
    const status = isSuppressionActive(suppression.expires_at, now) ? "active" : "expired";
    const matchedOn = matchedFields(finding, suppression);
    return {
      ...finding,
      suppression: {
        id: suppression.id,
        status,
        match_scope: suppressionMatchScope(matchedOn),
        reason: suppression.reason,
        owner: suppression.owner,
        expires_at: suppression.expires_at,
        matched_on: matchedOn,
        applied_at: now.toISOString()
      } satisfies FindingSuppression
    };
  });
}

export function applyRecommendedControls(findings: Finding[], policy: Policy, now = new Date()): Finding[] {
  return findings.map((finding) => {
    const recommendedControl = policy.recommended_controls.find((entry) => recommendedControlMatches(finding, entry));
    if (!recommendedControl) return finding;
    const control = recommendedControl.control as Control;
    const matchedOn = recommendedControlMatchedFields(finding, recommendedControl);
    return {
      ...finding,
      recommended_control: control,
      policy_control: {
        id: recommendedControl.id,
        control,
        previous_control: finding.recommended_control,
        match_scope: policyControlMatchScope(matchedOn),
        change_direction: policyControlChangeDirection(finding.recommended_control, control),
        reason: recommendedControl.reason,
        matched_on: matchedOn,
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

function suppressionMatchScope(fields: string[]): SuppressionMatchScope {
  if (fields.includes("finding_id")) return "specific_finding";
  if (fields.includes("object_id")) return "specific_object";
  if (fields.includes("rule_id") && fields.includes("path")) return "rule_and_path";
  if (fields.includes("rule_id")) return "rule";
  if (fields.includes("path")) return "path";
  if (fields.includes("category")) return "category";
  if (fields.includes("severity")) return "severity";
  return "broad";
}

function policyControlMatchScope(fields: string[]): PolicyControlMatchScope {
  if (fields.includes("finding_id")) return "specific_finding";
  if (fields.includes("object_id")) return "specific_object";
  if (fields.includes("rule_id") && fields.includes("path")) return "rule_and_path";
  if (fields.includes("rule_id")) return "rule";
  if (fields.includes("path")) return "path";
  if (fields.includes("category")) return "category";
  if (fields.includes("severity")) return "severity";
  if (fields.includes("object_type")) return "object_type";
  if (fields.includes("trust_level")) return "trust_level";
  if (fields.includes("data_class")) return "data_class";
  if (fields.includes("action")) return "action";
  return fields.length > 0 ? "custom" : "broad";
}

function policyControlChangeDirection(previous: Control, next: Control): PolicyControlChangeDirection {
  const previousRank = controlRank(previous);
  const nextRank = controlRank(next);
  if (nextRank > previousRank) return "strengthened";
  if (nextRank < previousRank) return "weakened";
  return "unchanged";
}

function controlRank(control: Control): number {
  switch (control) {
    case "allow":
      return 1;
    case "warn":
      return 2;
    case "redact":
      return 3;
    case "require_approval":
      return 4;
    case "quarantine":
      return 5;
    case "deny":
      return 6;
  }
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
