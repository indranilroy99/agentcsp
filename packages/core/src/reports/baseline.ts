import fs from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import {
  ContentDigestSchema,
  ManifestFingerprintSchema,
  type BaselineComparison,
  type ContentDigest,
  type ConfidenceCounts,
  type Finding,
  type ManifestFingerprint,
  type SeverityCounts
} from "../schemas/index.js";
import { isPathInsideRoot, relativePath } from "../utils/paths.js";
import { riskDriverOrder, riskDriversForFinding } from "./risk-drivers.js";

const BaselineFindingRecordSchema = z.object({ id: z.string() }).passthrough();
const BaselineFindingsFileSchema = z.array(BaselineFindingRecordSchema);
const BaselineManifestFileSchema = z
  .object({
    findings: z.array(BaselineFindingRecordSchema),
    metadata: z
      .object({
        fingerprint: ManifestFingerprintSchema.optional(),
        rule_pack: z
          .object({
            fingerprint: ContentDigestSchema.optional()
          })
          .passthrough()
          .optional()
      })
      .passthrough()
      .optional()
  })
  .passthrough();
export const baselineFindingIdLimit = 50;

export interface BaselineResult {
  findings: Finding[];
  comparison: BaselineComparison;
}

export async function applyBaselineComparison(
  findings: Finding[],
  baselinePath: string,
  rootPath?: string
): Promise<BaselineResult> {
  const absoluteBaselinePath = path.resolve(baselinePath);
  const displayBaselinePath = baselineComparisonPath(absoluteBaselinePath, rootPath);
  const baseline = await loadBaselineFindingIds(absoluteBaselinePath, displayBaselinePath);
  const baselineIds = new Set(baseline.findingIds);
  const currentIds = new Set(findings.map((finding) => finding.id));

  const findingsWithStatus = findings.map((finding) => ({
    ...finding,
    baseline_status: baselineIds.has(finding.id) ? "existing" : "new"
  })) satisfies Finding[];

  const newFindingIds = findingsWithStatus
    .filter((finding) => finding.baseline_status === "new")
    .map((finding) => finding.id)
    .sort((a, b) => a.localeCompare(b));
  const newFindings = findingsWithStatus.filter((finding) => finding.baseline_status === "new");

  const resolvedFindingIds = baseline.findingIds
    .filter((findingId) => !currentIds.has(findingId))
    .sort((a, b) => a.localeCompare(b));

  return {
    findings: findingsWithStatus,
    comparison: {
      title: "AgentCSP Baseline Comparison",
      baseline_path: displayBaselinePath,
      baseline_format: baseline.format,
      baseline_fingerprint: baseline.fingerprint,
      baseline_rule_pack_fingerprint: baseline.rulePackFingerprint,
      current_findings: findings.length,
      baseline_findings: baseline.findingIds.length,
      new_findings: newFindingIds.length,
      new_findings_by_severity: countBySeverity(newFindings),
      new_findings_by_confidence: countByConfidence(newFindings),
      new_findings_by_risk_driver: countByRiskDriver(newFindings),
      existing_findings: findingsWithStatus.length - newFindingIds.length,
      resolved_findings: resolvedFindingIds.length,
      baseline_id_limit: baselineFindingIdLimit,
      baseline_ids_truncated:
        newFindingIds.length > baselineFindingIdLimit || resolvedFindingIds.length > baselineFindingIdLimit,
      new_finding_ids: limitIds(newFindingIds),
      new_finding_ids_truncated: newFindingIds.length > baselineFindingIdLimit,
      resolved_finding_ids: limitIds(resolvedFindingIds),
      resolved_finding_ids_truncated: resolvedFindingIds.length > baselineFindingIdLimit
    }
  };
}

function baselineComparisonPath(absoluteBaselinePath: string, rootPath?: string): string {
  if (!rootPath) return absoluteBaselinePath;
  return isPathInsideRoot(rootPath, absoluteBaselinePath) ? relativePath(rootPath, absoluteBaselinePath) : "<external-baseline>";
}

async function loadBaselineFindingIds(
  baselinePath: string,
  displayBaselinePath = baselinePath
): Promise<{
  findingIds: string[];
  format: BaselineComparison["baseline_format"];
  fingerprint?: ManifestFingerprint;
  rulePackFingerprint?: ContentDigest;
}> {
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(await fs.readFile(baselinePath, "utf8"));
  } catch (error) {
    throw new Error(`Unable to read baseline file ${displayBaselinePath}: ${baselineErrorMessage(error, baselinePath, displayBaselinePath)}`);
  }

  const findingsFile = BaselineFindingsFileSchema.safeParse(parsedJson);
  if (findingsFile.success) {
    return {
      findingIds: uniqueSortedIds(findingsFile.data),
      format: "findings"
    };
  }

  const manifestFile = BaselineManifestFileSchema.safeParse(parsedJson);
  if (manifestFile.success) {
    return {
      findingIds: uniqueSortedIds(manifestFile.data.findings),
      format: "manifest",
      fingerprint: manifestFile.data.metadata?.fingerprint,
      rulePackFingerprint: manifestFile.data.metadata?.rule_pack?.fingerprint
    };
  }

  throw new Error("Baseline file must be a findings.json array or an agent-manifest.json object with a findings array.");
}

function baselineErrorMessage(error: unknown, baselinePath: string, displayBaselinePath: string): string {
  if (displayBaselinePath !== baselinePath) {
    const code = error && typeof error === "object" && "code" in error ? String((error as { code?: unknown }).code) : "";
    if (code) return code;
    if (error instanceof SyntaxError) return error.message;
    return "baseline could not be read or parsed";
  }
  return error instanceof Error ? error.message : String(error);
}

function uniqueSortedIds(findings: Array<{ id: string }>): string[] {
  return [...new Set(findings.map((finding) => finding.id))].sort((a, b) => a.localeCompare(b));
}

function limitIds(ids: string[], limit = baselineFindingIdLimit): string[] {
  return ids.slice(0, limit);
}

function countBySeverity(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

function countByConfidence(findings: Finding[]): ConfidenceCounts {
  const counts: ConfidenceCounts = { very_high: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) counts[finding.confidence] += 1;
  return counts;
}

function countByRiskDriver(findings: Finding[]): BaselineComparison["new_findings_by_risk_driver"] {
  const counts = new Map<
    BaselineComparison["new_findings_by_risk_driver"][number]["driver"],
    { count: number; max_risk_score: number; by_severity: SeverityCounts }
  >();

  for (const finding of findings) {
    for (const driver of riskDriversForFinding(finding)) {
      const current = counts.get(driver) ?? {
        count: 0,
        max_risk_score: 0,
        by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
      };
      current.count += 1;
      current.max_risk_score = Math.max(current.max_risk_score, finding.risk.score);
      current.by_severity[finding.severity] += 1;
      counts.set(driver, current);
    }
  }

  return [...counts.entries()]
    .map(([driver, summary]) => ({ driver, ...summary }))
    .sort(
      (a, b) =>
        b.count - a.count ||
        b.max_risk_score - a.max_risk_score ||
        riskDriverOrder.indexOf(a.driver) - riskDriverOrder.indexOf(b.driver)
    );
}
