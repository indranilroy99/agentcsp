import fs from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import type { BaselineComparison, Finding } from "../schemas/index.js";
import { isPathInsideRoot, relativePath } from "../utils/paths.js";

const BaselineFindingRecordSchema = z.object({ id: z.string() }).passthrough();
const BaselineFindingsFileSchema = z.array(BaselineFindingRecordSchema);
const BaselineManifestFileSchema = z.object({ findings: z.array(BaselineFindingRecordSchema) }).passthrough();

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

  const resolvedFindingIds = baseline.findingIds
    .filter((findingId) => !currentIds.has(findingId))
    .sort((a, b) => a.localeCompare(b));

  return {
    findings: findingsWithStatus,
    comparison: {
      title: "AgentCSP Baseline Comparison",
      baseline_path: displayBaselinePath,
      baseline_format: baseline.format,
      current_findings: findings.length,
      baseline_findings: baseline.findingIds.length,
      new_findings: newFindingIds.length,
      existing_findings: findingsWithStatus.length - newFindingIds.length,
      resolved_findings: resolvedFindingIds.length,
      new_finding_ids: newFindingIds,
      resolved_finding_ids: resolvedFindingIds
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
): Promise<{ findingIds: string[]; format: BaselineComparison["baseline_format"] }> {
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
      format: "manifest"
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
