import fs from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import {
  BaselineEnvelopeSchema,
  ContentDigestSchema,
  FindingIdentityVersion,
  ManifestFingerprintSchema,
  ScannerVersion,
  type BaselineEnvelope,
  type BaselineComparison,
  type ContentDigest,
  type ConfidenceCounts,
  type Finding,
  type ManifestFingerprint,
  type SeverityCounts
} from "../schemas/index.js";
import { AgentCspError } from "../errors.js";
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
const baselineMaxBytes = 10 * 1024 * 1024;
export const baselineFindingIdLimit = 50;

export interface BaselineResult {
  findings: Finding[];
  comparison: BaselineComparison;
}

export async function applyBaselineComparison(
  findings: Finding[],
  baselinePath: string,
  rootPath?: string,
  verifiedContent?: Uint8Array
): Promise<BaselineResult> {
  const absoluteBaselinePath = path.resolve(baselinePath);
  const displayBaselinePath = baselineComparisonPath(absoluteBaselinePath, rootPath);
  const baseline = await loadBaselineFindingIds(absoluteBaselinePath, displayBaselinePath, verifiedContent);
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
  displayBaselinePath = baselinePath,
  verifiedContent?: Uint8Array
): Promise<{
  findingIds: string[];
  format: BaselineComparison["baseline_format"];
  fingerprint?: ManifestFingerprint;
  rulePackFingerprint?: ContentDigest;
}> {
  let parsedJson: unknown;
  try {
    parsedJson = verifiedContent
      ? JSON.parse(Buffer.from(verifiedContent).toString("utf8"))
      : await readBaselineJson(baselinePath);
  } catch (error) {
    throw classifyBaselineReadError(error, displayBaselinePath);
  }

  const envelope = BaselineEnvelopeSchema.safeParse(parsedJson);
  if (envelope.success) {
    return {
      findingIds: uniqueSortedIds(envelope.data.findings),
      format: "envelope",
      fingerprint: envelope.data.source.manifest_fingerprint,
      rulePackFingerprint: envelope.data.source.rule_pack_fingerprint
    };
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

  throw new AgentCspError({
    code: "AGENTCSP-E1002",
    kind: "configuration",
    problem: `Baseline ${displayBaselinePath} is not a supported baseline document.`,
    fix: "Use a v0.2 baseline envelope, findings.json array, or agent-manifest.json object with a findings array.",
    help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md#baselines"
  });
}

function classifyBaselineReadError(error: unknown, displayBaselinePath: string): AgentCspError {
  if (error instanceof AgentCspError) return error;
  const code = error && typeof error === "object" && "code" in error ? String(error.code) : undefined;
  if (code === "ENOENT") {
    return new AgentCspError({
      code: "AGENTCSP-E1001",
      kind: "input",
      problem: `Baseline ${displayBaselinePath} does not exist.`,
      fix: "Check the configured baseline path and rerun the scan.",
      help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md#baselines",
      cause: error
    });
  }
  if (code === "EACCES" || code === "EPERM") {
    return new AgentCspError({
      code: "AGENTCSP-E1003",
      kind: "input",
      problem: `Baseline ${displayBaselinePath} is not readable.`,
      fix: "Grant the minimum required read permission or select an accessible baseline.",
      help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md#baselines",
      cause: error
    });
  }
  return new AgentCspError({
    code: "AGENTCSP-E1002",
    kind: "configuration",
    problem: `Baseline ${displayBaselinePath} is not valid JSON.`,
    fix: "Validate the baseline JSON or create a new v0.2 baseline envelope.",
    help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md#baselines",
    cause: error
  });
}

export async function createBaselineEnvelopeFromFile(
  sourcePath: string,
  now = new Date()
): Promise<BaselineEnvelope> {
  let parsed: unknown;
  try {
    parsed = await readBaselineJson(path.resolve(sourcePath));
  } catch (error) {
    throw classifyBaselineReadError(error, sourcePath);
  }
  return createBaselineEnvelope(parsed, now);
}

export function createBaselineEnvelope(source: unknown, now = new Date()): BaselineEnvelope {
  const existing = BaselineEnvelopeSchema.safeParse(source);
  if (existing.success) {
    return BaselineEnvelopeSchema.parse({
      ...existing.data,
      findings: uniqueBaselineRecords(existing.data.findings)
    });
  }

  const findingsFile = BaselineFindingsFileSchema.safeParse(source);
  if (findingsFile.success) {
    return baselineEnvelope(uniqueBaselineRecords(findingsFile.data), {}, now);
  }

  const manifestFile = BaselineManifestFileSchema.safeParse(source);
  if (manifestFile.success) {
    return baselineEnvelope(
      uniqueBaselineRecords(manifestFile.data.findings),
      {
        manifest_fingerprint: manifestFile.data.metadata?.fingerprint,
        rule_pack_fingerprint: manifestFile.data.metadata?.rule_pack?.fingerprint
      },
      now
    );
  }

  throw new AgentCspError({
    code: "AGENTCSP-E1002",
    kind: "configuration",
    problem: "Baseline source is not a supported findings, manifest, or baseline document.",
    fix: "Pass findings.json, agent-manifest.json, or a v0.2 baseline envelope.",
    help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md#baselines"
  });
}

export function diffBaselineEnvelopes(
  baseline: BaselineEnvelope,
  current: BaselineEnvelope
): { added: string[]; removed: string[]; unchanged: string[] } {
  const baselineIds = new Set(baseline.findings.map((finding) => finding.id));
  const currentIds = new Set(current.findings.map((finding) => finding.id));
  return {
    added: [...currentIds].filter((id) => !baselineIds.has(id)).sort((a, b) => a.localeCompare(b)),
    removed: [...baselineIds].filter((id) => !currentIds.has(id)).sort((a, b) => a.localeCompare(b)),
    unchanged: [...currentIds].filter((id) => baselineIds.has(id)).sort((a, b) => a.localeCompare(b))
  };
}

async function readBaselineJson(baselinePath: string): Promise<unknown> {
  const stats = await fs.stat(baselinePath);
  if (!stats.isFile() || stats.size > baselineMaxBytes) {
    throw new AgentCspError({
      code: "AGENTCSP-E2003",
      kind: "configuration",
      problem: `Baseline must be a regular JSON file no larger than ${baselineMaxBytes} bytes.`,
      fix: "Use a compact v0.2 baseline envelope or reduce the baseline file size.",
      help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md#baselines"
    });
  }
  return JSON.parse(await fs.readFile(baselinePath, "utf8"));
}

function baselineEnvelope(
  findings: BaselineEnvelope["findings"],
  source: BaselineEnvelope["source"],
  now: Date
): BaselineEnvelope {
  return BaselineEnvelopeSchema.parse({
    schema_version: "0.2.0",
    identity_version: FindingIdentityVersion,
    created_at: now.toISOString(),
    scanner_version: ScannerVersion,
    source,
    findings
  });
}

function uniqueBaselineRecords(findings: Array<{ id: string; rule_id?: string }>): BaselineEnvelope["findings"] {
  const records = new Map<string, { id: string; rule_id?: string }>();
  for (const finding of findings) {
    const current = records.get(finding.id);
    if (!current || (!current.rule_id && finding.rule_id)) records.set(finding.id, finding);
  }
  return [...records.values()].sort((a, b) => a.id.localeCompare(b.id));
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
