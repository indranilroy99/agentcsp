import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  ScanConfigSchema,
  type AgentManifest,
  type Finding,
  type Policy,
  type Rule,
  type RulePackSummary,
  type ScanConfig,
  type ScanCoverageSummary,
  type ScanDiagnostic,
  type SeverityCounts
} from "../schemas/index.js";
import { buildManifest } from "../manifest/build.js";
import { buildStaticGraph } from "../graph/build-graph.js";
import {
  applyFindingSuppressions,
  applyRecommendedControls,
  applyTrustOverrides,
  loadPolicyWithDiagnostics
} from "../policy/load-policy.js";
import { detectSurfaces, type DetectedSurfaces } from "./detect.js";
import { walkProjectWithCoverage } from "./walk.js";
import { loadRules, loadRulesWithDiagnostics, ruleDiagnostic, runRules } from "../rules/engine.js";
import { buildStaticBlastRadiusSummary } from "../reports/blast-radius.js";
import { renderMarkdownReport } from "../reports/markdown.js";
import { renderSarifReport } from "../reports/sarif.js";
import { buildTriageSummary } from "../reports/triage.js";
import { buildActionPlan } from "../reports/action-plan.js";
import { buildCiGateSummary } from "../reports/gates.js";
import { applyBaselineComparison } from "../reports/baseline.js";
import { stableId } from "../utils/ids.js";
import { resolvePathFromRoot } from "../utils/paths.js";
import { sortObjects } from "../utils/sort.js";

const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));

export interface ScanResult {
  manifest: AgentManifest;
  findings: Finding[];
  reportMarkdown: string;
  outputFiles: {
    manifest?: string;
    findings?: string;
    report?: string;
    sarif?: string;
  };
  shouldFail: boolean;
}

export async function scanProject(rawConfig: Partial<ScanConfig> & { root_path: string }): Promise<ScanResult> {
  const config = ScanConfigSchema.parse(rawConfig);
  const rootPath = path.resolve(config.root_path);
  const outputPath = resolvePathFromRoot(rootPath, config.output_path);
  if (path.resolve(outputPath) === rootPath) {
    throw new Error("AgentCSP output_path must be a directory outside or below the scan root, not the scan root itself.");
  }
  const baselinePath = config.baseline_path ? resolvePathFromRoot(rootPath, config.baseline_path) : undefined;
  const resolvedConfig: ScanConfig = { ...config, output_path: outputPath, baseline_path: baselinePath };

  const walkResult = await walkProjectWithCoverage(resolvedConfig);
  const files = walkResult.files;
  const policyResult = await loadPolicyWithDiagnostics(rootPath, config.config_path);
  const policy = policyResult.policy;
  const detected = await detectSurfaces(files);
  const ruleLoad = await loadScanRules(rootPath);
  detected.diagnostics.push(...walkResult.diagnostics, ...policyResult.diagnostics, ...ruleLoad.diagnostics);
  if (walkResult.coverage.max_files_reached) {
    detected.diagnostics.push(maxFilesReachedDiagnostic(walkResult.coverage.max_files));
  }
  const surfaces = applyPolicyToSurfaces(detected, policy);
  const scanCoverage = withDiagnosticCoverage(walkResult.coverage, surfaces.diagnostics);

  const policyControlledFindings = applyRecommendedControls(runRules(surfaces, ruleLoad.rules), policy);
  const suppressedFindings = applyFindingSuppressions(policyControlledFindings, policy);
  const baselineResult = resolvedConfig.baseline_path
    ? await applyBaselineComparison(suppressedFindings, resolvedConfig.baseline_path, rootPath)
    : undefined;
  const findings = baselineResult?.findings ?? suppressedFindings;
  const activeFindings = findings.filter((finding) => finding.suppression?.status !== "active");
  const graph = buildStaticGraph(surfaces, activeFindings);
  const staticBlastRadius = buildStaticBlastRadiusSummary(surfaces, findings, graph.relationships, graph.attackPaths, {
    limit: graph.attackPathLimit,
    total: graph.attackPathsTotal,
    truncated: graph.attackPathsTruncated
  });
  const triageSummary = buildTriageSummary(findings);
  const actionPlan = buildActionPlan(findings);
  const ciGateSummary = buildCiGateSummary({
    findings,
    diagnostics: surfaces.diagnostics,
    scanCoverage,
    config: resolvedConfig
  });
  const manifest = buildManifest({
    rootPath,
    scanConfig: resolvedConfig,
    surfaces,
    findings,
    relationships: graph.relationships,
    attackPaths: graph.attackPaths,
    triageSummary,
    actionPlan,
    baselineComparison: baselineResult?.comparison,
    ciGateSummary,
    rulePackSummary: ruleLoad.summary,
    scanCoverage,
    staticBlastRadius
  });
  const reportMarkdown = renderMarkdownReport(manifest);

  await fs.mkdir(outputPath, { recursive: true });
  const outputFiles: ScanResult["outputFiles"] = {};
  if (config.formats.includes("json")) {
    outputFiles.manifest = path.join(outputPath, "agent-manifest.json");
    outputFiles.findings = path.join(outputPath, "findings.json");
    await fs.writeFile(outputFiles.manifest, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    await fs.writeFile(outputFiles.findings, `${JSON.stringify(findings, null, 2)}\n`, "utf8");
  }
  if (config.formats.includes("md")) {
    outputFiles.report = path.join(outputPath, "report.md");
    await fs.writeFile(outputFiles.report, `${reportMarkdown}\n`, "utf8");
  }
  if (config.formats.includes("sarif")) {
    outputFiles.sarif = path.join(outputPath, "agentcsp.sarif");
    await fs.writeFile(outputFiles.sarif, `${JSON.stringify(renderSarifReport(manifest), null, 2)}\n`, "utf8");
  }

  return {
    manifest,
    findings,
    reportMarkdown,
    outputFiles,
    shouldFail: ciGateSummary.should_fail
  };
}

function maxFilesReachedDiagnostic(maxFiles: number): ScanDiagnostic {
  return {
    id: stableId("diagnostic", ["SCAN_MAX_FILES_REACHED", String(maxFiles)]),
    severity: "warning",
    code: "SCAN_MAX_FILES_REACHED",
    file_path: ".",
    parser: "scanner",
    reason: `Scan stopped after reaching the configured max_files limit (${maxFiles}). Results may be incomplete; increase --max-files or narrow the scan scope before relying on a quiet report.`,
    content_redacted: true
  };
}

async function loadScanRules(rootPath: string): Promise<{
  rules: Rule[];
  diagnostics: ScanDiagnostic[];
  summary: RulePackSummary;
}> {
  const builtInRulesDirectory = await builtInRulesDirectoryPath();
  const builtInRules = await loadRules(builtInRulesDirectory);
  const rules = [...builtInRules];
  const diagnostics: ScanDiagnostic[] = [];
  const seenRuleIds = new Set(builtInRules.map((rule) => rule.id));
  const projectRulesDirectory = path.resolve(rootPath, "rules");
  let projectRuleCount = 0;

  if ((await directoryExists(projectRulesDirectory)) && !sameDirectory(projectRulesDirectory, builtInRulesDirectory)) {
    const projectRuleLoad = await loadRulesWithDiagnostics(projectRulesDirectory, rootPath);
    diagnostics.push(...projectRuleLoad.diagnostics);
    for (const rule of projectRuleLoad.rules) {
      if (seenRuleIds.has(rule.id)) {
        diagnostics.push(
          ruleDiagnostic(rootPath, projectRuleLoad.pathsByRuleId.get(rule.id) ?? projectRulesDirectory, {
            code: "RULE_ID_DUPLICATE",
            reason: `Project-local rule id ${rule.id} duplicates an existing AgentCSP rule and was skipped.`
          })
        );
        continue;
      }
      rules.push(rule);
      seenRuleIds.add(rule.id);
      projectRuleCount += 1;
    }
  }

  return {
    rules: rules.sort((a, b) => a.id.localeCompare(b.id)),
    diagnostics: diagnostics.sort((a, b) => a.id.localeCompare(b.id)),
    summary: {
      built_in_rules: builtInRules.length,
      project_rules: projectRuleCount,
      total_rules: builtInRules.length + projectRuleCount,
      project_rules_loaded: projectRuleCount > 0,
      rule_diagnostics: diagnostics.length,
      ...summarizeRulePack(rules)
    }
  };
}

function summarizeRulePack(rules: Rule[]): Pick<RulePackSummary, "by_category" | "by_severity" | "by_object_type"> {
  const categories = new Map<string, number>();
  const objectTypes = new Map<string, number>();
  const by_severity: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const rule of rules) {
    categories.set(rule.category, (categories.get(rule.category) ?? 0) + 1);
    by_severity[rule.severity] += 1;
    const objectType = rule.match.object_type ?? "any";
    objectTypes.set(objectType, (objectTypes.get(objectType) ?? 0) + 1);
  }

  return {
    by_category: sortedCounts(categories, "category"),
    by_severity,
    by_object_type: sortedCounts(objectTypes, "object_type")
  };
}

function sortedCounts<Key extends string>(
  counts: Map<string, number>,
  key: Key
): Array<Record<Key, string> & { count: number }> {
  return [...counts.entries()]
    .map(([value, count]) => ({ [key]: value, count }) as Record<Key, string> & { count: number })
    .sort((a, b) => b.count - a.count || a[key].localeCompare(b[key]));
}

function withDiagnosticCoverage(
  coverage: ScanCoverageSummary,
  diagnostics: ScanDiagnostic[]
): ScanCoverageSummary {
  const counts = diagnostics.reduce(
    (summary, diagnostic) => {
      if (diagnostic.severity === "error") summary.errors += 1;
      if (diagnostic.severity === "warning") summary.warnings += 1;
      if (diagnostic.severity === "info") summary.info += 1;
      return summary;
    },
    { errors: 0, warnings: 0, info: 0 }
  );
  const scanHealth = summarizeScanHealth(coverage, diagnostics, counts);

  return {
    ...coverage,
    scan_health: scanHealth.scan_health,
    scan_health_reasons: scanHealth.scan_health_reasons,
    diagnostics_total: diagnostics.length,
    diagnostics_errors: counts.errors,
    diagnostics_warnings: counts.warnings,
    diagnostics_info: counts.info
  };
}

function summarizeScanHealth(
  coverage: ScanCoverageSummary,
  diagnostics: ScanDiagnostic[],
  counts: { errors: number; warnings: number; info: number }
): Pick<ScanCoverageSummary, "scan_health" | "scan_health_reasons"> {
  const reasons = new Set<string>();
  if (coverage.max_files_reached) reasons.add("max_files_reached");
  if (diagnostics.some((diagnostic) => diagnostic.code === "SCAN_DIRECTORY_READ_FAILED")) {
    reasons.add("directory_read_failed");
  }
  if (diagnostics.some((diagnostic) => diagnostic.code === "SCAN_FILE_STAT_FAILED")) {
    reasons.add("file_stat_failed");
  }
  if (coverage.files_skipped_for_size > 0) reasons.add("files_skipped_for_size");
  if (counts.errors > 0) reasons.add("diagnostic_errors");
  if (counts.warnings > 0) reasons.add("diagnostic_warnings");

  const scan_health =
    coverage.max_files_reached ||
    diagnostics.some((diagnostic) => diagnostic.code === "SCAN_DIRECTORY_READ_FAILED" || diagnostic.code === "SCAN_FILE_STAT_FAILED")
      ? "incomplete"
      : reasons.size > 0
        ? "degraded"
        : "complete";

  return {
    scan_health,
    scan_health_reasons: [...reasons].sort((a, b) => a.localeCompare(b))
  };
}

function applyPolicyToSurfaces(surfaces: DetectedSurfaces, policy: Policy): DetectedSurfaces {
  return {
    agents: sortObjects(applyTrustOverrides(surfaces.agents, policy)),
    instructions: sortObjects(applyTrustOverrides(surfaces.instructions, policy)),
    skills: sortObjects(applyTrustOverrides(surfaces.skills, policy)),
    plugins: sortObjects(applyTrustOverrides(surfaces.plugins, policy)),
    mcp_servers: sortObjects(applyTrustOverrides(surfaces.mcp_servers, policy)),
    tools: sortObjects(applyTrustOverrides(surfaces.tools, policy)),
    prompts: sortObjects(applyTrustOverrides(surfaces.prompts, policy)),
    rag_sources: sortObjects(applyTrustOverrides(surfaces.rag_sources, policy)),
    memory: sortObjects(applyTrustOverrides(surfaces.memory, policy)),
    secrets: sortObjects(applyTrustOverrides(surfaces.secrets, policy)),
    runtime_config: sortObjects(applyTrustOverrides(surfaces.runtime_config, policy)),
    ci_cd: sortObjects(applyTrustOverrides(surfaces.ci_cd, policy)),
    automations: sortObjects(applyTrustOverrides(surfaces.automations, policy)),
    diagnostics: [...surfaces.diagnostics].sort((a, b) => a.id.localeCompare(b.id))
  };
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
  throw new Error(
    `No built-in rules directory with YAML rules found in ${candidates.length} packaged AgentCSP rule locations. Reinstall AgentCSP or verify the package includes the built-in rules.`
  );
}

async function builtInRulesDirectoryPath(): Promise<string> {
  return firstExistingDirectory([
    path.resolve(moduleDirectory, "../builtin-rules"),
    path.resolve(moduleDirectory, "../../rules"),
    path.resolve(moduleDirectory, "../../../../rules")
  ]);
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

async function directoryExists(candidate: string): Promise<boolean> {
  try {
    const stats = await fs.stat(candidate);
    return stats.isDirectory();
  } catch {
    return false;
  }
}

function sameDirectory(left: string, right: string): boolean {
  return path.resolve(left) === path.resolve(right);
}
