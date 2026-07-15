import fs from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
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
import { buildStaticAttackPaths, buildStaticRelationships } from "../graph/build-graph.js";
import {
  applyFindingSuppressions,
  applyRecommendedControls,
  applyTrustOverrides,
  loadPolicyWithDiagnostics
} from "../policy/load-policy.js";
import { detectSurfaces, type DetectedSurfaces } from "./detect.js";
import { walkProjectWithCoverage } from "./walk.js";
import { loadRulesWithDiagnostics, ruleDiagnostic, runRules } from "../rules/engine.js";
import { buildStaticBlastRadiusSummary } from "../reports/blast-radius.js";
import { renderMarkdownReport } from "../reports/markdown.js";
import { renderSarifReport } from "../reports/sarif.js";
import { buildTriageSummary } from "../reports/triage.js";
import { buildActionPlan } from "../reports/action-plan.js";
import { buildCiGateSummary } from "../reports/gates.js";
import { applyBaselineComparison } from "../reports/baseline.js";
import { buildInventorySummary } from "../reports/inventory.js";
import { stableId } from "../utils/ids.js";
import { isPathInsideRoot, resolvePathFromRoot } from "../utils/paths.js";
import { sortObjects } from "../utils/sort.js";
import { canonicalJson } from "../utils/canonical-json.js";
import { verifyTrustedInput } from "../security/trusted-input.js";
import { publishArtifactSet, type ArtifactPayload } from "../reports/artifact-transaction.js";
import { toAgentManifestArtifact, toFindingArtifacts } from "../manifest/artifact.js";
import { builtInRulesDirectoryPath, loadBuiltInRuleset } from "../rules/catalog.js";

export interface ScanResult {
  manifest: AgentManifest;
  findings: Finding[];
  reportMarkdown: string;
  outputFiles: {
    manifest?: string;
    findings?: string;
    report?: string;
    sarif?: string;
    receipt?: string;
  };
  shouldFail: boolean;
}

export async function scanProject(rawConfig: Partial<ScanConfig> & { root_path: string }): Promise<ScanResult> {
  const parsedConfig = ScanConfigSchema.parse(rawConfig);
  const config: ScanConfig =
    parsedConfig.profile === "ci_strict"
      ? {
          ...parsedConfig,
          fail_on_diagnostics: true,
          fail_on_expired_suppressions: true,
          fail_on_scan_health: "degraded"
        }
      : parsedConfig;
  const rootPath = path.resolve(config.root_path);
  const outputPath = resolvePathFromRoot(rootPath, config.output_path);
  if (path.resolve(outputPath) === rootPath) {
    throw new Error("AgentCSP output_path must be a directory outside or below the scan root, not the scan root itself.");
  }
  let policyPath = config.config_path ? resolvePathFromRoot(rootPath, config.config_path) : undefined;
  let baselinePath = config.baseline_path ? resolvePathFromRoot(rootPath, config.baseline_path) : undefined;
  let verifiedPolicyContent: Uint8Array | undefined;
  let verifiedBaselineContent: Uint8Array | undefined;
  if (policyPath && config.config_sha256) {
    const verified = await verifyTrustedInput({
      rootPath,
      inputPath: policyPath,
      expectedSha256: config.config_sha256,
      label: "policy",
      maxBytes: 1024 * 1024
    });
    policyPath = verified.real_path;
    verifiedPolicyContent = verified.content;
  }
  if (baselinePath && config.baseline_sha256) {
    const verified = await verifyTrustedInput({
      rootPath,
      inputPath: baselinePath,
      expectedSha256: config.baseline_sha256,
      label: "baseline",
      maxBytes: 10 * 1024 * 1024
    });
    baselinePath = verified.real_path;
    verifiedBaselineContent = verified.content;
  }
  const resolvedConfig: ScanConfig = {
    ...config,
    output_path: outputPath,
    config_path: policyPath,
    baseline_path: baselinePath
  };

  const walkResult = await walkProjectWithCoverage(resolvedConfig);
  const files = walkResult.files;
  const policyResult = await loadPolicyWithDiagnostics(rootPath, policyPath, {
    loadProjectDefault: config.profile !== "ci_strict",
    maxBytes: 1024 * 1024,
    verifiedContent: verifiedPolicyContent
  });
  const policy = policyResult.policy;
  const detected = await detectSurfaces(files);
  const ruleLoad = await loadScanRules(rootPath, config.profile, config.ruleset);
  detected.diagnostics.push(...walkResult.diagnostics, ...policyResult.diagnostics, ...ruleLoad.diagnostics);
  if (walkResult.coverage.max_files_reached) {
    detected.diagnostics.push(maxFilesReachedDiagnostic(walkResult.coverage.max_files));
  }
  if (walkResult.coverage.max_directories_reached) {
    detected.diagnostics.push(maxDirectoriesReachedDiagnostic(walkResult.coverage.max_directories));
  }
  if (walkResult.coverage.directories_skipped_for_entry_limit > 0) {
    detected.diagnostics.push(
      directoryEntryLimitDiagnostic(
        walkResult.coverage.max_entries_per_directory,
        walkResult.coverage.directories_skipped_for_entry_limit,
        walkResult.coverage.directory_entry_limit_paths[0] ?? "."
      )
    );
  }
  const policyAuthority = policyPath && !isPathInsideRoot(rootPath, policyPath) ? "operator" : "project";
  const surfaces = applyPolicyToSurfaces(detected, policy, policyAuthority);
  const scanCoverage = withDiagnosticCoverage(walkResult.coverage, surfaces.diagnostics);
  const relationshipGraph = buildStaticRelationships(surfaces);

  const policyControlledFindings = applyRecommendedControls(runRules(surfaces, ruleLoad.rules), policy);
  const suppressedFindings = applyFindingSuppressions(
    policyControlledFindings,
    policy,
    new Date(),
    policyAuthority
  );
  const baselineResult = resolvedConfig.baseline_path
    ? await applyBaselineComparison(
        suppressedFindings,
        resolvedConfig.baseline_path,
        rootPath,
        verifiedBaselineContent
      )
    : undefined;
  const findings = baselineResult?.findings ?? suppressedFindings;
  const activeFindings = findings.filter((finding) => finding.suppression?.status !== "active");
  const graph = buildStaticAttackPaths(surfaces, relationshipGraph.relationships, activeFindings);
  const staticBlastRadius = buildStaticBlastRadiusSummary(surfaces, findings, graph.relationships, graph.attackPaths, {
    limit: graph.attackPathLimit,
    total: graph.attackPathsTotal,
    truncated: graph.attackPathsTruncated
  });
  const triageSummary = buildTriageSummary(findings);
  const actionPlan = buildActionPlan(findings);
  const inventorySummary = buildInventorySummary(surfaces);
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
    inventorySummary,
    staticBlastRadius
  });
  const reportMarkdown = renderMarkdownReport(manifest);
  const artifactManifest =
    config.artifact_profile === "internal" ? manifest : toAgentManifestArtifact(manifest);
  const artifactFindings =
    config.artifact_profile === "internal" ? manifest.findings : toFindingArtifacts(manifest.findings);

  const artifacts: ArtifactPayload[] = [];
  const outputFiles: ScanResult["outputFiles"] = {};
  if (config.formats.includes("json")) {
    artifacts.push({ name: "agent-manifest.json", content: JSON.stringify(artifactManifest, null, 2) });
    artifacts.push({ name: "findings.json", content: JSON.stringify(artifactFindings, null, 2) });
  }
  if (config.formats.includes("md")) {
    artifacts.push({ name: "report.md", content: reportMarkdown });
  }
  if (config.formats.includes("sarif")) {
    artifacts.push({ name: "agentcsp.sarif", content: JSON.stringify(renderSarifReport(manifest), null, 2) });
  }
  const published = await publishArtifactSet({
    outputPath,
    artifactProfile: config.artifact_profile,
    artifacts
  });
  outputFiles.manifest = published.files["agent-manifest.json"];
  outputFiles.findings = published.files["findings.json"];
  outputFiles.report = published.files["report.md"];
  outputFiles.sarif = published.files["agentcsp.sarif"];
  outputFiles.receipt = published.receiptPath;

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

function maxDirectoriesReachedDiagnostic(maxDirectories: number): ScanDiagnostic {
  return {
    id: stableId("diagnostic", ["SCAN_MAX_DIRECTORIES_REACHED", String(maxDirectories)]),
    severity: "warning",
    code: "SCAN_MAX_DIRECTORIES_REACHED",
    file_path: ".",
    parser: "scanner",
    reason: `Scan reached the configured max_directories limit (${maxDirectories}). Some subtrees were omitted; increase --max-directories or narrow the scan scope before relying on a quiet report.`,
    content_redacted: true
  };
}

function directoryEntryLimitDiagnostic(maxEntries: number, skippedDirectories: number, firstPath: string): ScanDiagnostic {
  return {
    id: stableId("diagnostic", ["SCAN_DIRECTORY_ENTRY_LIMIT_REACHED", String(maxEntries), String(skippedDirectories)]),
    severity: "warning",
    code: "SCAN_DIRECTORY_ENTRY_LIMIT_REACHED",
    file_path: firstPath,
    parser: "scanner",
    reason: `${skippedDirectories} directory or directories exceeded the configured max_entries_per_directory limit (${maxEntries}) and were omitted as complete units to preserve deterministic bounded traversal.`,
    content_redacted: true
  };
}

async function loadScanRules(
  rootPath: string,
  profile: ScanConfig["profile"],
  ruleset: ScanConfig["ruleset"]
): Promise<{
  rules: Rule[];
  diagnostics: ScanDiagnostic[];
  summary: RulePackSummary;
}> {
  const builtInRulesDirectory = await builtInRulesDirectoryPath();
  const builtInRules = (await loadBuiltInRuleset(ruleset)).rules;
  const rules = [...builtInRules];
  const diagnostics: ScanDiagnostic[] = [];
  const seenRuleIds = new Set(builtInRules.map((rule) => rule.id));
  const projectRulesDirectory = path.resolve(rootPath, "rules");
  let projectRuleCount = 0;

  if (
    profile === "ci_strict" &&
    (await directoryExists(projectRulesDirectory)) &&
    !sameDirectory(projectRulesDirectory, builtInRulesDirectory)
  ) {
    diagnostics.push({
      id: stableId("diagnostic", ["PROJECT_RULES_IGNORED", "rules"]),
      severity: "info",
      code: "PROJECT_RULES_IGNORED",
      file_path: "rules",
      parser: "rule",
      reason: "Repository rules were discovered but not applied by the ci_strict profile.",
      content_redacted: true
    });
  } else if ((await directoryExists(projectRulesDirectory)) && !sameDirectory(projectRulesDirectory, builtInRulesDirectory)) {
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
      fingerprint: fingerprintRules(rules),
      built_in_rules: builtInRules.length,
      project_rules: projectRuleCount,
      total_rules: builtInRules.length + projectRuleCount,
      project_rules_loaded: projectRuleCount > 0,
      rule_diagnostics: diagnostics.length,
      ...summarizeRulePack(rules)
    }
  };
}

function fingerprintRules(rules: Rule[]): RulePackSummary["fingerprint"] {
  return {
    algorithm: "sha256",
    value: createHash("sha256").update(canonicalJson([...rules].sort((a, b) => a.id.localeCompare(b.id)))).digest("hex")
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
  if (coverage.max_directories_reached) reasons.add("max_directories_reached");
  if (coverage.directories_skipped_for_entry_limit > 0) reasons.add("directory_entry_limit_reached");
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
    coverage.max_directories_reached ||
    coverage.directories_skipped_for_entry_limit > 0 ||
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

function applyPolicyToSurfaces(
  surfaces: DetectedSurfaces,
  policy: Policy,
  authority: "project" | "operator"
): DetectedSurfaces {
  return {
    agents: sortObjects(applyTrustOverrides(surfaces.agents, policy, authority)),
    instructions: sortObjects(applyTrustOverrides(surfaces.instructions, policy, authority)),
    skills: sortObjects(applyTrustOverrides(surfaces.skills, policy, authority)),
    plugins: sortObjects(applyTrustOverrides(surfaces.plugins, policy, authority)),
    mcp_servers: sortObjects(applyTrustOverrides(surfaces.mcp_servers, policy, authority)),
    tools: sortObjects(applyTrustOverrides(surfaces.tools, policy, authority)),
    prompts: sortObjects(applyTrustOverrides(surfaces.prompts, policy, authority)),
    rag_sources: sortObjects(applyTrustOverrides(surfaces.rag_sources, policy, authority)),
    memory: sortObjects(applyTrustOverrides(surfaces.memory, policy, authority)),
    secrets: sortObjects(applyTrustOverrides(surfaces.secrets, policy, authority)),
    runtime_config: sortObjects(applyTrustOverrides(surfaces.runtime_config, policy, authority)),
    ci_cd: sortObjects(applyTrustOverrides(surfaces.ci_cd, policy, authority)),
    automations: sortObjects(applyTrustOverrides(surfaces.automations, policy, authority)),
    diagnostics: [...surfaces.diagnostics].sort((a, b) => a.id.localeCompare(b.id))
  };
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
