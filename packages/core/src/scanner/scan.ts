import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  ScanConfigSchema,
  type AgentManifest,
  type Finding,
  type Policy,
  type ScanConfig,
  type ScanCoverageSummary,
  type ScanDiagnostic
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
import { applyBaselineComparison } from "../reports/baseline.js";
import { shouldFail } from "../risk/score.js";
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
  const outputPath = path.resolve(config.output_path);

  const walkResult = await walkProjectWithCoverage(config);
  const files = walkResult.files;
  const policyResult = await loadPolicyWithDiagnostics(rootPath, config.config_path);
  const policy = policyResult.policy;
  const detected = await detectSurfaces(files);
  const ruleLoad = await loadScanRules(rootPath);
  detected.diagnostics.push(...policyResult.diagnostics, ...ruleLoad.diagnostics);
  const surfaces = applyPolicyToSurfaces(detected, policy);
  const scanCoverage = withDiagnosticCoverage(walkResult.coverage, surfaces.diagnostics);

  const policyControlledFindings = applyRecommendedControls(runRules(surfaces, ruleLoad.rules), policy);
  const suppressedFindings = applyFindingSuppressions(policyControlledFindings, policy);
  const baselineResult = config.baseline_path
    ? await applyBaselineComparison(suppressedFindings, config.baseline_path)
    : undefined;
  const findings = baselineResult?.findings ?? suppressedFindings;
  const activeFindings = findings.filter((finding) => finding.suppression?.status !== "active");
  const failGateFindings = config.fail_on_new
    ? findings.filter((finding) => finding.baseline_status === "new")
    : findings;
  const graph = buildStaticGraph(surfaces, activeFindings);
  const staticBlastRadius = buildStaticBlastRadiusSummary(surfaces, findings, graph.relationships, graph.attackPaths);
  const triageSummary = buildTriageSummary(findings);
  const manifest = buildManifest({
    rootPath,
    scanConfig: config,
    surfaces,
    findings,
    relationships: graph.relationships,
    attackPaths: graph.attackPaths,
    triageSummary,
    baselineComparison: baselineResult?.comparison,
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
    shouldFail: shouldFail(failGateFindings, config.fail_on, config.fail_on_confidence)
  };
}

async function loadScanRules(rootPath: string): Promise<{ rules: Awaited<ReturnType<typeof loadRules>>; diagnostics: ScanDiagnostic[] }> {
  const builtInRulesDirectory = await builtInRulesDirectoryPath();
  const builtInRules = await loadRules(builtInRulesDirectory);
  const rules = [...builtInRules];
  const diagnostics: ScanDiagnostic[] = [];
  const seenRuleIds = new Set(builtInRules.map((rule) => rule.id));
  const projectRulesDirectory = path.resolve(rootPath, "rules");

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
    }
  }

  return {
    rules: rules.sort((a, b) => a.id.localeCompare(b.id)),
    diagnostics: diagnostics.sort((a, b) => a.id.localeCompare(b.id))
  };
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

  return {
    ...coverage,
    diagnostics_total: diagnostics.length,
    diagnostics_errors: counts.errors,
    diagnostics_warnings: counts.warnings,
    diagnostics_info: counts.info
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
      if (stats.isDirectory()) return candidate;
    } catch {
      continue;
    }
  }
  throw new Error(`No rules directory found. Checked: ${candidates.join(", ")}`);
}

async function builtInRulesDirectoryPath(): Promise<string> {
  return firstExistingDirectory([
    path.resolve(moduleDirectory, "../../rules"),
    path.resolve(moduleDirectory, "../../../../rules")
  ]);
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
