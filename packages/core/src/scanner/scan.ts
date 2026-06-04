import fs from "node:fs/promises";
import path from "node:path";
import { ScanConfigSchema, type AgentManifest, type Finding, type ScanConfig } from "../schemas/index.js";
import { buildManifest } from "../manifest/build.js";
import { buildStaticGraph } from "../graph/build-graph.js";
import { applyTrustOverrides, loadPolicy } from "../policy/load-policy.js";
import { detectSurfaces, type DetectedSurfaces } from "./detect.js";
import { walkProject } from "./walk.js";
import { loadRules, runRules } from "../rules/engine.js";
import { buildStaticBlastRadiusSummary } from "../reports/blast-radius.js";
import { renderMarkdownReport } from "../reports/markdown.js";
import { renderSarifReport } from "../reports/sarif.js";
import { shouldFail } from "../risk/score.js";
import { sortObjects } from "../utils/sort.js";

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
  const outputPath = path.resolve(rootPath, config.output_path);

  const files = await walkProject(config);
  const policy = await loadPolicy(rootPath, config.config_path);
  const detected = await detectSurfaces(files);
  const surfaces = applyPolicyToSurfaces(detected, policy);

  const rulesDirectory = path.resolve(rootPath, "rules");
  const fallbackRulesDirectory = path.resolve(process.cwd(), "rules");
  const rules = await loadRules(await firstExistingDirectory([rulesDirectory, fallbackRulesDirectory]));
  const findings = runRules(surfaces, rules);
  const graph = buildStaticGraph(surfaces, findings);
  const staticBlastRadius = buildStaticBlastRadiusSummary(surfaces, findings, graph.relationships, graph.attackPaths);
  const manifest = buildManifest({
    rootPath,
    scanConfig: config,
    surfaces,
    findings,
    relationships: graph.relationships,
    attackPaths: graph.attackPaths,
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
    shouldFail: shouldFail(findings, config.fail_on)
  };
}

function applyPolicyToSurfaces(surfaces: DetectedSurfaces, policy: Awaited<ReturnType<typeof loadPolicy>>): DetectedSurfaces {
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
    automations: sortObjects(applyTrustOverrides(surfaces.automations, policy))
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
