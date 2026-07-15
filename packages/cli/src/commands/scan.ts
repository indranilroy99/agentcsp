import path from "node:path";
import {
  ArtifactProfileSchema,
  ConfidenceSchema,
  RulesetSchema,
  scanProject,
  ScanHealthGateSchema,
  ScanProfileSchema,
  SeveritySchema,
  type ArtifactProfile,
  type Confidence,
  type Finding,
  type Ruleset,
  type ScanHealthGate,
  type ScanProfile,
  type Severity
} from "@agentcsp/core";
import { printBanner } from "../banner.js";
import { configurationError, type LogFormat } from "../errors.js";

const allowedFormats = new Set(["json", "md", "sarif"]);

export async function runScanCommand(targetPath: string, options: Record<string, unknown>): Promise<void> {
  const rootPath = path.resolve(targetPath);
  const formats = parseFormats(String(options.format ?? "json,md"));
  const profile = parseProfile(options.profile);
  const artifactProfile = parseArtifactProfile(options.artifactProfile);
  const ruleset = parseRuleset(options.ruleset);
  const logFormat = parseLogFormat(options.logFormat);
  const failOn = parseFailOn(options.failOn);
  const failOnConfidence = parseFailOnConfidence(options.failOnConfidence);
  if (failOnConfidence && !failOn) {
    throw configurationError(
      "--fail-on-confidence has no severity gate.",
      "Add --fail-on high (or another severity), or remove --fail-on-confidence."
    );
  }
  const baselinePath = options.baseline ? String(options.baseline) : undefined;
  const baselineSha256 = parseDigest(options.baselineSha256, "--baseline-sha256");
  const configSha256 = parseDigest(options.configSha256, "--config-sha256");
  const failOnNew = Boolean(options.failOnNew);
  const failOnExpiredSuppressions = Boolean(options.failOnExpiredSuppressions);
  const failOnDiagnostics = Boolean(options.failOnDiagnostics);
  const failOnScanHealth = parseFailOnScanHealth(options.failOnScanHealth);
  if (failOnNew && !failOn) {
    throw configurationError("--fail-on-new has no severity gate.", "Add --fail-on and --baseline, or remove --fail-on-new.");
  }
  if (failOnNew && !baselinePath) {
    throw configurationError("--fail-on-new has no baseline.", "Add --baseline <path>, or remove --fail-on-new.");
  }
  const includeHidden = options.hidden !== false;
  const includeLogs = Boolean(options.includeLogs);
  const quiet = Boolean(options.quiet);
  const verbose = Boolean(options.verbose);
  const showBanner = options.banner !== false && logFormat === "text" && !quiet;

  if (showBanner) await printBanner({ animate: Boolean(process.stdout.isTTY) });

  const result = await scanProject({
    root_path: rootPath,
    output_path: String(options.out ?? ".agentcsp"),
    profile,
    artifact_profile: artifactProfile,
    ruleset,
    config_path: typeof options.config === "string" ? options.config : undefined,
    config_sha256: configSha256,
    formats,
    include_hidden: includeHidden,
    include_logs: includeLogs,
    max_file_size_bytes: typeof options.maxFileSize === "number" ? options.maxFileSize : 1024 * 1024,
    max_files: typeof options.maxFiles === "number" ? options.maxFiles : 5000,
    max_directories: typeof options.maxDirectories === "number" ? options.maxDirectories : 10_000,
    max_entries_per_directory:
      typeof options.maxEntriesPerDirectory === "number" ? options.maxEntriesPerDirectory : 10_000,
    quiet,
    fail_on: failOn,
    fail_on_confidence: failOnConfidence,
    baseline_path: baselinePath,
    baseline_sha256: baselineSha256,
    fail_on_new: failOnNew,
    fail_on_expired_suppressions: failOnExpiredSuppressions,
    fail_on_diagnostics: failOnDiagnostics,
    fail_on_scan_health: failOnScanHealth
  });

  if (!quiet) {
    printReceipt(result, logFormat, verbose);
  }

  if (result.shouldFail) {
    const failedGates = result.manifest.ci_gate_summary?.failed_gates ?? [];
    const integrityGate = failedGates.some((gate) =>
      ["diagnostics", "scan_health", "expired_suppressions"].includes(gate)
    );
    process.exitCode = integrityGate ? 3 : 1;
  }
}

function printReceipt(
  result: Awaited<ReturnType<typeof scanProject>>,
  logFormat: LogFormat,
  verbose: boolean
): void {
  const active = result.findings.filter((finding) => finding.suppression?.status !== "active");
  const coverage = result.manifest.scan_coverage;
  const gate = result.manifest.ci_gate_summary;
  const topFindings = [...active].sort(compareFindings).slice(0, 3);
  const status = gate?.status === "fail" ? "FAIL" : active.length > 0 ? "RISK" : coverage?.scan_health === "complete" ? "PASS" : "WARN";

  if (logFormat === "json") {
    console.log(
      JSON.stringify({
        type: "agentcsp_scan_receipt",
        status: status.toLowerCase(),
        profile: result.manifest.metadata.config.profile,
        findings: { active: active.length, total: result.findings.length },
        coverage: coverage
          ? { health: coverage.scan_health, files_indexed: coverage.files_indexed, reasons: coverage.scan_health_reasons }
          : undefined,
        gate: gate ? { status: gate.status, failed: gate.failed_gates } : undefined,
        top_findings: topFindings.map((finding) => ({
          id: finding.id,
          rule_id: finding.rule_id,
          severity: finding.severity,
          confidence: finding.confidence,
          disposition: finding.disposition ?? "advisory",
          path: finding.file_path
        })),
        outputs: result.outputFiles
      })
    );
    return;
  }

  const highest = result.manifest.triage_summary?.highest_active_severity ?? "info";
  console.log(
    `[${status}] ${active.length} active finding(s), highest ${highest}; coverage ${coverage?.scan_health ?? "unknown"}; gate ${gate?.status ?? "not configured"}`
  );
  if (coverage && coverage.scan_health !== "complete") {
    console.log(`Coverage: ${coverage.scan_health_reasons.join(", ") || "unspecified degradation"}`);
  }
  if (topFindings.length > 0) {
    console.log("Top findings:");
    for (const finding of topFindings) {
      console.log(
        `  ${finding.severity.toUpperCase()} ${finding.rule_id} ${finding.file_path} (${finding.support_tier ?? "heuristic"}, ${finding.disposition ?? "advisory"})`
      );
    }
  }
  if (result.outputFiles.report) console.log(`Report: ${result.outputFiles.report}`);
  else if (result.outputFiles.manifest) console.log(`Manifest: ${result.outputFiles.manifest}`);
  if (topFindings[0]) console.log(`Explain: agentcsp rules explain ${topFindings[0].rule_id}`);

  if (verbose) printVerboseReceipt(result);
}

function printVerboseReceipt(result: Awaited<ReturnType<typeof scanProject>>): void {
  const coverage = result.manifest.scan_coverage;
  const gate = result.manifest.ci_gate_summary;
  console.log(`Findings: ${result.findings.length}; attack paths: ${result.manifest.attack_paths.length}`);
  if (coverage) {
    console.log(
      `Files: ${coverage.files_indexed} indexed, ${coverage.files_skipped_for_size} oversized; diagnostics: ${coverage.diagnostics_total}`
    );
  }
  if (gate) console.log(`Failed gates: ${gate.failed_gates.join(", ") || "none"}`);
  if (result.outputFiles.manifest) console.log(`Manifest: ${result.outputFiles.manifest}`);
  if (result.outputFiles.findings) console.log(`Findings JSON: ${result.outputFiles.findings}`);
  if (result.outputFiles.sarif) console.log(`SARIF: ${result.outputFiles.sarif}`);
}

function compareFindings(a: Finding, b: Finding): number {
  const severityRank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  return severityRank[b.severity] - severityRank[a.severity] || b.risk.score - a.risk.score || a.id.localeCompare(b.id);
}

function parseFormats(value: string): Array<"json" | "md" | "sarif"> {
  const formats = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  for (const format of formats) {
    if (!allowedFormats.has(format)) {
      throw configurationError(
        `Unsupported output format "${format}".`,
        "Use a comma-separated subset of json, md, and sarif."
      );
    }
  }
  return formats.length > 0 ? (formats as Array<"json" | "md" | "sarif">) : ["json", "md"];
}

function parseProfile(value: unknown): ScanProfile {
  const normalized = String(value ?? "advisory").replaceAll("-", "_");
  const parsed = ScanProfileSchema.safeParse(normalized);
  if (!parsed.success) {
    throw configurationError("Unsupported scan profile.", "Use --profile advisory or --profile ci-strict.");
  }
  return parsed.data;
}

function parseArtifactProfile(value: unknown): ArtifactProfile {
  const parsed = ArtifactProfileSchema.safeParse(value ?? "portable");
  if (!parsed.success) {
    throw configurationError(
      "Unsupported artifact profile.",
      "Use --artifact-profile portable or --artifact-profile internal."
    );
  }
  return parsed.data;
}

function parseRuleset(value: unknown): Ruleset {
  const parsed = RulesetSchema.safeParse(value ?? "recommended");
  if (!parsed.success) {
    throw configurationError("Unsupported ruleset.", "Use --ruleset recommended or --ruleset extended.");
  }
  return parsed.data;
}

function parseLogFormat(value: unknown): LogFormat {
  if (value === undefined || value === "text") return "text";
  if (value === "json") return "json";
  throw configurationError("Unsupported terminal log format.", "Use --log-format text or --log-format json.");
}

function parseDigest(value: unknown, option: string): string | undefined {
  if (value === undefined || value === null || value === false) return undefined;
  const digest = String(value).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(digest)) {
    throw configurationError(`${option} is not a SHA-256 digest.`, `Pass exactly 64 hexadecimal characters to ${option}.`);
  }
  return digest;
}

function formatSeverityMix(counts: {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}): string {
  return `critical=${counts.critical}, high=${counts.high}, medium=${counts.medium}, low=${counts.low}, info=${counts.info}`;
}

function formatConfidenceMix(counts: {
  very_high: number;
  high: number;
  medium: number;
  low: number;
}): string {
  return `very_high=${counts.very_high}, high=${counts.high}, medium=${counts.medium}, low=${counts.low}`;
}

function formatRiskDriverMix(counts: Array<{ driver: string; count: number }>): string {
  return counts.length > 0
    ? counts.map((item) => `${item.driver.replaceAll("_", "-")}=${item.count}`).join(", ")
    : "none";
}

function parseFailOn(value: unknown): Severity | undefined {
  if (value === undefined || value === null || value === false) return undefined;
  const parsed = SeveritySchema.safeParse(value);
  if (!parsed.success || parsed.data === "info") {
    throw configurationError(
      "--fail-on has an unsupported severity.",
      "Use critical, high, medium, or low."
    );
  }
  return parsed.data;
}

function parseFailOnConfidence(value: unknown): Confidence | undefined {
  if (value === undefined || value === null || value === false) return undefined;
  const parsed = ConfidenceSchema.safeParse(value);
  if (!parsed.success) {
    throw configurationError(
      "--fail-on-confidence has an unsupported confidence.",
      "Use very_high, high, medium, or low."
    );
  }
  return parsed.data;
}

function parseFailOnScanHealth(value: unknown): ScanHealthGate | undefined {
  if (value === undefined || value === null || value === false) return undefined;
  const parsed = ScanHealthGateSchema.safeParse(value);
  if (!parsed.success) {
    throw configurationError(
      "--fail-on-scan-health has an unsupported threshold.",
      "Use degraded or incomplete."
    );
  }
  return parsed.data;
}
