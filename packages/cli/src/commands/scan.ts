import path from "node:path";
import { ConfidenceSchema, scanProject, SeveritySchema, type Confidence, type Severity } from "@agentcsp/core";
import { printBanner } from "../banner.js";

const allowedFormats = new Set(["json", "md", "sarif"]);

export async function runScanCommand(targetPath: string, options: Record<string, unknown>): Promise<void> {
  const rootPath = path.resolve(targetPath);
  const formats = parseFormats(String(options.format ?? "json,md"));
  const failOn = parseFailOn(options.failOn);
  const failOnConfidence = parseFailOnConfidence(options.failOnConfidence);
  if (failOnConfidence && !failOn) {
    throw new Error("--fail-on-confidence requires --fail-on");
  }
  const baselinePath = options.baseline ? path.resolve(String(options.baseline)) : undefined;
  const failOnNew = Boolean(options.failOnNew);
  const failOnDiagnostics = Boolean(options.failOnDiagnostics);
  if (failOnNew && !failOn) {
    throw new Error("--fail-on-new requires --fail-on");
  }
  if (failOnNew && !baselinePath) {
    throw new Error("--fail-on-new requires --baseline");
  }
  const includeHidden = options.hidden !== false;
  const includeLogs = Boolean(options.includeLogs);
  const quiet = Boolean(options.quiet);

  const result = await scanProject({
    root_path: rootPath,
    output_path: String(options.out ?? ".agentcsp"),
    config_path: String(options.config ?? "agentcsp.yaml"),
    formats,
    include_hidden: includeHidden,
    include_logs: includeLogs,
    max_file_size_bytes: typeof options.maxFileSize === "number" ? options.maxFileSize : 1024 * 1024,
    max_files: typeof options.maxFiles === "number" ? options.maxFiles : 5000,
    quiet,
    fail_on: failOn,
    fail_on_confidence: failOnConfidence,
    baseline_path: baselinePath,
    fail_on_new: failOnNew
  });

  if (!quiet) {
    await printBanner({ animate: true });
    console.log(`AgentCSP scan complete: ${result.findings.length} finding(s)`);
    console.log(
      `Suppressed findings: ${result.findings.filter((finding) => finding.suppression?.status === "active").length}`
    );
    console.log(
      `Attack paths: ${result.manifest.attack_paths.length} (${result.manifest.static_blast_radius?.critical_attack_paths ?? 0} critical)`
    );
    if (result.manifest.scan_coverage) {
      console.log(
        `Coverage: ${result.manifest.scan_coverage.files_indexed} indexed, ${result.manifest.scan_coverage.files_skipped_for_size} oversized, max files reached: ${result.manifest.scan_coverage.max_files_reached}`
      );
    }
    if (result.manifest.scan_coverage) {
      console.log(
        `Diagnostics: ${result.manifest.scan_coverage.diagnostics_total} (${result.manifest.scan_coverage.diagnostics_warnings} warnings, ${result.manifest.scan_coverage.diagnostics_errors} errors)`
      );
    } else {
      console.log(`Diagnostics: ${result.manifest.diagnostics.length}`);
    }
    if (result.manifest.baseline_comparison) {
      console.log(
        `Baseline: ${result.manifest.baseline_comparison.new_findings} new, ${result.manifest.baseline_comparison.existing_findings} existing, ${result.manifest.baseline_comparison.resolved_findings} resolved`
      );
    }
    if (result.outputFiles.manifest) console.log(`Manifest: ${result.outputFiles.manifest}`);
    if (result.outputFiles.findings) console.log(`Findings: ${result.outputFiles.findings}`);
    if (result.outputFiles.report) console.log(`Report: ${result.outputFiles.report}`);
    if (result.outputFiles.sarif) console.log(`SARIF: ${result.outputFiles.sarif}`);
  }

  if (result.shouldFail || (failOnDiagnostics && result.manifest.diagnostics.length > 0)) {
    process.exitCode = 1;
  }
}

function parseFormats(value: string): Array<"json" | "md" | "sarif"> {
  const formats = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  for (const format of formats) {
    if (!allowedFormats.has(format)) {
      throw new Error(`Unsupported format "${format}". Expected json,md,sarif.`);
    }
  }
  return formats.length > 0 ? (formats as Array<"json" | "md" | "sarif">) : ["json", "md"];
}

function parseFailOn(value: unknown): Severity | undefined {
  if (value === undefined || value === null || value === false) return undefined;
  const parsed = SeveritySchema.safeParse(value);
  if (!parsed.success || parsed.data === "info") {
    throw new Error("--fail-on must be one of critical, high, medium, or low");
  }
  return parsed.data;
}

function parseFailOnConfidence(value: unknown): Confidence | undefined {
  if (value === undefined || value === null || value === false) return undefined;
  const parsed = ConfidenceSchema.safeParse(value);
  if (!parsed.success) {
    throw new Error("--fail-on-confidence must be one of very_high, high, medium, or low");
  }
  return parsed.data;
}
