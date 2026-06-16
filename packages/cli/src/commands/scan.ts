import path from "node:path";
import {
  ConfidenceSchema,
  scanProject,
  ScanHealthGateSchema,
  SeveritySchema,
  type Confidence,
  type ScanHealthGate,
  type Severity
} from "@agentcsp/core";
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
  const baselinePath = options.baseline ? String(options.baseline) : undefined;
  const failOnNew = Boolean(options.failOnNew);
  const failOnExpiredSuppressions = Boolean(options.failOnExpiredSuppressions);
  const failOnDiagnostics = Boolean(options.failOnDiagnostics);
  const failOnScanHealth = parseFailOnScanHealth(options.failOnScanHealth);
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
    config_path: typeof options.config === "string" ? options.config : undefined,
    formats,
    include_hidden: includeHidden,
    include_logs: includeLogs,
    max_file_size_bytes: typeof options.maxFileSize === "number" ? options.maxFileSize : 1024 * 1024,
    max_files: typeof options.maxFiles === "number" ? options.maxFiles : 5000,
    quiet,
    fail_on: failOn,
    fail_on_confidence: failOnConfidence,
    baseline_path: baselinePath,
    fail_on_new: failOnNew,
    fail_on_expired_suppressions: failOnExpiredSuppressions,
    fail_on_diagnostics: failOnDiagnostics,
    fail_on_scan_health: failOnScanHealth
  });

  if (!quiet) {
    await printBanner({ animate: true });
    console.log(`AgentCSP scan complete: ${result.findings.length} finding(s)`);
    console.log(
      `Suppressed findings: ${result.findings.filter((finding) => finding.suppression?.status === "active").length}`
    );
    console.log(
      `Expired suppressions: ${result.findings.filter((finding) => finding.suppression?.status === "expired").length}`
    );
    console.log(
      `Attack paths: ${result.manifest.attack_paths.length} (${result.manifest.static_blast_radius?.critical_attack_paths ?? 0} critical)`
    );
    if (result.manifest.triage_summary) {
      console.log(
        `Triage: ${result.manifest.triage_summary.active_findings} active, highest severity: ${result.manifest.triage_summary.highest_active_severity}, max risk score: ${result.manifest.triage_summary.max_active_risk_score}`
      );
      console.log(
        `Triage preview: top ${result.manifest.triage_summary.top_active_limit} risks, truncated: ${result.manifest.triage_summary.top_active_risks_truncated}`
      );
    }
    if (result.manifest.action_plan) {
      console.log(
        `Action plan: ${result.manifest.action_plan.total_actions} action(s), immediate: ${result.manifest.action_plan.immediate_actions}, truncated: ${result.manifest.action_plan.truncated}`
      );
    }
    if (result.manifest.static_blast_radius) {
      console.log(
        `Blast-radius preview: ${result.manifest.static_blast_radius.high_risk_objects.length}/${result.manifest.static_blast_radius.high_risk_objects_total} high-risk object(s), truncated: ${result.manifest.static_blast_radius.high_risk_objects_truncated}`
      );
      console.log(
        `Attack-path preview: ${result.manifest.static_blast_radius.attack_path_limit} limit, ${result.manifest.static_blast_radius.attack_paths_total} total, truncated: ${result.manifest.static_blast_radius.attack_paths_truncated}`
      );
    }
    if (result.manifest.scan_coverage) {
      console.log(
        `Scan health: ${result.manifest.scan_coverage.scan_health} (${result.manifest.scan_coverage.scan_health_reasons.join(", ") || "no health issues"})`
      );
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
    if (result.manifest.ci_gate_summary) {
      const failedGates = result.manifest.ci_gate_summary.failed_gates.join(", ") || "none";
      console.log(`CI gate: ${result.manifest.ci_gate_summary.status} (failed gates: ${failedGates})`);
      console.log(
        `CI blockers: severity ${formatSeverityMix(result.manifest.ci_gate_summary.severity_gate_by_severity)}, confidence ${formatConfidenceMix(result.manifest.ci_gate_summary.severity_gate_by_confidence)}, active suppressions ${formatSeverityMix(result.manifest.ci_gate_summary.active_suppressions_by_severity)}, expired suppressions ${formatSeverityMix(result.manifest.ci_gate_summary.expired_suppression_by_severity)}, truncated: ${result.manifest.ci_gate_summary.blocker_ids_truncated}`
      );
      console.log(
        `CI risk drivers: severity ${formatRiskDriverMix(result.manifest.ci_gate_summary.severity_gate_by_risk_driver)}, expired suppressions ${formatRiskDriverMix(result.manifest.ci_gate_summary.expired_suppression_by_risk_driver)}`
      );
    }
    if (result.outputFiles.manifest) console.log(`Manifest: ${result.outputFiles.manifest}`);
    if (result.outputFiles.findings) console.log(`Findings: ${result.outputFiles.findings}`);
    if (result.outputFiles.report) console.log(`Report: ${result.outputFiles.report}`);
    if (result.outputFiles.sarif) console.log(`SARIF: ${result.outputFiles.sarif}`);
  }

  if (result.shouldFail) {
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

function parseFailOnScanHealth(value: unknown): ScanHealthGate | undefined {
  if (value === undefined || value === null || value === false) return undefined;
  const parsed = ScanHealthGateSchema.safeParse(value);
  if (!parsed.success) {
    throw new Error("--fail-on-scan-health must be one of degraded or incomplete");
  }
  return parsed.data;
}
