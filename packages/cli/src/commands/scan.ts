import path from "node:path";
import { scanProject, SeveritySchema, type Severity } from "@agentcsp/core";
import { printBanner } from "../banner.js";

const allowedFormats = new Set(["json", "md", "sarif"]);

export async function runScanCommand(targetPath: string, options: Record<string, unknown>): Promise<void> {
  const rootPath = path.resolve(targetPath);
  const formats = parseFormats(String(options.format ?? "json,md"));
  const failOn = parseFailOn(options.failOn);
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
    quiet,
    fail_on: failOn
  });

  if (!quiet) {
    await printBanner({ animate: true });
    console.log(`AgentCSP scan complete: ${result.findings.length} finding(s)`);
    console.log(
      `Attack paths: ${result.manifest.attack_paths.length} (${result.manifest.static_blast_radius?.critical_attack_paths ?? 0} critical)`
    );
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

function parseFailOn(value: unknown): Severity | undefined {
  if (value === undefined || value === null || value === false) return undefined;
  const parsed = SeveritySchema.safeParse(value);
  if (!parsed.success || parsed.data === "info" || parsed.data === "critical") {
    throw new Error("--fail-on must be one of high, medium, or low");
  }
  return parsed.data;
}
