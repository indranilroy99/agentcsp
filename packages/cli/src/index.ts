#!/usr/bin/env node
import { Command } from "commander";
import { renderBanner } from "./banner.js";
import { runScanCommand } from "./commands/scan.js";

const program = new Command();

program
  .name("agentcsp")
  .description("Context Security Policy for AI Agents.")
  .version("0.1.0")
  .addHelpText("beforeAll", renderBanner({ color: Boolean(process.stdout.isTTY) }));

program
  .command("scan")
  .argument("[path]", "project path to scan", ".")
  .option("--out <path>", "output directory", ".agentcsp")
  .option("--config <path>", "policy config path", "agentcsp.yaml")
  .option("--format <formats>", "comma-separated output formats: json,md,sarif", "json,md")
  .option("--fail-on <severity>", "fail when findings meet severity: critical,high,medium,low")
  .option("--fail-on-confidence <confidence>", "with --fail-on, require minimum confidence: very_high,high,medium,low")
  .option("--baseline <path>", "compare findings against a previous findings.json or agent-manifest.json")
  .option("--fail-on-new", "with --baseline and --fail-on, fail only on new findings")
  .option("--no-hidden", "skip hidden AI/security folders")
  .option("--include-logs", "include log directories")
  .option("--max-file-size <bytes>", "maximum file size to inspect", parseInteger)
  .option("--quiet", "suppress non-error output")
  .action(async (targetPath: string, options: Record<string, unknown>) => {
    await runScanCommand(targetPath, options);
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`agentcsp: ${message}`);
  process.exitCode = 1;
});

function parseInteger(value: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`Expected a positive integer, received ${value}`);
  }
  return parsed;
}
