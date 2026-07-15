#!/usr/bin/env node
import { Command, CommanderError } from "commander";
import { FindingIdentityVersion, ManifestSchemaVersion, ObjectIdentityVersion } from "@agentcsp/core";
import { renderBanner } from "./banner.js";
import { runScanCommand } from "./commands/scan.js";
import { runBaselineCreate, runBaselineDiff, runBaselineMigrate } from "./commands/baseline.js";
import { runConfigValidate } from "./commands/config.js";
import { runDoctor } from "./commands/doctor.js";
import { runRulesExplain, runRulesList } from "./commands/rules.js";
import { runGuardCheck, runGuardInstall, runGuardStatus, runGuardUninstall, type GuardHook } from "./commands/guard.js";
import {
  configurationError,
  exitCodeForError,
  normalizeCliError,
  renderCliError,
  requestedLogFormat
} from "./errors.js";
import { CLI_VERSION } from "./version.js";

const program = new Command();

program
  .name("agentcsp")
  .description("Local-first AI agent repository posture scanner.")
  .version(CLI_VERSION)
  .exitOverride()
  .configureOutput({ writeErr: () => undefined })
  .addHelpText("beforeAll", renderBanner({ color: Boolean(process.stdout.isTTY) }));

program
  .command("scan")
  .description("Discover AI agent surfaces, evaluate security rules, and write redacted evidence artifacts.")
  .argument("[path]", "project path to scan", ".")
  .option("--out <path>", "output directory", ".agentcsp")
  .option("--profile <profile>", "scan profile: advisory or ci-strict", "advisory")
  .option("--artifact-profile <profile>", "artifact privacy profile: portable or internal", "portable")
  .option("--ruleset <ruleset>", "built-in ruleset: recommended or extended", "recommended")
  .option("--config <path>", "policy config path")
  .option("--config-sha256 <digest>", "expected SHA-256 for a protected policy")
  .option("--format <formats>", "comma-separated output formats: json,md,sarif", "json,md")
  .option("--fail-on <severity>", "fail when findings meet severity: critical,high,medium,low")
  .option("--fail-on-confidence <confidence>", "with --fail-on, require minimum confidence: very_high,high,medium,low")
  .option("--baseline <path>", "compare findings against a previous findings.json or agent-manifest.json")
  .option("--baseline-sha256 <digest>", "expected SHA-256 for a protected baseline")
  .option("--fail-on-new", "with --baseline and --fail-on, fail only on new findings")
  .option("--fail-on-expired-suppressions", "fail when any matched suppression has expired")
  .option("--fail-on-diagnostics", "fail when security-relevant scan diagnostics are emitted")
  .option("--fail-on-scan-health <health>", "fail when scan health is degraded or incomplete")
  .option("--no-hidden", "skip hidden AI/security folders")
  .option("--include-logs", "include log directories")
  .option("--max-file-size <bytes>", "maximum file size to inspect", parseInteger)
  .option("--max-files <count>", "maximum number of files to index", parseInteger)
  .option("--max-directories <count>", "maximum number of directories to visit", parseInteger)
  .option("--max-entries-per-directory <count>", "maximum entries accepted in one directory", parseInteger)
  .option("--log-format <format>", "terminal log format: text or json", "text")
  .option("--verbose", "print detailed scan counters")
  .option("--no-banner", "suppress the terminal banner")
  .option("--quiet", "suppress non-error output")
  .action(async (targetPath: string, options: Record<string, unknown>) => {
    await runScanCommand(targetPath, options);
  });

const configCommand = program.command("config").description("Validate AgentCSP policy configuration.");
configCommand
  .command("validate")
  .description("Validate policy YAML and schema without running a scan.")
  .argument("[path]", "policy path", "agentcsp.yaml")
  .option("--json", "emit a machine-readable result")
  .action(async (configPath: string, options: { json?: boolean }) => runConfigValidate(configPath, options));

const rulesCommand = program.command("rules").description("Inspect built-in detection rules and pack metadata.");
rulesCommand
  .command("list")
  .description("List rules in a built-in ruleset.")
  .option("--ruleset <ruleset>", "recommended or extended", "recommended")
  .option("--json", "emit a machine-readable result")
  .action(async (options: { ruleset?: string; json?: boolean }) => runRulesList(options));
rulesCommand
  .command("explain")
  .description("Explain one built-in rule, its evidence tier, and recommended control.")
  .argument("<rule-id>", "exact built-in rule ID")
  .option("--json", "emit a machine-readable result")
  .action(async (ruleId: string, options: { json?: boolean }) => runRulesExplain(ruleId, options));

const baselineCommand = program.command("baseline").description("Create, compare, and migrate stable finding baselines.");
baselineCommand
  .command("create")
  .description("Create a v0.2 baseline envelope from findings or a manifest.")
  .argument("<source>", "findings.json, agent-manifest.json, or baseline file")
  .requiredOption("--out <path>", "baseline output path")
  .option("--json", "emit a machine-readable result")
  .action(async (source: string, options: { out: string; json?: boolean }) => runBaselineCreate(source, options));
baselineCommand
  .command("diff")
  .description("Compare two finding sets or baseline envelopes.")
  .argument("<baseline>", "previous baseline or scan artifact")
  .argument("<current>", "current baseline or scan artifact")
  .option("--json", "emit a machine-readable result")
  .action(async (baseline: string, current: string, options: { json?: boolean }) =>
    runBaselineDiff(baseline, current, options)
  );
baselineCommand
  .command("migrate")
  .description("Migrate a legacy findings or manifest baseline to the v0.2 envelope.")
  .argument("<source>", "legacy findings or manifest baseline")
  .requiredOption("--out <path>", "migrated baseline output path")
  .option("--json", "emit a machine-readable result")
  .action(async (source: string, options: { out: string; json?: boolean }) => runBaselineMigrate(source, options));

const guardCommand = program.command("guard").description("Install and operate redacted Git secret guards.");
guardCommand
  .command("install")
  .description("Install managed pre-commit and pre-push guards in a Git repository.")
  .argument("[path]", "repository path", ".")
  .option("--json", "emit a machine-readable result")
  .action(async (targetPath: string, options: { json?: boolean }) => runGuardInstall(targetPath, options));
guardCommand
  .command("status")
  .description("Show managed Git guard status without reading staged content.")
  .argument("[path]", "repository path", ".")
  .option("--json", "emit a machine-readable result")
  .action(async (targetPath: string, options: { json?: boolean }) => runGuardStatus(targetPath, options));
guardCommand
  .command("uninstall")
  .description("Remove managed Git guards and restore a preserved hook when available.")
  .argument("[path]", "repository path", ".")
  .option("--json", "emit a machine-readable result")
  .action(async (targetPath: string, options: { json?: boolean }) => runGuardUninstall(targetPath, options));
guardCommand
  .command("check")
  .description("Inspect staged or outgoing Git diffs for secret exposure without printing values.")
  .argument("[path]", "repository path", ".")
  .option("--hook <hook>", "diff source: pre-commit or pre-push", "pre-commit")
  .option("--json", "emit a machine-readable result")
  .action(async (targetPath: string, options: { hook?: GuardHook; json?: boolean }) => {
    if (options.hook !== "pre-commit" && options.hook !== "pre-push") {
      throw configurationError("Guard hook must be pre-commit or pre-push.", "Use --hook pre-commit or --hook pre-push.");
    }
    await runGuardCheck(targetPath, options);
  });

program
  .command("doctor")
  .description("Verify the local runtime and packaged AgentCSP assets.")
  .option("--json", "emit a machine-readable result")
  .action(async (options: { json?: boolean }) => runDoctor(options));

program
  .command("version")
  .description("Print AgentCSP version and compatibility metadata.")
  .option("--json", "emit a machine-readable result")
  .action((options: { json?: boolean }) => {
    if (options.json) {
      console.log(
        JSON.stringify({
          type: "agentcsp_version",
          version: CLI_VERSION,
          manifest_schema: ManifestSchemaVersion,
          object_identity: ObjectIdentityVersion,
          finding_identity: FindingIdentityVersion,
          node: process.versions.node
        })
      );
    } else {
      console.log(`AgentCSP ${CLI_VERSION}`);
    }
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  if (error instanceof CommanderError && (error.code === "commander.helpDisplayed" || error.code === "commander.version")) {
    process.exitCode = 0;
    return;
  }
  const normalized = normalizeCliError(error);
  console.error(renderCliError(normalized, requestedLogFormat(process.argv)));
  process.exitCode = exitCodeForError(normalized);
});

function parseInteger(value: string): number {
  const parsed = Number(value);
  if (!/^[1-9]\d*$/u.test(value) || !Number.isSafeInteger(parsed)) {
    throw configurationError(
      `Expected a positive integer but received "${value}".`,
      "Pass an integer greater than zero."
    );
  }
  return parsed;
}
