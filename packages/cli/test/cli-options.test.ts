import { describe, expect, it, vi } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { runScanCommand } from "../src/commands/scan.js";
import { isVersionAtLeast } from "../src/commands/doctor.js";
import { tempPath } from "./temp-path.js";

describe("cli options", () => {
  it("accepts scanner versions at or above a pack minimum", () => {
    expect(isVersionAtLeast("0.2.0", "0.2.0")).toBe(true);
    expect(isVersionAtLeast("0.2.1", "0.2.0")).toBe(true);
    expect(isVersionAtLeast("0.3.0", "0.2.9")).toBe(true);
    expect(isVersionAtLeast("1.0.0", "0.99.99")).toBe(true);
    expect(isVersionAtLeast("0.1.9", "0.2.0")).toBe(false);
    expect(isVersionAtLeast("invalid", "0.2.0")).toBe(false);
  });

  it("rejects unsupported fail-on values", async () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    await expect(
      runScanCommand(".", {
        failOn: "info",
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("--fail-on has an unsupported severity");
    spy.mockRestore();
  });

  it("rejects unsupported output formats", async () => {
    await expect(
      runScanCommand(".", {
        format: "json,xml",
        quiet: true
      })
    ).rejects.toThrow('Unsupported output format "xml"');
  });

  it("rejects the scan root as the output directory", async () => {
    const root = await createPolicyConfigFixture();
    await expect(
      runScanCommand(root, {
        out: ".",
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("output_path must be a directory outside or below the scan root");
  });

  it("rejects unsupported fail-on confidence values", async () => {
    await expect(
      runScanCommand(".", {
        failOn: "high",
        failOnConfidence: "certain",
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("--fail-on-confidence has an unsupported confidence");
  });

  it("rejects unsupported fail-on scan health values", async () => {
    await expect(
      runScanCommand(".", {
        failOnScanHealth: "complete",
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("--fail-on-scan-health has an unsupported threshold");
  });

  it("requires fail-on when fail-on confidence is set", async () => {
    await expect(
      runScanCommand(".", {
        failOnConfidence: "high",
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("--fail-on-confidence has no severity gate");
  });

  it("requires fail-on when fail-on-new is set", async () => {
    await expect(
      runScanCommand(".", {
        baseline: tempPath("agentcsp-baseline.json"),
        failOnNew: true,
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("--fail-on-new has no severity gate");
  });

  it("requires a baseline when fail-on-new is set", async () => {
    await expect(
      runScanCommand(".", {
        failOn: "high",
        failOnNew: true,
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("--fail-on-new has no baseline");
  });

  it("fails on diagnostics only when explicitly requested", async () => {
    const root = await createDiagnosticsFixture();
    process.exitCode = undefined;
    await runScanCommand(root, {
      out: tempPath("agentcsp-cli-diagnostics-default-output"),
      format: "json",
      quiet: true
    });
    expect(process.exitCode).toBeUndefined();

    process.exitCode = undefined;
    await runScanCommand(root, {
      out: tempPath("agentcsp-cli-diagnostics-fail-output"),
      failOnDiagnostics: true,
      format: "json",
      quiet: true
    });
    expect(process.exitCode).toBe(3);
    process.exitCode = undefined;
  });

  it("fails on degraded scan health only when explicitly requested", async () => {
    const root = await createOversizedFileFixture();
    process.exitCode = undefined;
    await runScanCommand(root, {
      out: tempPath("agentcsp-cli-scan-health-default-output"),
      format: "json",
      maxFileSize: 16,
      quiet: true
    });
    expect(process.exitCode).toBeUndefined();

    process.exitCode = undefined;
    await runScanCommand(root, {
      out: tempPath("agentcsp-cli-scan-health-fail-output"),
      failOnScanHealth: "degraded",
      format: "json",
      maxFileSize: 16,
      quiet: true
    });
    expect(process.exitCode).toBe(3);
    process.exitCode = undefined;
  });

  it("emits diagnostics for explicitly missing policy configs", async () => {
    const root = await createPolicyConfigFixture();
    const outputPath = tempPath("agentcsp-cli-missing-policy-output");
    process.exitCode = undefined;
    await runScanCommand(root, {
      out: outputPath,
      config: "missing-agentcsp.yaml",
      format: "json",
      quiet: true
    });
    expect(process.exitCode).toBeUndefined();

    const manifest = JSON.parse(await fs.readFile(path.join(outputPath, "agent-manifest.json"), "utf8")) as {
      diagnostics: Array<{ code?: string; content_redacted?: boolean }>;
      scan_coverage?: { diagnostics_total?: number; diagnostics_warnings?: number };
    };
    expect(manifest.diagnostics).toEqual([
      expect.objectContaining({
        code: "POLICY_CONFIG_NOT_FOUND",
        content_redacted: true
      })
    ]);
    expect(manifest.scan_coverage).toMatchObject({
      diagnostics_total: 1,
      diagnostics_warnings: 1
    });
    process.exitCode = undefined;
  });

  it("resolves relative baseline paths from the scanned project root", async () => {
    const root = await createRelativeBaselineFixture();
    process.exitCode = undefined;
    await runScanCommand(root, {
      out: "scan-output",
      baseline: "baselines/agent-manifest.json",
      format: "json",
      quiet: true
    });

    const manifestPath = path.join(root, "scan-output", "agent-manifest.json");
    const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8")) as {
      baseline_comparison?: { baseline_path?: string; baseline_format?: string };
    };
    expect(manifest.baseline_comparison).toMatchObject({
      baseline_path: "baselines/agent-manifest.json",
      baseline_format: "manifest"
    });
    process.exitCode = undefined;
  });

  it("prints a compact receipt and verbose operational counters", async () => {
    const root = await createCliSummaryFixture();
    const outputPath = tempPath("agentcsp-cli-summary-output");
    const spy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    process.exitCode = undefined;

    await runScanCommand(root, {
      out: outputPath,
      format: "json",
      quiet: false,
      banner: false,
      verbose: true
    });

    const output = spy.mock.calls.map((call) => call.join(" ")).join("\n");
    expect(output).toContain("[PASS] 0 active finding(s), highest info; coverage complete; gate pass");
    expect(output).toContain("Findings: 0; attack paths: 0");
    expect(output).toContain("Files: 1 indexed, 0 oversized; diagnostics: 0");
    expect(output).toContain("Failed gates: none");
    expect(output).toContain("Manifest:");

    spy.mockRestore();
    process.exitCode = undefined;
  });
});

async function createDiagnosticsFixture(): Promise<string> {
  const root = tempPath("agentcsp-cli-diagnostics-fixture");
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(path.join(root, ".codex"), { recursive: true });
  await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
  await fs.writeFile(path.join(root, "mcp.json"), '{"mcpServers": {"bad": {"command": "run"', "utf8");
  await fs.writeFile(path.join(root, ".codex", "config.toml"), 'sandbox = "danger-full-access"\n[', "utf8");
  return root;
}

async function createPolicyConfigFixture(): Promise<string> {
  const root = tempPath("agentcsp-cli-policy-config-fixture");
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(root, { recursive: true });
  await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
  return root;
}

async function createOversizedFileFixture(): Promise<string> {
  const root = tempPath("agentcsp-cli-oversized-fixture");
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(root, { recursive: true });
  await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
  await fs.writeFile(path.join(root, "large-agent-config.md"), "x".repeat(128), "utf8");
  return root;
}

async function createRelativeBaselineFixture(): Promise<string> {
  const root = tempPath("agentcsp-cli-relative-baseline-fixture");
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(path.join(root, "baselines"), { recursive: true });
  await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
  await fs.writeFile(path.join(root, "baselines", "agent-manifest.json"), '{"findings": []}\n', "utf8");
  return root;
}

async function createCliSummaryFixture(): Promise<string> {
  const root = tempPath("agentcsp-cli-summary-fixture");
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(root, { recursive: true });
  await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
  return root;
}
