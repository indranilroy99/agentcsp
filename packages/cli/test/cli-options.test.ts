import { describe, expect, it, vi } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { runScanCommand } from "../src/commands/scan.js";

describe("cli options", () => {
  it("rejects unsupported fail-on values", async () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    await expect(
      runScanCommand(".", {
        failOn: "info",
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("--fail-on must be one of critical, high, medium, or low");
    spy.mockRestore();
  });

  it("rejects unsupported output formats", async () => {
    await expect(
      runScanCommand(".", {
        format: "json,xml",
        quiet: true
      })
    ).rejects.toThrow("Expected json,md,sarif");
  });

  it("rejects unsupported fail-on confidence values", async () => {
    await expect(
      runScanCommand(".", {
        failOn: "high",
        failOnConfidence: "certain",
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("--fail-on-confidence must be one of very_high, high, medium, or low");
  });

  it("requires fail-on when fail-on confidence is set", async () => {
    await expect(
      runScanCommand(".", {
        failOnConfidence: "high",
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("--fail-on-confidence requires --fail-on");
  });

  it("requires fail-on when fail-on-new is set", async () => {
    await expect(
      runScanCommand(".", {
        baseline: "/private/tmp/agentcsp-baseline.json",
        failOnNew: true,
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("--fail-on-new requires --fail-on");
  });

  it("requires a baseline when fail-on-new is set", async () => {
    await expect(
      runScanCommand(".", {
        failOn: "high",
        failOnNew: true,
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("--fail-on-new requires --baseline");
  });

  it("fails on diagnostics only when explicitly requested", async () => {
    const root = await createDiagnosticsFixture();
    process.exitCode = undefined;
    await runScanCommand(root, {
      out: "/private/tmp/agentcsp-cli-diagnostics-default-output",
      format: "json",
      quiet: true
    });
    expect(process.exitCode).toBeUndefined();

    process.exitCode = undefined;
    await runScanCommand(root, {
      out: "/private/tmp/agentcsp-cli-diagnostics-fail-output",
      failOnDiagnostics: true,
      format: "json",
      quiet: true
    });
    expect(process.exitCode).toBe(1);
    process.exitCode = undefined;
  });
});

async function createDiagnosticsFixture(): Promise<string> {
  const root = "/private/tmp/agentcsp-cli-diagnostics-fixture";
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(path.join(root, ".codex"), { recursive: true });
  await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
  await fs.writeFile(path.join(root, "mcp.json"), '{"mcpServers": {"bad": {"command": "run"', "utf8");
  await fs.writeFile(path.join(root, ".codex", "config.toml"), 'sandbox = "danger-full-access"\n[', "utf8");
  return root;
}
