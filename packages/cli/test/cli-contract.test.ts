import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const cliPath = path.resolve("packages/cli/dist/index.js");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

describe("CLI process contract", () => {
  it("classifies missing input as exit 2 without leaking a raw OS error", () => {
    const result = runCli(["scan", path.join(os.tmpdir(), "agentcsp-path-that-does-not-exist"), "--quiet"]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("AGENTCSP-E1001 input error");
    expect(result.stderr).toContain("Problem:");
    expect(result.stderr).toContain("Fix:");
    expect(result.stderr).toContain("Help:");
    expect(result.stderr).not.toContain("ENOENT");
  });

  it("emits the same classified error as one JSON record", () => {
    const result = runCli([
      "scan",
      path.join(os.tmpdir(), "agentcsp-path-that-does-not-exist-json"),
      "--quiet",
      "--log-format",
      "json"
    ]);
    expect(result.status).toBe(2);
    expect(JSON.parse(result.stderr)).toMatchObject({
      type: "agentcsp_error",
      code: "AGENTCSP-E1001",
      category: "input"
    });
  });

  it("rejects an invalid option dependency as configuration exit 2", () => {
    const result = runCli(["scan", ".", "--fail-on-new", "--quiet"]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("AGENTCSP-E1002 configuration error");
  });

  it("rejects partially numeric and unsafe integer limits", () => {
    for (const value of ["1junk", "1.5", "9007199254740992"]) {
      const result = runCli(["scan", ".", "--max-files", value, "--quiet"]);
      expect(result.status).toBe(2);
      expect(result.stderr).toContain("AGENTCSP-E1002 configuration error");
    }
  });

  it("honors the equals form of machine-readable error output", () => {
    const result = runCli(["scan", ".", "--max-files", "invalid", "--log-format=json"]);
    expect(result.status).toBe(2);
    expect(JSON.parse(result.stderr)).toMatchObject({
      type: "agentcsp_error",
      code: "AGENTCSP-E1002",
      category: "configuration"
    });
  });

  it("classifies missing and malformed scan baselines as operator errors", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentcsp-cli-baseline-"));
    temporaryDirectories.push(root);
    await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");

    const missing = runCli(["scan", root, "--baseline", "missing.json", "--quiet"]);
    expect(missing.status).toBe(2);
    expect(missing.stderr).toContain("AGENTCSP-E1001 input error");

    await fs.writeFile(path.join(root, "malformed.json"), "{not-json}\n", "utf8");
    const malformed = runCli(["scan", root, "--baseline", "malformed.json", "--quiet"]);
    expect(malformed.status).toBe(2);
    expect(malformed.stderr).toContain("AGENTCSP-E1002 configuration error");

    const lifecycle = runCli([
      "baseline",
      "create",
      path.join(root, "malformed.json"),
      "--out",
      path.join(root, "baseline.json")
    ]);
    expect(lifecycle.status).toBe(2);
    expect(lifecycle.stderr).toContain("AGENTCSP-E1002 configuration error");
  });

  it("prints machine-readable version and doctor contracts", () => {
    const version = runCli(["version", "--json"]);
    const doctor = runCli(["doctor", "--json"]);
    expect(version.status).toBe(0);
    expect(JSON.parse(version.stdout)).toMatchObject({
      type: "agentcsp_version",
      version: "0.2.0",
      manifest_schema: "0.2.0",
      finding_identity: "agentcsp-finding-v1"
    });
    expect(doctor.status).toBe(0);
    expect(JSON.parse(doctor.stdout)).toMatchObject({ type: "agentcsp_doctor", status: "pass" });
  });

  it("runs the default recommended scan and publishes a completion receipt", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentcsp-cli-contract-"));
    temporaryDirectories.push(root);
    await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
    const outputPath = path.join(root, ".agentcsp-test");

    const result = runCli([
      "scan",
      root,
      "--out",
      outputPath,
      "--format",
      "json,md",
      "--no-banner",
      "--log-format",
      "json"
    ]);

    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      type: "agentcsp_scan_receipt",
      profile: "advisory"
    });
    const manifest = JSON.parse(await fs.readFile(path.join(outputPath, "agent-manifest.json"), "utf8")) as {
      metadata?: {
        config?: { ruleset?: string; max_directories?: number; max_entries_per_directory?: number };
        rule_pack?: { built_in_rules?: number };
      };
    };
    expect(manifest.metadata?.config?.ruleset).toBe("recommended");
    expect(manifest.metadata?.config?.max_directories).toBe(10_000);
    expect(manifest.metadata?.config?.max_entries_per_directory).toBe(10_000);
    expect(manifest.metadata?.rule_pack?.built_in_rules).toBe(17);
    expect(JSON.parse(await fs.readFile(path.join(outputPath, "receipt.json"), "utf8"))).toMatchObject({
      status: "complete",
      artifact_profile: "portable"
    });
  });
});

function runCli(args: string[]): ReturnType<typeof spawnSync> & { stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [cliPath, ...args], {
    cwd: path.resolve("."),
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" }
  });
  if (result.error) throw result.error;
  return result as ReturnType<typeof spawnSync> & { stdout: string; stderr: string };
}
