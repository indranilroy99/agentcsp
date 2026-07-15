import { execFileSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { findSecretExposures, runGuardCheck, runGuardInstall, runGuardUninstall } from "../src/commands/guard.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  process.exitCode = undefined;
  vi.restoreAllMocks();
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

describe("Git secret guard", () => {
  it("detects high-confidence secret material without returning matched values", () => {
    const githubToken = ["ghp_", "a".repeat(36)].join("");
    const awsKey = ["AKIA", "A".repeat(16)].join("");
    const genericSecret = "qwertyuiopasdfghjklzxcvbnm";
    const diff = [
      "diff --git a/.env b/.env",
      "+++ b/.env",
      `+GITHUB_TOKEN=${githubToken}`,
      `+AWS_ACCESS_KEY_ID=${awsKey}`,
      `+SERVICE_SECRET=${genericSecret}`,
      "+-----BEGIN PRIVATE KEY-----"
    ].join("\n");

    const findings = findSecretExposures(diff);

    expect(findings.map((finding) => finding.secret_type)).toEqual(
      expect.arrayContaining(["environment_file", "github_token", "aws_access_key", "generic_secret_assignment", "private_key"])
    );
    expect(findings.every((finding) => finding.fingerprint.startsWith("sha256:"))).toBe(true);
    expect(JSON.stringify(findings)).not.toContain(githubToken);
    expect(JSON.stringify(findings)).not.toContain(awsKey);
    expect(JSON.stringify(findings)).not.toContain(genericSecret);
  });

  it("allows template environment files and variable references", () => {
    const findings = findSecretExposures(
      [
        "diff --git a/.env.example b/.env.example",
        "+++ b/.env.example",
        "+API_TOKEN=${API_TOKEN}",
        "+SERVICE_SECRET=replace-me"
      ].join("\n")
    );
    expect(findings).toEqual([]);
  });

  it("installs managed hooks, preserves an existing hook, blocks staged secrets, and restores on uninstall", async () => {
    const repository = await createGitRepository();
    const hooksDirectory = path.join(repository, "managed-hooks");
    git(repository, ["config", "--local", "core.hooksPath", "managed-hooks"]);
    await fs.mkdir(hooksDirectory, { recursive: true });
    const originalHook = path.join(hooksDirectory, "pre-commit");
    await fs.writeFile(originalHook, "#!/bin/sh\nexit 0\n", { encoding: "utf8", mode: 0o755 });
    await fs.chmod(originalHook, 0o755);

    const output = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    await runGuardInstall(repository);

    const managedHook = await fs.readFile(originalHook, "utf8");
    expect(managedHook).toContain("AGENTCSP_GIT_GUARD_V1");
    expect(managedHook).toContain("guard check --hook pre-commit");
    expect(await fs.readFile(`${originalHook}.agentcsp-user`, "utf8")).toBe("#!/bin/sh\nexit 0\n");
    expect(await fs.readFile(path.join(hooksDirectory, "pre-push"), "utf8")).toContain("mktemp");

    const leakedValue = "qwertyuiopasdfghjklzxcvbnm";
    await fs.writeFile(path.join(repository, "settings.env"), `SERVICE_TOKEN=${leakedValue}\n`, "utf8");
    git(repository, ["add", "settings.env"]);
    await runGuardCheck(repository, { hook: "pre-commit" });

    expect(process.exitCode).toBe(1);
    expect(output.mock.calls.flat().join("\n")).not.toContain(leakedValue);
    expect(errors.mock.calls.flat().join("\n")).not.toContain(leakedValue);

    await runGuardUninstall(repository);
    expect(await fs.readFile(originalHook, "utf8")).toBe("#!/bin/sh\nexit 0\n");
    expect(await fs.stat(path.join(hooksDirectory, "pre-push")).then(() => false, () => true)).toBe(true);
  });
});

async function createGitRepository(): Promise<string> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentcsp-guard-"));
  temporaryDirectories.push(directory);
  git(directory, ["init"]);
  git(directory, ["config", "user.email", "guard@example.invalid"]);
  git(directory, ["config", "user.name", "AgentCSP Guard Test"]);
  return directory;
}

function git(cwd: string, args: string[]): void {
  execFileSync("git", args, { cwd, stdio: "ignore" });
}
