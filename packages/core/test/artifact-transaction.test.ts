import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { publishArtifactSet } from "../src/reports/artifact-transaction.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

describe("artifact transactions", () => {
  it("publishes a complete private generation with verified digests", async () => {
    const base = await temporaryDirectory();
    const outputPath = path.join(base, ".agentcsp");
    const result = await publishArtifactSet({
      outputPath,
      artifactProfile: "portable",
      artifacts: [
        { name: "report.md", content: "# Report" },
        { name: "findings.json", content: "[]" }
      ]
    });

    const findingsContent = await fs.readFile(path.join(outputPath, "findings.json"), "utf8");
    expect(result.receipt.status).toBe("complete");
    expect(result.receipt.files.map((file) => file.name)).toEqual(["findings.json", "report.md"]);
    expect(result.receipt.files.find((file) => file.name === "findings.json")?.sha256).toBe(
      createHash("sha256").update(findingsContent).digest("hex")
    );
    expect(JSON.parse(await fs.readFile(result.receiptPath, "utf8"))).toEqual(result.receipt);
    await expect(fs.readFile(path.join(outputPath, ".agentcsp-owned"), "utf8")).resolves.toBe(
      "agentcsp-artifact-set-v1\n"
    );
    if (process.platform !== "win32") {
      expect((await fs.stat(path.join(outputPath, "findings.json"))).mode & 0o777).toBe(0o600);
      expect((await fs.stat(outputPath)).mode & 0o777).toBe(0o700);
    }
  });

  it("replaces the previous generation without retaining stale artifacts", async () => {
    const base = await temporaryDirectory();
    const outputPath = path.join(base, ".agentcsp");
    await publishArtifactSet({
      outputPath,
      artifactProfile: "portable",
      artifacts: [{ name: "stale.json", content: "{}" }]
    });

    await publishArtifactSet({
      outputPath,
      artifactProfile: "portable",
      artifacts: [{ name: "agent-manifest.json", content: "{}" }]
    });

    await expect(fs.access(path.join(outputPath, "stale.json"))).rejects.toMatchObject({ code: "ENOENT" });
    await expect(fs.access(path.join(outputPath, "receipt.json"))).resolves.toBeUndefined();
  });

  it("claims an existing empty output directory", async () => {
    const base = await temporaryDirectory();
    const outputPath = path.join(base, ".agentcsp");
    await fs.mkdir(outputPath);

    await publishArtifactSet({
      outputPath,
      artifactProfile: "portable",
      artifacts: [{ name: "findings.json", content: "[]" }]
    });

    await expect(fs.readFile(path.join(outputPath, "findings.json"), "utf8")).resolves.toBe("[]\n");
    await expect(fs.readFile(path.join(outputPath, ".agentcsp-owned"), "utf8")).resolves.toBe(
      "agentcsp-artifact-set-v1\n"
    );
  });

  it("refuses to replace an unowned directory and preserves its files", async () => {
    const base = await temporaryDirectory();
    const outputPath = path.join(base, "user-data");
    await fs.mkdir(outputPath);
    await fs.writeFile(path.join(outputPath, "important.txt"), "keep\n", "utf8");

    await expect(
      publishArtifactSet({
        outputPath,
        artifactProfile: "portable",
        artifacts: [{ name: "findings.json", content: "[]" }]
      })
    ).rejects.toMatchObject({ code: "AGENTCSP-E3006", kind: "integrity" });

    await expect(fs.readFile(path.join(outputPath, "important.txt"), "utf8")).resolves.toBe("keep\n");
    await expect(fs.access(path.join(outputPath, "findings.json"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("refuses to replace an owned generation containing unknown files", async () => {
    const base = await temporaryDirectory();
    const outputPath = path.join(base, ".agentcsp");
    await publishArtifactSet({
      outputPath,
      artifactProfile: "portable",
      artifacts: [{ name: "findings.json", content: "[]" }]
    });
    await fs.writeFile(path.join(outputPath, "analyst-notes.txt"), "preserve\n", "utf8");

    await expect(
      publishArtifactSet({
        outputPath,
        artifactProfile: "portable",
        artifacts: [{ name: "agent-manifest.json", content: "{}" }]
      })
    ).rejects.toMatchObject({ code: "AGENTCSP-E3006" });

    await expect(fs.readFile(path.join(outputPath, "analyst-notes.txt"), "utf8")).resolves.toBe("preserve\n");
    await expect(fs.readFile(path.join(outputPath, "findings.json"), "utf8")).resolves.toBe("[]\n");
  });

  it("refuses to replace a tampered managed generation", async () => {
    const base = await temporaryDirectory();
    const outputPath = path.join(base, ".agentcsp");
    await publishArtifactSet({
      outputPath,
      artifactProfile: "portable",
      artifacts: [{ name: "findings.json", content: "[]" }]
    });
    await fs.writeFile(path.join(outputPath, "findings.json"), "[{}]\n", "utf8");

    await expect(
      publishArtifactSet({
        outputPath,
        artifactProfile: "portable",
        artifacts: [{ name: "agent-manifest.json", content: "{}" }]
      })
    ).rejects.toMatchObject({ code: "AGENTCSP-E3006" });

    await expect(fs.readFile(path.join(outputPath, "findings.json"), "utf8")).resolves.toBe("[{}]\n");
  });

  it("refuses to replace a symlinked output path", async () => {
    if (process.platform === "win32") return;
    const base = await temporaryDirectory();
    const targetPath = path.join(base, "target");
    const outputPath = path.join(base, ".agentcsp");
    await fs.mkdir(targetPath);
    await fs.writeFile(path.join(targetPath, "important.txt"), "keep\n", "utf8");
    await fs.symlink(targetPath, outputPath, "dir");

    await expect(
      publishArtifactSet({
        outputPath,
        artifactProfile: "portable",
        artifacts: [{ name: "findings.json", content: "[]" }]
      })
    ).rejects.toMatchObject({ code: "AGENTCSP-E3006" });

    expect((await fs.lstat(outputPath)).isSymbolicLink()).toBe(true);
    await expect(fs.readFile(path.join(targetPath, "important.txt"), "utf8")).resolves.toBe("keep\n");
  });

  it("keeps the previous generation when staged content is invalid", async () => {
    const base = await temporaryDirectory();
    const outputPath = path.join(base, ".agentcsp");
    await fs.mkdir(outputPath);
    await fs.writeFile(path.join(outputPath, "previous.txt"), "keep\n", "utf8");

    await expect(
      publishArtifactSet({
        outputPath,
        artifactProfile: "portable",
        artifacts: [{ name: "findings.json", content: "not-json" }]
      })
    ).rejects.toMatchObject({ code: "AGENTCSP-E4003" });

    await expect(fs.readFile(path.join(outputPath, "previous.txt"), "utf8")).resolves.toBe("keep\n");
  });

  it("rejects concurrent writers for the same output", async () => {
    const base = await temporaryDirectory();
    const outputPath = path.join(base, ".agentcsp");
    const lockPath = path.join(base, ".agentcsp.lock");
    await fs.writeFile(lockPath, "active\n", "utf8");

    await expect(
      publishArtifactSet({
        outputPath,
        artifactProfile: "portable",
        artifacts: [{ name: "findings.json", content: "[]" }]
      })
    ).rejects.toMatchObject({ code: "AGENTCSP-E3002", kind: "integrity" });

    await expect(fs.readFile(lockPath, "utf8")).resolves.toBe("active\n");
  });
});

async function temporaryDirectory(): Promise<string> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentcsp-artifacts-"));
  temporaryDirectories.push(directory);
  return directory;
}
