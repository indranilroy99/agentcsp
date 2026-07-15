import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { scanProject } from "../src/scanner/scan.js";
import { tempPath } from "./temp-path.js";

describe("scan output paths", () => {
  it("resolves relative output paths from the scan root", async () => {
    const root = await createOutputFixture();
    const result = await scanProject({
      root_path: root,
      output_path: "security/agentcsp-output",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    const expectedOutputPath = path.join(root, "security", "agentcsp-output");
    expect(result.outputFiles.manifest).toBe(path.join(expectedOutputPath, "agent-manifest.json"));
    expect(result.outputFiles.findings).toBe(path.join(expectedOutputPath, "findings.json"));
    expect(result.outputFiles.report).toBe(path.join(expectedOutputPath, "report.md"));
    expect(result.outputFiles.sarif).toBe(path.join(expectedOutputPath, "agentcsp.sarif"));
    await expect(fs.stat(result.outputFiles.manifest!)).resolves.toMatchObject({ isFile: expect.any(Function) });
    await expect(fs.stat(result.outputFiles.report!)).resolves.toMatchObject({ isFile: expect.any(Function) });

    expect(result.manifest.instructions.map((surface) => surface.path)).toEqual(["AGENTS.md"]);
    expect(result.manifest.scan_coverage).toMatchObject({
      directories_skipped_by_ignore: 1,
      files_indexed: 1
    });
  });

  it("preserves absolute output paths", async () => {
    const root = await createOutputFixture();
    const outputPath = tempPath("agentcsp-absolute-output-fixture-result");
    await fs.rm(outputPath, { recursive: true, force: true });
    const result = await scanProject({
      root_path: root,
      output_path: outputPath,
      formats: ["json"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    expect(result.outputFiles.manifest).toBe(path.join(outputPath, "agent-manifest.json"));
    await expect(fs.stat(result.outputFiles.manifest!)).resolves.toMatchObject({ isFile: expect.any(Function) });
  });

  it("rejects the scan root as the output directory", async () => {
    const root = await createOutputFixture();
    await expect(
      scanProject({
        root_path: root,
        output_path: ".",
        formats: ["json"],
        include_hidden: true,
        include_logs: false,
        max_file_size_bytes: 1024 * 1024,
        max_files: 5000,
        quiet: true
      })
    ).rejects.toThrow("output_path must be a directory outside or below the scan root");
  });

  it("emits a stable manifest fingerprint across equivalent scan roots", async () => {
    const firstRoot = await createFingerprintFixture(tempPath("agentcsp-fingerprint-a"));
    const secondRoot = await createFingerprintFixture(tempPath("agentcsp-fingerprint-b"));

    const first = await scanProject({
      root_path: firstRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const second = await scanProject({
      root_path: secondRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    expect(first.manifest.metadata.root_path).toBe(".");
    expect(second.manifest.metadata.root_path).toBe(".");
    expect(first.manifest.metadata.generated_at).not.toBe("");
    expect(second.manifest.metadata.generated_at).not.toBe("");
    expect(first.manifest.metadata.fingerprint?.value).toBe(second.manifest.metadata.fingerprint?.value);
    expect(first.manifest.metadata.fingerprint?.value).toMatch(/^[a-f0-9]{64}$/u);
    expect(first.reportMarkdown).toContain(`- Manifest fingerprint: \`${first.manifest.metadata.fingerprint?.value}\``);
  });
});

async function createOutputFixture(): Promise<string> {
  const root = tempPath("agentcsp-output-path-fixture");
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(path.join(root, "security", "agentcsp-output"), { recursive: true });
  await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
  return root;
}

async function createFingerprintFixture(root: string): Promise<string> {
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(root, { recursive: true });
  await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
  return root;
}
