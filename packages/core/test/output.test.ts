import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { scanProject } from "../src/scanner/scan.js";

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
    const outputPath = "/private/tmp/agentcsp-absolute-output-fixture-result";
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
});

async function createOutputFixture(): Promise<string> {
  const root = "/private/tmp/agentcsp-output-path-fixture";
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(path.join(root, "security", "agentcsp-output"), { recursive: true });
  await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
  await fs.writeFile(path.join(root, "security", "agentcsp-output", "agent-manifest.json"), '{"old": true}\n', "utf8");
  return root;
}
