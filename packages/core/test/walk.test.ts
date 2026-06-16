import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { walkProjectWithCoverage } from "../src/scanner/walk.js";

describe("walkProjectWithCoverage", () => {
  it("reports ignored, hidden, log, and oversized scan coverage", async () => {
    const root = await createCoverageFixture();
    const result = await walkProjectWithCoverage({
      root_path: root,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 32,
      max_files: 100,
      quiet: true
    });

    expect(result.files.map((file) => file.relativePath)).toEqual([
      ".agentcspignore",
      ".codex/config.toml",
      "AGENTS.md",
      "large.md"
    ]);
    expect(result.coverage).toMatchObject({
      files_seen: 4,
      files_indexed: 4,
      files_skipped_for_size: 1,
      files_skipped_by_ignore: 1,
      directories_skipped_by_ignore: 5,
      directories_skipped_hidden: 1,
      directories_skipped_logs: 1,
      max_files_reached: false,
      max_files: 100,
      max_file_size_bytes: 32
    });
  });

  it("reports when the max file limit is reached", async () => {
    const root = await createCoverageFixture();
    const result = await walkProjectWithCoverage({
      root_path: root,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024,
      max_files: 1,
      quiet: true
    });

    expect(result.files).toHaveLength(1);
    expect(result.coverage.max_files_reached).toBe(true);
    expect(result.coverage.files_indexed).toBe(1);
  });
});

async function createCoverageFixture(): Promise<string> {
  const root = "/private/tmp/agentcsp-walk-coverage-fixture";
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(path.join(root, ".codex"), { recursive: true });
  await fs.mkdir(path.join(root, ".agentcsp"), { recursive: true });
  await fs.mkdir(path.join(root, ".agentcsp-debug"), { recursive: true });
  await fs.mkdir(path.join(root, ".agentcsp_tmp"), { recursive: true });
  await fs.mkdir(path.join(root, ".hidden"), { recursive: true });
  await fs.mkdir(path.join(root, "dist"), { recursive: true });
  await fs.mkdir(path.join(root, "logs"), { recursive: true });
  await fs.mkdir(path.join(root, "node_modules", "pkg"), { recursive: true });
  await fs.writeFile(path.join(root, ".agentcspignore"), "ignored.txt\n", "utf8");
  await fs.writeFile(path.join(root, ".agentcsp", "agent-manifest.json"), '{"old": true}\n', "utf8");
  await fs.writeFile(path.join(root, ".agentcsp-debug", "findings.json"), "[]\n", "utf8");
  await fs.writeFile(path.join(root, ".agentcsp_tmp", "report.md"), "# old report\n", "utf8");
  await fs.writeFile(path.join(root, ".codex", "config.toml"), "sandbox = \"workspace-write\"\n", "utf8");
  await fs.writeFile(path.join(root, ".hidden", "secret.md"), "hidden\n", "utf8");
  await fs.writeFile(path.join(root, "AGENTS.md"), "review only\n", "utf8");
  await fs.writeFile(path.join(root, "dist", "bundle.js"), "generated\n", "utf8");
  await fs.writeFile(path.join(root, "ignored.txt"), "ignored\n", "utf8");
  await fs.writeFile(path.join(root, "large.md"), "this file is intentionally larger than ten bytes\n", "utf8");
  await fs.writeFile(path.join(root, "logs", "agent.log"), "log\n", "utf8");
  await fs.writeFile(path.join(root, "node_modules", "pkg", "index.js"), "module.exports = {}\n", "utf8");
  return root;
}
