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
      scan_health: "degraded",
      scan_health_reasons: ["files_skipped_for_size"],
      files_seen: 4,
      files_indexed: 4,
      files_skipped_for_size: 1,
      skipped_path_limit: 50,
      oversized_file_paths: ["large.md"],
      oversized_file_paths_truncated: false,
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
    expect(result.coverage.scan_health).toBe("incomplete");
    expect(result.coverage.scan_health_reasons).toEqual(["max_files_reached"]);
    expect(result.coverage.files_indexed).toBe(1);
  });

  it("bounds oversized file path previews while preserving exact counts", async () => {
    const root = "/private/tmp/agentcsp-oversized-preview-fixture";
    await fs.rm(root, { recursive: true, force: true });
    await fs.mkdir(root, { recursive: true });
    await Promise.all(
      Array.from({ length: 55 }, (_, index) =>
        fs.writeFile(path.join(root, `large_${index.toString().padStart(3, "0")}.md`), "oversized\n", "utf8")
      )
    );

    const result = await walkProjectWithCoverage({
      root_path: root,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 4,
      max_files: 100,
      quiet: true
    });

    expect(result.coverage.files_skipped_for_size).toBe(55);
    expect(result.coverage.skipped_path_limit).toBe(50);
    expect(result.coverage.oversized_file_paths).toHaveLength(50);
    expect(result.coverage.oversized_file_paths[0]).toBe("large_000.md");
    expect(result.coverage.oversized_file_paths.at(-1)).toBe("large_049.md");
    expect(result.coverage.oversized_file_paths_truncated).toBe(true);
  });

  it("ignores the configured output directory when it is inside the scan root", async () => {
    const root = await createCustomOutputFixture();
    const result = await walkProjectWithCoverage({
      root_path: root,
      output_path: path.join(root, "security", "agentcsp-output"),
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024,
      max_files: 100,
      quiet: true
    });

    expect(result.files.map((file) => file.relativePath)).toEqual(["AGENTS.md"]);
    expect(result.coverage).toMatchObject({
      files_seen: 1,
      files_indexed: 1,
      directories_skipped_by_ignore: 1
    });
  });

  it("does not add an output-directory ignore when output is outside the scan root", async () => {
    const root = await createCustomOutputFixture();
    const result = await walkProjectWithCoverage({
      root_path: root,
      output_path: "/private/tmp/agentcsp-outside-root-output",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024,
      max_files: 100,
      quiet: true
    });

    expect(result.files.map((file) => file.relativePath)).toEqual([
      "AGENTS.md",
      "security/agentcsp-output/agent-manifest.json",
      "security/agentcsp-output/findings.json"
    ]);
    expect(result.coverage.directories_skipped_by_ignore).toBe(0);
  });

  it("ignores in-root output directories whose names begin with two dots", async () => {
    const root = await createDotPrefixedOutputFixture();
    const result = await walkProjectWithCoverage({
      root_path: root,
      output_path: path.join(root, "..agentcsp-output"),
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024,
      max_files: 100,
      quiet: true
    });

    expect(result.files.map((file) => file.relativePath)).toEqual(["AGENTS.md"]);
    expect(result.coverage.directories_skipped_by_ignore).toBe(1);
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

async function createCustomOutputFixture(): Promise<string> {
  const root = "/private/tmp/agentcsp-custom-output-fixture";
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(path.join(root, "security", "agentcsp-output"), { recursive: true });
  await fs.writeFile(path.join(root, "AGENTS.md"), "review only\n", "utf8");
  await fs.writeFile(path.join(root, "security", "agentcsp-output", "agent-manifest.json"), '{"old": true}\n', "utf8");
  await fs.writeFile(path.join(root, "security", "agentcsp-output", "findings.json"), "[]\n", "utf8");
  return root;
}

async function createDotPrefixedOutputFixture(): Promise<string> {
  const root = "/private/tmp/agentcsp-dot-prefixed-output-fixture";
  await fs.rm(root, { recursive: true, force: true });
  await fs.mkdir(path.join(root, "..agentcsp-output"), { recursive: true });
  await fs.writeFile(path.join(root, "AGENTS.md"), "review only\n", "utf8");
  await fs.writeFile(path.join(root, "..agentcsp-output", "agent-manifest.json"), '{"old": true}\n', "utf8");
  return root;
}
