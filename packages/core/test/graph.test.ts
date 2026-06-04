import { describe, expect, it } from "vitest";
import path from "node:path";
import { scanProject } from "../src/scanner/scan.js";

describe("static graph", () => {
  it("generates bounded, high-signal attack paths", async () => {
    const result = await scanProject({
      root_path: path.resolve("examples/vulnerable-agent"),
      output_path: "/private/tmp/agentcsp-graph-test-output",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    expect(result.manifest.relationships.length).toBeGreaterThan(0);
    expect(result.manifest.attack_paths.length).toBeGreaterThan(0);
    expect(result.manifest.attack_paths.length).toBeLessThanOrEqual(25);
    expect(result.manifest.static_blast_radius?.critical_attack_paths).toBeGreaterThan(0);
    expect(result.manifest.attack_paths.every((path) => path.evidence.every((item) => item.redacted))).toBe(true);
  });
});
