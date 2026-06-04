import { describe, expect, it } from "vitest";
import path from "node:path";
import { scanProject } from "../src/scanner/scan.js";

describe("scanProject", () => {
  it("emits a manifest, findings, and a static blast-radius report", async () => {
    const result = await scanProject({
      root_path: path.resolve("examples/vulnerable-agent"),
      output_path: "/private/tmp/agentcsp-test-output",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    expect(result.manifest.metadata.config.secret_values_collected).toBe(false);
    expect(result.manifest.static_blast_radius?.title).toBe("Static Blast-Radius Summary");
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.outputFiles.sarif).toBeDefined();
    expect(result.reportMarkdown).toContain("Recommended Controls");
    expect(result.reportMarkdown).toContain("Policy actions in this MVP are recommended controls");
  });
});
