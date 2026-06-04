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
    expect(result.manifest.attack_paths.length).toBeLessThanOrEqual(15);
    expect(result.manifest.static_blast_radius?.critical_attack_paths).toBeGreaterThan(0);
    expect(result.manifest.attack_paths.every((path) => path.evidence.every((item) => item.redacted))).toBe(true);

    const influenceEdges = result.manifest.relationships.filter((edge) => edge.relation === "influences");
    expect(influenceEdges.length).toBeGreaterThan(0);
    expect(influenceEdges.every((edge) => edge.reason.includes("Specific context signal"))).toBe(true);
    expect(result.manifest.relationships.some((edge) => edge.source.path === "rag")).toBe(false);
    expect(result.manifest.relationships.some((edge) => edge.source.path === "memory")).toBe(false);
    expect(
      result.manifest.attack_paths.some(
        (attackPath) =>
          attackPath.source.path === "rag/customer-note.md" &&
          attackPath.target.name === "publish_summary" &&
          attackPath.reason.includes("tool directive")
      )
    ).toBe(true);
  });

  it("correlates generated-state replay with privileged capability paths when logs are included", async () => {
    const result = await scanProject({
      root_path: path.resolve("examples/vulnerable-agent"),
      output_path: "/private/tmp/agentcsp-graph-log-test-output",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: true,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    const replayPath = result.manifest.attack_paths.find(
      (attackPath) =>
        attackPath.source.path === "logs/session-transcript.txt" &&
        attackPath.reason.includes("generated-state replay")
    );
    expect(replayPath).toBeDefined();
    expect(replayPath?.severity).toBe("critical");
    expect(replayPath?.confidence).toBe("very_high");
    expect(JSON.stringify(replayPath)).not.toContain("Ignore previous repository instructions");
  });

  it("does not create graph paths from negated safety policy text", async () => {
    const result = await scanProject({
      root_path: path.resolve("examples/safe-agent"),
      output_path: "/private/tmp/agentcsp-graph-safe-test-output",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    expect(result.manifest.relationships).toHaveLength(0);
    expect(result.manifest.attack_paths).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
  });
});
