import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { scanProject } from "../src/scanner/scan.js";

const fixtureRoot = path.resolve("examples/vulnerable-agent");

describe("policy suppressions", () => {
  it("marks active suppressions and excludes them from fail gates", async () => {
    const policyPath = await writePolicy("active", "2999-12-31T23:59:59.000Z");
    const result = await scanProject({
      root_path: fixtureRoot,
      output_path: "/private/tmp/agentcsp-suppression-active",
      config_path: policyPath,
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true,
      fail_on: "critical"
    });

    const suppressed = result.findings.filter((finding) => finding.suppression?.status === "active");
    expect(suppressed.length).toBeGreaterThan(0);
    expect(suppressed.every((finding) => finding.suppression?.owner === "security@example.com")).toBe(true);
    expect(result.manifest.static_blast_radius?.active_suppressions).toBe(suppressed.length);
    expect(result.shouldFail).toBe(false);
    expect(result.reportMarkdown).toContain("Suppressed Findings");
  });

  it("keeps expired suppressions as active risk", async () => {
    const policyPath = await writePolicy("expired", "2000-01-01T00:00:00.000Z");
    const result = await scanProject({
      root_path: fixtureRoot,
      output_path: "/private/tmp/agentcsp-suppression-expired",
      config_path: policyPath,
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true,
      fail_on: "critical"
    });

    const expired = result.findings.filter((finding) => finding.suppression?.status === "expired");
    expect(expired.length).toBeGreaterThan(0);
    expect(result.manifest.static_blast_radius?.expired_suppressions).toBe(expired.length);
    expect(result.manifest.static_blast_radius?.active_suppressions).toBe(0);
    expect(result.shouldFail).toBe(true);
  });
});

async function writePolicy(name: string, expiresAt: string): Promise<string> {
  const policyPath = `/private/tmp/agentcsp-${name}-policy.yaml`;
  await fs.writeFile(
    policyPath,
    [
      'schema_version: "0.1"',
      "suppressions:",
      `  - id: "${name}-critical-demo-risk"`,
      '    reason: "Accepted for fixture regression only."',
      '    owner: "security@example.com"',
      `    expires_at: "${expiresAt}"`,
      "    match:",
      '      severity: "critical"',
      ""
    ].join("\n"),
    "utf8"
  );
  return policyPath;
}
