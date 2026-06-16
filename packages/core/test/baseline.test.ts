import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { scanProject } from "../src/scanner/scan.js";

const fixtureRoot = path.resolve("examples/vulnerable-agent");

describe("baseline comparison", () => {
  it("marks unchanged findings as existing when scanning against a manifest baseline", async () => {
    const baseline = await scanProject({
      root_path: fixtureRoot,
      output_path: "/private/tmp/agentcsp-baseline-source",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    const result = await scanProject({
      root_path: fixtureRoot,
      output_path: "/private/tmp/agentcsp-baseline-existing",
      baseline_path: baseline.outputFiles.manifest,
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true,
      fail_on: "critical",
      fail_on_confidence: "very_high",
      fail_on_new: true
    });

    expect(result.shouldFail).toBe(false);
    expect(result.manifest.baseline_comparison).toMatchObject({
      baseline_format: "manifest",
      current_findings: baseline.findings.length,
      baseline_findings: baseline.findings.length,
      new_findings: 0,
      existing_findings: baseline.findings.length,
      resolved_findings: 0
    });
    expect(result.findings.every((finding) => finding.baseline_status === "existing")).toBe(true);
    expect(result.reportMarkdown).toContain("## Baseline Comparison");
    expect(result.reportMarkdown).toContain("No new findings were introduced.");
    const sarif = JSON.parse(await fs.readFile(result.outputFiles.sarif!, "utf8")) as {
      runs: Array<{
        results: Array<{ baselineState?: string }>;
        properties?: { agentcsp_baseline_comparison?: { new_findings?: number } };
      }>;
    };
    expect(sarif.runs[0]?.results.every((item) => item.baselineState === "unchanged")).toBe(true);
    expect(sarif.runs[0]?.properties?.agentcsp_baseline_comparison?.new_findings).toBe(0);
  }, 30_000);

  it("tracks new and resolved findings from a findings baseline", async () => {
    const baseline = await scanProject({
      root_path: fixtureRoot,
      output_path: "/private/tmp/agentcsp-baseline-source-findings",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const targetNewFinding = baseline.findings.find(
      (finding) => finding.rule_id === "AGENTCSP-TOOL-004" && finding.confidence === "very_high"
    );
    expect(targetNewFinding).toBeDefined();

    const baselinePath = "/private/tmp/agentcsp-findings-baseline-with-drift.json";
    await fs.writeFile(
      baselinePath,
      `${JSON.stringify([
        ...baseline.findings
          .filter((finding) => finding.id !== targetNewFinding?.id)
          .map((finding) => ({ id: finding.id })),
        { id: "finding_resolved_demo" }
      ], null, 2)}\n`,
      "utf8"
    );

    const result = await scanProject({
      root_path: fixtureRoot,
      output_path: "/private/tmp/agentcsp-baseline-drift",
      baseline_path: baselinePath,
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true,
      fail_on: "critical",
      fail_on_confidence: "very_high",
      fail_on_new: true
    });

    expect(result.shouldFail).toBe(true);
    expect(result.manifest.baseline_comparison).toMatchObject({
      baseline_format: "findings",
      new_findings: 1,
      resolved_findings: 1
    });
    expect(result.manifest.baseline_comparison?.new_finding_ids).toEqual([targetNewFinding?.id]);
    expect(result.manifest.baseline_comparison?.resolved_finding_ids).toEqual(["finding_resolved_demo"]);
    expect(result.findings.find((finding) => finding.id === targetNewFinding?.id)?.baseline_status).toBe("new");
    expect(result.reportMarkdown).toContain("New findings: 1");
    const sarif = JSON.parse(await fs.readFile(result.outputFiles.sarif!, "utf8")) as {
      runs: Array<{ results: Array<{ partialFingerprints?: { agentcspFindingId?: string }; baselineState?: string }> }>;
    };
    const sarifFinding = sarif.runs[0]?.results.find(
      (item) => item.partialFingerprints?.agentcspFindingId === targetNewFinding?.id
    );
    expect(sarifFinding?.baselineState).toBe("new");
  });

  it("resolves relative baseline paths from the scan root", async () => {
    const root = "/private/tmp/agentcsp-relative-baseline-fixture";
    await fs.rm(root, { recursive: true, force: true });
    await fs.mkdir(path.join(root, "baselines"), { recursive: true });
    await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
    await fs.writeFile(path.join(root, "baselines", "agent-manifest.json"), '{"findings": []}\n', "utf8");

    const result = await scanProject({
      root_path: root,
      output_path: "scan-output",
      baseline_path: "baselines/agent-manifest.json",
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    expect(result.manifest.baseline_comparison).toMatchObject({
      baseline_path: "baselines/agent-manifest.json",
      baseline_format: "manifest"
    });
    expect(result.reportMarkdown).toContain("- Baseline: `baselines/agent-manifest.json`");
    const sarif = JSON.parse(await fs.readFile(result.outputFiles.sarif!, "utf8")) as {
      runs: Array<{ properties?: { agentcsp_baseline_comparison?: { baseline_path?: string } } }>;
    };
    expect(sarif.runs[0]?.properties?.agentcsp_baseline_comparison?.baseline_path).toBe(
      "baselines/agent-manifest.json"
    );
  });

  it("redacts external baseline paths in emitted artifacts", async () => {
    const root = "/private/tmp/agentcsp-external-baseline-fixture";
    const externalBaselinePath = "/private/tmp/agentcsp-external-baseline-store/team/accepted.json";
    await fs.rm(root, { recursive: true, force: true });
    await fs.rm("/private/tmp/agentcsp-external-baseline-store", { recursive: true, force: true });
    await fs.mkdir(root, { recursive: true });
    await fs.mkdir(path.dirname(externalBaselinePath), { recursive: true });
    await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
    await fs.writeFile(externalBaselinePath, "[]\n", "utf8");

    const result = await scanProject({
      root_path: root,
      output_path: "scan-output",
      baseline_path: externalBaselinePath,
      formats: ["json", "md", "sarif"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });

    expect(result.manifest.baseline_comparison).toMatchObject({
      baseline_path: "<external-baseline>",
      baseline_format: "findings"
    });
    expect(JSON.stringify(result.manifest)).not.toContain("/private/tmp/agentcsp-external-baseline-store");
    expect(result.reportMarkdown).toContain("`<external-baseline>`");
    expect(result.reportMarkdown).not.toContain("/private/tmp/agentcsp-external-baseline-store");
    const sarif = JSON.parse(await fs.readFile(result.outputFiles.sarif!, "utf8")) as {
      runs: Array<{ properties?: { agentcsp_baseline_comparison?: { baseline_path?: string } } }>;
    };
    expect(sarif.runs[0]?.properties?.agentcsp_baseline_comparison?.baseline_path).toBe("<external-baseline>");
  });

  it("redacts external baseline paths in read errors", async () => {
    const root = "/private/tmp/agentcsp-missing-external-baseline-fixture";
    const externalBaselinePath = "/private/tmp/agentcsp-missing-external-baseline-store/team/accepted.json";
    await fs.rm(root, { recursive: true, force: true });
    await fs.rm("/private/tmp/agentcsp-missing-external-baseline-store", { recursive: true, force: true });
    await fs.mkdir(root, { recursive: true });
    await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");

    let message = "";
    try {
      await scanProject({
        root_path: root,
        output_path: "scan-output",
        baseline_path: externalBaselinePath,
        formats: ["json", "md"],
        include_hidden: true,
        include_logs: false,
        max_file_size_bytes: 1024 * 1024,
        max_files: 5000,
        quiet: true
      });
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect(message).toContain("Unable to read baseline file <external-baseline>: ENOENT");
    expect(message).not.toContain("/private/tmp/agentcsp-missing-external-baseline-store");
  });
});
