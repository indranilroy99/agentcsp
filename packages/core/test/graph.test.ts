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
    expect(
      result.manifest.relationships.some(
        (edge) =>
          edge.relation === "calls" &&
          edge.source.path === ".codex/config.toml" &&
          edge.target.name === "filesystem-admin"
      )
    ).toBe(true);
    expect(
      result.manifest.relationships.some(
        (edge) =>
          edge.relation === "triggers" &&
          edge.source.path === ".github/workflows/agent-maintenance.yml" &&
          edge.target.name === "package-script:agent:run"
      )
    ).toBe(true);
    const promptToolEdge = result.manifest.relationships.find(
      (edge) =>
        edge.relation === "influences" &&
        edge.source.path === "prompts/support-ticket.prompt.md" &&
        edge.target.name === "publish_summary"
    );
    expect(promptToolEdge).toBeDefined();
    expect(promptToolEdge?.reason).toContain("explicit tool reference");
    const promptExplicitToolPath = result.manifest.attack_paths.find(
      (attackPath) =>
        attackPath.source.path === "prompts/support-ticket.prompt.md" &&
        attackPath.target.name === "publish_summary" &&
        attackPath.title === "support-ticket.prompt.md can route untrusted input to publish_summary"
    );
    expect(promptExplicitToolPath).toBeDefined();
    expect(promptExplicitToolPath?.severity).toBe("critical");
    expect(promptExplicitToolPath?.confidence).toBe("very_high");
    expect(promptExplicitToolPath?.recommended_control).toBe("require_approval");
    expect(promptExplicitToolPath?.reason).toContain("explicit tool reference");
    expect(promptExplicitToolPath?.reason).toContain("specific agent-callable capability");
    expect(JSON.stringify(promptExplicitToolPath)).not.toContain("Review ticket");
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
    const ragDataEgressPath = result.manifest.attack_paths.find(
      (attackPath) =>
        attackPath.source.path === "rag/customer-note.md" &&
        attackPath.target.name === "publish_summary" &&
        attackPath.title === "customer-note.md can route sensitive context to publish_summary"
    );
    expect(ragDataEgressPath).toBeDefined();
    expect(ragDataEgressPath?.severity).toBe("critical");
    expect(ragDataEgressPath?.confidence).toBe("very_high");
    expect(ragDataEgressPath?.recommended_control).toBe("quarantine");
    expect(ragDataEgressPath?.reason).toContain("data-egress directive");
    expect(ragDataEgressPath?.reason).toContain("concrete exfiltration path");
    expect(ragDataEgressPath?.risk.data_classes).toContain("confidential");
    expect(ragDataEgressPath?.risk.external_reach).toBe(true);
    expect(JSON.stringify(ragDataEgressPath)).not.toContain("latest internal summary");
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
