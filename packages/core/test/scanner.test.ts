import { describe, expect, it } from "vitest";
import path from "node:path";
import { detectSurfaces } from "../src/scanner/detect.js";
import { walkProject } from "../src/scanner/walk.js";

const fixtureRoot = path.resolve("examples/vulnerable-agent");

describe("scanner", () => {
  it("collects env key names without exposing env values", async () => {
    const files = await walkProject({
      root_path: fixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);
    const envSurface = surfaces.secrets.find((surface) => surface.path === ".env.example");

    expect(envSurface).toBeDefined();
    expect(envSurface?.metadata.env_key_names).toEqual([
      "GITHUB_TOKEN",
      "OPENAI_API_KEY",
      "SLACK_WEBHOOK_URL"
    ]);
    expect(JSON.stringify(envSurface)).not.toContain("replace-me");
    expect(JSON.stringify(envSurface)).not.toContain("https://example.invalid/webhook");
  });

  it("detects agent security surfaces across the vulnerable fixture", async () => {
    const files = await walkProject({
      root_path: fixtureRoot,
      output_path: ".agentcsp",
      formats: ["json", "md"],
      include_hidden: true,
      include_logs: false,
      max_file_size_bytes: 1024 * 1024,
      max_files: 5000,
      quiet: true
    });
    const surfaces = await detectSurfaces(files);

    expect(surfaces.instructions.some((surface) => surface.path === "AGENTS.md")).toBe(true);
    expect(surfaces.skills.some((surface) => surface.path === "skills/exfil-skill/SKILL.md")).toBe(true);
    expect(surfaces.mcp_servers.length).toBeGreaterThanOrEqual(2);
    expect(surfaces.tools.some((surface) => surface.name === "package-script:sync:docs")).toBe(true);
    expect(surfaces.ci_cd.length).toBe(1);
    expect(surfaces.rag_sources.length).toBeGreaterThanOrEqual(1);
    expect(surfaces.memory.length).toBeGreaterThanOrEqual(1);
  });
});
