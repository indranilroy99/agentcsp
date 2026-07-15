import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanProject } from "../src/scanner/scan.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

describe("report integrity", () => {
  it("renders repository-controlled rule text as inert Markdown plain text", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentcsp-report-integrity-"));
    temporaryDirectories.push(root);
    await fs.mkdir(path.join(root, "rules"));
    await fs.writeFile(path.join(root, "AGENTS.md"), "Review repository changes only.\n", "utf8");
    await fs.writeFile(
      path.join(root, "rules", "output-injection.yaml"),
      [
        "id: PROJECT-OUTPUT-INTEGRITY",
        "name: '[Open review](https://attacker.example/phish)'",
        "description: |-",
        "  ![tracking](https://attacker.example/pixel)",
        "  <img src=https://attacker.example/raw>",
        "category: output_integrity",
        "severity: critical",
        "maps_to:",
        "  owasp:",
        "    - '[mapping](https://attacker.example/map)'",
        "  mitre_atlas: []",
        "  nist_ai_rmf: []",
        "match:",
        "  object_type: instruction",
        "  where: []",
        "recommendation:",
        "  control: warn",
        "  text: Review the project rule.",
        ""
      ].join("\n"),
      "utf8"
    );

    const result = await scanProject({
      root_path: root,
      output_path: ".agentcsp-test",
      formats: ["json", "md", "sarif"],
      quiet: true
    });
    const sarif = JSON.parse(await fs.readFile(result.outputFiles.sarif!, "utf8")) as {
      runs?: Array<{
        tool?: { driver?: { rules?: Array<{ id?: string; help?: { markdown?: string } }> } };
      }>;
    };
    const help = sarif.runs?.[0]?.tool?.driver?.rules?.find((rule) => rule.id === "PROJECT-OUTPUT-INTEGRITY")?.help?.markdown;

    expect(help).toBeDefined();
    expect(help).not.toContain("](https://");
    expect(help).not.toContain("![");
    expect(help).not.toContain("<img");
    expect(help).not.toContain("https://attacker.example");
    expect(help).toContain("https&#58;//attacker.example");
    expect(result.reportMarkdown).not.toContain("](https://");
    expect(result.reportMarkdown).not.toContain("https://attacker.example");
    expect(result.reportMarkdown).toContain("https&#58;//attacker.example/phish");
  });
});
