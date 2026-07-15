import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanProject } from "../src/index.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

describe("GitHub workflow credential posture", () => {
  it("does not treat disabled checkout credential persistence as secret exposure", async () => {
    const root = await workflowFixture(`
name: CI
on: push
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd
        with:
          persist-credentials: false
`);

    const result = await scanWorkflow(root);
    expect(result.manifest.ci_cd).toHaveLength(1);
    expect(result.manifest.ci_cd[0]).toMatchObject({
      secret_exposure: false,
      data_classes: ["unknown"]
    });
    expect(result.findings.some((finding) => finding.rule_id === "AGENTCSP-CICD-001")).toBe(false);
  });

  it("records an actual GitHub token reference as credential exposure", async () => {
    const root = await workflowFixture(`
name: Release
on: workflow_dispatch
permissions:
  contents: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: gh release create v0.2.0
        env:
          GH_TOKEN: \${{ github.token }}
`);

    const result = await scanWorkflow(root);
    expect(result.manifest.ci_cd).toHaveLength(1);
    expect(result.manifest.ci_cd[0]).toMatchObject({
      secret_exposure: true,
      data_classes: ["credential"]
    });
    expect(result.manifest.ci_cd[0]?.metadata).toMatchObject({
      mentions_secrets_context: false,
      references_github_token: true
    });
    expect(result.findings.some((finding) => finding.rule_id === "AGENTCSP-CICD-001")).toBe(true);
  });
});

async function workflowFixture(content: string): Promise<string> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentcsp-workflow-"));
  temporaryDirectories.push(root);
  const workflows = path.join(root, ".github", "workflows");
  await fs.mkdir(workflows, { recursive: true });
  await fs.writeFile(path.join(workflows, "workflow.yml"), content.trimStart(), "utf8");
  return root;
}

async function scanWorkflow(root: string) {
  return scanProject({
    root_path: root,
    output_path: ".agentcsp-test",
    ruleset: "recommended",
    artifact_profile: "internal",
    formats: ["json"]
  });
}
