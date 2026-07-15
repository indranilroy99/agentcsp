import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AgentCspError, loadPolicyWithDiagnostics, verifyTrustedInput } from "../src/index.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

describe("verifyTrustedInput", () => {
  it("accepts an external regular file with the expected digest", async () => {
    const fixture = await createFixture();
    const content = "schema_version: '0.1'\n";
    await fs.writeFile(fixture.externalPolicy, content, "utf8");

    const result = await verifyTrustedInput({
      rootPath: fixture.root,
      inputPath: fixture.externalPolicy,
      expectedSha256: sha256(content),
      label: "policy",
      maxBytes: 1024
    });

    expect(result.sha256).toBe(sha256(content));
    expect(result.real_path).toBe(await fs.realpath(fixture.externalPolicy));
    expect(result.content.toString("utf8")).toBe(content);
  });

  it("parses the exact policy bytes that passed digest verification", async () => {
    const fixture = await createFixture();
    const approved = "trust_overrides:\n  - path: AGENTS.md\n    trust_level: trusted\n";
    await fs.writeFile(fixture.externalPolicy, approved, "utf8");
    const verified = await verifyTrustedInput({
      rootPath: fixture.root,
      inputPath: fixture.externalPolicy,
      expectedSha256: sha256(approved),
      label: "policy",
      maxBytes: 1024
    });

    await fs.writeFile(
      fixture.externalPolicy,
      "trust_overrides:\n  - path: AGENTS.md\n    trust_level: untrusted\n",
      "utf8"
    );
    const loaded = await loadPolicyWithDiagnostics(fixture.root, fixture.externalPolicy, {
      verifiedContent: verified.content
    });

    expect(loaded.policy.trust_overrides).toEqual([{ path: "AGENTS.md", trust_level: "trusted" }]);
  });

  it("rejects a policy inside the scanned checkout", async () => {
    const fixture = await createFixture();
    const inside = path.join(fixture.root, "agentcsp.yaml");
    const content = "schema_version: '0.1'\n";
    await fs.writeFile(inside, content, "utf8");

    await expect(
      verifyTrustedInput({
        rootPath: fixture.root,
        inputPath: inside,
        expectedSha256: sha256(content),
        label: "policy",
        maxBytes: 1024
      })
    ).rejects.toMatchObject({ code: "AGENTCSP-E2001", kind: "configuration" } satisfies Partial<AgentCspError>);
  });

  it("rejects a trusted input that is not a regular file", async () => {
    const fixture = await createFixture();
    const directoryInput = path.join(fixture.base, "policy-directory");
    await fs.mkdir(directoryInput);

    await expect(
      verifyTrustedInput({
        rootPath: fixture.root,
        inputPath: directoryInput,
        expectedSha256: "0".repeat(64),
        label: "policy",
        maxBytes: 1024
      })
    ).rejects.toMatchObject({ code: "AGENTCSP-E1002", kind: "configuration" } satisfies Partial<AgentCspError>);
  });

  it("rejects a symlink that resolves into the scanned checkout", async () => {
    const fixture = await createFixture();
    const inside = path.join(fixture.root, "protected.yaml");
    const link = path.join(fixture.base, "policy-link.yaml");
    const content = "schema_version: '0.1'\n";
    await fs.writeFile(inside, content, "utf8");
    await fs.symlink(inside, link);

    await expect(
      verifyTrustedInput({
        rootPath: fixture.root,
        inputPath: link,
        expectedSha256: sha256(content),
        label: "policy",
        maxBytes: 1024
      })
    ).rejects.toMatchObject({ code: "AGENTCSP-E2001" });
  });

  it("rejects a digest mismatch without exposing content", async () => {
    const fixture = await createFixture();
    await fs.writeFile(fixture.externalPolicy, "suppressions: []\n", "utf8");

    await expect(
      verifyTrustedInput({
        rootPath: fixture.root,
        inputPath: fixture.externalPolicy,
        expectedSha256: "0".repeat(64),
        label: "policy",
        maxBytes: 1024
      })
    ).rejects.toMatchObject({
      code: "AGENTCSP-E2002",
      kind: "integrity",
      message: "Trusted policy digest does not match the expected SHA-256 value."
    });
  });
});

async function createFixture(): Promise<{ base: string; root: string; externalPolicy: string }> {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), "agentcsp-trusted-input-"));
  temporaryDirectories.push(base);
  const root = path.join(base, "checkout");
  await fs.mkdir(root);
  return { base, root, externalPolicy: path.join(base, "policy.yaml") };
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
