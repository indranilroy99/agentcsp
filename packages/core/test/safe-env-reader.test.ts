import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readEnvKeyNames } from "../src/scanner/read-safe.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

describe("readEnvKeyNames", () => {
  it("returns deterministic key names without returning values", async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentcsp-env-reader-"));
    temporaryDirectories.push(directory);
    const absolutePath = path.join(directory, ".env.production");
    const secretValue = "sentinel-secret-value-that-must-not-escape";
    await fs.writeFile(
      absolutePath,
      [
        `OPENAI_API_KEY=${secretValue}`,
        "export DATABASE_URL=postgres://user:password@example.invalid/db",
        "# COMMENTED_SECRET=ignored",
        "INVALID-KEY=ignored",
        "SAFE_FLAG=true",
        "OPENAI_API_KEY=duplicate"
      ].join("\n"),
      "utf8"
    );

    const keys = await readEnvKeyNames({
      absolutePath,
      relativePath: ".env.production",
      size: (await fs.stat(absolutePath)).size,
      skippedForSize: false
    });

    expect(keys).toEqual(["DATABASE_URL", "OPENAI_API_KEY", "SAFE_FLAG"]);
    expect(JSON.stringify(keys)).not.toContain(secretValue);
    expect(JSON.stringify(keys)).not.toContain("postgres://");
  });

  it("does not open an oversized env file", async () => {
    await expect(
      readEnvKeyNames({
        absolutePath: "/path/that/must/not/be/opened",
        relativePath: ".env",
        size: 2_000_000,
        skippedForSize: true
      })
    ).resolves.toEqual([]);
  });
});
