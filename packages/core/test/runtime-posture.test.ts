import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { detectSurfaces } from "../src/scanner/detect.js";
import type { WalkedFile } from "../src/scanner/walk.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

describe("runtime posture classification", () => {
  it("does not classify near-miss enum values by substring", async () => {
    const detected = await detectRuntime({
      sandbox_mode: "full-isolation",
      approval_policy: "auto-deny"
    });
    const runtime = detected.runtime_config[0];

    expect(runtime?.metadata).toMatchObject({
      sandbox_disabled: false,
      approval_bypass: false,
      runtime_posture_conflict: false
    });
  });

  it("uses only the selected runtime profile and records redacted field provenance", async () => {
    const detected = await detectRuntime({
      profile: "production",
      profiles: {
        development: {
          sandbox_mode: "danger-full-access",
          approval_policy: "never"
        },
        production: {
          sandbox_mode: "read-only",
          approval_policy: "on-request"
        }
      }
    });
    const runtime = detected.runtime_config[0];

    expect(runtime?.metadata).toMatchObject({
      runtime_profile: "production",
      runtime_profile_resolution: "active_profile",
      sandbox_disabled: false,
      approval_bypass: false
    });
    expect(runtime?.evidence[0]).toMatchObject({
      parser: "json",
      profile: "production",
      field_paths: ["profiles.production.approval_policy", "profiles.production.sandbox_mode"],
      classifications: expect.arrayContaining(["approval:not-bypassed", "sandbox:not-disabled"]),
      redacted: true
    });
  });

  it("diagnoses unresolved profiles and conflicting posture instead of classifying them", async () => {
    const detected = await detectRuntime({
      runtime: { sandbox_mode: "read-only", approval_policy: "on-request" },
      agent: { sandbox_mode: "danger-full-access", approval_policy: "never" },
      profiles: { unsafe: { sandbox_mode: "danger-full-access", approval_policy: "never" } }
    });
    const runtime = detected.runtime_config[0];

    expect(runtime?.metadata).toMatchObject({
      runtime_profile_resolution: "unresolved_profiles",
      runtime_posture_conflict: true,
      sandbox_disabled: false,
      approval_bypass: false
    });
    expect(detected.diagnostics).toEqual([
      expect.objectContaining({ code: "RUNTIME_POSTURE_AMBIGUOUS", content_redacted: true })
    ]);
  });

  it("diagnoses a selected runtime profile that is absent from the profile map", async () => {
    const detected = await detectRuntime({
      profile: "prodution",
      profiles: {
        production: {
          sandbox_mode: "danger-full-access",
          approval_policy: "never"
        }
      }
    });
    const runtime = detected.runtime_config[0];

    expect(runtime?.metadata).toMatchObject({
      runtime_profile: "prodution",
      runtime_profile_resolution: "unresolved_profiles",
      sandbox_disabled: false,
      approval_bypass: false
    });
    expect(detected.diagnostics).toEqual([
      expect.objectContaining({ code: "RUNTIME_POSTURE_AMBIGUOUS", content_redacted: true })
    ]);
  });
});

async function detectRuntime(value: unknown) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentcsp-runtime-posture-"));
  temporaryDirectories.push(directory);
  const relativePath = ".codex/config.json";
  const absolutePath = path.join(directory, relativePath);
  await fs.mkdir(path.dirname(absolutePath), { recursive: true });
  await fs.writeFile(absolutePath, JSON.stringify(value), "utf8");
  const file: WalkedFile = {
    absolutePath,
    relativePath,
    size: (await fs.stat(absolutePath)).size,
    skippedForSize: false
  };
  return detectSurfaces([file]);
}
