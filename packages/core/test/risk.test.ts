import { describe, expect, it } from "vitest";
import { shouldFail } from "../src/risk/score.js";
import { ScanConfigSchema, type Finding } from "../src/schemas/index.js";

describe("risk gates", () => {
  it("keeps severity-only fail gates backward compatible", () => {
    expect(shouldFail([finding("high", "low")], "high")).toBe(true);
    expect(shouldFail([finding("medium", "very_high")], "high")).toBe(false);
  });

  it("supports optional confidence-aware fail gates", () => {
    expect(shouldFail([finding("critical", "medium")], "critical", "high")).toBe(false);
    expect(shouldFail([finding("critical", "high")], "critical", "high")).toBe(true);
    expect(shouldFail([finding("critical", "very_high")], "critical", "high")).toBe(true);
  });

  it("does not fail on active suppressions even when severity and confidence match", () => {
    expect(shouldFail([finding("critical", "very_high", true)], "critical", "very_high")).toBe(false);
  });

  it("requires a severity threshold when a confidence threshold is configured", () => {
    expect(() =>
      ScanConfigSchema.parse({
        root_path: ".",
        fail_on_confidence: "high"
      })
    ).toThrow("fail_on_confidence requires fail_on");
  });

  it("requires severity and baseline thresholds when new-only failure is configured", () => {
    expect(() =>
      ScanConfigSchema.parse({
        root_path: ".",
        fail_on_new: true
      })
    ).toThrow("fail_on_new requires fail_on");

    expect(() =>
      ScanConfigSchema.parse({
        root_path: ".",
        fail_on: "high",
        fail_on_new: true
      })
    ).toThrow("fail_on_new requires baseline_path");
  });

  it("allows diagnostic and expired-suppression gates without a severity threshold", () => {
    const parsed = ScanConfigSchema.parse({
      root_path: ".",
      fail_on_diagnostics: true,
      fail_on_expired_suppressions: true
    });

    expect(parsed.fail_on).toBeUndefined();
    expect(parsed.fail_on_diagnostics).toBe(true);
    expect(parsed.fail_on_expired_suppressions).toBe(true);
  });
});

function finding(severity: Finding["severity"], confidence: Finding["confidence"], suppressed = false): Finding {
  return {
    severity,
    confidence,
    suppression: suppressed
      ? {
          id: "accepted-risk",
          status: "active",
          match_scope: "severity",
          reason: "Accepted for regression test.",
          owner: "security@example.com",
          expires_at: "2999-12-31T23:59:59.000Z",
          matched_on: ["severity"],
          applied_at: "2026-01-01T00:00:00.000Z"
        }
      : undefined
  } as Finding;
}
