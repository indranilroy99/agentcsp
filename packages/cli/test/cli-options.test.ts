import { describe, expect, it, vi } from "vitest";
import { runScanCommand } from "../src/commands/scan.js";

describe("cli options", () => {
  it("rejects unsupported fail-on values", async () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    await expect(
      runScanCommand(".", {
        failOn: "info",
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("--fail-on must be one of critical, high, medium, or low");
    spy.mockRestore();
  });

  it("rejects unsupported output formats", async () => {
    await expect(
      runScanCommand(".", {
        format: "json,xml",
        quiet: true
      })
    ).rejects.toThrow("Expected json,md,sarif");
  });

  it("rejects unsupported fail-on confidence values", async () => {
    await expect(
      runScanCommand(".", {
        failOn: "high",
        failOnConfidence: "certain",
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("--fail-on-confidence must be one of very_high, high, medium, or low");
  });

  it("requires fail-on when fail-on confidence is set", async () => {
    await expect(
      runScanCommand(".", {
        failOnConfidence: "high",
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("--fail-on-confidence requires --fail-on");
  });
});
