import { describe, expect, it, vi } from "vitest";
import { runScanCommand } from "../src/commands/scan.js";

describe("cli options", () => {
  it("rejects unsupported fail-on values", async () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    await expect(
      runScanCommand(".", {
        failOn: "critical",
        format: "json",
        quiet: true
      })
    ).rejects.toThrow("--fail-on must be one of high, medium, or low");
    spy.mockRestore();
  });
});
