import { describe, expect, it } from "vitest";
import path from "node:path";
import { isPathInsideRoot, resolvePathFromRoot } from "../src/utils/paths.js";

describe("path helpers", () => {
  it("resolves relative paths from the supplied root and preserves absolute paths", () => {
    const root = "/private/tmp/agentcsp-path-root";

    expect(resolvePathFromRoot(root, "reports/agentcsp.json")).toBe(
      path.join(root, "reports", "agentcsp.json")
    );
    expect(resolvePathFromRoot(root, "/private/tmp/shared/agentcsp.json")).toBe(
      "/private/tmp/shared/agentcsp.json"
    );
  });

  it("classifies root boundaries without treating in-root dot-prefixed names as external", () => {
    const root = "/private/tmp/agentcsp-path-root";

    expect(isPathInsideRoot(root, path.join(root, "agentcsp.yaml"))).toBe(true);
    expect(isPathInsideRoot(root, path.join(root, "..agentcsp-policy", "agentcsp.yaml"))).toBe(true);
    expect(isPathInsideRoot(root, root)).toBe(false);
    expect(isPathInsideRoot(root, path.join(root, "..", "outside", "agentcsp.yaml"))).toBe(false);
    expect(isPathInsideRoot(root, `${root}-sibling/agentcsp.yaml`)).toBe(false);
  });
});
