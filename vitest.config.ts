import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  resolve: {
    alias: {
      "@agentcsp/core": fileURLToPath(new URL("./packages/core/src/index.ts", import.meta.url))
    }
  },
  test: {
    include: ["packages/**/*.test.ts"],
    globals: false,
    pool: "forks",
    maxWorkers: 2,
    testTimeout: 15000
  }
});
