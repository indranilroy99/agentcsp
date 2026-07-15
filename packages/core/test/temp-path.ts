import os from "node:os";
import path from "node:path";
import { mkdirSync } from "node:fs";

const testRunRoot = path.join(os.tmpdir(), "agentcsp-tests", `${process.pid}-${Date.now()}`);
mkdirSync(testRunRoot, { recursive: true });

export function tempPath(relativePath?: string): string {
  return relativePath ? path.join(testRunRoot, relativePath) : testRunRoot;
}
