import fs from "node:fs/promises";
import type { WalkedFile } from "./walk.js";

export async function readTextFile(file: WalkedFile): Promise<string | undefined> {
  if (file.skippedForSize) return undefined;
  const buffer = await fs.readFile(file.absolutePath);
  if (buffer.includes(0)) return undefined;
  return buffer.toString("utf8");
}

export function redactedEvidence(reason: string): { snippet: "[redacted by default]"; redacted: true; reason: string } {
  return {
    snippet: "[redacted by default]",
    redacted: true,
    reason
  };
}
