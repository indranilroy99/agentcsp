import fs from "node:fs/promises";
import type { WalkedFile } from "./walk.js";

export async function readTextFile(file: WalkedFile): Promise<string | undefined> {
  if (file.skippedForSize) return undefined;
  const buffer = await fs.readFile(file.absolutePath);
  if (buffer.includes(0)) return undefined;
  return buffer.toString("utf8");
}

export async function readEnvKeyNames(file: WalkedFile, maxKeys = 1000): Promise<string[]> {
  if (file.skippedForSize) return [];
  const handle = await fs.open(file.absolutePath, "r");
  const keys = new Set<string>();
  const buffer = Buffer.allocUnsafe(4096);
  let prefix: number[] = [];
  let readingValue = false;
  let prefixOverflow = false;

  try {
    while (keys.size < maxKeys) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      for (let index = 0; index < bytesRead; index += 1) {
        const byte = buffer[index];
        if (byte === undefined) continue;
        if (byte === 10 || byte === 13) {
          prefix = [];
          readingValue = false;
          prefixOverflow = false;
          continue;
        }
        if (readingValue || prefixOverflow) continue;
        if (byte === 61) {
          const key = parseEnvKeyPrefix(prefix);
          if (key) keys.add(key);
          readingValue = true;
          continue;
        }
        if (prefix.length < 512) {
          prefix.push(byte);
        } else {
          prefixOverflow = true;
          prefix = [];
        }
      }
    }
  } finally {
    buffer.fill(0);
    await handle.close();
  }

  return [...keys].sort((a, b) => a.localeCompare(b));
}

function parseEnvKeyPrefix(bytes: number[]): string | undefined {
  const prefix = Buffer.from(bytes).toString("ascii").trim().replace(/^export\s+/, "").trim();
  if (prefix.startsWith("#") || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(prefix)) return undefined;
  return prefix;
}

export function redactedEvidence(reason: string): {
  field_paths: string[];
  classifications: string[];
  snippet: "[redacted by default]";
  redacted: true;
  reason: string;
} {
  return {
    field_paths: [],
    classifications: [],
    snippet: "[redacted by default]",
    redacted: true,
    reason
  };
}
