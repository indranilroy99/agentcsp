import { createHash } from "node:crypto";

export function stableId(prefix: string, parts: Array<string | undefined>): string {
  const normalized = parts
    .filter((part): part is string => Boolean(part))
    .map((part) => part.replaceAll("\\", "/").trim().toLowerCase())
    .join("|");
  const digest = createHash("sha256").update(normalized).digest("hex").slice(0, 16);
  return `${prefix}_${digest}`;
}
