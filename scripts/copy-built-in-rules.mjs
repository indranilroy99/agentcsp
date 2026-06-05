import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourceRules = path.join(repoRoot, "rules");
const legacyPackagedRules = path.join(repoRoot, "packages", "core", "dist", "rules", "core");
const packagedRules = path.join(repoRoot, "packages", "core", "dist", "builtin-rules");

await fs.rm(legacyPackagedRules, { recursive: true, force: true });
await fs.rm(packagedRules, { recursive: true, force: true });
await fs.mkdir(path.dirname(packagedRules), { recursive: true });
await fs.cp(sourceRules, packagedRules, { recursive: true });

console.log(`Copied built-in rules to ${packagedRules}`);
