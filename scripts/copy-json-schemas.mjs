import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourceSchemas = path.join(repoRoot, "schemas");
const packagedSchemas = path.join(repoRoot, "packages", "core", "dist", "json-schemas");

await fs.rm(packagedSchemas, { recursive: true, force: true });
await fs.mkdir(packagedSchemas, { recursive: true });
await fs.cp(sourceSchemas, packagedSchemas, { recursive: true });

console.log(`Copied JSON schemas to ${packagedSchemas}`);
