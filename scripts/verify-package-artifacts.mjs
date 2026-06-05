import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const checks = [
  path.join(repoRoot, "packages", "core", "dist", "index.js"),
  path.join(repoRoot, "packages", "core", "dist", "rules", "engine.js"),
  path.join(repoRoot, "packages", "core", "dist", "scanner", "scan.js"),
  path.join(repoRoot, "packages", "cli", "dist", "index.js")
];

for (const filePath of checks) {
  await assertFile(filePath);
}

const sourceRuleCount = await countRuleFiles(path.join(repoRoot, "rules"));
const packagedRuleCount = await countRuleFiles(path.join(repoRoot, "packages", "core", "dist", "builtin-rules"));
if (sourceRuleCount === 0) {
  throw new Error("No source built-in rules found under rules/");
}
if (sourceRuleCount !== packagedRuleCount) {
  throw new Error(`Packaged built-in rule count mismatch: source=${sourceRuleCount} packaged=${packagedRuleCount}`);
}

await assertPackageFiles("packages/core/package.json");
await assertPackageFiles("packages/cli/package.json");

console.log(`Package artifacts verified: ${packagedRuleCount} built-in rules packaged`);

async function assertFile(filePath) {
  const stats = await fs.stat(filePath);
  if (!stats.isFile()) throw new Error(`Expected file artifact: ${filePath}`);
}

async function assertPackageFiles(relativePackageJson) {
  const packageJsonPath = path.join(repoRoot, relativePackageJson);
  const packageJson = JSON.parse(await fs.readFile(packageJsonPath, "utf8"));
  if (!Array.isArray(packageJson.files) || !packageJson.files.includes("dist")) {
    throw new Error(`${relativePackageJson} must include dist in package files`);
  }
}

async function countRuleFiles(directory) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  let count = 0;
  for (const entry of entries) {
    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      count += await countRuleFiles(absolutePath);
      continue;
    }
    if (entry.isFile() && (entry.name.endsWith(".yaml") || entry.name.endsWith(".yml"))) {
      count += 1;
    }
  }
  return count;
}
