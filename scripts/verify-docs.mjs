import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const markdownFiles = await collectMarkdownFiles();
const failures = [];

for (const file of markdownFiles) {
  const content = await fs.readFile(file, "utf8");
  for (const target of localTargets(content)) {
    const relativeTarget = target.split("#", 1)[0]?.split("?", 1)[0];
    if (!relativeTarget) continue;
    let decodedTarget;
    try {
      decodedTarget = decodeURIComponent(relativeTarget);
    } catch {
      failures.push(`${path.relative(repoRoot, file)}: invalid URL encoding in ${target}`);
      continue;
    }
    const absoluteTarget = path.resolve(path.dirname(file), decodedTarget);
    try {
      await fs.access(absoluteTarget);
    } catch {
      failures.push(`${path.relative(repoRoot, file)}: missing local target ${target}`);
    }
  }
}

if (failures.length > 0) {
  throw new Error(`Documentation link verification failed:\n${failures.join("\n")}`);
}

console.log(`Documentation links verified: ${markdownFiles.length} Markdown files`);

async function collectMarkdownFiles() {
  const files = [];
  for (const entry of await fs.readdir(repoRoot, { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith(".md")) files.push(path.join(repoRoot, entry.name));
  }
  for (const directory of ["docs", ".github"]) {
    await collect(path.join(repoRoot, directory), files);
  }
  return files.sort((a, b) => a.localeCompare(b));
}

async function collect(directory, files) {
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) await collect(absolute, files);
    if (entry.isFile() && entry.name.endsWith(".md")) files.push(absolute);
  }
}

function localTargets(content) {
  const targets = [];
  for (const match of content.matchAll(/!?\[[^\]]*\]\((?:<([^>]+)>|([^\s)]+))(?:\s+["'][^"']*["'])?\)/gu)) {
    targets.push(match[1] ?? match[2]);
  }
  for (const match of content.matchAll(/<(?:a|img)\s+[^>]*(?:href|src)="([^"]+)"[^>]*>/giu)) {
    targets.push(match[1]);
  }
  return targets.filter(
    (target) =>
      typeof target === "string" &&
      !target.startsWith("#") &&
      !target.startsWith("/") &&
      !/^[a-z][a-z0-9+.-]*:/iu.test(target)
  );
}
