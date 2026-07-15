import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workspacePackage = await readJson("package.json");
const corePackage = await readJson("packages/core/package.json");
const cliPackage = await readJson("packages/cli/package.json");
const expectedVersion = workspacePackage.version;
const failures = [];

assertVersion("packages/core/package.json", corePackage.version);
assertVersion("packages/cli/package.json", cliPackage.version);
await assertSourceVersion("packages/cli/src/version.ts", /CLI_VERSION\s*=\s*"([^"]+)"/u, "CLI --version");
await assertSourceVersion("packages/core/src/schemas/index.ts", /ScannerVersion\s*=\s*"([^"]+)"/u, "core scanner version");
await assertSourceReference("packages/core/src/manifest/build.ts", "version: ScannerVersion", "shared scanner version");
await assertSourceReference("packages/core/src/reports/baseline.ts", "scanner_version: ScannerVersion", "shared scanner version");
await assertWorkflowVersion("examples/ci/github-code-scanning-advisory.yml");
await assertWorkflowVersion("examples/ci/github-code-scanning-gated.yml");
await assertDocVersion("docs/ci.md");

if (failures.length > 0) {
  throw new Error(`Version verification failed:\n${failures.map((failure) => `- ${failure}`).join("\n")}`);
}

console.log(`Versions verified: ${expectedVersion}`);

async function readJson(relativePath) {
  return JSON.parse(await fs.readFile(path.join(repoRoot, relativePath), "utf8"));
}

function assertVersion(label, actualVersion) {
  if (actualVersion !== expectedVersion) {
    failures.push(`${label} version ${actualVersion} does not match workspace version ${expectedVersion}`);
  }
}

async function assertSourceVersion(relativePath, pattern, label) {
  const source = await fs.readFile(path.join(repoRoot, relativePath), "utf8");
  const actualVersion = source.match(pattern)?.[1];
  if (!actualVersion) {
    failures.push(`${relativePath} is missing ${label}`);
    return;
  }
  assertVersion(`${relativePath} ${label}`, actualVersion);
}

async function assertSourceReference(relativePath, expected, label) {
  const source = await fs.readFile(path.join(repoRoot, relativePath), "utf8");
  if (!source.includes(expected)) failures.push(`${relativePath} is missing ${label}`);
}

async function assertWorkflowVersion(relativePath) {
  const workflow = YAML.parse(await fs.readFile(path.join(repoRoot, relativePath), "utf8"));
  const jobs = Object.values(workflow?.jobs ?? {});
  const actualVersion = jobs[0]?.env?.AGENTCSP_VERSION;
  assertVersion(`${relativePath} AGENTCSP_VERSION`, String(actualVersion ?? ""));
}

async function assertDocVersion(relativePath) {
  const source = await fs.readFile(path.join(repoRoot, relativePath), "utf8");
  const actualVersion = source.match(/AGENTCSP_VERSION:\s*([0-9]+\.[0-9]+\.[0-9]+)/u)?.[1];
  if (!actualVersion) {
    failures.push(`${relativePath} is missing documented AGENTCSP_VERSION`);
    return;
  }
  assertVersion(`${relativePath} documented AGENTCSP_VERSION`, actualVersion);
}
