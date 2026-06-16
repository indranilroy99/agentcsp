import fs from "node:fs/promises";
import { execFile } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const execFileAsync = promisify(execFile);

const checks = [
  path.join(repoRoot, "packages", "core", "dist", "index.js"),
  path.join(repoRoot, "packages", "core", "dist", "rules", "engine.js"),
  path.join(repoRoot, "packages", "core", "dist", "scanner", "scan.js"),
  path.join(repoRoot, "packages", "core", "dist", "schemas", "index.js"),
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
await assertPublishMetadata("package.json", { privatePackage: true });
await assertPublishMetadata("packages/core/package.json", { directory: "packages/core" });
await assertPublishMetadata("packages/cli/package.json", { directory: "packages/cli" });
await assertCorePackageMetadata();
await assertCliPackageMetadata();
await verifyPackedPackageInstall(packagedRuleCount);

console.log(
  `Package artifacts verified: ${packagedRuleCount} built-in rules packaged, tarballs verified, install smoke passed`
);

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

async function assertPublishMetadata(relativePackageJson, options = {}) {
  const packageJson = await readPackageJson(relativePackageJson);
  const packageLabel = relativePackageJson;
  const requiredKeywords = [
    "ai-security",
    "agent-security",
    "context-security-policy",
    "mcp",
    "sarif",
    "security-scanner"
  ];

  if (packageJson.license !== "Apache-2.0") {
    throw new Error(`${packageLabel} must publish with Apache-2.0 license metadata`);
  }
  if (options.privatePackage && packageJson.private !== true) {
    throw new Error(`${packageLabel} must remain private so only workspace packages are published`);
  }
  if (packageJson.repository?.type !== "git") {
    throw new Error(`${packageLabel} must declare a git repository`);
  }
  if (packageJson.repository?.url !== "git+https://github.com/indranilroy99/agentcsp.git") {
    throw new Error(`${packageLabel} must point repository metadata at the canonical GitHub repo`);
  }
  if (options.directory && packageJson.repository?.directory !== options.directory) {
    throw new Error(`${packageLabel} must declare repository.directory=${options.directory}`);
  }
  if (!options.directory && packageJson.repository?.directory) {
    throw new Error(`${packageLabel} should not declare a package repository.directory`);
  }
  if (packageJson.bugs?.url !== "https://github.com/indranilroy99/agentcsp/issues") {
    throw new Error(`${packageLabel} must declare the canonical issue tracker`);
  }
  if (packageJson.homepage !== "https://github.com/indranilroy99/agentcsp#readme") {
    throw new Error(`${packageLabel} must declare the canonical README homepage`);
  }
  if (packageJson.engines?.node !== ">=20") {
    throw new Error(`${packageLabel} must declare Node.js >=20 runtime support`);
  }
  if (!Array.isArray(packageJson.keywords)) {
    throw new Error(`${packageLabel} must declare npm keywords`);
  }
  const keywords = new Set(packageJson.keywords);
  const missingKeywords = requiredKeywords.filter((keyword) => !keywords.has(keyword));
  if (missingKeywords.length > 0) {
    throw new Error(`${packageLabel} is missing npm keywords: ${missingKeywords.join(", ")}`);
  }
}

async function assertCorePackageMetadata() {
  const packageJson = await readPackageJson("packages/core/package.json");
  if (packageJson.main !== "./dist/index.js") {
    throw new Error("packages/core/package.json main must point at ./dist/index.js");
  }
  if (packageJson.types !== "./dist/index.d.ts") {
    throw new Error("packages/core/package.json types must point at ./dist/index.d.ts");
  }
  if (packageJson.exports?.["."]?.import !== "./dist/index.js") {
    throw new Error("packages/core/package.json must export the core entrypoint");
  }
  if (packageJson.exports?.["./schemas"]?.import !== "./dist/schemas/index.js") {
    throw new Error("packages/core/package.json must export compiled schemas");
  }
}

async function assertCliPackageMetadata() {
  const packageJson = await readPackageJson("packages/cli/package.json");
  if (packageJson.bin?.agentcsp !== "./dist/index.js") {
    throw new Error("packages/cli/package.json must expose the agentcsp bin at ./dist/index.js");
  }
  if (packageJson.main !== "./dist/index.js") {
    throw new Error("packages/cli/package.json main must point at ./dist/index.js");
  }
  if (packageJson.types !== "./dist/index.d.ts") {
    throw new Error("packages/cli/package.json types must point at ./dist/index.d.ts");
  }
}

async function verifyPackedPackageInstall(expectedRuleCount) {
  const packRoot = await fs.mkdtemp(path.join(os.tmpdir(), "agentcsp-pack-"));
  try {
    const coreTarball = await packWorkspacePackage("@agentcsp/core", path.join(packRoot, "core"));
    const cliTarball = await packWorkspacePackage("agentcsp", path.join(packRoot, "cli"));
    const coreEntries = await listTarballEntries(coreTarball);
    const cliEntries = await listTarballEntries(cliTarball);

    assertTarballEntries("@agentcsp/core", coreEntries, [
      "package/package.json",
      "package/LICENSE",
      "package/dist/index.js",
      "package/dist/index.d.ts",
      "package/dist/rules/engine.js",
      "package/dist/scanner/scan.js",
      "package/dist/schemas/index.js",
      "package/dist/schemas/index.d.ts"
    ]);

    const tarballRuleCount = coreEntries.filter(
      (entry) =>
        entry.startsWith("package/dist/builtin-rules/core/") &&
        (entry.endsWith(".yaml") || entry.endsWith(".yml"))
    ).length;
    if (tarballRuleCount !== expectedRuleCount) {
      throw new Error(
        `Packed @agentcsp/core built-in rule count mismatch: expected=${expectedRuleCount} packed=${tarballRuleCount}`
      );
    }

    assertTarballEntries("agentcsp", cliEntries, [
      "package/package.json",
      "package/LICENSE",
      "package/dist/index.js",
      "package/dist/index.d.ts",
      "package/dist/banner.js",
      "package/dist/commands/scan.js"
    ]);

    await smokeTestInstalledCli(coreTarball, cliTarball, path.join(packRoot, "install"));
  } finally {
    await fs.rm(packRoot, { recursive: true, force: true });
  }
}

async function packWorkspacePackage(packageName, destination) {
  await fs.mkdir(destination, { recursive: true });
  await execFileAsync("pnpm", ["--filter", packageName, "pack", "--pack-destination", destination], {
    cwd: repoRoot,
    maxBuffer: 10 * 1024 * 1024
  });
  const tarballs = (await fs.readdir(destination))
    .filter((entry) => entry.endsWith(".tgz"))
    .map((entry) => path.join(destination, entry))
    .sort();
  if (tarballs.length !== 1) {
    throw new Error(`Expected exactly one packed tarball for ${packageName}, found ${tarballs.length}`);
  }
  return tarballs[0];
}

async function listTarballEntries(tarballPath) {
  const { stdout } = await execFileAsync("tar", ["-tf", tarballPath], {
    cwd: repoRoot,
    maxBuffer: 10 * 1024 * 1024
  });
  return stdout.split(/\r?\n/u).filter(Boolean).sort();
}

function assertTarballEntries(packageName, entries, expectedEntries) {
  const entrySet = new Set(entries);
  const missing = expectedEntries.filter((entry) => !entrySet.has(entry));
  if (missing.length > 0) {
    throw new Error(`${packageName} tarball is missing expected entries: ${missing.join(", ")}`);
  }
}

async function smokeTestInstalledCli(coreTarball, cliTarball, installRoot) {
  await fs.mkdir(installRoot, { recursive: true });
  const runtimeDependencies = await collectRuntimeDependencies();
  await fs.writeFile(
    path.join(installRoot, "package.json"),
    `${JSON.stringify(
      {
        name: "agentcsp-package-smoke",
        version: "0.0.0",
        private: true,
        type: "module",
        dependencies: runtimeDependencies
      },
      null,
      2
    )}\n`
  );

  await execFileAsync("pnpm", ["install", "--offline"], {
    cwd: installRoot,
    maxBuffer: 20 * 1024 * 1024
  });

  const installedCorePath = path.join(installRoot, "node_modules", "@agentcsp", "core");
  const installedCliPath = path.join(installRoot, "node_modules", "agentcsp");
  await extractTarball(coreTarball, installedCorePath);
  await extractTarball(cliTarball, installedCliPath);

  const outputPath = path.join(installRoot, "scan-output");
  await assertInstalledPackageMetadata(installedCorePath, installedCliPath);
  const installedCliEntrypoint = path.join(installedCliPath, "dist", "index.js");
  await assertFile(installedCliEntrypoint);
  await assertFile(path.join(installedCorePath, "dist", "index.js"));
  await assertExecutableCliEntrypoint(installedCliEntrypoint, installedCliPath);

  await execFileAsync(
    installedCliEntrypoint,
    [
      "scan",
      path.join(repoRoot, "examples", "safe-agent"),
      "--out",
      outputPath,
      "--format",
      "json,md",
      "--quiet"
    ],
    {
      cwd: installRoot,
      maxBuffer: 20 * 1024 * 1024
    }
  );

  await assertFile(path.join(outputPath, "agent-manifest.json"));
  await assertFile(path.join(outputPath, "findings.json"));
  await assertFile(path.join(outputPath, "report.md"));

  const manifest = JSON.parse(await fs.readFile(path.join(outputPath, "agent-manifest.json"), "utf8"));
  const findings = JSON.parse(await fs.readFile(path.join(outputPath, "findings.json"), "utf8"));
  const report = await fs.readFile(path.join(outputPath, "report.md"), "utf8");
  if (!Array.isArray(findings)) {
    throw new Error("Installed CLI smoke test produced a non-array findings.json");
  }
  if (findings.length !== 0) {
    throw new Error(`Installed CLI smoke test expected the safe fixture to stay clean, found ${findings.length}`);
  }
  if (!report.includes("- Root: `<scan-root>`")) {
    throw new Error("Installed CLI smoke test report did not redact the scan root");
  }
  if (typeof manifest?.metadata?.root_path === "string" && report.includes(manifest.metadata.root_path)) {
    throw new Error("Installed CLI smoke test report leaked the absolute scan root");
  }
}

async function assertExecutableCliEntrypoint(installedCliEntrypoint, installedCliPath) {
  const entrypoint = await fs.readFile(installedCliEntrypoint, "utf8");
  if (!entrypoint.startsWith("#!/usr/bin/env node")) {
    throw new Error("Packed CLI entrypoint is missing the Node shebang required for npm bin execution");
  }

  const stats = await fs.stat(installedCliEntrypoint);
  if ((stats.mode & 0o111) === 0) {
    throw new Error("Packed CLI entrypoint is not executable");
  }

  const cliPackageJson = JSON.parse(await fs.readFile(path.join(installedCliPath, "package.json"), "utf8"));
  const { stdout } = await execFileAsync(installedCliEntrypoint, ["--version"], {
    cwd: path.dirname(installedCliPath),
    maxBuffer: 1024 * 1024
  });
  if (stdout.trim() !== cliPackageJson.version) {
    throw new Error(`Packed CLI --version mismatch: expected ${cliPackageJson.version}, received ${stdout.trim()}`);
  }
}

async function collectRuntimeDependencies() {
  const dependencies = {};
  for (const relativePackageJson of ["packages/core/package.json", "packages/cli/package.json"]) {
    const packageJson = await readPackageJson(relativePackageJson);
    for (const [name, version] of Object.entries(packageJson.dependencies ?? {})) {
      if (name === "@agentcsp/core" || name === "agentcsp") continue;
      dependencies[name] = version;
    }
  }
  return Object.fromEntries(Object.entries(dependencies).sort(([left], [right]) => left.localeCompare(right)));
}

async function assertInstalledPackageMetadata(installedCorePath, installedCliPath) {
  const corePackageJson = JSON.parse(await fs.readFile(path.join(installedCorePath, "package.json"), "utf8"));
  const cliPackageJson = JSON.parse(await fs.readFile(path.join(installedCliPath, "package.json"), "utf8"));
  if (corePackageJson.name !== "@agentcsp/core") {
    throw new Error("Installed-tree smoke test unpacked an invalid core package");
  }
  if (cliPackageJson.name !== "agentcsp") {
    throw new Error("Installed-tree smoke test unpacked an invalid CLI package");
  }
  if (cliPackageJson.bin?.agentcsp !== "./dist/index.js") {
    throw new Error("Packed CLI package does not expose the agentcsp bin at ./dist/index.js");
  }
  const packedCoreDependency = cliPackageJson.dependencies?.["@agentcsp/core"];
  const compatibleCoreVersions = new Set([
    corePackageJson.version,
    `^${corePackageJson.version}`,
    `~${corePackageJson.version}`
  ]);
  if (!compatibleCoreVersions.has(packedCoreDependency)) {
    throw new Error(
      `Packed CLI dependency on @agentcsp/core is not publish-compatible: expected ${corePackageJson.version}, found ${packedCoreDependency}`
    );
  }
}

async function extractTarball(tarballPath, destination) {
  await fs.mkdir(destination, { recursive: true });
  await execFileAsync("tar", ["-xzf", tarballPath, "-C", destination, "--strip-components", "1"], {
    cwd: repoRoot,
    maxBuffer: 10 * 1024 * 1024
  });
}

async function readPackageJson(relativePackageJson) {
  const packageJsonPath = path.join(repoRoot, relativePackageJson);
  return JSON.parse(await fs.readFile(packageJsonPath, "utf8"));
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
