import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

const execFileAsync = promisify(execFile);
const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export async function buildSbom() {
  const { stdout } = await execFileAsync("pnpm", ["list", "--prod", "--depth", "Infinity", "--json"], {
    cwd: workspaceRoot,
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024
  });
  const projects = JSON.parse(stdout);
  const cliProject = projects.find((project) => project.name === "agentcsp");
  if (!cliProject) throw new Error("Unable to resolve the installed agentcsp production dependency graph.");

  const workspaceVersions = new Map(
    await Promise.all(
      ["packages/cli/package.json", "packages/core/package.json"].map(async (relativePath) => {
        const packageJson = JSON.parse(await fs.readFile(path.join(workspaceRoot, relativePath), "utf8"));
        return [packageJson.name, packageJson.version];
      })
    )
  );
  const nodes = new Map();

  async function collect(name, dependency) {
    const version = resolvedVersion(name, dependency.version, workspaceVersions);
    const ref = packageUrl(name, version);
    const dependencyNames = Object.keys(dependency.dependencies ?? {}).sort((a, b) => a.localeCompare(b));
    const dependsOn = dependencyNames.map((childName) => {
      const child = dependency.dependencies[childName];
      return packageUrl(childName, resolvedVersion(childName, child.version, workspaceVersions));
    });
    const current = nodes.get(ref);
    const packageMetadata = await readPackageMetadata(dependency.path);
    nodes.set(ref, {
      name,
      version,
      ref,
      dependsOn: [...new Set([...(current?.dependsOn ?? []), ...dependsOn])].sort((a, b) => a.localeCompare(b)),
      license: current?.license ?? packageMetadata.license,
      repository: current?.repository ?? packageMetadata.repository,
      distribution: current?.distribution ?? safeUrl(dependency.resolved)
    });
    for (const childName of dependencyNames) {
      await collect(childName, dependency.dependencies[childName]);
    }
  }

  const rootVersion = resolvedVersion(cliProject.name, cliProject.version, workspaceVersions);
  const rootDependency = { ...cliProject, dependencies: cliProject.dependencies ?? {} };
  await collect(cliProject.name, rootDependency);
  const rootRef = packageUrl(cliProject.name, rootVersion);
  const rootNode = nodes.get(rootRef);
  if (!rootNode) throw new Error("Unable to build the root SBOM component.");
  nodes.delete(rootRef);

  const components = [...nodes.values()]
    .sort((a, b) => a.ref.localeCompare(b.ref))
    .map((node) => component(node));
  const dependencies = [rootNode, ...nodes.values()]
    .sort((a, b) => a.ref.localeCompare(b.ref))
    .map((node) => ({ ref: node.ref, dependsOn: node.dependsOn }));

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    metadata: {
      component: component(rootNode, "application")
    },
    components,
    dependencies
  };
}

export async function writeSbom(outputPath) {
  const absoluteOutput = path.resolve(workspaceRoot, outputPath);
  await fs.mkdir(path.dirname(absoluteOutput), { recursive: true });
  await fs.writeFile(absoluteOutput, `${JSON.stringify(await buildSbom(), null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  return absoluteOutput;
}

function component(node, type = "library") {
  return {
    type,
    "bom-ref": node.ref,
    name: node.name,
    version: node.version,
    purl: node.ref,
    ...(node.license ? { licenses: [{ license: { id: node.license } }] } : {}),
    ...(externalReferences(node).length > 0 ? { externalReferences: externalReferences(node) } : {})
  };
}

function externalReferences(node) {
  return [
    ...(node.repository ? [{ type: "vcs", url: node.repository }] : []),
    ...(node.distribution ? [{ type: "distribution", url: node.distribution }] : [])
  ].sort((a, b) => a.type.localeCompare(b.type) || a.url.localeCompare(b.url));
}

async function readPackageMetadata(packagePath) {
  if (!packagePath) return {};
  try {
    const packageJson = JSON.parse(await fs.readFile(path.join(packagePath, "package.json"), "utf8"));
    return {
      license: typeof packageJson.license === "string" ? packageJson.license : undefined,
      repository: repositoryUrl(packageJson.repository)
    };
  } catch {
    return {};
  }
}

function repositoryUrl(repository) {
  const value = typeof repository === "string" ? repository : repository?.url;
  return safeUrl(typeof value === "string" ? value.replace(/^git\+/u, "") : undefined);
}

function safeUrl(value) {
  if (typeof value !== "string" || !/^https:\/\//u.test(value)) return undefined;
  return value;
}

function resolvedVersion(name, version, workspaceVersions) {
  const workspaceVersion = workspaceVersions.get(name);
  if (workspaceVersion) return workspaceVersion;
  if (typeof version !== "string" || version.startsWith("link:") || version.startsWith("workspace:")) {
    throw new Error(`Unable to resolve an exact production version for ${name}.`);
  }
  return version;
}

function packageUrl(name, version) {
  if (name.startsWith("@")) {
    const [scope, packageName] = name.slice(1).split("/");
    return `pkg:npm/%40${encodeURIComponent(scope)}/${encodeURIComponent(packageName)}@${encodeURIComponent(version)}`;
  }
  return `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
}

function parseOutputPath(argv) {
  const index = argv.indexOf("--out");
  if (index === -1 || !argv[index + 1]) throw new Error("Usage: node scripts/generate-sbom.mjs --out <path>");
  return argv[index + 1];
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const output = await writeSbom(parseOutputPath(process.argv.slice(2)));
  console.log(`CycloneDX SBOM written to ${path.relative(workspaceRoot, output)}`);
}
