import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { buildSbom } from "./generate-sbom.mjs";

const first = await buildSbom();
const second = await buildSbom();
assert.equal(JSON.stringify(first), JSON.stringify(second), "SBOM generation must be deterministic");
assert.equal(first.bomFormat, "CycloneDX");
assert.equal(first.specVersion, "1.6");
assert.equal(first.version, 1);
assert.equal(first.metadata.component.name, "agentcsp");
assert.match(first.metadata.component.version, /^\d+\.\d+\.\d+$/u);

const components = new Map(first.components.map((component) => [component.name, component]));
for (const expected of ["@agentcsp/core", "commander", "minimatch", "brace-expansion", "balanced-match", "smol-toml", "yaml", "zod"]) {
  assert(components.has(expected), `SBOM is missing production component ${expected}`);
}
for (const excluded of ["typescript", "vitest", "vite", "esbuild", "jiti", "rimraf", "@types/node"]) {
  assert(!components.has(excluded), `SBOM must not include development component ${excluded}`);
}
for (const component of [first.metadata.component, ...first.components]) {
  assert.match(component["bom-ref"], /^pkg:npm\//u);
  assert.equal(component.purl, component["bom-ref"]);
  assert(!JSON.stringify(component).includes(os.homedir()), "SBOM must not contain local filesystem paths");
}

const dependencyRefs = new Set(first.dependencies.map((dependency) => dependency.ref));
assert(dependencyRefs.has(first.metadata.component["bom-ref"]), "SBOM dependency graph is missing the root component");
for (const component of first.components) {
  assert(dependencyRefs.has(component["bom-ref"]), `SBOM dependency graph is missing ${component.name}`);
}

const tempDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "agentcsp-sbom-"));
try {
  const output = path.join(tempDirectory, "agentcsp.cdx.json");
  await fs.writeFile(output, `${JSON.stringify(first, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  const parsed = JSON.parse(await fs.readFile(output, "utf8"));
  assert.deepEqual(parsed, first);
} finally {
  await fs.rm(tempDirectory, { recursive: true, force: true });
}

console.log(`CycloneDX SBOM verified: ${first.components.length} production components`);
