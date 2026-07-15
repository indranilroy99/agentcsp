import fs from "node:fs/promises";
import path from "node:path";

const packageJson = JSON.parse(await fs.readFile(path.resolve("package.json"), "utf8"));
const expectedTag = `v${packageJson.version}`;
const actualTag = process.env.GITHUB_REF_NAME ?? process.argv[2];

if (!actualTag) {
  throw new Error("Release tag is required through GITHUB_REF_NAME or the first argument.");
}
if (actualTag !== expectedTag) {
  throw new Error(`Release tag ${actualTag} does not match workspace version ${packageJson.version}; expected ${expectedTag}.`);
}

console.log(`Release tag verified: ${actualTag}`);
