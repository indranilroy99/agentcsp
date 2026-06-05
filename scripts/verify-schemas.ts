import fs from "node:fs/promises";
import path from "node:path";
import { renderSchemaJson, schemaExports } from "./schema-exports.js";

const outputDirectory = path.resolve("schemas");
const mismatches: string[] = [];

for (const [fileName, schema, title] of schemaExports) {
  const expected = renderSchemaJson(schema, title);
  const filePath = path.join(outputDirectory, fileName);
  let actual: string;
  try {
    actual = await fs.readFile(filePath, "utf8");
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      mismatches.push(`${fileName} is missing`);
      continue;
    }
    throw error;
  }

  if (actual !== expected) {
    mismatches.push(`${fileName} is stale; run pnpm generate:schemas`);
  }
}

if (mismatches.length > 0) {
  throw new Error(`Schema export verification failed:\n${mismatches.map((item) => `- ${item}`).join("\n")}`);
}

console.log(`Schema exports verified: ${schemaExports.length} files`);
