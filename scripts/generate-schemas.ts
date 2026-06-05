import fs from "node:fs/promises";
import path from "node:path";
import { renderSchemaJson, schemaExports } from "./schema-exports.js";

const outputDirectory = path.resolve("schemas");

await fs.mkdir(outputDirectory, { recursive: true });

for (const [fileName, schema, title] of schemaExports) {
  await fs.writeFile(path.join(outputDirectory, fileName), renderSchemaJson(schema, title), "utf8");
}

console.log(`Generated ${schemaExports.length} schema files in ${outputDirectory}`);
