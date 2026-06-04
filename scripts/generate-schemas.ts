import fs from "node:fs/promises";
import path from "node:path";
import { zodToJsonSchema } from "zod-to-json-schema";
import {
  AgentManifestSchema,
  FindingSchema,
  PolicySchema,
  RuleSchema
} from "../packages/core/src/schemas/index.js";

const outputDirectory = path.resolve("schemas");

const schemas = [
  ["manifest.schema.json", AgentManifestSchema, "AgentCSP Agent Manifest"],
  ["finding.schema.json", FindingSchema, "AgentCSP Finding"],
  ["rule.schema.json", RuleSchema, "AgentCSP Rule"],
  ["policy.schema.json", PolicySchema, "AgentCSP Policy"]
] as const;

await fs.mkdir(outputDirectory, { recursive: true });

for (const [fileName, schema, title] of schemas) {
  const jsonSchema = zodToJsonSchema(schema, {
    name: title,
    $refStrategy: "root"
  });
  await fs.writeFile(path.join(outputDirectory, fileName), `${JSON.stringify(jsonSchema, null, 2)}\n`, "utf8");
}

console.log(`Generated ${schemas.length} schema files in ${outputDirectory}`);
