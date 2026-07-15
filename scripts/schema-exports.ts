import { zodToJsonSchema } from "zod-to-json-schema";
import {
  AgentManifestArtifactSchema,
  FindingArtifactSchema,
  PolicySchema,
  RuleSchema
} from "../packages/core/src/schemas/index.js";

export const schemaExports = [
  ["manifest.schema.json", AgentManifestArtifactSchema, "AgentCSP Agent Manifest"],
  ["finding.schema.json", FindingArtifactSchema, "AgentCSP Finding"],
  ["rule.schema.json", RuleSchema, "AgentCSP Rule"],
  ["policy.schema.json", PolicySchema, "AgentCSP Policy"]
] as const;

export function renderSchemaJson(schema: (typeof schemaExports)[number][1], title: string): string {
  const jsonSchema = zodToJsonSchema(schema, {
    name: title,
    $refStrategy: "root"
  });
  return `${JSON.stringify(jsonSchema, null, 2)}\n`;
}
