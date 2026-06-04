import fs from "node:fs/promises";
import path from "node:path";
import { minimatch } from "minimatch";
import YAML from "yaml";
import { PolicySchema, type Policy, type SurfaceObject, type TrustLevel } from "../schemas/index.js";

export async function loadPolicy(rootPath: string, configPath?: string): Promise<Policy> {
  const candidate = configPath ? path.resolve(rootPath, configPath) : path.join(rootPath, "agentcsp.yaml");
  try {
    const content = await fs.readFile(candidate, "utf8");
    return PolicySchema.parse(YAML.parse(content) ?? {});
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return PolicySchema.parse({});
    throw error;
  }
}

export function applyTrustOverrides<T extends SurfaceObject>(objects: T[], policy: Policy): T[] {
  return objects.map((object) => {
    const override = policy.trust_overrides.find((entry) =>
      minimatch(object.path, entry.path, { dot: true })
    );
    if (!override) return object;
    return { ...object, trust_level: override.trust_level as TrustLevel };
  });
}
