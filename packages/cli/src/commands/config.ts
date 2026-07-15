import path from "node:path";
import { loadPolicyWithDiagnostics } from "@agentcsp/core";
import { configurationError } from "../errors.js";

export async function runConfigValidate(configPath: string, options: { json?: boolean }): Promise<void> {
  const absolutePath = path.resolve(configPath);
  const result = await loadPolicyWithDiagnostics(process.cwd(), absolutePath, { loadProjectDefault: false });
  if (result.diagnostics.length > 0) {
    const codes = result.diagnostics.map((diagnostic) => diagnostic.code).join(", ");
    throw configurationError(
      `Policy validation failed (${codes}).`,
      "Correct the YAML and policy schema errors, then rerun agentcsp config validate."
    );
  }
  const summary = {
    type: "agentcsp_config_validation",
    status: "valid",
    schema_version: result.policy.schema_version,
    trust_overrides: result.policy.trust_overrides.length,
    recommended_controls: result.policy.recommended_controls.length,
    suppressions: result.policy.suppressions.length
  };
  if (options.json) console.log(JSON.stringify(summary));
  else console.log(`[PASS] Policy is valid (${summary.suppressions} suppression(s), ${summary.trust_overrides} trust override(s)).`);
}
