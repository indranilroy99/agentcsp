import { loadBuiltInRuleset } from "@agentcsp/core";
import { CLI_VERSION } from "../version.js";

export async function runDoctor(options: { json?: boolean }): Promise<void> {
  const checks: Array<{ name: string; status: "pass" | "fail"; detail: string }> = [];
  const nodeMajor = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
  checks.push({
    name: "node_runtime",
    status: nodeMajor >= 20 ? "pass" : "fail",
    detail: `Node.js ${process.versions.node}; supported major version is 20 or newer`
  });
  try {
    const recommended = await loadBuiltInRuleset("recommended");
    const manifest = recommended.manifest;
    const uniqueRuleIds = new Set(recommended.rules.map((rule) => rule.id));
    const packValid =
      recommended.rules.length > 0 &&
      uniqueRuleIds.size === recommended.rules.length &&
      manifest?.enforcement_status === "advisory_only" &&
      manifest.calibrated_rule_ids.length === 0 &&
      isVersionAtLeast(CLI_VERSION, manifest.minimum_scanner_version);
    checks.push({
      name: "recommended_rule_pack",
      status: packValid ? "pass" : "fail",
      detail: `${recommended.rules.length} unique packaged rule(s); advisory-only metadata and scanner compatibility verified`
    });
  } catch (error) {
    checks.push({
      name: "recommended_rule_pack",
      status: "fail",
      detail: error instanceof Error ? error.message : "packaged rules could not be verified"
    });
  }
  try {
    const extended = await loadBuiltInRuleset("extended");
    checks.push({
      name: "extended_rule_catalog",
      status: extended.rules.length > 17 ? "pass" : "fail",
      detail: `${extended.rules.length} packaged extended rule(s) verified`
    });
  } catch (error) {
    checks.push({
      name: "extended_rule_catalog",
      status: "fail",
      detail: error instanceof Error ? error.message : "extended rules could not be verified"
    });
  }
  const status = checks.every((check) => check.status === "pass") ? "pass" : "fail";
  if (options.json) {
    console.log(JSON.stringify({ type: "agentcsp_doctor", version: CLI_VERSION, status, checks }));
  } else {
    console.log(`AgentCSP doctor: ${status}`);
    for (const check of checks) console.log(`  [${check.status.toUpperCase()}] ${check.name}: ${check.detail}`);
  }
  if (status === "fail") process.exitCode = 3;
}

export function isVersionAtLeast(current: string, minimum: string): boolean {
  const currentParts = stableVersionParts(current);
  const minimumParts = stableVersionParts(minimum);
  if (!currentParts || !minimumParts) return false;
  for (let index = 0; index < currentParts.length; index += 1) {
    const currentPart = currentParts[index] ?? 0;
    const minimumPart = minimumParts[index] ?? 0;
    if (currentPart > minimumPart) return true;
    if (currentPart < minimumPart) return false;
  }
  return true;
}

function stableVersionParts(version: string): [number, number, number] | undefined {
  const match = /^(\d+)\.(\d+)\.(\d+)$/u.exec(version);
  if (!match) return undefined;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}
