import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { AgentManifestSchema, FindingSchema } from "../packages/core/dist/schemas/index.js";

const execFileAsync = promisify(execFile);

const sensitivePolicyReason = "Organization policy forbids unsandboxed runtime without approval.";

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "agentcsp-policy-redaction-"));
try {
  const policyPath = path.join(tempRoot, "agentcsp-policy.yaml");
  const outputPath = path.join(tempRoot, "out");
  await fs.writeFile(
    policyPath,
    [
      'schema_version: "0.1"',
      "recommended_controls:",
      '  - id: "deny-unsandboxed-runtime"',
      `    reason: "${sensitivePolicyReason}"`,
      '    control: "deny"',
      "    match:",
      '      rule_id: "AGENTCSP-RUNTIME-001"',
      '      path: ".codex/config.toml"',
      ""
    ].join("\n"),
    "utf8"
  );

  await execFileAsync(
    process.execPath,
    [
      "packages/cli/dist/index.js",
      "scan",
      "examples/vulnerable-agent",
      "--out",
      outputPath,
      "--config",
      policyPath,
      "--format",
      "json,md,sarif",
      "--quiet"
    ],
    {
      cwd: path.resolve("."),
      maxBuffer: 1024 * 1024 * 32
    }
  );

  const rawManifest = await fs.readFile(path.join(outputPath, "agent-manifest.json"), "utf8");
  const rawFindings = await fs.readFile(path.join(outputPath, "findings.json"), "utf8");
  const rawReport = await fs.readFile(path.join(outputPath, "report.md"), "utf8");
  const rawSarif = await fs.readFile(path.join(outputPath, "agentcsp.sarif"), "utf8");
  const manifest = AgentManifestSchema.parse(JSON.parse(rawManifest));
  const findings = FindingSchema.array().parse(JSON.parse(rawFindings));
  const sarif = JSON.parse(rawSarif);

  const finding = findings.find((item) => item.rule_id === "AGENTCSP-RUNTIME-001" && item.policy_control);
  assert(finding, "policy-control scan did not produce the expected runtime finding");
  assertEqual(finding.recommended_control, "deny", "policy-control finding did not apply deny control");
  assertEqual(finding.policy_control.reason, sensitivePolicyReason, "JSON finding did not retain audit reason");
  assertEqual(finding.policy_control.match_scope, "rule_and_path", "JSON finding policy match scope");
  assertEqual(finding.policy_control.change_direction, "strengthened", "JSON finding policy direction");
  assert(JSON.stringify(manifest.findings).includes(sensitivePolicyReason), "manifest findings did not retain audit reason");

  assert(!rawReport.includes(sensitivePolicyReason), "Markdown report leaked policy-control reason");
  assert(rawReport.includes("policy override from require approval to deny"), "Markdown report missing policy override summary");
  assert(rawReport.includes("direction: strengthened"), "Markdown report missing policy direction");
  assert(rawReport.includes("scope: rule and path"), "Markdown report missing policy match scope");
  assert(rawReport.includes("reason redacted"), "Markdown report missing policy reason redaction marker");

  assert(!rawSarif.includes(sensitivePolicyReason), "SARIF leaked policy-control reason");
  const sarifPolicyControl = sarif.runs?.[0]?.results?.find(
    (result) => result.properties?.policy_control
  )?.properties?.policy_control;
  assert(sarifPolicyControl, "SARIF result missing sanitized policy-control metadata");
  assertEqual(sarifPolicyControl.control, "deny", "SARIF policy control");
  assertEqual(sarifPolicyControl.previous_control, "require_approval", "SARIF previous policy control");
  assertEqual(sarifPolicyControl.match_scope, "rule_and_path", "SARIF policy match scope");
  assertEqual(sarifPolicyControl.change_direction, "strengthened", "SARIF policy direction");
  assertEqual(sarifPolicyControl.reason_redacted, true, "SARIF policy reason redaction marker");

  console.log("Policy artifact redaction verified");
} finally {
  await fs.rm(tempRoot, { recursive: true, force: true });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  assert(actual === expected, `${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}
