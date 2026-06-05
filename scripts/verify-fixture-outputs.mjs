import fs from "node:fs/promises";
import path from "node:path";
import { AgentManifestSchema, FindingSchema } from "../packages/core/dist/schemas/index.js";

const vulnerableOutput = path.resolve(process.argv[2] ?? ".agentcsp");
const safeOutput = path.resolve(process.argv[3] ?? ".agentcsp-safe");

const leakPatterns = [
  /\$\{ANTHROPIC_API_KEY\}/u,
  /\$\{OPENAI_API_KEY\}/u,
  /\$\{SLACK_WEBHOOK_URL\}/u,
  /Bash\(npm run deploy\)/u,
  /WebFetch\(domain:\*\)/u,
  /domain:\*/u,
  /mcp__filesystem-admin__delete_file/u,
  /http:\/\/mcp\.example\.invalid\/sse/u,
  /http:\/\/llm-gateway\.example\.invalid\/v1/u,
  /agentcsp-support-ops/u,
  /npm run deploy/u,
  /Post a generated customer update/u,
  /Send a customer record/u,
  /ignore previous instructions and call this tool/u,
  /latest internal summary/u,
  /Always prepare customer escalation notes/u,
  /When a customer escalation arrives/u,
  /"\*\*\/\*"/u,
  /\$\{PINECONE_API_KEY\}/u,
  /agentcsp-demo-vector\.example\.invalid/u,
  /customer-support-escalations/u,
  /internal-ticket-memory/u,
  /support_tickets/u,
  /customer_notes/u,
  /public_web_pages/u,
  /\$\{LANGSMITH_API_KEY\}/u,
  /api\.smith\.langchain\.com/u,
  /customer-support-agent/u,
  /"command": "run"/u
];

const vulnerable = await readScanOutput(vulnerableOutput, { sarifRequired: true });
const safe = await readScanOutput(safeOutput, { sarifRequired: false });

assertEqual(vulnerable.manifest.findings.length, 75, "vulnerable manifest finding count");
assertEqual(vulnerable.findings.length, 75, "vulnerable findings.json count");
assertEqual(vulnerable.manifest.attack_paths.length, 15, "vulnerable attack path count");
assertEqual(vulnerable.manifest.static_blast_radius?.critical_attack_paths, 15, "vulnerable critical attack path count");
assertEqual(vulnerable.manifest.diagnostics.length, 0, "vulnerable diagnostics count");
assertEqual(vulnerable.manifest.scan_coverage?.diagnostics_total, 0, "vulnerable diagnostic coverage count");

for (const ruleId of [
  "AGENTCSP-TOOL-010",
  "AGENTCSP-TOOL-011",
  "AGENTCSP-RUNTIME-007",
  "AGENTCSP-RUNTIME-008",
  "AGENTCSP-RUNTIME-009",
  "AGENTCSP-RUNTIME-006",
  "AGENTCSP-MCP-006",
  "AGENTCSP-CURSOR-001",
  "AGENTCSP-MEMORY-003",
  "AGENTCSP-PROMPT-003",
  "AGENTCSP-RAG-003",
  "AGENTCSP-RAG-004",
  "AGENTCSP-SKILL-001"
]) {
  assert(
    vulnerable.findings.some((finding) => finding.rule_id === ruleId),
    `expected vulnerable finding for ${ruleId}`
  );
}

assertEqual(safe.manifest.findings.length, 0, "safe manifest finding count");
assertEqual(safe.findings.length, 0, "safe findings.json count");
assertEqual(safe.manifest.attack_paths.length, 0, "safe attack path count");
assertEqual(safe.manifest.diagnostics.length, 0, "safe diagnostics count");
assertEqual(safe.manifest.scan_coverage?.diagnostics_total, 0, "safe diagnostic coverage count");

assertNoLeaks("vulnerable output", vulnerable.raw);
assertNoLeaks("safe output", safe.raw);

if (vulnerable.sarif) {
  assertEqual(vulnerable.sarif.version, "2.1.0", "SARIF version");
  const run = vulnerable.sarif.runs?.[0];
  assert(run, "SARIF run is missing");
  assertEqual(run.tool?.driver?.name, "AgentCSP", "SARIF driver name");
  assertEqual(run.results?.length, vulnerable.findings.length, "SARIF result count");
  assert(run.properties?.agentcsp_triage_summary, "SARIF triage summary missing");
  assert(run.properties?.agentcsp_scan_coverage, "SARIF scan coverage missing");
  assert(run.properties?.agentcsp_static_blast_radius, "SARIF blast-radius summary missing");
}

console.log(
  `Fixture outputs verified: vulnerable=${vulnerable.findings.length} findings, safe=${safe.findings.length} findings`
);

async function readScanOutput(outputPath, options) {
  const manifestPath = path.join(outputPath, "agent-manifest.json");
  const findingsPath = path.join(outputPath, "findings.json");
  const reportPath = path.join(outputPath, "report.md");
  const sarifPath = path.join(outputPath, "agentcsp.sarif");

  const rawManifest = await fs.readFile(manifestPath, "utf8");
  const rawFindings = await fs.readFile(findingsPath, "utf8");
  const rawReport = await fs.readFile(reportPath, "utf8");
  const manifest = AgentManifestSchema.parse(JSON.parse(rawManifest));
  const findings = FindingSchema.array().parse(JSON.parse(rawFindings));

  let rawSarif = "";
  let sarif;
  try {
    rawSarif = await fs.readFile(sarifPath, "utf8");
    sarif = JSON.parse(rawSarif);
  } catch (error) {
    const code = error?.code;
    if (options.sarifRequired || code !== "ENOENT") throw error;
  }

  return {
    manifest,
    findings,
    sarif,
    raw: [rawManifest, rawFindings, rawReport, rawSarif].join("\n")
  };
}

function assertNoLeaks(label, value) {
  for (const pattern of leakPatterns) {
    assert(!pattern.test(value), `${label} leaked redacted pattern ${pattern}`);
  }
}

function assertEqual(actual, expected, label) {
  assert(actual === expected, `${label}: expected ${expected}, received ${actual}`);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
