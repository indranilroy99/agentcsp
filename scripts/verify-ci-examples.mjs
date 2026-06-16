import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const examples = [
  {
    file: "examples/ci/github-code-scanning-advisory.yml",
    gated: false
  },
  {
    file: "examples/ci/github-code-scanning-gated.yml",
    gated: true
  }
];

for (const example of examples) {
  const workflowPath = path.join(repoRoot, example.file);
  const raw = await fs.readFile(workflowPath, "utf8");
  const workflow = YAML.parse(raw);
  assert(workflow?.permissions?.contents === "read", `${example.file} must use read-only contents permission`);
  assert(
    workflow?.permissions?.["security-events"] === "write",
    `${example.file} must grant security-events: write for SARIF upload`
  );
  assert(workflow?.on?.pull_request !== undefined, `${example.file} must run on pull_request`);
  assert(workflow?.on?.push?.branches?.includes("main"), `${example.file} must run on main pushes`);

  const jobs = Object.values(workflow?.jobs ?? {});
  assert(jobs.length === 1, `${example.file} must define exactly one job`);
  const steps = jobs[0]?.steps ?? [];
  assert(Array.isArray(steps), `${example.file} job steps must be an array`);
  assert(steps.some((step) => step.uses === "actions/checkout@v4"), `${example.file} must checkout source`);
  assert(steps.some((step) => step.uses === "actions/setup-node@v4"), `${example.file} must setup Node.js`);

  const scanStep = steps.find((step) => step.name === "Run AgentCSP");
  assert(scanStep, `${example.file} must run AgentCSP`);
  const scanCommand = String(scanStep.run ?? "");
  assert(scanCommand.includes("npx --yes"), `${example.file} must install the pinned AgentCSP CLI through npx`);
  assert(scanCommand.includes("agentcsp@${AGENTCSP_VERSION}"), `${example.file} must pin through AGENTCSP_VERSION`);
  assert(scanCommand.includes("--out .agentcsp"), `${example.file} must write the standard output directory`);
  assert(scanCommand.includes("--format json,md,sarif"), `${example.file} must emit SARIF with JSON and Markdown`);
  assert(scanCommand.includes("--quiet"), `${example.file} must keep CI logs concise`);

  const uploadStep = steps.find((step) => step.uses === "github/codeql-action/upload-sarif@v4");
  assert(uploadStep, `${example.file} must upload SARIF to GitHub code scanning`);
  assert(uploadStep.if?.includes("always()"), `${example.file} SARIF upload must run even when gated scans fail`);
  assert(uploadStep.if?.includes("github.event.pull_request.head.repo.full_name == github.repository"), `${example.file} SARIF upload must be fork-safe`);
  assert(uploadStep.with?.sarif_file === ".agentcsp/agentcsp.sarif", `${example.file} must upload AgentCSP SARIF`);
  assert(uploadStep.with?.category === "agentcsp", `${example.file} must set the AgentCSP SARIF category`);

  if (example.gated) {
    assert(scanStep["continue-on-error"] === true, `${example.file} must continue so SARIF can upload before failing`);
    assert(scanStep.id === "agentcsp_scan", `${example.file} must expose the scan outcome by id`);
    assert(scanCommand.includes("--fail-on high"), `${example.file} must enable a severity gate`);
    assert(scanCommand.includes("--fail-on-confidence high"), `${example.file} must enable a confidence gate`);
    assert(scanCommand.includes("--fail-on-diagnostics"), `${example.file} must fail on diagnostics`);
    assert(scanCommand.includes("--fail-on-expired-suppressions"), `${example.file} must fail on expired suppressions`);
    const enforceStep = steps.find((step) => step.name === "Enforce AgentCSP CI gate");
    assert(enforceStep?.if === "steps.agentcsp_scan.outcome == 'failure'", `${example.file} must enforce scan failure`);
    assert(enforceStep?.run === "exit 1", `${example.file} enforce step must fail the job`);
  } else {
    assert(!scanCommand.includes("--fail-on "), `${example.file} advisory scan must not enable severity gates`);
    assert(!scanCommand.includes("--fail-on-diagnostics"), `${example.file} advisory scan must not fail on diagnostics`);
    assert(!scanCommand.includes("--fail-on-expired-suppressions"), `${example.file} advisory scan must not fail on waivers`);
  }
}

const internalCiPath = path.join(repoRoot, ".github/workflows/ci.yml");
const internalCi = YAML.parse(await fs.readFile(internalCiPath, "utf8"));
const internalSteps = Object.values(internalCi?.jobs ?? {})[0]?.steps ?? [];
assert(Array.isArray(internalSteps), ".github/workflows/ci.yml job steps must be an array");
const internalAuditStep = internalSteps.find((step) => String(step.name ?? "").startsWith("Audit "));
assert(internalAuditStep, ".github/workflows/ci.yml must include dependency audit");
assert(
  internalAuditStep.name === "Audit moderate and above vulnerabilities",
  ".github/workflows/ci.yml dependency audit must describe the moderate threshold"
);
assert(
  internalAuditStep.run === "pnpm audit --audit-level moderate",
  ".github/workflows/ci.yml dependency audit must fail on moderate and above vulnerabilities"
);
const internalFixtureStep = internalSteps.find((step) => step.name === "Verify fixture outputs");
assert(internalFixtureStep?.run === "pnpm verify:fixtures", ".github/workflows/ci.yml must use the self-contained fixture verifier");
const internalUploadStep = internalSteps.find((step) => step.uses === "github/codeql-action/upload-sarif@v4");
assert(
  internalUploadStep?.with?.sarif_file === "examples/vulnerable-agent/.agentcsp/agentcsp.sarif",
  ".github/workflows/ci.yml must upload the SARIF generated by verify:fixtures"
);

console.log(`CI examples verified: ${examples.length} workflows plus internal CI`);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
