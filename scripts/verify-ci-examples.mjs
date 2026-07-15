import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const actionRefs = {
  checkout: "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
  setupNode: "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38",
  setupPnpm: "pnpm/action-setup@fc06bc1257f339d1d5d8b3a19a8cae5388b55320",
  uploadArtifact: "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
  downloadArtifact: "actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53",
  uploadSarif: "github/codeql-action/upload-sarif@99df26d4f13ea111d4ec1a7dddef6063f76b97e9"
};
const workspacePackage = JSON.parse(await fs.readFile(path.join(repoRoot, "package.json"), "utf8"));
const releaseGate = String(workspacePackage.scripts?.verify ?? "");
for (const requiredCommand of [
  "pnpm verify:schemas",
  "pnpm verify:versions",
  "pnpm verify:docs",
  "pnpm verify:rules",
  "pnpm build",
  "pnpm verify:packages",
  "pnpm verify:ci-examples",
  "pnpm lint",
  "pnpm test",
  "pnpm verify:fixtures",
  "pnpm audit --audit-level moderate"
]) {
  assert(releaseGate.includes(requiredCommand), `package.json verify script must include ${requiredCommand}`);
}

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
    workflow?.permissions?.["security-events"] === undefined,
    `${example.file} must not grant security-events authority workflow-wide`
  );
  assert(workflow?.on?.pull_request !== undefined, `${example.file} must run on pull_request`);
  assert(workflow?.on?.push?.branches?.includes("main"), `${example.file} must run on main pushes`);

  const jobs = Object.values(workflow?.jobs ?? {});
  assert(jobs.length === 2, `${example.file} must separate scanning from SARIF publication`);
  const scanJob = workflow?.jobs?.agentcsp;
  assert(
    scanJob?.permissions?.contents === "read" && scanJob?.permissions?.["security-events"] === undefined,
    `${example.file} scan job must remain read-only`
  );
  const steps = scanJob?.steps ?? [];
  assert(Array.isArray(steps), `${example.file} job steps must be an array`);
  assert(steps.some((step) => step.uses === actionRefs.checkout), `${example.file} must checkout source immutably`);
  assert(steps.some((step) => step.uses === actionRefs.setupNode), `${example.file} must setup Node.js immutably`);

  const scanStep = steps.find((step) => step.name === "Run AgentCSP");
  assert(scanStep, `${example.file} must run AgentCSP`);
  const scanCommand = String(scanStep.run ?? "");
  assert(scanCommand.includes("npx --yes"), `${example.file} must install the pinned AgentCSP CLI through npx`);
  assert(scanCommand.includes("agentcsp@${AGENTCSP_VERSION}"), `${example.file} must pin through AGENTCSP_VERSION`);
  assert(scanCommand.includes("--out .agentcsp"), `${example.file} must write the standard output directory`);
  assert(scanCommand.includes("--format json,md,sarif"), `${example.file} must emit SARIF with JSON and Markdown`);
  assert(scanCommand.includes("--quiet"), `${example.file} must keep CI logs concise`);

  const stageStep = steps.find((step) => step.uses === actionRefs.uploadArtifact);
  assert(stageStep, `${example.file} must stage SARIF as a read-only job artifact`);
  assert(stageStep.if?.includes("always()"), `${example.file} must stage SARIF even when gated scans fail`);
  assert(stageStep.with?.name === "agentcsp-sarif", `${example.file} must use the stable SARIF artifact name`);
  assert(stageStep.with?.path === ".agentcsp/agentcsp.sarif", `${example.file} must stage AgentCSP SARIF`);

  const publishJob = workflow?.jobs?.["publish-sarif"];
  assert(publishJob?.needs === "agentcsp", `${example.file} SARIF publication must depend on the scan`);
  assert(publishJob?.if?.includes("always()"), `${example.file} SARIF publication must survive a gated scan failure`);
  assert(
    publishJob?.if?.includes("github.event.pull_request.head.repo.full_name == github.repository"),
    `${example.file} SARIF publication must be fork-safe`
  );
  assert(
    publishJob?.permissions?.contents === "read" && publishJob?.permissions?.["security-events"] === "write",
    `${example.file} must isolate security-events authority in the publication job`
  );
  const publishSteps = publishJob?.steps ?? [];
  assert(
    publishSteps.some((step) => step.uses === actionRefs.downloadArtifact && step.with?.name === "agentcsp-sarif"),
    `${example.file} must download the staged SARIF artifact`
  );
  const uploadStep = publishSteps.find((step) => step.uses === actionRefs.uploadSarif);
  assert(uploadStep?.with?.sarif_file === "sarif/agentcsp.sarif", `${example.file} must upload AgentCSP SARIF`);
  assert(uploadStep?.with?.category === "agentcsp", `${example.file} must set the AgentCSP SARIF category`);

  if (example.gated) {
    assert(scanStep["continue-on-error"] === true, `${example.file} must continue so SARIF can upload before failing`);
    assert(scanStep.id === "agentcsp_scan", `${example.file} must expose the scan outcome by id`);
    assert(scanCommand.includes("--fail-on high"), `${example.file} must enable a severity gate`);
    assert(scanCommand.includes("--fail-on-confidence high"), `${example.file} must enable a confidence gate`);
    assert(scanCommand.includes("--fail-on-diagnostics"), `${example.file} must fail on diagnostics`);
    assert(scanCommand.includes("--fail-on-expired-suppressions"), `${example.file} must fail on expired suppressions`);
    assert(scanCommand.includes("--fail-on-scan-health degraded"), `${example.file} must fail on degraded scan health`);
    const enforceStep = steps.find((step) => step.name === "Enforce AgentCSP CI gate");
    assert(enforceStep?.if === "steps.agentcsp_scan.outcome == 'failure'", `${example.file} must enforce scan failure`);
    assert(enforceStep?.run === "exit 1", `${example.file} enforce step must fail the job`);
  } else {
    assert(!scanCommand.includes("--fail-on "), `${example.file} advisory scan must not enable severity gates`);
    assert(!scanCommand.includes("--fail-on-diagnostics"), `${example.file} advisory scan must not fail on diagnostics`);
    assert(!scanCommand.includes("--fail-on-expired-suppressions"), `${example.file} advisory scan must not fail on waivers`);
    assert(!scanCommand.includes("--fail-on-scan-health"), `${example.file} advisory scan must not fail on scan health`);
  }
}

const internalCiPath = path.join(repoRoot, ".github/workflows/ci.yml");
const internalCi = YAML.parse(await fs.readFile(internalCiPath, "utf8"));
assert(internalCi?.permissions?.contents === "read", ".github/workflows/ci.yml must use read-only contents permission");
assert(
  internalCi?.jobs?.verify?.permissions?.contents === "read" &&
    internalCi?.jobs?.verify?.permissions?.["security-events"] === undefined,
  ".github/workflows/ci.yml verify job must remain read-only"
);
const internalSteps = internalCi?.jobs?.verify?.steps ?? [];
assert(Array.isArray(internalSteps), ".github/workflows/ci.yml job steps must be an array");
assert(
  internalSteps.some((step) => step.uses === actionRefs.checkout && step.with?.["persist-credentials"] === false),
  ".github/workflows/ci.yml must use immutable checkout without persisted credentials"
);
const internalPnpmStep = internalSteps.find((step) => step.uses === actionRefs.setupPnpm);
assert(internalPnpmStep, ".github/workflows/ci.yml must setup pnpm with an immutable action reference");
assert(internalPnpmStep.with?.version === "11.0.9", ".github/workflows/ci.yml must pin pnpm to 11.0.9");
const internalNodeStep = internalSteps.find((step) => step.uses === actionRefs.setupNode);
assert(internalNodeStep, ".github/workflows/ci.yml must setup Node.js with an immutable action reference");
assert(internalNodeStep.with?.["node-version"] === 24, ".github/workflows/ci.yml must run on Node.js 24");
assert(internalNodeStep.with?.cache === "pnpm", ".github/workflows/ci.yml must cache pnpm dependencies");
const internalInstallStep = internalSteps.find((step) => step.name === "Install dependencies");
assert(
  internalInstallStep?.run === "pnpm install --frozen-lockfile",
  ".github/workflows/ci.yml must install from the lockfile without mutation"
);
const internalVerifyStep = internalSteps.find((step) => step.name === "Verify release gate");
assert(
  internalVerifyStep?.run === "pnpm verify",
  ".github/workflows/ci.yml must run the canonical release verification gate"
);
const internalStageStep = internalSteps.find((step) => step.uses === actionRefs.uploadArtifact);
assert(
  internalStageStep?.if === "github.event_name == 'push'" && internalStageStep?.with?.name === "agentcsp-sarif",
  ".github/workflows/ci.yml must stage internal SARIF only for push events"
);
assert(
  internalStageStep?.with?.path === "examples/vulnerable-agent/.agentcsp/agentcsp.sarif",
  ".github/workflows/ci.yml must stage the SARIF generated by verify:fixtures"
);
const sarifJob = internalCi?.jobs?.["publish-sarif"];
assert(sarifJob?.needs === "verify", ".github/workflows/ci.yml SARIF publication must depend on verification");
assert(sarifJob?.if === "github.event_name == 'push'", ".github/workflows/ci.yml SARIF publication must be push-only");
assert(sarifJob?.permissions?.contents === "read", ".github/workflows/ci.yml SARIF publication needs read-only contents");
assert(
  sarifJob?.permissions?.["security-events"] === "write",
  ".github/workflows/ci.yml must isolate security-events: write in the SARIF publication job"
);
const sarifSteps = sarifJob?.steps ?? [];
assert(
  sarifSteps.some((step) => step.uses === actionRefs.downloadArtifact && step.with?.name === "agentcsp-sarif"),
  ".github/workflows/ci.yml SARIF publication must download the verified artifact"
);
assert(
  sarifSteps.some(
    (step) =>
      step.uses === actionRefs.uploadSarif &&
      step.with?.sarif_file === "sarif/agentcsp.sarif" &&
      step.with?.category === "agentcsp"
  ),
  ".github/workflows/ci.yml must upload the verified AgentCSP SARIF"
);

const releasePath = path.join(repoRoot, ".github/workflows/release.yml");
const release = YAML.parse(await fs.readFile(releasePath, "utf8"));
assert(release?.jobs?.build?.permissions?.contents === "read", "release build job must be read-only");
assert(release?.jobs?.publish?.needs === "build", "release publication must consume the verified build job");
assert(release?.jobs?.publish?.permissions?.contents === "write", "release publication must declare contents write");
assert(release?.jobs?.publish?.permissions?.["id-token"] === "write", "release publication must declare OIDC authority");
assert(release?.jobs?.publish?.permissions?.attestations === "write", "release publication must declare attestation authority");
assert(
  !(release?.jobs?.publish?.steps ?? []).some((step) => String(step.uses ?? "").startsWith("pnpm/action-setup@")),
  "privileged release publication must not run package-manager setup actions"
);
const releasePackageStep = (release?.jobs?.build?.steps ?? []).find((step) => step.name === "Build package tarballs");
assert(
  String(releasePackageStep?.run ?? "").includes("pnpm sbom --out release/agentcsp.cdx.json"),
  "release build must generate the deterministic CycloneDX SBOM"
);
assert(
  String(releasePackageStep?.run ?? "").includes("sha256sum release/*.tgz release/*.json > release/SHA256SUMS"),
  "release build must checksum package, version, and SBOM artifacts"
);

for (const workflowPath of [
  ...examples.map((example) => path.join(repoRoot, example.file)),
  internalCiPath,
  releasePath
]) {
  const workflow = YAML.parse(await fs.readFile(workflowPath, "utf8"));
  assertImmutableActionReferences(workflow, path.relative(repoRoot, workflowPath));
}

console.log(`CI examples verified: ${examples.length} workflows plus internal CI`);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertImmutableActionReferences(workflow, label) {
  for (const job of Object.values(workflow?.jobs ?? {})) {
    for (const step of job?.steps ?? []) {
      const reference = String(step.uses ?? "");
      if (!reference || reference.startsWith("./") || reference.startsWith("docker://")) continue;
      assert(/^[^/\s]+\/.+@[a-f0-9]{40}$/u.test(reference), `${label} has mutable action reference ${reference}`);
    }
  }
}
