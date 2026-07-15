# Release Process

AgentCSP releases are built from a clean `main` checkout. Package publication and GitHub release creation are explicit maintainer actions.

## Preconditions

1. The release version is consistent in the workspace, core, CLI, manifest metadata, CLI metadata, CI examples, and documentation.
2. `CHANGELOG.md` has a dated release entry.
3. The working tree contains no generated scan output or private material.
4. The full verification gate passes:

```bash
pnpm install --frozen-lockfile
pnpm verify:release
```

## Package Verification

`pnpm verify:packages` builds both packages, checks tarball allowlists, verifies bundled rules and JSON Schemas, installs the tarballs through pnpm into a clean temporary project, and runs the installed CLI against the safe fixture. The smoke uses the current Node runtime rather than direct JavaScript execution, so the same contract runs on Linux, macOS, and Windows.

Before publication, inspect package contents:

```bash
pnpm --filter @agentcsp/core pack --pack-destination release
pnpm --filter agentcsp pack --pack-destination release
```

The release owner generates `agentcsp.cdx.json`, verifies that it contains only the lockfile-resolved production graph, records SHA-256 checksums for both tarballs, the SBOM, and version metadata, and verifies `agentcsp version --json` from the packed CLI.

## Publication

1. Create a signed `vX.Y.Z` tag from the verified commit. The tag must exactly match the workspace version.
2. The tag-only release workflow reruns `pnpm verify:release`, builds both tarballs, generates the deterministic CycloneDX 1.6 SBOM, records SHA-256 checksums, creates GitHub artifact attestations, and creates the GitHub release.
3. Verify installation in a clean environment with Node.js 22 and the current LTS release.
4. When registry distribution is approved, publish `@agentcsp/core` before `agentcsp` through a separate protected npm environment configured for trusted publishing. npm publication is not performed by the GitHub-release workflow.
5. Add known limitations and rollback instructions to the generated GitHub release notes.
6. Confirm the example advisory scan passes from the published package.

GitHub artifact attestations can be verified with:

```bash
gh attestation verify agentcsp-*.tgz -R indranilroy99/agentcsp
gh attestation verify agentcsp.cdx.json -R indranilroy99/agentcsp
```

All third-party actions are pinned to immutable commit SHAs. The read-only build job performs checkout, dependency installation, verification, packaging, SBOM generation, and checksums. Only the separate protected `release` environment job receives content, OIDC, and attestation write authority, and that job consumes the uploaded verified artifacts without checking out or installing code.

## Rollback

If package verification fails after publication:

1. mark the GitHub release as affected
2. deprecate the affected npm version with a precise message
3. publish a patch release; do not reuse or rewrite an existing version
4. document impact, mitigation, and fixed version in the changelog and security advisory when applicable
