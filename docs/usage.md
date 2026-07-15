# Usage

## Build From Source

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm build
pnpm agentcsp version --json
```

The repository currently distributes a source build. npm publication is handled as a separate release step.

## Scan

```bash
agentcsp scan [path] --out .agentcsp
```

`path` defaults to the current directory. Relative output, config, and baseline paths are resolved from the scan root. The output must be a dedicated directory, not the scan root itself.

The default scan is equivalent to:

```bash
agentcsp scan . \
  --profile advisory \
  --artifact-profile portable \
  --ruleset recommended \
  --format json,md \
  --out .agentcsp
```

Add SARIF for code scanning:

```bash
agentcsp scan . --format json,md,sarif
```

Use `--quiet` for automation and `--verbose` for detailed traversal counters. The terminal receipt is a bounded summary; generated artifacts are authoritative.

## Outputs

| File | Purpose |
| --- | --- |
| `agent-manifest.json` | Versioned AI agent surface, relationship, coverage, and triage inventory |
| `findings.json` | Machine-readable findings |
| `report.md` | Analyst-readable report and Static Blast-Radius Summary |
| `agentcsp.sarif` | Optional SARIF 2.1.0 output |
| `receipt.json` | Completion record with artifact sizes and SHA-256 digests |

Portable output uses stable references instead of embedding full normalized objects in every finding. Use the internal profile only for protected local analysis:

```bash
agentcsp scan . --artifact-profile internal
```

Internal artifacts retain parser metadata, policy ownership, and full normalized objects. Secret values and evidence snippets remain redacted, but the artifact should still be treated as sensitive.

## Scan Scope

Default included hidden paths:

```text
.codex .agents .claude .cline .continue .cursor .github .junie .kiro .opencode .roo .well-known .windsurf
```

Default excluded paths include `.git`, dependency directories, build output, coverage, caches, prior AgentCSP output, and logs. Use:

```bash
agentcsp scan . --no-hidden
agentcsp scan . --include-logs
agentcsp scan . \
  --max-file-size 1048576 \
  --max-files 5000 \
  --max-directories 10000 \
  --max-entries-per-directory 10000
```

The advisory profile supports `.agentcspignore`. `ci-strict` ignores repository-controlled ignore files.

See [Ecosystem Support](ecosystem-support.md) for named repository adapters and their boundaries.

`scan_coverage.scan_health` is:

- `complete`: configured scope completed without health signals
- `degraded`: parse failures or oversized files reduced confidence
- `incomplete`: traversal did not cover the configured scope

## Strict CI

```bash
agentcsp scan . \
  --profile ci-strict \
  --ruleset recommended \
  --format json,md,sarif \
  --quiet
```

`ci-strict` ignores repository policy, project rules, and `.agentcspignore`; it enables diagnostic, expired-suppression, and incomplete-scan integrity gates. It does not turn advisory findings into automatic blockers.

Use protected external policy with a digest:

```bash
agentcsp scan . \
  --profile ci-strict \
  --config /opt/security/agentcsp.yaml \
  --config-sha256 "$AGENTCSP_POLICY_SHA256"
```

Trusted policy and baseline inputs must resolve outside the scan root, be regular files, remain within size limits, and match the expected SHA-256 digest. AgentCSP parses the bytes read from the verified open file handle; it does not reopen the path after approval.

## Finding Gates

Scans exit `0` after successful advisory analysis unless a gate is configured.

```bash
agentcsp scan . --fail-on high
agentcsp scan . --fail-on high --fail-on-confidence high
agentcsp scan . --fail-on-scan-health degraded
agentcsp scan . --fail-on-diagnostics
agentcsp scan . --fail-on-expired-suppressions
```

`--fail-on-confidence` requires `--fail-on`. Severity values are `critical`, `high`, `medium`, and `low`; confidence values are `very_high`, `high`, `medium`, and `low`.

See [CI Integration](ci.md) and [Detection Quality](detection-quality.md) before using findings as a merge policy.

## Git Guard

Install an opt-in local guard for Git operations performed by a developer or coding assistant:

```bash
agentcsp guard install
agentcsp guard status
```

The managed `pre-commit` hook inspects staged changes. The managed `pre-push` hook receives Git's outgoing ref ranges and inspects the commits that would be sent. The guard blocks likely GitHub and GitLab tokens, OpenAI and Anthropic API keys, Slack tokens, AWS access keys, private-key headers, credentialed URLs, high-confidence secret assignments, and non-template `.env` files.

```bash
agentcsp guard check
agentcsp guard check --hook pre-push
agentcsp guard uninstall
```

Guard output contains only a file path, secret class, and SHA-256 fingerprint. It never prints the matched value or writes it into AgentCSP scan artifacts.

An existing regular hook is preserved as `HOOK.agentcsp-user` and chained before the AgentCSP hook. AgentCSP refuses to modify a shared or globally inherited `core.hooksPath`; configure a repository-local hooks path or use your central hooks-management workflow instead. Git hooks are bypassable with `--no-verify` and do not intercept non-Git outbound transfers, so use CI, protected branches, and provider-side push protection for layered control.

## Rules

```bash
agentcsp rules list
agentcsp rules list --ruleset extended --json
agentcsp rules explain AGENTCSP-RUNTIME-001
```

`recommended` is the bounded default. `extended` provides the complete research catalog. Both are advisory in v0.2.

## Policy Validation

```bash
agentcsp config validate agentcsp.yaml
agentcsp config validate agentcsp.yaml --json
```

Validation does not run a scan. See [Policy](policy.md).

## Baselines

Create a reviewed baseline envelope:

```bash
agentcsp baseline create .agentcsp/findings.json --out agentcsp-baseline.json
```

Compare artifacts:

```bash
agentcsp baseline diff agentcsp-baseline.json .agentcsp/findings.json
```

Migrate a supported legacy findings array or manifest:

```bash
agentcsp baseline migrate legacy-findings.json --out agentcsp-baseline.json
```

Gate only new findings:

```bash
agentcsp scan . \
  --baseline agentcsp-baseline.json \
  --fail-on-new \
  --fail-on high \
  --fail-on-confidence high
```

## Doctor And Version

```bash
agentcsp doctor
agentcsp doctor --json
agentcsp version --json
```

`doctor` verifies the Node.js runtime and packaged recommended and extended rule catalogs. `version --json` reports scanner, manifest schema, object identity, finding identity, and Node.js versions.

## Artifact Transactions

AgentCSP writes a complete generation to a private staging directory, validates JSON, writes files with mode `0600`, creates a receipt, then atomically publishes the directory. The output directory uses mode `0700` where the platform supports POSIX permissions.

Replacement is deliberately ownership-aware. AgentCSP replaces an existing output path only when it is empty or contains the ownership marker, a bounded valid receipt, the exact managed file set, and matching file sizes and SHA-256 digests. An unowned directory, unknown file, symlink, or modified artifact produces `AGENTCSP-E3006`; the existing output remains in place.

A lock prevents concurrent writers to the same output path. If a process is interrupted, a later scan never treats an incomplete staged directory as a completed artifact set. Remove a stale lock only after confirming no AgentCSP process is writing that output.

## Exit Codes

| Code | Meaning |
| ---: | --- |
| `0` | Scan or lifecycle command completed successfully |
| `1` | Configured finding gate failed |
| `2` | Invalid configuration or input |
| `3` | Scanner integrity, coverage, diagnostic, suppression, or packaged-artifact gate failed |
| `4` | Unexpected internal failure |

Machine-readable CLI errors include a stable code, problem, fix, and help URL.
