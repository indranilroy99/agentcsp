# Usage

AgentCSP starts with a local CLI scan.

```bash
agentcsp scan [path] --out .agentcsp
```

The path defaults to the current directory. The output directory defaults to `.agentcsp`. Relative output and baseline paths are resolved from the scanned project root; absolute paths are honored as provided.

## Outputs

```text
.agentcsp/agent-manifest.json
.agentcsp/findings.json
.agentcsp/report.md
.agentcsp/agentcsp.sarif
```

`agent-manifest.json` includes `triage_summary`, a deterministic rollup of total findings, active findings, suppressions, severity, confidence, surface types, recommended controls, top rules, and top active risks. It also includes `action_plan`, a prioritized remediation list with baseline status and deterministic owner hints for routing work across agent platform, runtime platform, CI/CD, identity/secrets, data/RAG, and application-security owners. The Markdown report renders both near the top for human triage.

`scan_coverage` records files indexed, oversized files, ignored entries, skipped hidden/log directories, diagnostic counts, and whether `max_files` was reached. AgentCSP output directories such as `.agentcsp`, `.agentcsp-*`, and `.agentcsp_*` are ignored by default, and a custom `--out` directory is also ignored when it lives inside the scanned root. This prevents repeated scans from ingesting prior manifests, findings, reports, or SARIF files. Use coverage to catch partial or parser-degraded scans before treating a quiet report as clean. When traversal reaches `max_files`, AgentCSP also emits a redacted `SCAN_MAX_FILES_REACHED` diagnostic so CI and dashboards can treat incomplete scans as scan-health events.

Tune traversal limits with:

```bash
agentcsp scan . --max-file-size 1048576 --max-files 5000
```

Use `--include-logs` when transcripts, cached tool outputs, or generated run summaries may be replayed into future agent context:

```bash
agentcsp scan . --include-logs
```

`diagnostics` records redacted scan health warnings, such as malformed MCP, runtime, workflow, package, policy, rule, or tool definition files, transient traversal read/stat failures, and incomplete traversal caused by `max_files` exhaustion. `scan_coverage.diagnostics_total`, `diagnostics_warnings`, `diagnostics_errors`, and `diagnostics_info` provide stable machine-readable counts for CI and dashboards. Treat diagnostics as evidence that a file may need syntax repair, scan-scope tuning, or manual review before relying on a quiet scan.

## CI Behavior

AgentCSP does not fail CI by default. A completed scan exits with code `0` even when findings are present.

Use `--fail-on` to opt into failure behavior:

```bash
agentcsp scan . --fail-on high
```

Supported values are `critical`, `high`, `medium`, and `low`.

Use `--fail-on-confidence` with `--fail-on` when a CI gate should require both impact and confidence:

```bash
agentcsp scan . --fail-on high --fail-on-confidence high
```

Supported confidence values are `very_high`, `high`, `medium`, and `low`. If no confidence threshold is supplied, severity-only behavior is unchanged.

Active suppressions in `agentcsp.yaml` are excluded from `--fail-on` gates. Expired suppressions are not excluded.

Use `--fail-on-expired-suppressions` when CI should fail on stale accepted-risk records even without a severity gate:

```bash
agentcsp scan . --fail-on-expired-suppressions
```

Policy `recommended_controls` can change the recommended control shown in JSON, Markdown, and SARIF, but they do not suppress findings or change `--fail-on` behavior.

Use `--fail-on-diagnostics` when parse failures in security-relevant files should fail CI:

```bash
agentcsp scan . --fail-on-diagnostics
```

This remains separate from finding severity gates. It is useful for repositories where malformed MCP, runtime, workflow, package, policy, rule, or tool-definition files, or incomplete scans caused by traversal limits, should block a release until the scan can inspect them reliably.

## Baselines

Use a previous `findings.json` or `agent-manifest.json` as a baseline when introducing AgentCSP to an existing project:

```bash
agentcsp scan . --baseline .agentcsp/agent-manifest.json --out .agentcsp
```

The manifest and Markdown report include a baseline comparison with new, existing, and resolved finding counts. Current findings receive `baseline_status: "new"` or `baseline_status: "existing"` when a baseline is provided.

Relative `--baseline` paths are resolved from the scanned project root. This keeps multi-repo CI jobs stable when the command is launched from a parent workspace or automation directory. Baselines inside the scanned root are emitted as root-relative paths in JSON, Markdown, and SARIF. If the baseline file lives outside the scanned root, AgentCSP reads it normally but emits `<external-baseline>` in JSON, Markdown, SARIF, and baseline read errors instead of exposing the absolute local path.

Use `--fail-on-new` with `--baseline` and `--fail-on` when CI should fail only on newly introduced risk:

```bash
agentcsp scan . \
  --baseline .agentcsp/agent-manifest.json \
  --fail-on high \
  --fail-on-confidence high \
  --fail-on-new
```

## SARIF

Use SARIF when integrating AgentCSP with CI systems or code-scanning platforms:

```bash
agentcsp scan . --format json,md,sarif --out .agentcsp
```

The generated SARIF file is:

```text
.agentcsp/agentcsp.sarif
```

SARIF run properties include `agentcsp_triage_summary`, `agentcsp_action_plan`, `agentcsp_ci_gate_summary`, `agentcsp_baseline_comparison`, `agentcsp_scan_coverage`, `agentcsp_diagnostics`, and `agentcsp_static_blast_radius` so CI systems can consume scan-level context without parsing Markdown. Rules and results include precision, tags, rank, and GitHub code-scanning compatible `security-severity` metadata. When a baseline is provided, SARIF results include `baselineState` values for current findings.

GitHub code-scanning workflow examples are available in `examples/ci/`. See `docs/ci.md` for advisory and gated rollout patterns.

## Scanner Safety

AgentCSP does not read or emit secret values by default. For `.env*` files, it records file presence and key names only. Evidence snippets are redacted, and raw file contents are not written to the manifest. Markdown reports use `<scan-root>` instead of printing the absolute local scan path. RAG and memory files are reduced to normalized content signals rather than raw text.
