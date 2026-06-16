# Usage

AgentCSP starts with a local CLI scan.

```bash
agentcsp scan [path] --out .agentcsp
```

The path defaults to the current directory. The output directory defaults to `.agentcsp`. Relative output and baseline paths are resolved from the scanned project root; absolute paths are honored as provided.

The output path must be a dedicated directory outside or below the scanned root, not the scanned root itself. AgentCSP rejects root-as-output because repeated scans could otherwise ingest stale `agent-manifest.json`, `findings.json`, `report.md`, or SARIF artifacts as project input.

Interactive scans print a bounded terminal summary with finding counts, active triage, action-plan status, scan health, diagnostics, coverage, CI gate status, and explicit truncation flags for top risks, action plans, high-risk object previews, and attack paths. Use this as a scan receipt, not as the audit artifact. JSON, Markdown, and SARIF remain the authoritative outputs.

Use `--quiet` for CI jobs or scripts that should rely only on output files and exit codes:

```bash
agentcsp scan . --out .agentcsp --format json,md,sarif --quiet
```

## Outputs

```text
.agentcsp/agent-manifest.json
.agentcsp/findings.json
.agentcsp/report.md
.agentcsp/agentcsp.sarif
```

`agent-manifest.json` includes `triage_summary`, a deterministic rollup of total findings, active findings, suppressions, severity, confidence, surface types, recommended controls, top rules, and top active risks. It also includes `action_plan`, a bounded prioritized remediation list with truncation metadata, baseline status, and deterministic owner hints for routing work across agent platform, runtime platform, CI/CD, identity/secrets, data/RAG, and application-security owners. The Markdown report renders both near the top for human triage.

`metadata.config` captures the safe scan contract behind the output, including requested formats, traversal limits, hidden/log settings, CI gates, and whether policy or baseline inputs were configured. Raw output, policy, and baseline paths are not copied into this metadata; path-sensitive details stay redacted or scoped elsewhere.

`scan_coverage` records files indexed, oversized files, ignored entries, skipped hidden/log directories, diagnostic counts, whether `max_files` was reached, and explicit `scan_health`. AgentCSP output directories such as `.agentcsp`, `.agentcsp-*`, and `.agentcsp_*` are ignored by default, and a custom `--out` directory is also ignored when it lives inside the scanned root. This prevents repeated scans from ingesting prior manifests, findings, reports, or SARIF files. Use coverage to catch partial or parser-degraded scans before treating a quiet report as clean. `scan_health: "complete"` means the configured scope completed cleanly, `"degraded"` means the scan completed with parser or oversized-file health signals, and `"incomplete"` means traversal missed part of the configured scope. `scan_health_reasons` gives stable machine-readable reasons. When traversal reaches `max_files`, AgentCSP also emits a redacted `SCAN_MAX_FILES_REACHED` diagnostic so CI and dashboards can treat incomplete scans as scan-health events.

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

Use `--fail-on-scan-health` when scan completeness itself should be a gate:

```bash
agentcsp scan . --fail-on-scan-health degraded
```

`degraded` fails on degraded or incomplete scans, including oversized skipped files and parser-degraded scope. `incomplete` fails only when traversal missed part of the configured scope, such as `max_files` exhaustion or unreadable directories. This gate is useful when a quiet scan should never be treated as clean unless AgentCSP inspected the configured scope.

## Baselines

Use a previous `findings.json` or `agent-manifest.json` as a baseline when introducing AgentCSP to an existing project:

```bash
agentcsp scan . --baseline .agentcsp/agent-manifest.json --out .agentcsp
```

The manifest and Markdown report include a baseline comparison with new, existing, and resolved finding counts. Current findings receive `baseline_status: "new"` or `baseline_status: "existing"` when a baseline is provided. New and resolved finding ID previews are bounded; `baseline_id_limit` and the `*_ids_truncated` flags make it explicit when the preview arrays are not complete inventories.

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

SARIF run properties include `agentcsp_scan_config`, `agentcsp_triage_summary`, `agentcsp_action_plan`, `agentcsp_ci_gate_summary`, `agentcsp_baseline_comparison`, `agentcsp_scan_coverage`, `agentcsp_diagnostics`, and `agentcsp_static_blast_radius` so CI systems can consume scan-level context without parsing Markdown. Rules and results include precision, tags, rank, and GitHub code-scanning compatible `security-severity` metadata. When a baseline is provided, SARIF results include `baselineState` values for current findings.

GitHub code-scanning workflow examples are available in `examples/ci/`. See `docs/ci.md` for advisory and gated rollout patterns.

## Scanner Safety

AgentCSP does not read or emit secret values by default. For `.env*` files, it records file presence and key names only. Evidence snippets are redacted, and raw file contents are not written to the manifest. Markdown reports use `<scan-root>` instead of printing the absolute local scan path. RAG and memory files are reduced to normalized content signals rather than raw text.
