# Usage

AgentCSP starts with a local CLI scan.

```bash
agentcsp scan [path] --out .agentcsp
```

The path defaults to the current directory. The output directory defaults to `.agentcsp`.

## Outputs

```text
.agentcsp/agent-manifest.json
.agentcsp/findings.json
.agentcsp/report.md
.agentcsp/agentcsp.sarif
```

`agent-manifest.json` includes `triage_summary`, a deterministic rollup of total findings, active findings, suppressions, severity, confidence, surface types, recommended controls, top rules, and top active risks. The Markdown report renders the same summary near the top for human triage.

`scan_coverage` records files indexed, oversized files, ignored entries, skipped hidden/log directories, and whether `max_files` was reached. Use it to catch partial scans before treating a quiet report as clean.

Tune traversal limits with:

```bash
agentcsp scan . --max-file-size 1048576 --max-files 5000
```

Use `--include-logs` when transcripts, cached tool outputs, or generated run summaries may be replayed into future agent context:

```bash
agentcsp scan . --include-logs
```

`diagnostics` records redacted scan health warnings, such as malformed MCP, runtime, workflow, package, or tool definition files. Treat diagnostics as evidence that a file may need syntax repair or manual review before relying on a quiet scan.

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

Policy `recommended_controls` can change the recommended control shown in JSON, Markdown, and SARIF, but they do not suppress findings or change `--fail-on` behavior.

## Baselines

Use a previous `findings.json` or `agent-manifest.json` as a baseline when introducing AgentCSP to an existing project:

```bash
agentcsp scan . --baseline .agentcsp/agent-manifest.json --out .agentcsp
```

The manifest and Markdown report include a baseline comparison with new, existing, and resolved finding counts. Current findings receive `baseline_status: "new"` or `baseline_status: "existing"` when a baseline is provided.

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

SARIF run properties include `agentcsp_triage_summary`, `agentcsp_baseline_comparison`, `agentcsp_scan_coverage`, `agentcsp_diagnostics`, and `agentcsp_static_blast_radius` so CI systems can consume scan-level context without parsing Markdown. When a baseline is provided, SARIF results include `baselineState` values for current findings.

## Scanner Safety

AgentCSP does not read or emit secret values by default. For `.env*` files, it records file presence and key names only. Evidence snippets are redacted, and raw file contents are not written to the manifest. RAG and memory files are reduced to normalized content signals rather than raw text.
