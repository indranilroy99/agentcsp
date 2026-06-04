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

## CI Behavior

AgentCSP does not fail CI by default. A completed scan exits with code `0` even when findings are present.

Use `--fail-on` to opt into failure behavior:

```bash
agentcsp scan . --fail-on high
```

Supported values are `critical`, `high`, `medium`, and `low`.

Active suppressions in `agentcsp.yaml` are excluded from `--fail-on` gates. Expired suppressions are not excluded.

Policy `recommended_controls` can change the recommended control shown in JSON, Markdown, and SARIF, but they do not suppress findings or change `--fail-on` behavior.

## SARIF

Use SARIF when integrating AgentCSP with CI systems or code-scanning platforms:

```bash
agentcsp scan . --format json,md,sarif --out .agentcsp
```

The generated SARIF file is:

```text
.agentcsp/agentcsp.sarif
```

SARIF run properties include `agentcsp_triage_summary` and `agentcsp_static_blast_radius` so CI systems can consume scan-level context without parsing Markdown.

## Scanner Safety

AgentCSP does not read or emit secret values by default. For `.env*` files, it records file presence and key names only. Evidence snippets are redacted, and raw file contents are not written to the manifest. RAG and memory files are reduced to normalized content signals rather than raw text.
