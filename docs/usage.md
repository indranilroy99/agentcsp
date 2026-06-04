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

## Scanner Safety

AgentCSP does not read or emit secret values by default. For `.env*` files, it records file presence and key names only. Evidence snippets are redacted, and raw file contents are not written to the manifest.
