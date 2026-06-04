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
```

## CI Behavior

AgentCSP does not fail CI by default. A completed scan exits with code `0` even when findings are present.

Use `--fail-on` to opt into failure behavior:

```bash
agentcsp scan . --fail-on high
```

Supported values are `high`, `medium`, and `low`.

## Scanner Safety

AgentCSP does not read or emit secret values by default. For `.env*` files, it records file presence and key names only. Evidence snippets are redacted, and raw file contents are not written to the manifest.
