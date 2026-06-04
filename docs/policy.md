# Policy

`agentcsp.yaml` is advisory in v1. It supports trust overrides and recommended controls.

Runtime enforcement comes later through MCP and agent-framework adapters.

Example:

```yaml
schema_version: "0.1"

trust_overrides:
  - path: "rag/**"
    trust_level: "untrusted"
```

Reports use "recommended controls" until runtime adapters can enforce decisions before tool calls or sensitive memory writes.
