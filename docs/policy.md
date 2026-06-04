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

## Suppressions

Suppressions are explicit accepted-risk records. They do not delete findings from JSON, Markdown, or SARIF output. Active suppressions are excluded from `--fail-on` gates, while expired suppressions remain active risk.

Every suppression requires:

- `id`
- `reason`
- `owner`
- `expires_at`
- `match`

Example:

```yaml
suppressions:
  - id: "accepted-risk-demo-package-script"
    reason: "Demo fixture intentionally contains a network-to-shell package script."
    owner: "security@example.com"
    expires_at: "2026-12-31T23:59:59.000Z"
    match:
      rule_id: "AGENTCSP-TOOL-002"
      path: "examples/vulnerable-agent/package.json"
```

Supported match fields:

- `finding_id`
- `rule_id`
- `object_id`
- `path`
- `category`
- `severity`
