# Policy

`agentcsp.yaml` is advisory in v1. It supports trust overrides, recommended controls, and suppressions.

Runtime enforcement comes later through MCP and agent-framework adapters.

Example:

```yaml
schema_version: "0.1"

trust_overrides:
  - path: "rag/**"
    trust_level: "untrusted"
```

Reports use "recommended controls" until runtime adapters can enforce decisions before tool calls or sensitive memory writes.

## Policy Health

Default missing policy files are allowed and do not produce diagnostics. If a policy file exists but cannot be parsed, fails schema validation, or an explicitly supplied `--config` path is missing, AgentCSP records a redacted scan diagnostic and continues with empty advisory policy.

This keeps scanner output available for CI, SARIF, and audit review while making policy failures visible through `diagnostics` and `scan_coverage` diagnostic counters. Use `--fail-on-diagnostics` when policy health issues should fail CI.

## Recommended Controls

Recommended controls let a team strengthen or change a finding recommendation without suppressing evidence.

They are advisory in v1. When a policy control matches, AgentCSP updates `recommended_control` and records a `policy_control` object with the previous control, reason, match fields, and application time.

Example:

```yaml
recommended_controls:
  - id: "deny-unsandboxed-runtime"
    reason: "Organization policy forbids unsandboxed runtime without approval."
    control: "deny"
    match:
      rule_id: "AGENTCSP-RUNTIME-001"
      path: ".codex/config.toml"
```

Supported match fields:

- `finding_id`
- `rule_id`
- `object_id`
- `path`
- `category`
- `severity`
- `confidence`
- `object_type`
- `trust_level`
- `data_class`
- `action`

Dotted fields are also supported for exact matches against finding fields, such as `matched_object.metadata.parsed_runtime_config`.

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
      path: "package.json"
```

Supported match fields:

- `finding_id`
- `rule_id`
- `object_id`
- `path`
- `category`
- `severity`
