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

Default missing policy files are allowed and do not produce diagnostics. If a policy file exists but cannot be parsed, fails schema validation, or an explicitly supplied `--config` path is missing, AgentCSP records a redacted scan diagnostic and continues with empty advisory policy. Relative `--config` paths are resolved from the scanned project root, while absolute paths can point to shared policy files outside the repository.

This keeps scanner output available for CI, SARIF, and audit review while making policy failures visible through `diagnostics` and `scan_coverage` diagnostic counters. Diagnostics for policy files outside the scanned root use `<external-policy-config>` instead of exposing absolute local paths. Use `--fail-on-diagnostics` when policy health issues should fail CI.

## Policy Integrity Signals

AgentCSP also models project-local policy files as scan-control posture. A policy file can be security-sensitive because it can change trust levels, downgrade recommended controls, or suppress findings before CI gates evaluate them.

The scanner records redacted policy-integrity metadata for:

- broad suppressions that match high or critical severity without a specific finding, object, or rule
- long-lived active suppressions
- `allow` or `warn` recommended controls scoped to high-impact findings
- trust overrides that mark untrusted context paths as trusted, project, or workspace scope

Policy-integrity metadata does not emit raw suppression IDs, owners, reasons, paths, categories, or match values.

## Recommended Controls

Recommended controls let a team strengthen or change a finding recommendation without suppressing evidence.

They are advisory in v1. When a policy control matches, AgentCSP updates `recommended_control` and records a `policy_control` object with the previous control, reason, match fields, match scope, change direction, and application time.

Internal-profile JSON findings retain the full policy-control reason for protected audit workflows. Portable JSON, Markdown, and SARIF redact the reason by default while preserving whether the control was strengthened, weakened, or unchanged, how narrowly the policy matched, and which match fields were used.

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

Suppressions are explicit accepted-risk records. They do not delete findings from JSON, Markdown, or SARIF output. Active suppressions are excluded from `--fail-on` gates, while expired suppressions remain active risk. Use `--fail-on-expired-suppressions` when CI should block stale waivers even when no severity threshold is configured.

Internal-profile JSON findings retain suppression ownership, reason, expiry, matched fields, and deterministic match scope for protected audit workflows. Portable JSON, Markdown, and SARIF redact ownership and reasons by default while preserving suppression status, expiry, match scope, and matched-field context for shared CI artifacts.

Suppression match scope is derived from the fields that matched a finding:

- `specific_finding`
- `specific_object`
- `rule_and_path`
- `rule`
- `path`
- `category`
- `severity`
- `broad`

Treat broader scopes such as `category`, `severity`, or `broad` as accepted-risk records that need stronger review, shorter expiry, and clear security ownership.

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
