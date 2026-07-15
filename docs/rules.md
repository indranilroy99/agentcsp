# Rules

AgentCSP rules are constrained YAML documents evaluated against normalized manifest objects. Rules are data, not plugins: they cannot execute JavaScript, shell commands, templates, or network requests.

## Packs

| Pack | Selection | Purpose | Status |
| --- | --- | --- | --- |
| Recommended | `--ruleset recommended` | Bounded first-run detections for structured, high-impact agent authority failures | Advisory |
| Extended | `--ruleset extended` | Broad research, hunting, fixture, and rule-development coverage | Advisory |

The CLI defaults to `recommended`. The pack manifest is [`rules/packs/recommended.json`](../rules/packs/recommended.json).

```bash
agentcsp rules list
agentcsp rules list --ruleset extended
agentcsp rules explain AGENTCSP-RUNTIME-001
```

No v0.2 rule is eligible for automatic blocking. See [Detection Quality](detection-quality.md).

## Loading And Trust

Built-in rules ship inside `@agentcsp/core`. In the advisory profile, a repository may add rules under `rules/`; project rules are additive and cannot replace a built-in rule ID.

Project rules are always normalized to:

- `origin: project`
- `maturity: experimental`
- `disposition: advisory`
- `suppressibility: policy`

The `ci-strict` profile ignores repository rules entirely. Malformed, duplicate, or schema-invalid rules produce redacted diagnostics.

## Schema

Required fields:

- `id`
- `name`
- `description`
- `category`
- `severity`
- `maps_to`
- `match`
- `recommendation`

Optional evidence-governance fields:

- `maturity`: `calibrated`, `stable`, or `experimental`
- `disposition`: reserved schema field; v0.2 normalizes detections to `advisory`
- `suppressibility`: `never`, `trusted_policy_only`, or `policy`
- `support_tier`: `typed_path`, `structured`, or `heuristic`

Supported surface types:

```text
agent instruction skill plugin mcp_server tool prompt rag_source memory
secret runtime_config ci_cd automation
```

Supported operators:

| Operator | Behavior |
| --- | --- |
| `equals`, `not_equals` | Exact scalar comparison |
| `includes` | Array contains one exact value |
| `contains_any` | Array contains any supplied exact value |
| `exists` | Field is present and non-null |
| `in` | Actual scalar is present in a supplied array |
| `gt`, `gte`, `lt`, `lte` | Numeric comparison |

All conditions in `match.where` must pass. Empty condition arrays are rejected by the rule verifier.

## Example

```yaml
id: AGENTCSP-TOOL-004
maturity: stable
disposition: advisory
suppressibility: policy
support_tier: structured
name: Tool schema exposes destructive filesystem authority
description: >-
  An agent-callable tool accepts a filesystem path and exposes a destructive
  operation, creating irreversible local authority.
category: tool_schema_authority
severity: critical
maps_to:
  owasp:
    - "LLM06:2025 Excessive Agency"
  mitre_atlas:
    - "AML.T0051 LLM Plugin Compromise"
  nist_ai_rmf:
    - "MANAGE 2.4"
match:
  object_type: tool
  where:
    - field: metadata.parsed_tool_schema
      op: equals
      value: true
    - field: metadata.accepts_path_input
      op: equals
      value: true
    - field: reversible
      op: equals
      value: false
recommendation:
  control: require_approval
  text: Require approval and constrain destructive filesystem operations to an allowlisted workspace root.
```

## Quality Requirements

A recommended rule should correlate multiple independent facts. A keyword, filename, SDK import, environment lookup, or single disabled flag is not enough for a high-severity finding by itself.

Rule changes require:

1. A written risk condition stated independently of implementation literals.
2. Positive fixtures representing the exact unsafe conjunction.
3. Negative fixtures where one required condition is absent.
4. Near-miss fixtures for safe values, negation, inactive profiles, and conflicting fields.
5. Redaction assertions proving no raw source, values, URLs, prompts, or secrets are emitted.
6. A specific control that changes the unsafe boundary.
7. OWASP, MITRE ATLAS, and NIST AI RMF mappings.

Run:

```bash
pnpm verify:rules
pnpm benchmark:rules
pnpm test
```

`pnpm verify:rules` rejects duplicate IDs, schema errors, empty conditions, invalid operators, missing framework mappings, and weak recommendations.

## Confidence

Confidence is computed from correlation depth, object scope, parsing support, data class, authority, external reach, side effects, and reversibility. The evidence tier sets a hard ceiling:

- `typed_path`: maximum `very_high`
- `structured`: maximum `high`
- `heuristic`: maximum `medium`

Confidence describes static evidence for the matched condition. It does not establish deployment, reachability, or exploitability.

## Pack Integrity

Package builds copy rules to `packages/core/dist/builtin-rules`. The release gate verifies:

- source and packaged rule counts match
- the recommended manifest references existing IDs
- tarballs contain the built-in catalog
- a clean installed CLI can load and run the packaged rules
- rule fingerprints are deterministic

A missing or invalid packaged rule catalog is an integrity error and exits with code `3`.
