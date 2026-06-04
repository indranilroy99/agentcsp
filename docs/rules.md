# Rules

AgentCSP rules are constrained YAML files. They are designed to be reviewable, portable, and safe for open rule packs.

MVP rules operate on normalized manifest objects. They do not execute JavaScript or arbitrary code.

The preferred rule style is correlated and evidence-backed. For example, a high-confidence rule should combine multiple signals such as external reach, shell execution, credential references, write permissions, untrusted provenance, or irreversible side effects.

Required fields:

- `id`
- `name`
- `description`
- `category`
- `severity`
- `maps_to`
- `match`
- `recommendation`

Example:

```yaml
id: AGENTCSP-TOOL-001
name: Package script exposes shell authority
category: unsafe_code_execution
severity: medium
match:
  object_type: tool
  where:
    - field: actions
      op: includes
      value: execute
recommendation:
  control: require_approval
  text: Require approval before agent-triggered shell execution.
```
