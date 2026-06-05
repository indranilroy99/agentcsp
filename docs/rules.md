# Rules

AgentCSP rules are constrained YAML files. They are designed to be reviewable, portable, and safe for open rule packs.

MVP rules operate on normalized manifest objects. They do not execute JavaScript or arbitrary code.

The preferred rule style is correlated and evidence-backed. For example, a high-confidence rule should combine multiple signals such as remote MCP plus credential-backed access, package-runner MCP launchers plus unpinned versions and credentials, instruction files plus untrusted context plus tool and memory bridges, tool-name collision plus authority mismatch, skill context inputs plus external output, prompt template variables plus tool/external directives, scheduled automation plus secrets and write authority, RAG content plus instruction-like tool directives, generated state plus instruction-like tool replay, external write plus credential-like tool input, local path input plus URL-like destination plus external write capability, open-world schema plus privileged tool authority, read-only hint conflicts plus side-effect signals, destructive action plus path-like input, unsandboxed runtime plus approval bypass, shell execution, write permissions, untrusted provenance, or irreversible side effects.

AgentCSP computes finding confidence from rule correlation depth, scoped object type, structured parsing, privileged actions, data class, external reach, and side-effect signals.

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
