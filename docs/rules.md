# Rules

AgentCSP rules are constrained YAML files. They are designed to be reviewable, portable, and safe for open rule packs.

MVP rules operate on normalized manifest objects. They do not execute JavaScript or arbitrary code.

## Rule Loading

AgentCSP always runs the built-in rule pack that ships with the scanner. When the scanned repository contains a project-local `rules/` directory, those rules are loaded additively after the built-in pack.

Malformed project-local rules, schema-invalid rules, and duplicate rule IDs are emitted as redacted diagnostics and skipped. They do not replace or disable built-in rules.

Package builds copy the built-in rule pack into `@agentcsp/core` under `dist/builtin-rules`, and the package allowlist includes that compiled distribution. Installed CLI builds should therefore load the same built-in rules without relying on repository-relative paths.

The preferred rule style is correlated and evidence-backed. For example, a high-confidence rule should combine multiple signals such as remote MCP plus credential-backed access, local MCP implementation paths missing from scan plus credentials and side effects, package-runner MCP launchers plus unpinned versions and credentials, runtime allowlists plus secret-backed MCP servers plus approval bypass, auto-approved destructive MCP tools plus credential-backed servers, auto-approved privileged runtime permissions plus secret env exposure, auto-approved runtime package scripts plus release authority, workflow automation plus agent package scripts plus secrets and write authority, instruction files plus untrusted context plus tool and memory bridges, tool-name collision plus authority mismatch, skill context inputs plus external output, prompt template variables plus explicit privileged-tool references, persisted memory plus explicit privileged-tool references, prompt template variables plus memory persistence, prompt template variables plus tool/external directives, scheduled automation plus secrets and write authority, RAG content plus instruction-like tool directives, retrieved content plus sensitive-context and external-egress directives, generated state plus instruction-like tool replay, external write plus credential-like tool input, external write plus prompt-like content input and URL destination, local path input plus URL-like destination plus external write capability, open-world schema plus privileged tool authority, read-only hint conflicts plus side-effect signals, destructive action plus path-like input, unsandboxed runtime plus approval bypass, shell execution, write permissions, untrusted provenance, or irreversible side effects.

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
