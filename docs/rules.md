# Rules

AgentCSP rules are constrained YAML files. They are designed to be reviewable, portable, and safe for open rule packs.

MVP rules operate on normalized manifest objects. They do not execute JavaScript or arbitrary code.

## Rule Loading

AgentCSP always runs the built-in rule pack that ships with the scanner. When the scanned repository contains a project-local `rules/` directory, those rules are loaded additively after the built-in pack.

Malformed project-local rules, schema-invalid rules, and duplicate rule IDs are emitted as redacted diagnostics and skipped. They do not replace or disable built-in rules.

Package builds copy the built-in rule pack into `@agentcsp/core` under `dist/builtin-rules`, and the package allowlist includes that compiled distribution. Installed CLI builds should therefore load the same built-in rules without relying on repository-relative paths.

The preferred rule style is correlated and evidence-backed. For example, a high-confidence rule should combine multiple signals such as remote MCP plus credential-backed access, remote MCP plus plaintext transport plus credential-backed access, local MCP implementation paths missing from scan plus credentials and side effects, package-runner MCP launchers plus unpinned versions and credentials, runtime allowlists plus secret-backed MCP servers plus approval bypass, auto-approved destructive MCP tools plus credential-backed servers, auto-approved privileged runtime permissions plus secret env exposure, auto-approved runtime package scripts plus release authority, authenticated browser sessions plus broad origins plus untrusted navigation plus click/form authority, authenticated browser sessions plus remote debugging and cookie/storage profile references, inbound email/chat/ticket/webhook payloads plus agent invocation plus tool/write authority plus credentials plus no approval, multi-agent delegation plus untrusted input plus shared memory plus privileged specialist tools plus credentials plus no approval, live eval harnesses plus adversarial prompts plus production agents plus privileged tools plus credentials plus no approval, disabled agent safety controls plus untrusted input plus privileged tools plus credentials plus no approval, SaaS connectors plus broad write scopes plus credentials plus untrusted input without approval, secret managers plus read/list scope plus tool injection plus untrusted input without approval, agent identity delegation plus credential issuance plus service-account impersonation plus broad scopes plus untrusted subject inputs without approval, remote extension loaders plus auto-install plus unpinned unsigned capabilities plus untrusted selector inputs plus privileged authority without approval, agent self-modification plus untrusted inputs plus auto-applied writes to instructions, policy, runtime config, and tool definitions without approval, model-mediated approval gates plus untrusted approval context plus default-allow behavior plus auto-executed privileged actions without a required human reviewer, context composers plus untrusted retrieval/tool/browser/memory context promoted into system or developer roles plus disabled sanitization and privileged tool authority, remote/shared memory stores plus untrusted writes plus tool-output, prompt, retrieval, and secret capture plus replay into future agent context plus no approval, artifact/output export plus public remote destination plus prompt, tool-output, browser, retrieval, memory, PII, or secret capture plus disabled redaction, webhook/callback egress plus model-generated or untrusted payloads, sensitive context, disabled redaction, credential reference, and no approval gate, privileged agent container plus Docker socket, host-root mount, host networking, credentials, untrusted input, and no approval gate, code interpreter runtime plus model-generated code execution, network/package-install authority, filesystem or credential mounts, untrusted input, output persistence, and no approval gate, AI training dataset export plus model-update authority, remote upload, prompt/tool/retrieval/memory/PII/secret capture, disabled redaction, untrusted inputs, credential reference, and no approval gate, LLM prompt cache plus shared remote storage, prompt/completion/tool/retrieval/memory/PII/secret capture, disabled redaction, replay into future calls, untrusted inputs, credential reference, and no approval gate, AI model router plus automatic third-party fallback, sensitive context forwarding, disabled redaction, untrusted input, credential reference, and no approval gate, AI model endpoint plaintext transport plus sensitive context plus credential reference, AI telemetry remote export plus sensitive capture plus disabled redaction, workflow automation plus agent package scripts plus secrets and write authority, workflow event payloads plus agent package scripts plus secrets and write authority, instruction files plus untrusted context plus tool and memory bridges, broad always-applied Cursor rules plus untrusted-to-privileged context bridges, remote vector-store connectors plus credentials plus untrusted write/sync ingestion, tool-name collision plus authority mismatch, skill context inputs plus external output, prompt template variables plus explicit privileged-tool references, prompt template variables plus system/developer role-boundary injection, persisted memory plus explicit privileged-tool references, prompt template variables plus memory persistence, prompt template variables plus tool/external directives, scheduled automation plus secrets and write authority, RAG content plus instruction-like tool directives, retrieved content plus sensitive-context and external-egress directives, generated state plus instruction-like tool replay, model-visible tool descriptions plus instruction override plus external/write authority, external write plus credential-like tool input, external write plus prompt-like content input and URL destination, local path input plus URL-like destination plus external write capability, open-world schema plus privileged tool authority, read-only hint conflicts plus side-effect signals, destructive action plus path-like input, unsandboxed runtime plus approval bypass, shell execution, write permissions, untrusted provenance, or irreversible side effects.

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
