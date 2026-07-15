# Contributing to AgentCSP

AgentCSP accepts focused contributions to the scanner, schemas, rules, fixtures, documentation, and CLI. Changes should preserve the project's local-first security model and produce evidence a security team can explain.

## Development Setup

Requirements:

- Node.js 20 or newer
- Corepack
- pnpm 11.0.9

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm build
pnpm test
```

Run the complete release gate before opening a pull request:

```bash
pnpm verify
```

## Contribution Principles

- Keep the core fully open source, local-first, self-hostable, and vendor-neutral.
- Prefer deterministic parsing and policy over model-only judgment.
- Treat repository content as untrusted input.
- Never add fixture secrets, credentials, private URLs, customer data, or raw transcripts.
- Do not emit raw source, prompt, memory, log, or secret values in findings.
- Use "recommended control" language until runtime enforcement exists.
- Keep project-local rules constrained to data; custom code execution is not accepted.
- Preserve stable IDs, ordering, schemas, and exit-code contracts unless the change includes an explicit migration.

## Scanner Changes

Scanner pull requests should include:

- a safe fixture and a vulnerable fixture when both states are meaningful
- parser-failure and oversized-input behavior
- redaction assertions for every sensitive input field
- deterministic output assertions
- tests for near misses and conflicting configuration
- documentation of unsupported or ambiguous forms

Use typed or structured parsers where practical. Heuristic text detection must remain bounded and cannot claim more than `medium` confidence.

## Rule Changes

Every rule must:

- match normalized manifest fields
- combine signals that materially reduce false positives
- include OWASP, MITRE ATLAS, and NIST AI RMF mappings
- provide a concrete recommended control
- include positive, negative, and near-miss tests
- remain advisory unless the independent calibration process in [`docs/detection-quality.md`](docs/detection-quality.md) is complete

Run:

```bash
pnpm verify:rules
pnpm benchmark:rules
```

Rule count is not a quality metric. A smaller precise pack is preferred to broad critical findings.

## Schemas And Compatibility

Zod schemas are the source of truth. After schema changes, run:

```bash
pnpm generate:schemas
pnpm verify:schemas
```

Call out changes to manifest, finding, evidence, baseline, identity, or CLI compatibility in the pull request. Breaking changes require a versioned migration plan.

## Pull Requests

Keep each pull request scoped to one concern. Include:

- the security problem and affected trust boundary
- the implementation approach
- tests and commands run
- user-visible output changes
- compatibility or migration impact
- residual limitations

Do not include generated scan output, temporary baselines, local credentials, or unrelated formatting changes.

## Reporting Security Issues

Do not open a public issue for a vulnerability. Follow [`SECURITY.md`](SECURITY.md).
