# Roadmap

AgentCSP is focused on AI agent security. General software supply-chain scanning is outside the product scope.

## v0.2: Trustworthy CLI Foundation

Status: release candidate.

- local repository scanner for instructions, skills, plugins, MCP, tools, runtime, CI, RAG, memory, env references, and automations
- versioned manifest, findings, evidence, baseline, identity, and artifact receipt contracts
- bounded recommended pack and complete extended research catalog
- advisory and protected `ci-strict` profiles
- portable and internal artifact profiles
- deterministic IDs, ordering, fingerprints, compact references, and transactional output
- JSON, Markdown, and SARIF
- static relationships, bounded attack paths, and Static Blast-Radius Summary
- lifecycle commands for config, rules, baselines, doctor, and compatibility metadata
- safe and vulnerable fixtures, redaction invariants, package smoke tests, and a measured 5,000-file/100 MiB envelope

Release criteria:

- all schemas, tests, fixtures, redaction checks, packages, CI examples, dependency audit, and scale benchmark pass
- public claims match static behavior
- no rule can become automatically blocking through rule-file metadata
- npm and GitHub artifacts have checksums and provenance when published

## v0.3: Detection Precision

- replace broad adapters with typed, versioned support for leading agent and MCP configuration formats
- split the extended catalog into explicit research packs by platform and security domain
- publish a sanitized, versioned evaluation corpus with independent labels and adjudication records
- add case-level detection quality reports, duplicate accounting, parser coverage, and regression history
- promote a small number of rules only after the blocking criteria in `docs/detection-quality.md` are met
- add graph-edge rule evaluation over finding-independent relationship facts
- improve source locations and remediation validation steps without exposing raw content

## v0.4: Organization Workflows

- signed manifest and policy bundle verification
- organization rule packs loaded only from protected external inputs
- baseline and suppression review workflows with ownership and expiry reporting
- repository fleet aggregation through local or self-hosted storage
- stable diff and migration contracts across scanner versions
- integration contracts for GitHub, GitLab, and common security data platforms

The CLI, schemas, and scanner remain independently usable without a hosted service.

## Runtime Phase

- MCP proxy and framework adapters that enforce policy outside the agent process where practical
- pre-tool approval, deny, redaction, and quarantine controls
- runtime reachability and observed data-flow evidence
- signed or tamper-evident decision records
- clear separation between static posture, deployed configuration, and observed runtime behavior

Runtime enforcement will not reuse static severity as an authorization decision. Each adapter requires its own threat model, bypass analysis, and fail-safe behavior.

## Platform Phase

After CLI and runtime contracts stabilize:

- self-hosted manifest and evidence registry
- agent inventory, ownership, and control coverage
- policy lifecycle and exception governance
- trend, regression, and deployment comparison views
- local deployment first, with optional cloud deployment

No empty dashboard application is maintained before the data contracts are ready.

## Deferred Ideas

- app-specific red-team generation from proven authority paths
- secure RAG and memory persistence experiments
- ecosystem rule exchange and signed community packs
- deeper deployed-environment discovery

These are discovery tracks, not commitments for the current release.
