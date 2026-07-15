# TODOS

## Runtime Security

### Runtime policy adapters

**What:** Enforce AgentCSP policy before sensitive MCP, tool, memory, browser, shell, and external-write actions.

**Why:** Static recommendations cannot stop unsafe actions after deployment.

**Pros:** Converts proven static controls into deterministic runtime prevention outside the model.

**Cons:** Requires framework-specific adapters, identity, fail-open/fail-closed semantics, latency budgets, and a separate threat model.

**Context:** Begin only after the CLI policy, finding, identity, and evidence contracts are stable in a public release. Reuse the trusted-policy authority and typed graph contracts from `docs/production-hardening.md`; do not embed enforcement inside an agent prompt.

**Effort:** L
**Priority:** P2
**Depends on:** Production-ready CLI schema and trusted-policy contract

### Signed evidence bundles

**What:** Add tamper-evident signatures and attestations for manifests, findings, policies, and rule-pack identities.

**Why:** Auditors and distributed control planes need proof that evidence was produced by an approved scanner and was not modified.

**Pros:** Enables durable audit chains and trustworthy ingestion.

**Cons:** Key management, rotation, verification UX, and attestation interoperability add substantial operational complexity.

**Context:** The v0.2 schema should reserve issuer and digest fields without claiming signatures. Evaluate Sigstore-compatible attestations after npm provenance and release identity are operational.

**Effort:** M
**Priority:** P3
**Depends on:** Stable manifest schema and release provenance

## Platform

### Local-first security dashboard

**What:** Build a self-hostable dashboard for inventory, history, triage, policy, exceptions, and blast-radius evidence.

**Why:** Security teams eventually need organization-wide workflows that are inefficient across individual repository artifacts.

**Pros:** Enables fleet visibility, ownership, trends, governance, and collaboration.

**Cons:** Introduces storage, authentication, tenancy, migrations, deployment, backup, and upgrade obligations before CLI adoption is proven.

**Context:** The dashboard must consume the public CLI artifact contracts rather than importing scanner internals. Start with local Docker deployment and vendor-neutral object storage/database interfaces only after real users validate the CLI data model.

**Effort:** L
**Priority:** P3
**Depends on:** Stable CLI artifacts, compatibility policy, and design-partner usage

### Deployment and workload inventory

**What:** Correlate repository manifests with deployed agent identities, commits, environments, workloads, and scanner attestations.

**Why:** Repository posture alone cannot prove which agent version is running or where its authority is deployed.

**Pros:** Unlocks organization inventory, drift detection, deployment risk, and incident scoping.

**Cons:** Requires collectors, identity resolution, deployment integrations, and a durable service-side model.

**Context:** First add optional source identity fields to portable manifests. Defer collectors and organization persistence until the dashboard architecture is approved.

**Effort:** L
**Priority:** P3
**Depends on:** Local-first dashboard and source identity schema

## Detection

### AST and interprocedural adapters

**What:** Introduce AST-backed JavaScript and TypeScript analysis, then extend it incrementally to additional languages and interprocedural scenarios.

**Why:** Regex and heuristic analysis cannot reliably prove aliases, wrappers, sanitizers, or interprocedural source-to-sink flow.

**Pros:** Improves confidence and expands graph-native blocking eligibility.

**Cons:** Each language/framework needs versioned source, sink, sanitizer, and performance models plus a labeled corpus.

**Context:** v0.2 source analysis is heuristic; structured JSON, YAML, and TOML configuration has stronger parser support. Add one AST adapter at a time. A new adapter remains advisory until its support tier, limitations, and independent holdout calibration satisfy the blocking-pack contract.

**Effort:** L
**Priority:** P2
**Depends on:** Adapter interface, reducer, graph rules, and benchmark protocol

### Sensitive deep-scan mode

**What:** Add an explicit opt-in mode for deeper secret and sensitive-content inspection.

**Why:** Some incident-response and pre-commit workflows need more than key names and credential references.

**Pros:** Can identify exposed values or sensitive content that reference-only scanning cannot see.

**Cons:** Raises collection, retention, process-memory, terminal, artifact, and legal risks.

**Context:** Default scanning must continue to avoid secret values. Deep scan requires an isolated threat model, explicit consent, no-value output guarantees, retention controls, and dedicated leak tests.

**Effort:** M
**Priority:** P3
**Depends on:** Production scanner safety and artifact privacy profiles

### 10,000-file scale gate

**What:** Raise the documented performance corpus from the default 5,000-file scope to 10,000 files and larger monorepos.

**Why:** Enterprise monorepos may exceed the first release's bounded default.

**Pros:** Expands enterprise applicability and validates worker scheduling and memory behavior.

**Cons:** Premature optimization before real scan profiles are measured could distort the architecture.

**Context:** First ship repeatable 5,000-file benchmarks and collect anonymized local timing summaries only with explicit user opt-in. Raise limits after bottlenecks are measured.

**Effort:** M
**Priority:** P2
**Depends on:** Fixed-runner benchmark and production performance telemetry design

## Integrations

### Native security workflow integrations

**What:** Add optional PR annotations, ticket creation, SIEM export, Slack, and email routing.

**Why:** Mature security programs need findings in existing triage systems.

**Pros:** Reduces manual routing and improves ownership workflows.

**Cons:** Adds vendor APIs, credentials, rate limits, data-sharing controls, and ongoing compatibility work.

**Context:** JSON and SARIF remain the vendor-neutral release interfaces. Prioritize native integrations only after usage shows where those formats are insufficient; no integration may be required for core scanning.

**Effort:** M
**Priority:** P3
**Depends on:** Stable artifact schemas and demonstrated user demand

## Completed

No completed deferred items yet.
