# Product Brief

## Product

AgentCSP is a local-first static security analysis tool for AI agent repositories.

It answers one operational question: **what context and data can influence which agent capability, with what authority and control posture?**

## Problem

Agent systems distribute security-relevant behavior across repository instructions, skills, MCP servers, tool schemas, runtime settings, workflows, retrieval, memory, logs, and credential references. Traditional application scanners rarely assemble those surfaces into an agent authority model. Prompt filters see model input but not the surrounding execution system.

Security teams need a reproducible inventory and evidence model before they can decide what requires approval, isolation, redaction, or investigation.

## Users

- application-security teams reviewing agent-enabled products
- platform-security teams governing internal agent runtimes and MCP access
- AI engineers validating tool, retrieval, memory, and workflow configuration
- open-source maintainers evaluating agent-related security changes
- security researchers developing reviewable AI security detections
- governance teams mapping evidence to OWASP, MITRE ATLAS, and NIST AI RMF

## v0.2 Product Contract

AgentCSP v0.2:

1. scans a local repository without a model or hosted service
2. inventories normalized AI agent surfaces and authority
3. evaluates a bounded advisory ruleset
4. emits a versioned agent manifest, findings, Markdown, SARIF, and artifact receipt
5. reports scan coverage and a Static Blast-Radius Summary
6. supports protected CI inputs, explicit gates, policy, suppressions, and baselines
7. preserves secret values and raw evidence outside emitted artifacts by default

The core is open source, self-hostable, vendor-neutral, and usable offline after dependencies are installed.

## Differentiation

AgentCSP does not score isolated suspicious strings. It normalizes three dimensions together:

```text
provenance and trust -> data and context -> capability and side effect
```

That lets an analyst distinguish a read-only local tool from an external credential-backed write path, or an inert instruction file from untrusted context that can influence privileged automation.

The product is intentionally evidence-led:

- every finding links to a normalized object and redacted evidence
- confidence is capped by parser support
- severity factors are explicit
- scan health is never hidden behind a clean finding count
- automatic blocking requires independent calibration, not a YAML severity label

## Current Boundary

AgentCSP is a repository posture scanner. It does not prove deployed runtime state, reachability, exploitation, or control enforcement. Policy actions are recommendations in v0.2.

The dashboard, manifest registry, runtime telemetry, graph traversal across deployed systems, and enforcement adapters are later phases built on the same data contracts.

## Non-Goals

- general software dependency or supply-chain scanning
- a chatbot or agent orchestration platform
- model-only prompt filtering as a security boundary
- hidden proprietary rule execution
- mandatory cloud ingestion
- claims of runtime blocking before adapters and calibration exist

## Success Measures

- security teams can get trustworthy first evidence in under two minutes
- the default pack produces bounded, explainable findings
- safe fixtures remain clean and vulnerable fixtures retain expected detections
- portable artifacts remain redacted, deterministic, compact, and CI-friendly
- scanner failures and partial coverage are distinguishable from security findings
- rule promotion is based on independent evidence rather than rule count
