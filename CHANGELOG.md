# Changelog

All notable changes to AgentCSP are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses semantic versioning for published packages.

## [Unreleased]

## [0.2.0] - 2026-07-15

### Added

- v0.2 manifest, finding, evidence, baseline, and artifact receipt contracts
- advisory and protected `ci-strict` scan profiles
- curated `recommended` and research-oriented `extended` rule packs
- portable and internal artifact privacy profiles
- deterministic stable IDs and compact object/evidence references
- transactional output generation with restrictive permissions, locking, rollback, and SHA-256 receipts
- classified CLI errors and stable exit codes
- `config validate`, `rules list`, `rules explain`, `baseline create`, `baseline diff`, `baseline migrate`, `doctor`, and machine-readable `version` commands
- explicit trusted-input digest verification for external policy and baselines
- byte-oriented `.env` key-name scanning that never converts values to strings
- static graph relationships, bounded attack paths, and Static Blast-Radius Summary
- redacted parser, field-path, profile, and normalized-classification evidence for runtime posture
- synthetic parser/rule conformance suite with explicit non-enforcement status
- bounded directory-count and per-directory entry traversal controls with incomplete-scan diagnostics
- deterministic CycloneDX 1.6 release SBOM for the lockfile-resolved production dependency graph
- release-gated local documentation-link verification
- hosted Linux, Windows, and macOS compatibility jobs that pack and clean-install the release artifacts
- regression coverage for trusted policy and baseline inputs that are not regular files

### Changed

- default CLI ruleset is the bounded 17-rule `recommended` pack
- generated artifacts use portable root paths and omit duplicated internal metadata
- project policy, project rules, and `.agentcspignore` are ignored in `ci-strict`
- heuristic evidence is capped at `medium` confidence and structured evidence at `high`
- runtime security values use exact semantic classification instead of broad substring matches
- workflow credential posture recognizes actual GitHub token and secret-context references without treating disabled credential persistence as exposure
- package smoke tests install the packed tarballs through pnpm and invoke the CLI through Node for Windows-compatible release verification
- public product language describes static posture analysis and recommended controls, not runtime enforcement

### Security

- output is staged and schema-validated before atomic publication
- existing output is replaced only when empty or cryptographically verified as an AgentCSP-owned generation
- untrusted project rule text is rendered inert in Markdown and SARIF help content
- release workflows use immutable action SHAs and separate read-only build authority from protected publication authority
- CI isolates `security-events: write` in a push-only SARIF publication job after read-only verification
- secret values and raw evidence snippets remain outside emitted artifacts by default
- no v0.2 rule can self-promote to automatic blocking through YAML metadata
- digest-pinned policy and baseline parsing consumes the exact bytes verified from the opened file handle
- `ci-strict` rejects every explicit policy or baseline that is not protected by a matching digest
