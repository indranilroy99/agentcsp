<p align="center">
  <img src="docs/assets/agentcsp-mark.svg" width="112" alt="AgentCSP security mark">
</p>

<h1 align="center">AgentCSP</h1>

<p align="center"><strong>Static security analysis for AI agent repositories.</strong></p>

<p align="center">
  <a href="https://github.com/indranilroy99/agentcsp/actions/workflows/ci.yml"><img src="https://github.com/indranilroy99/agentcsp/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-2f6feb" alt="Apache 2.0 license"></a>
  <img src="https://img.shields.io/badge/node-%3E%3D22-339933" alt="Node.js 22 or newer">
  <img src="https://img.shields.io/badge/rules-advisory-6b7280" alt="Advisory rules">
</p>

AgentCSP inventories what an AI agent can see, load, call, remember, and execute. It turns repository configuration into a versioned agent manifest, evaluates open security rules, and produces evidence that security teams can review or route into CI.

It is local-first, vendor-neutral, and does not require a model, hosted service, or paid API.

```text
    ___                    __  __________
   /   | ____ ____  ____  / /_/ ____/ ___/____
  / /| |/ __ '/ _ \/ __ \/ __/ /    \__ \/ __ \
 / ___ / /_/ /  __/ / / / /_/ /___ ___/ / /_/ /
/_/  |_\__, /\___/_/ /_/\__/\____//____/ .___/
      /____/                           /_/

  [ context ]==>[ surface ]==>[ capability ]==>[ control ]
       trust        data class        authority       evidence
```

## What It Finds

AgentCSP correlates agent context with authority. The default ruleset focuses on conditions that are useful to investigate, including:

- unsandboxed or approval-bypassed agent runtimes
- credential-backed and remote MCP authority
- plaintext MCP credential transport and broad environment passthrough
- destructive or misleading tool schemas
- untrusted GitHub events reaching agent workflows with write authority
- secret-bearing, external, memory, RAG, and privileged-tool boundaries
- disabled agent safety controls around sensitive capabilities

The scanner also inventories instructions, skills, plugins, prompts, MCP servers, source-defined tools, package scripts, workflows, env key references, RAG sources, memory, runtime configuration, and automations.

AgentCSP reports a **Static Blast-Radius Summary**. It does not claim runtime reachability or exploitability.

## Ecosystem Coverage

AgentCSP has named repository-scoped adapters for Agents.md, Codex, Claude Code, Gemini CLI, Cursor, GitHub Copilot, Continue, OpenCode, Kiro, Cline, Roo Code, Windsurf, and Junie. It also retains generic discovery for MCP, skills, tools, prompts, workflows, RAG, memory, and agent frameworks.

See [Ecosystem Support](docs/ecosystem-support.md) for exact paths, normalized surfaces, and the boundary around user-global and deployed configuration.

## Quick Start

The current release candidate is built from source. npm publication is a separate release step.

```bash
git clone https://github.com/indranilroy99/agentcsp.git
cd agentcsp
corepack enable
pnpm install --frozen-lockfile
pnpm build
pnpm agentcsp scan . --out .agentcsp
```

Scan the included vulnerable fixture:

```bash
pnpm agentcsp scan examples/vulnerable-agent \
  --out .agentcsp \
  --format json,md,sarif
```

Artifacts are written transactionally:

```text
.agentcsp/
  agent-manifest.json   portable AI agent inventory
  findings.json         compact machine-readable findings
  report.md             analyst-readable report
  agentcsp.sarif        optional code-scanning output
  receipt.json          artifact digests and completion record
```

An existing output path is replaced only when it is empty or contains an intact AgentCSP-owned generation. Unknown files, symlinks, receipt drift, or digest mismatches stop publication without deleting the existing directory.

## Why Security Teams Use It

**One agent authority inventory.** AgentCSP normalizes fragmented instructions, tools, MCP configuration, workflows, memory, retrieval, and runtime posture into stable objects.

**Evidence instead of raw content.** Findings reference deterministic object and evidence IDs. Values and evidence snippets remain redacted by default.

**Explainable risk.** Every finding carries trust, data class, action, side effect, reversibility, external reach, secret exposure, and untrusted-to-privileged factors.

**CI without surprise failures.** Advisory scans exit `0` after a successful scan. Teams opt into severity gates; scanner integrity and coverage failures use distinct exit codes.

**Open detection content.** Rules are constrained YAML over normalized objects. They cannot execute custom JavaScript.

## Scan Profiles

| Profile | Intended use | Repository-controlled inputs | Default finding behavior |
| --- | --- | --- | --- |
| `advisory` | Local discovery and rollout | Project policy, rules, and `.agentcspignore` may be used | Findings do not fail the command unless `--fail-on` is set |
| `ci-strict` | Protected CI automation | Project policy, project rules, and project ignore files are ignored | Coverage and diagnostic integrity gates are enabled; finding gates remain operator-selected |

Use external, digest-pinned policy in strict CI:

```bash
agentcsp scan . \
  --profile ci-strict \
  --config /opt/security/agentcsp.yaml \
  --config-sha256 "$AGENTCSP_POLICY_SHA256" \
  --ruleset recommended \
  --fail-on high \
  --fail-on-confidence high \
  --format json,md,sarif \
  --quiet
```

`ci-strict` is an input-integrity profile, not a claim that static findings are runtime-proven. See [Detection Quality](docs/detection-quality.md).

## Rule Packs

| Pack | Size | Purpose | Enforcement status |
| --- | ---: | --- | --- |
| `recommended` | 17 rules | Bounded first-run coverage for structured, high-impact agent authority failures | Advisory only |
| `extended` | 383 rules | Broad research, hunting, fixture, and rule-development coverage | Advisory only |

```bash
agentcsp rules list
agentcsp rules explain AGENTCSP-RUNTIME-001
agentcsp scan . --ruleset extended
```

Finding confidence is capped by evidence support:

- `typed_path`: concrete typed adapter and authority path; maximum `very_high`
- `structured`: supported parser and correlated fields; maximum `high`
- `heuristic`: redacted text or path signal; maximum `medium`

No v0.2 rule is independently calibrated for automatic blocking. The synthetic conformance suite verifies parser and rule behavior but is explicitly ineligible as production precision evidence.

## Scanner Safety

- `.env*` files are parsed byte-by-byte for key names; values are never converted to strings.
- Evidence snippets are always `[redacted by default]`.
- Raw file contents are not copied into the manifest.
- Files and directories have configurable limits.
- `.git`, dependencies, generated output, caches, and logs are excluded by default.
- Hidden AI/security paths such as `.codex`, `.agents`, `.claude`, `.cline`, `.continue`, `.cursor`, `.github`, `.kiro`, `.opencode`, `.roo`, and `.windsurf` are included by default.
- `.agentcspignore` is supported in advisory scans.
- Output is staged, schema-validated, permission-restricted, atomically published, and accompanied by SHA-256 digests.
- Paths, object IDs, finding IDs, ordering, and fingerprints are deterministic.

## CLI Reference

```text
agentcsp scan [path]           scan a repository and write evidence
agentcsp config validate      validate policy without scanning
agentcsp rules list           inspect a built-in pack
agentcsp rules explain <id>   inspect one rule
agentcsp baseline create      create a versioned findings baseline
agentcsp baseline diff        compare current findings to a baseline
agentcsp baseline migrate     migrate a supported baseline
agentcsp doctor               verify runtime and packaged assets
agentcsp version --json       print compatibility metadata
```

Common scan options:

```text
--out <path>                    output directory (default: .agentcsp)
--profile advisory|ci-strict    scanner trust profile
--ruleset recommended|extended  built-in rule pack
--artifact-profile portable|internal
--config <path>                 policy file
--baseline <path>               prior findings or manifest
--format json,md,sarif          output formats
--fail-on <severity>            explicit finding gate
--fail-on-confidence <level>    minimum confidence for the finding gate
--fail-on-new                   gate only new baseline findings
--no-hidden                     skip hidden AI/security directories
--include-logs                  include log directories
--max-file-size <bytes>         per-file inspection limit
--max-files <count>             traversal limit
--max-directories <count>       directory traversal limit
--max-entries-per-directory <count>
--quiet                         suppress non-error output
```

Exit codes are stable:

| Code | Meaning |
| ---: | --- |
| `0` | Scan completed and configured gates passed |
| `1` | An explicitly configured finding gate failed |
| `2` | Invalid configuration or input |
| `3` | Scanner integrity, coverage, diagnostic, suppression, or packaged-artifact gate failed |
| `4` | Unexpected internal failure |

## Manifest Contract

`agent-manifest.json` is an SBOM-style record for AI agent systems. Its v0.2 contract includes:

- versioned scanner, schema, identity, and fingerprint metadata
- normalized surface objects and trust levels
- data classes and authority actions
- static relationships and bounded attack paths
- compact findings linked by stable object and evidence references
- scan coverage, diagnostics, triage, action plan, and CI gate summaries
- portable redaction by default, with an explicit internal artifact profile

Generated JSON Schemas are published from [`schemas/`](schemas). Format details are documented in [Manifest](docs/manifest.md).

## Policy And Baselines

`agentcsp.yaml` supports trust overrides, recommended controls, and owned, reasoned, expiring suppressions. Policy is advisory in v0.2; reports say "recommended control" and never claim an action was blocked or quarantined.

```bash
agentcsp config validate agentcsp.yaml
agentcsp baseline create .agentcsp/findings.json --out agentcsp-baseline.json
agentcsp baseline diff agentcsp-baseline.json .agentcsp/findings.json
```

See [Policy](docs/policy.md), [Rules](docs/rules.md), and [CI](docs/ci.md).

## Scope And Limitations

AgentCSP analyzes repository state. It cannot prove which configuration is deployed, whether a capability is reachable, or whether a condition is exploitable after environment, command-line, user-global, deployment, or operating-system overrides. Runtime enforcement adapters and the dashboard are deliberately outside the v0.2 scope.

The project is focused on AI agent security. It is not a general dependency or software supply-chain scanner.

## Development

```bash
pnpm install --frozen-lockfile
pnpm verify
```

`pnpm verify` checks schemas, versions, documentation links, the rule catalog, detection conformance, builds, packed tarballs, clean-room installation, CI examples, deterministic CycloneDX SBOM output, types, tests, fixture outputs, redaction invariants, and dependency audit results.

`pnpm verify:release` adds the 5,000-file, 100 MiB release benchmark documented in [Performance Envelope](docs/performance.md).

Repository layout:

```text
packages/core   scanner, schemas, rules, graph, policy, and reporting
packages/cli    command-line interface
rules           built-in open rule catalog and pack manifests
schemas         generated JSON Schemas
examples        safe and vulnerable agent repositories
docs            architecture, security model, usage, and operations
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing scanner or rule changes. Security issues should follow [SECURITY.md](SECURITY.md), not the public issue tracker.

## Project Status

v0.2.0 is a CLI-first release candidate. The scanner, artifacts, and lifecycle commands are implemented and covered by automated tests. Automatic rule blocking, runtime enforcement, a hosted service, and a dashboard are not part of this release.

## License

Apache License 2.0. See [LICENSE](LICENSE).
