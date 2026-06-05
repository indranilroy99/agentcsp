# Production Hardening Plan

AgentCSP should become useful to cybersecurity teams by producing high-confidence findings with evidence, not by maximizing alert volume.

## Quality Bar

A finding should be considered production-grade when it includes:

- normalized object type
- file path
- trust level
- data class
- authority/action
- side effect and reversibility
- external reach
- secret exposure signal
- reason
- confidence and confidence rationale
- confidence-aware CI failure gates
- baseline comparison for new, existing, and resolved findings
- scan coverage counts for skipped files, ignored paths, and traversal limits
- redacted parser diagnostics for malformed security-relevant configuration
- negation-aware action classification so safety policy text is not treated as granted authority
- MCP package-runner posture for unpinned third-party runtime launchers
- tool-name collision metadata for authority ambiguity and shadowing
- tool-schema integrity signals for open-world privileged arguments and read-only hint conflicts
- tool-schema path-to-external data-flow signals for exfiltration risk
- prompt-template variables and redacted context signals for untrusted-input bridges
- skill data-flow signals for context-to-external-output bridges
- recommended control
- OWASP, MITRE ATLAS, and NIST AI RMF mappings where applicable
- redacted evidence

## High-Signal Rule Strategy

Prefer correlated rules over keyword rules.

Examples:

- network retrieval plus shell execution
- MCP server plus credential key names plus side effects
- remote third-party MCP server plus auth headers or credential references
- package-runner MCP server plus unpinned package version plus credential exposure
- tool-name collision plus different authority signatures and a privileged peer
- skill consumes retrieved/tool/memory context plus external publication
- prompt template with user/customer/context variables plus tool or external directives
- runtime config with unsandboxed execution plus no approval gate
- runtime config with network access plus secret env keys plus privileged tools
- pull request workflow plus write permissions plus secrets
- untrusted RAG source plus privileged tool path
- memory write plus untrusted source provenance
- RAG or memory content with instruction-like text plus tool/external directives
- generated transcripts or cached tool output with instruction-like tool/external directives
- local path input plus URL-like destination plus external write capability
- open-world tool schema plus external, filesystem, credential, or execution authority
- read-only tool hint plus destructive or external write behavior
- scheduled or externally dispatched automation plus secrets and write authority
- package publish/release authority plus agent-influenced workflow
- attack paths that connect specific context-risk signals to concrete privileged capabilities

## CI Expectations

Every production change should pass:

- reproducible install from lockfile
- TypeScript check
- unit tests
- build
- high/critical dependency audit for the tool's own release hygiene
- fixture scan
- SARIF validation

## Near-Term Production Work

- Add SARIF upload examples for adopters.
- Add MCP and tool schema parsing beyond config files.
- Expand runtime configuration inventory across more agent frameworks.
- Continue expanding graph edges between context sources, capabilities, data classes, and side effects while keeping heuristic-only paths out of prioritized attack paths.
- Add attack-path regression fixtures for common production AI architectures.
- Add suppression and waiver workflow with expiry.
- Calibrate confidence levels across larger true-positive and false-positive fixture sets.
- Add multi-fixture regression tests for true positives and false positives.
- Add benchmarking against known vulnerable agent patterns.
