# Security Policy

## Supported Versions

AgentCSP is currently preparing its first public release. Security fixes are applied to the latest release line and `main`.

| Version | Supported |
| --- | --- |
| `0.2.x` | Yes |
| `< 0.2` | No |

## Reporting A Vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/indranilroy99/agentcsp/security/advisories/new). Do not include secrets, customer data, exploit traffic, or private repository content beyond the minimum needed to reproduce the issue.

Include:

- affected version or commit
- impact and attacker-controlled boundary
- minimal reproduction steps
- whether secret values, arbitrary file reads, command execution, policy bypass, or artifact tampering are involved
- any suggested mitigation

The maintainer will acknowledge a complete report as soon as practical, coordinate remediation privately, and credit reporters who request attribution. Public disclosure should wait until a fix or mitigation is available.

## Security Boundaries

AgentCSP scans potentially hostile repositories. Reports involving any of the following are especially important:

- reading or emitting secret values
- traversal outside the configured scan root
- repository-controlled policy weakening `ci-strict`
- arbitrary code execution from rule or configuration files
- symlink or path-swap attacks against trusted inputs or output artifacts
- predictable temporary files or unsafe output permissions
- malformed input causing unbounded CPU, memory, disk, or recursion
- SARIF, Markdown, terminal, or JSON injection
- stable-ID collisions that suppress or misattribute findings

## Scope

Static findings are advisory and do not prove runtime exploitation. Detection disagreements or false positives without a security boundary failure belong in the public issue tracker; scanner vulnerabilities belong in private reporting.
