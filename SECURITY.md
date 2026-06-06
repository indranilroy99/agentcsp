# Security Policy

AgentCSP is an early-stage open-source AI security tool. Please report vulnerabilities responsibly so maintainers can validate impact, prepare fixes, and avoid exposing users to unnecessary risk.

## Supported Versions

Security fixes target the default branch until formal releases begin. After tagged releases exist, this policy will be updated with supported version ranges.

## Reporting a Vulnerability

Use GitHub private vulnerability reporting if it is available for this repository. If private reporting is not available, open a public issue that requests a maintainer contact path, but do not include exploit details, secrets, payloads, or proof-of-concept code in the public issue.

Useful reports include:

- affected version or commit
- reproducible steps
- expected and observed behavior
- security impact
- whether the issue exposes secrets, corrupts scan evidence, hides findings, or enables unsafe agent authority
- any relevant logs or fixtures with secrets removed

## Scope

In scope:

- scanner behavior that leaks secret values or raw sensitive context
- incorrect finding suppression or policy bypass
- rule or manifest behavior that materially misrepresents agent authority
- unsafe CLI behavior that reads outside the requested scan scope
- supply-chain or CI/CD issues that affect AgentCSP releases or packaged artifacts

Out of scope:

- findings in intentionally vulnerable demo fixtures
- reports that require access to private user data without authorization
- denial-of-service reports that rely only on unrealistic local resource exhaustion
- duplicate reports for already-known dependency advisories

## Handling

Maintainers should acknowledge security reports promptly, triage severity, keep raw exploit details private until a fix is available, and credit reporters when appropriate.
