# Governance

AgentCSP is maintained as an open-source AI security project. The current repository owner and lead maintainer is [Indranil Roy](https://github.com/indranilroy99).

## Decision Process

- Routine fixes and documentation changes are reviewed through pull requests.
- New scanner surfaces require a defined trust boundary, redaction contract, fixtures, and tests.
- New recommended rules require evidence-quality review and negative cases.
- Breaking schema, identity, policy, or CLI changes require a written proposal and migration plan.
- Automatic blocking or runtime enforcement changes require the independent calibration and threat-model review defined in `docs/detection-quality.md`.

The lead maintainer makes final release and security decisions while the project has a single-maintainer governance model. Decisions should be documented in issues, pull requests, architecture records, or release notes so they can be revisited as the maintainer group grows.

## Maintainer Responsibilities

- protect the local-first and vendor-neutral core
- keep product claims aligned with demonstrated behavior
- require redaction and hostile-input tests
- manage private vulnerability reports and coordinated disclosure
- publish reproducible release notes and verification evidence
- avoid merging changes that inflate finding volume without improving analyst value

## Becoming A Maintainer

Sustained contributors may be invited after demonstrating sound judgment across code review, detection quality, compatibility, and security response. Future maintainers will be listed in this file with their areas of responsibility.
