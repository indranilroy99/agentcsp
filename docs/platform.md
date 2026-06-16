# AgentCSP Platform Direction

AgentCSP can grow into a centralized AI agent security control plane without turning the open CLI into a hosted-only product.

The platform should be built on the same open contracts as the CLI:

- Agent Manifest
- findings JSON
- SARIF
- YAML rules
- `agentcsp.yaml` policy
- evidence records

The CLI now emits an `inventory_summary` inside each Agent Manifest. The platform should treat that summary as the first registry index for repository-level AI authority: total normalized objects, surface mix, trust mix, data-class mix, action mix, and high-authority counts. Detailed object records remain available for drill-down, but dashboards should use the summary for fast portfolio views.

## Product Thesis

The platform should answer higher-order security questions that standalone scanners miss:

- Which agents exist across the organization?
- Which agents can reach secrets, browsers, shell, databases, GitHub, Slack, email, or external APIs?
- Which MCP servers and tools are trusted, third-party, untrusted, or unknown?
- Which RAG and memory sources can carry poisoned context across sessions?
- Which repositories expose risky agent-triggered authority through package scripts, CI workflows, plugins, skills, or tool schemas?
- Which policies are missing, advisory, enforced, or failing?
- Which findings have enough evidence to support security review or audit?

## Deployment Models

AgentCSP should support three deployment profiles:

1. **Local single-user**
   - CLI plus local web UI.
   - SQLite database.
   - No network dependency.

2. **Self-hosted team**
   - Docker Compose or Kubernetes.
   - Postgres for manifests, findings, and evidence.
   - Object storage for report artifacts.
   - OIDC/SAML-ready auth boundary.

3. **Cloud-hosted optional**
   - Same backend model as self-hosted.
   - Tenant isolation, audit logging, and hosted workers.
   - Optional, never required for core scanning.

## Platform Modules

- **Manifest Registry**: stores versioned Agent Manifests per repo, agent, environment, and commit.
- **AI SBOM Explorer**: inventories skills, plugins, MCP servers, tools, prompts, memory, RAG, secrets references, runtime config, and CI/CD authority.
- **Trust Registry**: tracks approved MCP servers, tool schemas, plugins, skills, data sources, and model/runtime integrations.
- **Policy Center**: manages `agentcsp.yaml`, trust overrides, recommended controls, waivers, and future enforcement modes.
- **Evidence Console**: shows redacted evidence, risk factors, mappings to OWASP/MITRE/NIST, owner, status, and audit history.
- **Blast-Radius Graph**: visualizes context-to-capability-to-data-to-side-effect paths.
- **Attack Path Explorer**: ranks provenance-to-authority paths by severity, confidence, and recommended control.
- **Red-Team Lab**: generates and runs adversarial scenarios from discovered surfaces.
- **RAG and Memory Lab**: tests retrieval poisoning, memory persistence, source provenance, and contamination paths.
- **Agent Authority View**: correlates package scripts, GitHub Actions, MCP servers, plugin metadata, generated state, and secrets references as agent-reachable authority.
- **CI/CD and SARIF Integrations**: imports scan results and exports findings to code-scanning systems.

## Design Standard

The platform should look like a serious security operations product:

- dense but readable tables
- clear risk hierarchy
- neutral professional palette
- restrained charts
- graph views only where they explain authority or data flow
- no decorative gimmicks
- no vague "AI guardrail" language
- every finding must show evidence, risk factors, and recommended control

## Architecture

```text
repo / agent runtime
        |
        v
AgentCSP CLI / scanner workers
        |
        v
manifest + findings + SARIF + evidence
        |
        v
ingestion API ---- policy engine ---- rule registry
        |
        v
manifest registry / evidence store / graph index
        |
        v
platform UI / reports / integrations
```

## Product Guardrails

- The CLI remains useful without the platform.
- The platform should not require paid model APIs for core value.
- Evidence snippets stay redacted unless explicitly configured.
- Runtime enforcement remains outside the agent where feasible.
- Findings should prioritize authority, provenance, data class, and side effects over generic suspicious text.
