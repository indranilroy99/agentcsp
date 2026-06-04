# AgentCSP Agent Instructions

This project is an enterprise-grade open-source AI security platform. Keep the tone, naming, UX, and documentation professional and security-team credible.

## Product Direction

AgentCSP is a centralized control plane for AI agent security. It should cover everything an agent can see, load, call, remember, or execute:

- skills and plugin files
- MCP servers and tool schemas
- system, developer, repository, and custom instructions
- shell, browser, GitHub, email, Slack, database, filesystem, and API tools
- sandbox, approval, network, and runtime config
- secrets paths and token references
- RAG indexes, source documents, and vector stores
- memory stores, run summaries, logs, transcripts, and cached tool outputs
- CI/CD workflows, scheduled jobs, webhooks, and background agents

## Design Bias

- Favor deterministic controls over model-only judgment.
- Treat untrusted context as tainted until policy explicitly allows it.
- Represent risk as data flow and authority, not just suspicious text.
- Keep runtime enforcement outside the agent where possible.
- Produce evidence suitable for security review, OSS maintainers, and auditors.
- Avoid vague guardrail language unless it maps to concrete enforcement.

## Initial Implementation Bias

Start with a practical MVP:

- local scanner
- manifest format
- policy file format
- red-team rule format
- blast-radius report
- CI-friendly JSON/SARIF output
- lightweight dashboard after the CLI data model is stable

