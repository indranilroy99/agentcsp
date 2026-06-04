# Durable Context

This file captures decisions from the initial planning conversation.

## Project Decision

The project name is AgentCSP.

Professional positioning:

AgentCSP is an open-source control plane for discovering, testing, and enforcing security policy across AI agents, tools, skills, MCP servers, RAG, memory, and runtime actions.

## Key Requirement

The scanner must include everything available to the AI agent:

- skill files and scripts
- plugin metadata and assets
- MCP server configs and schemas
- prompts and instruction files
- tools and external integrations
- runtime config and approval settings
- secrets paths and auth references
- memory and RAG stores
- automation and generated state

## Strategic Take

The market has many isolated scanners and guardrail libraries. AgentCSP should not compete as another prompt scanner. Its center of gravity is agent attack surface management, provenance-aware policy, runtime enforcement, red-team validation, and audit evidence.

## Initial Build Recommendation

Start as a local CLI plus manifest/report generator. Add dashboard and runtime enforcement after the data model is solid.

