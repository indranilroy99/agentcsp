# Product Brief

## Name

AgentCSP

## Positioning

Context Security Policy for AI Agents.

AgentCSP is an open-source control plane for AI agent attack surface management, policy enforcement, red-team validation, and evidence generation.

## Problem

AI agent security is fragmented. Teams have scanners, prompt filters, red-team harnesses, guardrail libraries, and MCP tools, but they lack one coherent view of:

- what agents can access
- where untrusted context enters
- which tools and credentials are exposed
- whether memory and RAG can be poisoned
- what actions require approval
- what evidence exists after a policy decision

## Target Users

- AppSec teams securing AI-enabled applications
- platform teams deploying internal agents
- OSS maintainers triaging AI-generated security reports
- AI engineers building RAG and tool-using systems
- security researchers publishing AI attack and defense rules
- governance teams needing control mappings and evidence

## Differentiator

AgentCSP builds a provenance and authority graph:

`untrusted_webpage -> agent_context -> tool_call:shell -> reads:.env -> outbound_request`

That graph drives scanning, red-team generation, policy enforcement, and blast-radius analysis.

## Non-Goals

- Do not build a generic chatbot platform.
- Do not rely on prompt filtering as the primary security boundary.
- Do not become another isolated benchmark runner.
- Do not require vendor lock-in or a hosted service for core value.

