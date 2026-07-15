# Ecosystem Support

AgentCSP is vendor-neutral, but repository layouts are not. The scanner uses named adapters for documented repository-scoped configuration so that security teams can see which agent surface was discovered rather than receiving a generic file hit.

The adapters below are discovery and normalization adapters. They do not claim runtime reachability, deployed configuration, or enforcement.

| Ecosystem | Repository-scoped coverage | Normalized surfaces |
| --- | --- | --- |
| Agents.md | `AGENTS.md` at any repository depth | Instructions |
| Codex | `AGENTS.md`, `.codex/` runtime configuration, Codex plugin manifests | Instructions, runtime configuration, plugins |
| Claude Code | `CLAUDE.md`, `.claude/commands/`, `.claude/agents/`, `.claude/` runtime configuration | Instructions, runtime configuration, MCP |
| Gemini CLI | `GEMINI.md` | Instructions |
| Cursor | `CURSOR.md`, `.cursor/rules/`, `.cursor/` runtime configuration | Instructions, runtime configuration, MCP |
| GitHub Copilot | `.github/copilot-instructions.md`, `.github/instructions/**/*.instructions.md`, `.github/agents/**/*.md`, `.github/prompts/**/*.prompt.md` | Instructions and prompts |
| Continue | `.continue/config.{yaml,yml,json}`, `.continue/mcpServers/`, `.continue/rules/`, `.continue/prompts/`, `.continue/agents/` | Instructions, runtime configuration, MCP |
| OpenCode | `opencode.json`, `.opencode/agents/`, `.opencode/commands/`, `.opencode/skills/`, `.opencode/` runtime configuration | Instructions, runtime configuration |
| Kiro | `.kiro/steering/`, `.kiro/prompts/`, `.kiro/agents/`, `.kiro/settings/mcp.json`, `.kiro/hooks/`, `.kiro/permissions.yaml` | Instructions, runtime configuration, MCP |
| Cline | `.cline/` configuration, rules/workflows, `mcp_settings.json` | Instructions, runtime configuration, MCP |
| Roo Code | `.roo/` configuration, rules/workflows, `mcp.json` | Instructions, runtime configuration, MCP |
| Windsurf | `.windsurf/rules/`, `.windsurf/workflows/`, `.windsurf/` runtime configuration | Instructions, runtime configuration |
| Junie | `.junie/**/*.md` | Instructions |

MCP discovery accepts the common object form (`mcpServers: { name: ... }`) and array form (`mcpServers: [{ name: ... }]`) in JSON and YAML configuration files. Server endpoint values, header values, secret values, prompt text, and evidence snippets remain redacted.

## Scope Boundaries

Default scans are repository-scoped. AgentCSP does not automatically read user-home, organization-managed, IDE-managed, remote, or deployed configuration because those sources are environment-specific and can contain sensitive data. A repository scan can identify the local files it sees; it cannot prove which higher-precedence configuration is effective at runtime.

If an ecosystem is not listed, AgentCSP still applies its generic discovery for `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, skills, MCP JSON, tool schemas, workflows, prompt directories, RAG, memory, and common runtime configuration names. Additions to the named adapter catalog require a fixture, parser behavior, and redaction test.
