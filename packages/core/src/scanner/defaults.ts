export const DEFAULT_MAX_FILE_SIZE_BYTES = 1024 * 1024;
export const DEFAULT_MAX_FILES = 5000;

export const DEFAULT_EXCLUDED_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
  ".next",
  ".turbo",
  ".cache",
  "cache",
  "tmp",
  "temp"
]);

export const DEFAULT_INCLUDED_HIDDEN_DIRS = new Set([
  ".codex",
  ".agents",
  ".claude",
  ".cursor",
  ".github"
]);

export const DEFAULT_MCP_CONFIG_NAMES = new Set([
  "mcp.json",
  "mcp.config.json",
  ".mcp.json",
  "claude_desktop_config.json"
]);

export const INSTRUCTION_FILE_NAMES = new Set([
  "AGENTS.md",
  "CLAUDE.md",
  "GEMINI.md",
  "CURSOR.md",
  "SYSTEM.md",
  "system.md",
  "instructions.md",
  "prompt.md",
  "prompts.md"
]);

export const PROMPT_DIR_NAMES = new Set([
  "prompts",
  "prompt_templates",
  "prompt-templates",
  "templates"
]);

export const RAG_DIR_NAMES = new Set([
  "rag",
  "retrieval",
  "embeddings",
  "vectors",
  "vectorstore",
  "vector_store",
  "knowledge",
  "documents"
]);

export const MEMORY_DIR_NAMES = new Set([
  "memory",
  "memories",
  "transcripts",
  "summaries",
  "state"
]);

export const GENERATED_STATE_DIR_NAMES = new Set([
  "logs",
  "log",
  "transcripts",
  "summaries",
  "state",
  "runs",
  "sessions",
  "outputs",
  "tool-output",
  "tool_outputs"
]);

export const LOG_DIR_NAMES = new Set(["logs", "log"]);
