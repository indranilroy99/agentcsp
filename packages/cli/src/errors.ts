import { AgentCspError, isAgentCspError } from "@agentcsp/core";
import { CommanderError } from "commander";

export type LogFormat = "text" | "json";

export function configurationError(problem: string, fix: string): AgentCspError {
  return new AgentCspError({
    code: "AGENTCSP-E1002",
    kind: "configuration",
    problem,
    fix,
    help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md"
  });
}

export function normalizeCliError(error: unknown): AgentCspError {
  if (isAgentCspError(error)) return error;
  if (error instanceof CommanderError) {
    return configurationError(error.message, "Run the command with --help and correct the invalid option or argument.");
  }
  if (isZodError(error)) {
    return configurationError(
      "Scanner configuration failed validation.",
      "Review the command options and policy schema, then rerun the scan."
    );
  }
  const code = nodeErrorCode(error);
  if (code === "ENOENT") {
    return new AgentCspError({
      code: "AGENTCSP-E1001",
      kind: "input",
      problem: "A required scan path or file does not exist.",
      fix: "Check the scan root and configured input paths, then rerun the command.",
      help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md#scan"
    });
  }
  if (code === "EACCES" || code === "EPERM") {
    return new AgentCspError({
      code: "AGENTCSP-E1003",
      kind: "input",
      problem: "AgentCSP does not have permission to read an input or write the output.",
      fix: "Grant the minimum required filesystem permission or select an accessible path.",
      help: "https://github.com/indranilroy99/agentcsp/blob/main/docs/usage.md#troubleshooting"
    });
  }
  return new AgentCspError({
    code: "AGENTCSP-E4001",
    kind: "internal",
    problem: "AgentCSP encountered an unexpected internal failure.",
    fix: "Rerun with the same pinned version and report the error code with a minimal redacted reproduction.",
    help: "https://github.com/indranilroy99/agentcsp/issues",
    cause: error
  });
}

export function renderCliError(error: AgentCspError, format: LogFormat): string {
  if (format === "json") {
    return JSON.stringify({
      type: "agentcsp_error",
      code: error.code,
      category: error.kind,
      problem: error.message,
      fix: error.fix,
      help: error.help
    });
  }
  return [
    `${error.code} ${error.kind} error`,
    `Problem: ${error.message}`,
    `Fix: ${error.fix}`,
    `Help: ${error.help}`
  ].join("\n");
}

export function exitCodeForError(error: AgentCspError): 2 | 3 | 4 {
  if (error.kind === "integrity") return 3;
  if (error.kind === "internal") return 4;
  return 2;
}

export function requestedLogFormat(argv: string[]): LogFormat {
  const optionIndex = argv.findIndex((value) => value === "--log-format");
  if (optionIndex >= 0 && argv[optionIndex + 1] === "json") return "json";
  return argv.includes("--log-format=json") ? "json" : "text";
}

function isZodError(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "name" in error && error.name === "ZodError");
}

function nodeErrorCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object" || !("code" in error)) return undefined;
  return typeof error.code === "string" ? error.code : undefined;
}
