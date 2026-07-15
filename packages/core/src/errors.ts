export type AgentCspErrorKind = "input" | "configuration" | "integrity" | "internal";

export class AgentCspError extends Error {
  readonly code: string;
  readonly kind: AgentCspErrorKind;
  readonly fix: string;
  readonly help: string;

  constructor(input: {
    code: string;
    kind: AgentCspErrorKind;
    problem: string;
    fix: string;
    help: string;
    cause?: unknown;
  }) {
    super(input.problem, input.cause === undefined ? undefined : { cause: input.cause });
    this.name = "AgentCspError";
    this.code = input.code;
    this.kind = input.kind;
    this.fix = input.fix;
    this.help = input.help;
  }
}

export function isAgentCspError(error: unknown): error is AgentCspError {
  return error instanceof AgentCspError;
}
